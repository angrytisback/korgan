//! Hardened outbound HTTP client builder and bounded response reader.

use std::time::Duration;

use reqwest::Client;

use crate::ports::errors::PortError;

/// Maximum allowed response body size for outbound HTTP requests (64 KB).
pub const MAX_OUTBOUND_RESPONSE_BYTES: usize = 64 * 1024;

/// Constructs a hardened [`reqwest::ClientBuilder`] with strict timeouts, no redirects,
/// and HTTPS enforcement.
pub fn create_hardened_client_builder(allow_http: bool) -> reqwest::ClientBuilder {
    #[allow(unused_mut)]
    let mut builder = Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none());

    #[cfg(not(test))]
    if !allow_http {
        builder = builder.https_only(true);
    }

    #[cfg(test)]
    let _ = allow_http;

    builder
}

/// Constructs a hardened [`reqwest::Client`] with strict timeouts, no redirects,
/// and HTTPS enforcement.
pub fn create_hardened_client(
    service_name: &'static str,
    allow_http: bool,
) -> Result<Client, PortError> {
    create_hardened_client_builder(allow_http)
        .build()
        .map_err(|e| {
            PortError::external_service(
                service_name,
                format!("failed to initialize HTTP client: {e}"),
                Some(Box::new(e)),
            )
        })
}

/// Reads an HTTP response body with an enforced maximum byte limit to prevent unbounded memory consumption.
pub async fn read_response_body_limited(
    service_name: &'static str,
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, PortError> {
    if response
        .content_length()
        .is_some_and(|len| len > max_bytes as u64)
    {
        let content_length = response.content_length().unwrap_or_default();
        return Err(PortError::external_service(
            service_name,
            format!(
                "response Content-Length ({content_length} bytes) exceeded maximum allowed limit of {max_bytes} bytes"
            ),
            None,
        ));
    }

    let mut buffer = Vec::new();

    while let Some(chunk) = response.chunk().await.map_err(|e| {
        PortError::external_service(
            service_name,
            format!("failed to read response chunk: {e}"),
            Some(Box::new(e)),
        )
    })? {
        if buffer.len().saturating_add(chunk.len()) > max_bytes {
            return Err(PortError::external_service(
                service_name,
                format!("response body exceeded maximum allowed limit of {max_bytes} bytes"),
                None,
            ));
        }
        buffer.extend_from_slice(&chunk);
    }

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_http_request(socket: &mut tokio::net::TcpStream) {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 1024];
        let mut total = 0;
        while total < buf.len() {
            match socket.read(&mut buf[total..]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total += n;
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
    }

    #[test]
    fn test_create_hardened_client_succeeds() {
        let client = create_hardened_client("test-service", false);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_read_response_body_limited_within_bound() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                read_http_request(&mut socket).await;
                let payload = b"Hello, secure world!";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nHello, secure world!",
                    payload.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
                let _ = socket.shutdown().await;
            }
        });

        let client = reqwest::Client::new();
        let resp = client.get(format!("http://{addr}")).send().await?;
        let body = read_response_body_limited("test", resp, 64 * 1024).await?;
        assert_eq!(body, b"Hello, secure world!");
        Ok(())
    }

    #[tokio::test]
    async fn test_read_response_body_limited_exceeds_bound_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                read_http_request(&mut socket).await;
                let payload = vec![b'A'; 70 * 1024]; // 70 KB > 64 KB
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(&payload).await;
                let _ = socket.flush().await;
                let _ = socket.shutdown().await;
            }
        });

        let client = reqwest::Client::new();
        let resp = client.get(format!("http://{addr}")).send().await?;
        let res = read_response_body_limited("test", resp, 64 * 1024).await;
        let Err(err) = res else {
            return Err("expected error from oversized response body".into());
        };
        assert!(err.to_string().contains("exceeded maximum allowed limit"));
        Ok(())
    }
}
