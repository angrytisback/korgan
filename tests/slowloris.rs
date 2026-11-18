//! Slow-client (slow-loris) protection of the HTTP server loop (KRG-SEC-18).

use std::time::{Duration, Instant};

use axum::Router;
use axum::routing::get;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn start(
    header_timeout: Duration,
) -> Result<(std::net::SocketAddr, tokio::sync::oneshot::Sender<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let app = Router::new().route("/ping", get(|| async { "pong" }));
    tokio::spawn(async move {
        let _ = korgan::serve_with_header_timeout(
            listener,
            app,
            async {
                let _ = rx.await;
            },
            Duration::from_secs(2),
            header_timeout,
        )
        .await;
    });
    Ok((addr, tx))
}

#[tokio::test]
async fn connection_with_incomplete_headers_is_closed_after_the_header_timeout() -> TestResult {
    let (addr, _stop) = start(Duration::from_millis(500)).await?;

    let mut slow = TcpStream::connect(addr).await?;
    slow.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\nX-Slow: ")
        .await?;

    let started = Instant::now();
    let mut buf = [0u8; 256];
    let read = tokio::time::timeout(Duration::from_secs(5), slow.read(&mut buf)).await?;
    // Either an HTTP 408 or a plain close is acceptable; what matters is that
    // the server gave up long before our own 5 s patience ran out.
    assert!(read.is_ok());
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "server kept an incomplete-header connection open for {:?}",
        started.elapsed()
    );
    Ok(())
}

#[tokio::test]
async fn well_behaved_clients_are_unaffected_and_shutdown_is_graceful() -> TestResult {
    let (addr, stop) = start(Duration::from_millis(500)).await?;

    let mut ok = TcpStream::connect(addr).await?;
    ok.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await?;
    let mut body = String::new();
    ok.read_to_string(&mut body).await?;
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    assert!(body.ends_with("pong"), "{body}");

    let _ = stop.send(());
    // New connections are refused (or immediately dropped) after shutdown.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let refused = TcpStream::connect(addr).await.is_err();
    assert!(refused, "listener must be closed after shutdown");
    Ok(())
}
