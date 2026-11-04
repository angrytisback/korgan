//! End-to-end tests of the Phase 1 HTTP foundation: routing, RFC 9457 error
//! contract, correlation ids and security headers.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::response::Response;
use http::header::{CONTENT_TYPE, RETRY_AFTER};
use http::{Method, Request, StatusCode};
use korgan::adapters::inbound::http::ProblemDetails;
use korgan::build_app;
use korgan::config::Settings;
use tower::ServiceExt;
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// Throwaway key material generated solely for tests.
const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\\n-----END PRIVATE KEY-----";
const TEST_AES: &str = "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=";

fn app_with(extra: &[(&str, &str)]) -> Result<Router, Box<dyn std::error::Error>> {
    let mut env = HashMap::from([
        (
            "DATABASE_URL".to_owned(),
            "postgres://u:p@localhost:5432/db".to_owned(),
        ),
        ("REDIS_URL".to_owned(), "redis://localhost:6379".to_owned()),
        (
            "KORGAN__CRYPTO__ED25519_PRIVATE_KEY_PEM".to_owned(),
            TEST_PEM.to_owned(),
        ),
        (
            "KORGAN__CRYPTO__AES_MASTER_KEY".to_owned(),
            TEST_AES.to_owned(),
        ),
        ("KORGAN__RATE_LIMIT__ENABLED".to_owned(), "false".to_owned()),
    ]);
    for (key, value) in extra {
        env.insert((*key).to_owned(), (*value).to_owned());
    }
    let settings = Arc::new(Settings::load_from_env(env)?);
    Ok(build_app(settings)?)
}

fn app() -> Result<Router, Box<dyn std::error::Error>> {
    app_with(&[])
}

async fn send(app: Router, request: Request<Body>) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app.oneshot(request).await?)
}

async fn problem_of(response: Response) -> Result<ProblemDetails, Box<dyn std::error::Error>> {
    let bytes = to_bytes(response.into_body(), 64 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn header<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
    response.headers().get(name).and_then(|v| v.to_str().ok())
}

fn get(uri: &str) -> Result<Request<Body>, http::Error> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
}

#[tokio::test]
async fn health_live_returns_ok() -> TestResult {
    let response = send(app()?, get("/health/live")?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header(&response, "content-type"), Some("application/json"));

    let bytes = to_bytes(response.into_body(), 1024).await?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(json, serde_json::json!({ "status": "ok" }));
    Ok(())
}

#[tokio::test]
async fn unknown_route_is_rfc9457_with_request_id_instance() -> TestResult {
    let response = send(app()?, get("/does/not/exist")?).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        header(&response, CONTENT_TYPE.as_str()),
        Some("application/problem+json")
    );

    let request_id = header(&response, "x-request-id")
        .ok_or("missing x-request-id")?
        .to_owned();
    let problem = problem_of(response).await?;
    assert_eq!(problem.code, "RESOURCE_NOT_FOUND");
    assert_eq!(problem.status, 404);
    assert_eq!(problem.instance, format!("urn:uuid:{request_id}"));
    Ok(())
}

#[tokio::test]
async fn framework_method_error_is_normalised_to_problem_json() -> TestResult {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/health/live")
        .body(Body::empty())?;
    let response = send(app()?, request).await?;

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        header(&response, "content-type"),
        Some("application/problem+json")
    );
    assert!(header(&response, "allow").is_some_and(|v| v.contains("GET")));
    let problem = problem_of(response).await?;
    assert_eq!(problem.code, "METHOD_NOT_ALLOWED");
    Ok(())
}

#[tokio::test]
async fn oversized_body_is_rejected_with_problem_json() -> TestResult {
    let app = app_with(&[("KORGAN__SERVER__REQUEST_BODY_LIMIT_BYTES", "16")])?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/health/live")
        .header(CONTENT_TYPE, "application/json")
        .header("content-length", "1024")
        .body(Body::from(vec![b'a'; 1024]))?;
    let response = send(app, request).await?;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        header(&response, "content-type"),
        Some("application/problem+json")
    );
    let problem = problem_of(response).await?;
    assert_eq!(problem.code, "PAYLOAD_TOO_LARGE");
    Ok(())
}

#[tokio::test]
async fn valid_incoming_request_id_is_propagated() -> TestResult {
    let id = Uuid::now_v7().to_string();
    let request = Request::builder()
        .uri("/health/live")
        .header("x-request-id", &id)
        .body(Body::empty())?;
    let response = send(app()?, request).await?;
    assert_eq!(header(&response, "x-request-id"), Some(id.as_str()));
    Ok(())
}

#[tokio::test]
async fn invalid_incoming_request_id_is_replaced_by_uuid_v7() -> TestResult {
    let request = Request::builder()
        .uri("/health/live")
        .header("x-request-id", "definitely-not-a-uuid")
        .body(Body::empty())?;
    let response = send(app()?, request).await?;

    let generated = header(&response, "x-request-id").ok_or("missing x-request-id")?;
    let parsed = Uuid::parse_str(generated)?;
    assert_eq!(parsed.get_version(), Some(uuid::Version::SortRand));
    Ok(())
}

#[tokio::test]
async fn security_headers_are_present() -> TestResult {
    let response = send(app()?, get("/health/live")?).await?;
    assert_eq!(header(&response, "x-content-type-options"), Some("nosniff"));
    assert_eq!(header(&response, "x-frame-options"), Some("DENY"));
    assert_eq!(header(&response, "referrer-policy"), Some("no-referrer"));
    assert_eq!(header(&response, "cache-control"), Some("no-store"));
    assert!(header(&response, "strict-transport-security").is_some());
    assert!(header(&response, "content-security-policy").is_some());
    Ok(())
}

#[tokio::test]
async fn openapi_document_describes_the_problem_schema() -> TestResult {
    let response = send(app()?, get("/api-docs/openapi.json")?).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    let doc: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert!(doc.pointer("/paths/~1health~1live/get").is_some());
    assert!(doc.pointer("/components/schemas/ProblemDetails").is_some());
    assert!(
        doc.pointer("/paths/~1health~1live/get/responses/500/content/application~1problem+json")
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn scalar_docs_ui_is_served() -> TestResult {
    let response = send(app()?, get("/docs")?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(header(&response, "content-security-policy").is_none());
    Ok(())
}

#[tokio::test]
async fn cors_preflight_allows_only_configured_origins() -> TestResult {
    let preflight = |origin: &str| {
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/health/live")
            .header("origin", origin)
            .header("access-control-request-method", "GET")
            .body(Body::empty())
    };

    let allowed = send(app()?, preflight("http://localhost:3000")?).await?;
    assert_eq!(
        header(&allowed, "access-control-allow-origin"),
        Some("http://localhost:3000")
    );
    assert_eq!(
        header(&allowed, "access-control-allow-credentials"),
        Some("true")
    );

    let denied = send(app()?, preflight("https://evil.example")?).await?;
    assert!(header(&denied, "access-control-allow-origin").is_none());
    Ok(())
}

#[tokio::test]
async fn normaliser_preserves_protocol_headers() -> TestResult {
    // axum answers a wrong method with 405 + `Allow`; the normaliser must keep
    // `Allow` while replacing the body, and must not invent `Retry-After`.
    let request = Request::builder()
        .method(Method::DELETE)
        .uri("/health/live")
        .body(Body::empty())?;
    let response = send(app()?, request).await?;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(response.headers().get(http::header::ALLOW).is_some());
    assert!(response.headers().get(RETRY_AFTER).is_none());
    Ok(())
}
