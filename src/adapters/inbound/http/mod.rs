//! Inbound HTTP adapter (axum): router, state, handlers, middleware, RFC 9457
//! error rendering and OpenAPI documentation.

pub mod error;
pub mod extractors;
pub mod handlers;
pub mod middleware;
pub mod openapi;
pub mod router;
pub mod state;

pub use error::{ApiError, ApiResult, ErrorKind, FieldError, ProblemDetails};
pub use router::{RouterError, build_router};
pub use state::AppState;
