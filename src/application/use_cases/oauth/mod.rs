//! OAuth2 external authentication use cases.

pub mod callback;
pub mod generate_url;

pub use callback::OAuthCallbackUseCase;
pub use generate_url::GenerateOAuthUrlUseCase;
