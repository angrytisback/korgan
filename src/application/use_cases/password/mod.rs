//! Password use cases: forgot password, reset password and change password.

pub mod change;
pub mod forgot;
pub mod reset;

pub use change::ChangePasswordUseCase;
pub use forgot::{DEFAULT_PASSWORD_RESET_TTL, ForgotPasswordUseCase};
pub use reset::{DEFAULT_PASSWORD_HISTORY_DEPTH, ResetPasswordUseCase};
