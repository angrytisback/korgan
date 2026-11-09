//! Authentication use cases: register, verify e-mail, login, verify MFA,
//! refresh and logout.

pub mod issue_ws_ticket;
pub mod login;
pub mod refresh;
pub mod register;
pub mod verify_email;
pub mod verify_ws_ticket;

pub use issue_ws_ticket::{IssueWsTicketUseCase, WsTicketResult};
pub use login::{LoginConfig, LoginUseCase};
pub use refresh::RefreshSessionUseCase;
pub use register::{DEFAULT_EMAIL_VERIFICATION_TTL, RegisterUserUseCase};
pub use verify_email::VerifyEmailUseCase;
pub use verify_ws_ticket::VerifyWsTicketUseCase;
