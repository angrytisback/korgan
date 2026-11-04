//! Mail adapters: console, SMTP and Resend senders (selected via
//! `mail.provider`).

pub mod console;
pub mod resend;
pub mod smtp;

pub use console::ConsoleMailProvider;
pub use resend::ResendMailProvider;
pub use smtp::SmtpMailProvider;
