//! Console mail provider for local development.

use async_trait::async_trait;
use tracing::info;

use crate::domain::value_objects::EmailAddress;
use crate::ports::errors::PortError;
use crate::ports::services::MailProvider;

/// Console mail adapter that logs email content to tracing/stdout.
///
/// Intended strictly for local development and integration tests.
#[derive(Debug, Clone, Default)]
pub struct ConsoleMailProvider {
    from_address: String,
}

impl ConsoleMailProvider {
    /// Creates a new [`ConsoleMailProvider`].
    #[must_use]
    pub fn new(from_address: impl Into<String>) -> Self {
        Self {
            from_address: from_address.into(),
        }
    }
}

#[async_trait]
impl MailProvider for ConsoleMailProvider {
    async fn send_email(
        &self,
        to: &EmailAddress,
        subject: &str,
        text_body: &str,
        html_body: &str,
    ) -> Result<(), PortError> {
        info!(
            from = %self.from_address,
            to = %to.as_str(),
            subject = %subject,
            text_body = %text_body,
            html_body = %html_body,
            "--------------------------------------------------------------------------------\n\
             [DEV EMAIL DISPATCHED TO CONSOLE]\n\
             FROM:    {}\n\
             TO:      {}\n\
             SUBJECT: {}\n\
             -------------------------------- TEXT BODY -------------------------------------\n\
             {}\n\
             -------------------------------- HTML BODY -------------------------------------\n\
             {}\n\
             --------------------------------------------------------------------------------",
            self.from_address,
            to.as_str(),
            subject,
            text_body,
            html_body
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn console_provider_sends_email() -> TestResult {
        let provider = ConsoleMailProvider::new("no-reply@example.com");
        let to = EmailAddress::parse("user@example.com")?;
        let res = provider
            .send_email(
                &to,
                "Verify your email",
                "Code: 123456",
                "<p>Code: 123456</p>",
            )
            .await;
        assert!(res.is_ok());
        Ok(())
    }
}
