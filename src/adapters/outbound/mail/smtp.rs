//! SMTP mail provider using `lettre` with TLS and authentication support.

use async_trait::async_trait;
use lettre::message::{Mailbox, MultiPart, SinglePart, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use secrecy::ExposeSecret;

use crate::config::{SmtpSettings, SmtpTls};
use crate::domain::value_objects::EmailAddress;
use crate::ports::errors::PortError;
use crate::ports::services::MailProvider;

/// Production SMTP mail provider backed by [`AsyncSmtpTransport`].
#[derive(Clone)]
pub struct SmtpMailProvider {
    from_address: Mailbox,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl std::fmt::Debug for SmtpMailProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpMailProvider")
            .field("from_address", &self.from_address)
            .finish()
    }
}

impl SmtpMailProvider {
    /// Creates a new [`SmtpMailProvider`] from configuration.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if the sender address or SMTP configuration is invalid.
    pub fn new(from_address: &str, config: &SmtpSettings) -> Result<Self, PortError> {
        let from_mailbox: Mailbox = from_address.parse().map_err(|e| {
            PortError::crypto(format!("invalid sender address '{from_address}': {e}"))
        })?;

        let mut builder = match config.tls {
            SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host),
            SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .map_err(|e| {
                    PortError::external_service("smtp", format!("starttls failed: {e}"), None)
                })?,
            SmtpTls::Tls => {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host).map_err(|e| {
                    PortError::external_service("smtp", format!("tls relay failed: {e}"), None)
                })?
            }
        };

        builder = builder.port(config.port);

        if let (Some(username), Some(password)) = (&config.username, &config.password) {
            let creds = Credentials::new(username.clone(), password.expose_secret().to_string());
            builder = builder.credentials(creds);
        }

        let transport = builder.build();

        Ok(Self {
            from_address: from_mailbox,
            transport,
        })
    }
}

#[async_trait]
impl MailProvider for SmtpMailProvider {
    async fn send_email(
        &self,
        to: &EmailAddress,
        subject: &str,
        text_body: &str,
        html_body: &str,
    ) -> Result<(), PortError> {
        let to_mailbox: Mailbox = to.as_str().parse().map_err(|e| {
            PortError::crypto(format!("invalid recipient address '{}': {e}", to.as_str()))
        })?;

        let email = Message::builder()
            .from(self.from_address.clone())
            .to(to_mailbox)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text_body.to_string()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html_body.to_string()),
                    ),
            )
            .map_err(|e| PortError::crypto(format!("failed to construct email message: {e}")))?;

        self.transport.send(email).await.map_err(|e| {
            PortError::external_service(
                "smtp",
                format!("failed to deliver SMTP email: {e}"),
                Some(Box::new(e)),
            )
        })?;

        Ok(())
    }
}
