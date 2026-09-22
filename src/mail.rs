use crate::AppState;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::header::ContentTransferEncoding, message::header::ContentType,
    transport::smtp::authentication::Credentials,
};
use std::env;

fn smtp_transport(
    state: &AppState,
) -> Result<(AsyncSmtpTransport<Tokio1Executor>, lettre::message::Mailbox), String> {
    let host = env::var("SMTP_HOST")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            state
                .cfg
                .file
                .pointer("/smtp/host")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .ok_or("SMTP_HOST is required for email delivery.")?;
    let username = env::var("SMTP_USERNAME").unwrap_or_default();
    let password = env::var("SMTP_PASSWORD").unwrap_or_default();
    let from = env::var("SMTP_FROM")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| username.clone());
    if from.is_empty() {
        return Err("SMTP_FROM or SMTP_USERNAME is required for email.".into());
    }
    let port = env::var("SMTP_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(587);
    let ssl = env::var("SMTP_USE_SSL")
        .ok()
        .is_some_and(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"));
    let tls = env::var("SMTP_USE_TLS")
        .ok()
        .is_none_or(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"));
    let builder = if ssl {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
    } else if tls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
    } else {
        Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
            &host,
        ))
    }
    .map_err(|e| e.to_string())?;
    let mut builder = builder.port(port);
    if !username.is_empty() && !password.is_empty() {
        builder = builder.credentials(Credentials::new(username, password));
    }
    Ok((
        builder.build(),
        from.parse()
            .map_err(|e: lettre::address::AddressError| e.to_string())?,
    ))
}
fn message(
    from: &lettre::message::Mailbox,
    recipient: &str,
    subject: &str,
    html: &str,
) -> Result<Message, String> {
    Message::builder()
        .from(from.clone())
        .to(recipient
            .parse()
            .map_err(|e: lettre::address::AddressError| e.to_string())?)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        // Base64 keeps styled HTML portable across SMTP relays and mailbox
        // implementations without relying on quoted-printable edge cases.
        .header(ContentTransferEncoding::Base64)
        .body(html.to_owned())
        .map_err(|e| e.to_string())
}
pub async fn send(
    state: &AppState,
    recipients: &[String],
    _mode: &str,
    subject: &str,
    html: &str,
) -> Result<(), String> {
    if recipients.is_empty() {
        return Ok(());
    }
    let (transport, from) = smtp_transport(state)?;
    for recipient in recipients {
        let normalized = recipient.trim().to_lowercase();
        transport
            .send(message(&from, &normalized, subject, html)?)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_messages_use_zimbra_compatible_base64_encoding() {
        let from = "newsletter@example.com".parse().unwrap();
        let rendered = String::from_utf8(
            message(
                &from,
                "recipient@example.com",
                "Security update",
                "<p>Styled security notification</p>",
            )
            .unwrap()
            .formatted(),
        )
        .unwrap();
        assert!(rendered.contains("Content-Transfer-Encoding: base64\r\n"));
    }
}
