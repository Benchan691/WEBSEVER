use crate::AppState;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::header::ContentType,
    transport::smtp::authentication::Credentials,
};
use std::{env, str::FromStr};

pub async fn send(
    state: &AppState,
    recipients: &[String],
    mode: &str,
    subject: &str,
    html: &str,
) -> Result<(), String> {
    if recipients.is_empty() {
        return Ok(());
    }
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
        .ok_or("SMTP_HOST is required for email.")?;
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
        AsyncSmtpTransport::<Tokio1Executor>::relay(&host).map_err(|e| e.to_string())?
    } else if tls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host).map_err(|e| e.to_string())?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
    };
    let mut builder = builder.port(port);
    if !username.is_empty() && !password.is_empty() {
        builder = builder.credentials(Credentials::new(username, password))
    };
    let transport = builder.build();
    let sender = lettre::message::Mailbox::from_str(&from).map_err(|e| e.to_string())?;
    if mode == "grouped" {
        let mut message = Message::builder().from(sender).subject(subject);
        for recipient in recipients {
            message = message.to(recipient
                .parse()
                .map_err(|e: lettre::address::AddressError| e.to_string())?)
        }
        let message = message
            .header(ContentType::TEXT_HTML)
            .body(html.to_owned())
            .map_err(|e| e.to_string())?;
        transport.send(message).await.map_err(|e| e.to_string())?;
    } else {
        for recipient in recipients {
            let message = Message::builder()
                .from(sender.clone())
                .to(recipient
                    .parse()
                    .map_err(|e: lettre::address::AddressError| e.to_string())?)
                .subject(subject)
                .header(ContentType::TEXT_HTML)
                .body(html.to_owned())
                .map_err(|e| e.to_string())?;
            transport.send(message).await.map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
