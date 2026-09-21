use crate::{AppState, db, zimbra};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::header::ContentType,
    transport::smtp::authentication::Credentials,
};
use mongodb::bson::doc;
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
        .ok_or("SMTP_HOST is required for external recipients.")?;
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
        .body(html.to_owned())
        .map_err(|e| e.to_string())
}
fn direct_sender(state: &AppState, recipient: &str) -> Result<lettre::message::Mailbox, String> {
    if let Ok(value) = env::var("SMTP_FROM") {
        if !value.trim().is_empty() {
            return value
                .parse()
                .map_err(|e: lettre::address::AddressError| e.to_string());
        }
    }
    let domain = state
        .cfg
        .zimbra_base_url
        .split("//")
        .nth(1)
        .unwrap_or(&state.cfg.zimbra_base_url)
        .split('/')
        .next()
        .unwrap_or("localhost");
    format!("news@{}", domain)
        .parse()
        .or_else(|_| recipient.parse())
        .map_err(|e: lettre::address::AddressError| e.to_string())
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
    let mut smtp: Option<(AsyncSmtpTransport<Tokio1Executor>, lettre::message::Mailbox)> = None;
    for recipient in recipients {
        let normalized = recipient.trim().to_lowercase();
        let account = db::find_one(
            &state.web,
            &state.cfg.account_collection,
            doc! {"email_key":&normalized,"auth_source":"zimbra"},
        )
        .await
        .ok()
        .flatten();
        if let Some(account) = account {
            if db::bool_field(&account, "disabled") {
                return Err(format!("Zimbra account {normalized} is disabled."));
            }
            let encrypted = db::string(&account, "zimbra_password");
            if encrypted.is_empty() {
                return Err(format!(
                    "No saved Zimbra credential is available for {normalized}."
                ));
            }
            let password = zimbra::decrypt_password(&state.cfg, &encrypted)?;
            let session = zimbra::ZimbraSession::login(&state.cfg, &normalized, &password).await?;
            let folder = db::string(&account, "zimbra_folder_path");
            let folder = if folder.is_empty() {
                session.ensure_folder(&state.cfg, &normalized).await?.1
            } else {
                folder
            };
            let from = direct_sender(state, &normalized)?;
            let msg = message(&from, &normalized, subject, html)?.formatted();
            session
                .import_mime(&state.cfg, &normalized, &folder, &msg)
                .await?;
        } else {
            if smtp.is_none() {
                smtp = Some(smtp_transport(state)?)
            }
            let (transport, from) = smtp.as_ref().unwrap();
            transport
                .send(message(from, &normalized, subject, html)?)
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
