use crate::AppState;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::header::ContentTransferEncoding, message::header::ContentType,
    transport::smtp::authentication::Credentials,
    transport::smtp::client::{Certificate, Tls, TlsParameters},
};
use std::{env, fs, path::Path, time::Duration};

fn smtp_setting(state: &AppState, key: &str, field: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            state
                .cfg
                .file
                .pointer(&format!("/smtp/{field}"))
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string())
                })
        })
        .unwrap_or_else(|| default.to_owned())
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CopyRecipients {
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
}

/// TLS parameters for the relay. Internal relays often present certificates
/// issued by a private CA, so SMTP_CA_BUNDLE (a PEM file path, absolute or
/// relative to the application root) adds that CA to the trusted roots while
/// keeping full certificate and hostname verification.
fn tls_parameters(state: &AppState, host: &str) -> Result<TlsParameters, String> {
    let mut builder = TlsParameters::builder(host.to_owned());
    let bundle = smtp_setting(state, "SMTP_CA_BUNDLE", "ca_bundle", "");
    if !bundle.is_empty() {
        let path = Path::new(&bundle);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            state.cfg.root.join(path)
        };
        let pem = fs::read(&path)
            .map_err(|e| format!("SMTP_CA_BUNDLE {}: {e}", path.display()))?;
        let cert = Certificate::from_pem(&pem)
            .map_err(|e| format!("SMTP_CA_BUNDLE {}: {e}", path.display()))?;
        builder = builder.add_root_certificate(cert);
    }
    builder.build().map_err(|e| e.to_string())
}

fn smtp_transport(
    state: &AppState,
    timeout: Option<Duration>,
) -> Result<(AsyncSmtpTransport<Tokio1Executor>, lettre::message::Mailbox), String> {
    let host = smtp_setting(state, "SMTP_HOST", "host", "");
    if host.is_empty() {
        return Err("SMTP_HOST is required for email delivery.".into());
    }
    let username = smtp_setting(state, "SMTP_USERNAME", "username", "");
    let password = smtp_setting(state, "SMTP_PASSWORD", "password", "");
    let from = smtp_setting(state, "SMTP_FROM", "from", &username);
    if from.is_empty() {
        return Err("SMTP_FROM or SMTP_USERNAME is required for email.".into());
    }
    let port = smtp_setting(state, "SMTP_PORT", "port", "587")
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or("SMTP_PORT must be between 1 and 65535.")?;
    let enabled = |key, field, default| {
        matches!(
            smtp_setting(state, key, field, default)
                .to_lowercase()
                .as_str(),
            "1" | "true" | "yes" | "on"
        )
    };
    let ssl = enabled("SMTP_USE_SSL", "use_ssl", "false");
    let tls = enabled("SMTP_USE_TLS", "use_tls", "true");
    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host);
    if ssl {
        builder = builder.tls(Tls::Wrapper(tls_parameters(state, &host)?));
    } else if tls {
        builder = builder.tls(Tls::Required(tls_parameters(state, &host)?));
    }
    let mut builder = builder.port(port);
    if let Some(timeout) = timeout {
        builder = builder.timeout(Some(timeout));
    }
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
    copies: &CopyRecipients,
    subject: &str,
    html: &str,
) -> Result<Message, String> {
    let mut builder = Message::builder().from(from.clone()).to(recipient
        .parse()
        .map_err(|e: lettre::address::AddressError| e.to_string())?);
    for email in &copies.cc {
        builder = builder.cc(email
            .parse()
            .map_err(|e: lettre::address::AddressError| e.to_string())?);
    }
    for email in &copies.bcc {
        builder = builder.bcc(
            email
                .parse()
                .map_err(|e: lettre::address::AddressError| e.to_string())?,
        );
    }
    builder
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
    copies: &CopyRecipients,
    _mode: &str,
    subject: &str,
    html: &str,
) -> Result<(), String> {
    if recipients.is_empty() {
        return Ok(());
    }
    let (transport, from) = smtp_transport(state, None)?;
    for recipient in recipients {
        let normalized = recipient.trim().to_lowercase();
        transport
            .send(message(&from, &normalized, copies, subject, html)?)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Prepared before creating an account; plaintext stays only in memory and mail.
/// Never derive the login link from an untrusted request Host header.
pub(crate) struct TemporaryPasswordEmail {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    message: Message,
}

impl TemporaryPasswordEmail {
    pub fn prepare(
        state: &AppState,
        email: &str,
        username: &str,
        organization: &str,
        temporary: &str,
    ) -> Result<Self, String> {
        if !crate::auth::valid_email(email) {
            return Err("A valid account email address is required.".into());
        }
        let (transport, from) = smtp_transport(state, Some(Duration::from_secs(20)))?;
        let escape = |value: &str| {
            value
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#39;")
        };
        let public_url = state.cfg.value(
            "WEB_PUBLIC_URL",
            "/web_auth/public_url",
            serde_json::json!(""),
        );
        let public_url = public_url.as_str().unwrap_or("").trim();
        let login = if public_url.is_empty() {
            "Open the Security Portal sign-in page.".to_owned()
        } else {
            let mut url = reqwest::Url::parse(public_url)
                .map_err(|_| "WEB_PUBLIC_URL must be an HTTP or HTTPS URL.")?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(
                    "WEB_PUBLIC_URL must be an HTTP or HTTPS URL without credentials.".into(),
                );
            }
            url.set_path(&format!("{}/login", url.path().trim_end_matches('/')));
            url.set_query(None);
            url.set_fragment(None);
            format!(
                "<a href=\"{}\">Sign in to Security Portal</a>.",
                escape(url.as_str())
            )
        };
        let html = format!(
            "<h2>Your Security Portal temporary password</h2>\
             <p>Organization: <strong>{}</strong></p>\
             <p>Username: <strong>{}</strong></p>\
             <p>Temporary password: <code>{}</code></p>\
             <p>This password expires in 24 hours. You must replace it with a new local password after signing in.</p>\
             <p>{}</p><p>If you did not expect this email, contact your organization administrator.</p>",
            escape(organization),
            escape(username),
            escape(temporary),
            login
        );
        Ok(Self {
            transport,
            message: message(
                &from,
                email,
                &CopyRecipients::default(),
                "Your Security Portal temporary password",
                &html,
            )?,
        })
    }

    pub async fn send(self) -> Result<(), String> {
        self.transport
            .send(self.message)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        sync::mpsc,
        task::JoinHandle,
    };

    pub(crate) struct SmtpStub {
        pub accept: Arc<AtomicBool>,
        received: mpsc::UnboundedReceiver<String>,
        task: JoinHandle<()>,
    }
    impl Drop for SmtpStub {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl SmtpStub {
        pub async fn password_for(&mut self, recipient: &str) -> String {
            use base64::{Engine, engine::general_purpose::STANDARD};
            let raw = tokio::time::timeout(Duration::from_secs(3), self.received.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(raw.contains(&format!("To: {recipient}\r\n")));
            let (_, body) = raw.split_once("\r\n\r\n").unwrap();
            let html = String::from_utf8(
                STANDARD
                    .decode(body.split_whitespace().collect::<String>())
                    .unwrap(),
            )
            .unwrap();
            html.split_once("<code>")
                .unwrap()
                .1
                .split_once("</code>")
                .unwrap()
                .0
                .to_owned()
        }
    }
    pub(crate) async fn smtp_stub(state: &mut AppState) -> SmtpStub {
        // Never let a developer's exported SMTP settings redirect tests to real mail.
        for key in [
            "SMTP_HOST",
            "SMTP_PORT",
            "SMTP_FROM",
            "SMTP_USERNAME",
            "SMTP_PASSWORD",
            "SMTP_USE_TLS",
            "SMTP_USE_SSL",
            "WEB_PUBLIC_URL",
        ] {
            assert!(
                env::var_os(key).is_none(),
                "Unset {key} before running SMTP tests; tests only use a disposable loopback receiver."
            );
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        state.cfg.file["smtp"] = serde_json::json!({"host":"127.0.0.1","port":listener.local_addr().unwrap().port(),"from":"portal@example.test","use_tls":false,"use_ssl":false});
        state.cfg.file["web_auth"] =
            serde_json::json!({"public_url":"https://portal.example.test"});
        let accept = Arc::new(AtomicBool::new(true));
        let server_accept = accept.clone();
        let (sent, received) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let accept = server_accept.clone();
                let sent = sent.clone();
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);
                    if writer.write_all(b"220 localhost ESMTP\r\n").await.is_err() {
                        return;
                    }
                    let mut in_data = false;
                    let mut data = String::new();
                    loop {
                        let mut line = String::new();
                        if !matches!(reader.read_line(&mut line).await, Ok(n) if n > 0) {
                            break;
                        }
                        let reply = if in_data {
                            if line != ".\r\n" {
                                data.push_str(&line);
                                continue;
                            }
                            in_data = false;
                            if accept.load(Ordering::SeqCst) {
                                let _ = sent.send(std::mem::take(&mut data));
                                "250 Message accepted\r\n"
                            } else {
                                data.clear();
                                "550 Delivery rejected for test\r\n"
                            }
                        } else if line.starts_with("EHLO") {
                            "250-localhost\r\n250 8BITMIME\r\n"
                        } else if line.starts_with("DATA") {
                            in_data = true;
                            "354 End data with a dot\r\n"
                        } else if line.starts_with("QUIT") {
                            let _ = writer.write_all(b"221 Bye\r\n").await;
                            break;
                        } else {
                            "250 OK\r\n"
                        };
                        if writer.write_all(reply.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        SmtpStub {
            accept,
            received,
            task,
        }
    }

    #[tokio::test]
    async fn temporary_password_email_is_delivered_only_to_the_account() {
        let mut state = crate::rbac_tests::state().await;
        let mut smtp = smtp_stub(&mut state).await;
        let delivery = TemporaryPasswordEmail::prepare(
            &state,
            "member@example.test",
            "<Member>",
            "<Team>",
            "temporary-test-password",
        )
        .unwrap();
        let raw = String::from_utf8(delivery.message.formatted()).unwrap();
        assert!(!raw.contains("Cc:"));
        {
            use base64::{Engine, engine::general_purpose::STANDARD};
            let encoded = raw
                .split_once("\r\n\r\n")
                .unwrap()
                .1
                .split_whitespace()
                .collect::<String>();
            let html = String::from_utf8(STANDARD.decode(encoded).unwrap()).unwrap();
            assert!(html.contains("&lt;Member&gt;"));
            assert!(html.contains("&lt;Team&gt;"));
            assert!(html.contains("https://portal.example.test/login"));
            assert!(!html.contains("<Member>"));
        }
        delivery.send().await.unwrap();
        assert_eq!(
            smtp.password_for("member@example.test").await,
            "temporary-test-password"
        );
        smtp.accept.store(false, Ordering::SeqCst);
        assert!(
            TemporaryPasswordEmail::prepare(
                &state,
                "member@example.test",
                "Member",
                "Team",
                "another-test-password"
            )
            .unwrap()
            .send()
            .await
            .is_err()
        );
    }

    #[test]
    fn html_messages_use_zimbra_compatible_base64_encoding() {
        let from = "newsletter@example.com".parse().unwrap();
        let rendered = String::from_utf8(
            message(
                &from,
                "recipient@example.com",
                &CopyRecipients::default(),
                "Security update",
                "<p>Styled security notification</p>",
            )
            .unwrap()
            .formatted(),
        )
        .unwrap();
        assert!(rendered.contains("Content-Transfer-Encoding: base64\r\n"));
    }

    #[test]
    fn copy_recipients_receive_mail_without_exposing_bcc_headers() {
        let from = "newsletter@example.com".parse().unwrap();
        let email = message(
            &from,
            "to@example.com",
            &CopyRecipients {
                cc: vec!["cc@example.com".into()],
                bcc: vec!["hidden@example.com".into()],
            },
            "Security update",
            "<p>Update</p>",
        )
        .unwrap();
        let recipients = email
            .envelope()
            .to()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            recipients,
            ["to@example.com", "cc@example.com", "hidden@example.com"]
        );
        let rendered = String::from_utf8(email.formatted()).unwrap();
        assert!(rendered.contains("To: to@example.com\r\n"));
        assert!(rendered.contains("Cc: cc@example.com\r\n"));
        assert!(!rendered.contains("Bcc:"));
        assert!(!rendered.contains("hidden@example.com"));
    }
}
