//! Small native Zimbra client used by the portal.  The client deliberately
//! implements only the end-user operations we need: authentication, ensuring
//! a mailbox folder, and importing a MIME message into that folder.

use crate::{AppState, config::Config};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::RngCore;
use regex::Regex;
use reqwest::{Client, StatusCode, header};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ZimbraSession {
    pub token: String,
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn credential_key(config: &Config) -> Result<[u8; 32], String> {
    let bytes = STANDARD
        .decode(config.zimbra_credential_key.trim())
        .map_err(|_| "ZIMBRA_CREDENTIAL_KEY must be base64 encoded.".to_owned())?;
    bytes
        .try_into()
        .map_err(|_| "ZIMBRA_CREDENTIAL_KEY must decode to 32 bytes.".to_owned())
}

/// Encrypt a mailbox password as `base64(nonce || ciphertext || tag)`.
pub fn encrypt_password(config: &Config, password: &str) -> Result<String, String> {
    let key = credential_key(config)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| "Invalid credential key.".to_owned())?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), password.as_bytes())
        .map_err(|_| "Unable to encrypt mailbox password.".to_owned())?;
    let mut payload = nonce.to_vec();
    payload.extend(encrypted);
    Ok(STANDARD.encode(payload))
}

pub fn decrypt_password(config: &Config, value: &str) -> Result<String, String> {
    let key = credential_key(config)?;
    let payload = STANDARD
        .decode(value)
        .map_err(|_| "Stored mailbox credential is invalid.".to_owned())?;
    if payload.len() < 12 {
        return Err("Stored mailbox credential is invalid.".into());
    }
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| "Invalid credential key.".to_owned())?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&payload[..12]), &payload[12..])
        .map_err(|_| "Stored mailbox credential cannot be decrypted.".to_owned())?;
    String::from_utf8(plaintext).map_err(|_| "Stored mailbox credential is invalid.".to_owned())
}

fn client(config: &Config) -> Result<Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(config.zimbra_timeout_seconds.max(1)))
        .danger_accept_invalid_certs(!config.zimbra_verify_tls)
        .build()
        .map_err(|e| e.to_string())
}
fn endpoint(config: &Config, suffix: &str) -> String {
    format!(
        "{}/{}",
        config.zimbra_base_url.trim_end_matches('/'),
        suffix.trim_start_matches('/')
    )
}
fn soap(body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body>{body}</soap:Body></soap:Envelope>"#
    )
}
fn soap_context(body: &str, token: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Header><context xmlns="urn:zimbra"><authToken>{}</authToken></context></soap:Header><soap:Body>{body}</soap:Body></soap:Envelope>"#,
        xml_escape(token)
    )
}
fn mark_unread_request(item_id: &str, token: &str) -> String {
    soap_context(
        &format!(
            r#"<MsgActionRequest xmlns="urn:zimbraMail"><action id="{}" op="!read"/></MsgActionRequest>"#,
            xml_escape(item_id)
        ),
        token,
    )
}
fn token_from_xml(xml: &str) -> Option<String> {
    Regex::new(r#"(?is)<(?:\w+:)?authToken[^>]*>([^<]+)</(?:\w+:)?authToken>"#)
        .ok()?
        .captures(xml)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_owned())
}
fn folder_from_xml(xml: &str, name: &str) -> Option<(String, String)> {
    let escaped = regex::escape(name);
    let pattern = format!(
        r#"(?is)<(?:\w+:)?folder\b[^>]*\bname\s*=\s*["']{}["'][^>]*>"#,
        escaped
    );
    let re = Regex::new(&pattern).ok()?;
    let tag = re.find(xml)?.as_str();
    let id = Regex::new(r#"\bid\s*=\s*["']([^"']+)["']"#)
        .ok()?
        .captures(tag)?
        .get(1)?
        .as_str()
        .to_owned();
    Some((id, name.to_owned()))
}
async fn response_text(response: reqwest::Response) -> Result<String, String> {
    let status = response.status();
    let text = response.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("Zimbra request failed (HTTP {}).", status.as_u16()));
    }
    Ok(text)
}

impl ZimbraSession {
    pub async fn login(config: &Config, email: &str, password: &str) -> Result<Self, String> {
        if !crate::auth::valid_email(email) || password.is_empty() {
            return Err("Invalid email address or password.".into());
        }
        let body = soap(&format!(
            r#"<AuthRequest xmlns="urn:zimbraAccount"><account by="name">{}</account><password>{}</password></AuthRequest>"#,
            xml_escape(email.trim()),
            xml_escape(password)
        ));
        let http = client(config)?;
        let response = http
            .post(endpoint(config, "service/soap"))
            .header(header::CONTENT_TYPE, "application/soap+xml; charset=utf-8")
            .body(body)
            .send()
            .await
            .map_err(|_| "Zimbra is unavailable.".to_owned())?;
        let xml = response_text(response)
            .await
            .map_err(|_| "Invalid Zimbra email or password.".to_owned())?;
        let token =
            token_from_xml(&xml).ok_or_else(|| "Invalid Zimbra email or password.".to_owned())?;
        Ok(Self { token })
    }

    pub async fn ensure_folder(
        &self,
        config: &Config,
        _email: &str,
    ) -> Result<(String, String), String> {
        let http = client(config)?;
        let get = soap_context(
            r#"<GetFolderRequest xmlns="urn:zimbraMail"><folder l="1"/></GetFolderRequest>"#,
            &self.token,
        );
        let mut request = http
            .post(endpoint(config, "service/soap"))
            .header(header::CONTENT_TYPE, "application/soap+xml; charset=utf-8")
            .header("Cookie", format!("ZM_AUTH_TOKEN={}", self.token))
            .body(get);
        request = request.header("X-Zimbra-Auth-Token", &self.token);
        let xml = response_text(
            request
                .send()
                .await
                .map_err(|_| "Zimbra folder lookup failed.".to_owned())?,
        )
        .await?;
        if let Some(folder) = folder_from_xml(&xml, &config.zimbra_folder_name) {
            return Ok(folder);
        }
        let create = soap_context(
            &format!(
                r#"<CreateFolderRequest xmlns="urn:zimbraMail" fie="1"><folder name="{}" l="1"/></CreateFolderRequest>"#,
                xml_escape(&config.zimbra_folder_name)
            ),
            &self.token,
        );
        let response = http
            .post(endpoint(config, "service/soap"))
            .header(header::CONTENT_TYPE, "application/soap+xml; charset=utf-8")
            .header("Cookie", format!("ZM_AUTH_TOKEN={}", self.token))
            .header("X-Zimbra-Auth-Token", &self.token)
            .body(create)
            .send()
            .await
            .map_err(|_| "Zimbra folder creation failed.".to_owned())?;
        let xml = response_text(response).await?;
        folder_from_xml(&xml, &config.zimbra_folder_name)
            .ok_or_else(|| "Zimbra did not return the news folder.".to_owned())
    }

    pub async fn import_mime(
        &self,
        config: &Config,
        email: &str,
        folder: &str,
        mime: &[u8],
    ) -> Result<(), String> {
        let http = client(config)?;
        let path = format!(
            "home/{}/{}",
            urlencoding::encode(email),
            urlencoding::encode(folder)
        );
        let response = http
            .post(endpoint(config, &path))
            .header(header::CONTENT_TYPE, "message/rfc822")
            .header("Cookie", format!("ZM_AUTH_TOKEN={}", self.token))
            .header("X-Zimbra-Auth-Token", &self.token)
            .body(mime.to_vec())
            .send()
            .await
            .map_err(|_| "Zimbra message delivery failed.".to_owned())?;
        if response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::FORBIDDEN
        {
            return Err("Zimbra mailbox authentication failed.".into());
        }
        // The REST import endpoint on this Zimbra installation returns an
        // empty 200 response and does not include X-Zimbra-ItemId.  A
        // successful import is still a delivered message; imported messages
        // are unread by default.  If an item ID is provided, keep the
        // explicit unread safeguard, but never report a successful delivery
        // as failed merely because Zimbra omitted that optional header.
        let item_id = response
            .headers()
            .get("X-Zimbra-ItemId")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        response_text(response).await?;
        if let Some(item_id) = item_id
            && let Err(error) = self.mark_unread(config, &item_id).await
        {
            tracing::warn!(%error, %email, "Unable to explicitly keep imported Zimbra message unread");
        }
        Ok(())
    }

    async fn mark_unread(&self, config: &Config, item_id: &str) -> Result<(), String> {
        let http = client(config)?;
        let response = http
            .post(endpoint(config, "service/soap"))
            .header(header::CONTENT_TYPE, "application/soap+xml; charset=utf-8")
            .header("Cookie", format!("ZM_AUTH_TOKEN={}", self.token))
            .header("X-Zimbra-Auth-Token", &self.token)
            .body(mark_unread_request(item_id, &self.token))
            .send()
            .await
            .map_err(|_| "Zimbra unread status update failed.".to_owned())?;
        response_text(response).await.map(|_| ())
    }
}

pub async fn login_and_prepare(
    state: &AppState,
    email: &str,
    password: &str,
) -> Result<(ZimbraSession, String, String), String> {
    let session = ZimbraSession::login(&state.cfg, email, password).await?;
    let (folder_id, folder_path) = session.ensure_folder(&state.cfg, email).await?;
    Ok((session, folder_id, folder_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use serde_json::json;
    use std::path::PathBuf;

    fn config() -> Config {
        Config {
            root: PathBuf::new(),
            file: json!({}),
            mongo_uri: String::new(),
            web_database: "web".into(),
            vulnerabilities_database: "vulnerabilities".into(),
            secret: "test".into(),
            bootstrap_username: "admin".into(),
            bootstrap_password: "pw".into(),
            zimbra_base_url: "https://example.invalid".into(),
            zimbra_folder_name: "news".into(),
            zimbra_timeout_seconds: 1,
            zimbra_verify_tls: true,
            zimbra_credential_key: STANDARD.encode([7_u8; 32]),
            account_collection: "accounts".into(),
            newsletter_root: PathBuf::new(),
            review_view_suffix: "_review".into(),
            port: 9100,
        }
    }
    #[test]
    fn credentials_round_trip_without_exposing_plaintext() {
        let cfg = config();
        let encrypted = encrypt_password(&cfg, "secret").unwrap();
        assert_ne!(encrypted, "secret");
        assert_eq!(decrypt_password(&cfg, &encrypted).unwrap(), "secret");
    }
    #[test]
    fn parses_auth_and_folder_responses() {
        assert_eq!(
            token_from_xml("<authToken>abc</authToken>"),
            Some("abc".into())
        );
        assert_eq!(
            folder_from_xml("<folder name=\"news\" id=\"42\">", "news"),
            Some(("42".into(), "news".into()))
        );
        let request = soap_context("<GetFolderRequest xmlns=\"urn:zimbraMail\"/>", "token");
        assert!(
            request.contains(
                "<soap:Header><context xmlns=\"urn:zimbra\"><authToken>token</authToken>"
            )
        );
        assert!(request.contains("<soap:Body><GetFolderRequest"));
        let unread = mark_unread_request("42", "token");
        assert!(
            unread.contains(
                r#"<MsgActionRequest xmlns="urn:zimbraMail"><action id="42" op="!read"/>"#
            )
        );
    }
}
