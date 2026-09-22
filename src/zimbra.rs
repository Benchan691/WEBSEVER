//! Small native Zimbra client used by the portal.  The client deliberately
//! implements only the end-user operations we need: authentication, ensuring
//! a mailbox folder, and importing a MIME message into that folder.

use crate::config::Config;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::RngCore;
use regex::Regex;
use reqwest::{Client, header};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ZimbraSession {
    pub token: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthFailure {
    InvalidCredentials,
    InvalidTwoFactorCode,
    TwoFactorExpired,
    TwoFactorSetupRequired,
    Unavailable,
    Unexpected,
}

impl AuthFailure {
    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidCredentials => "Invalid Zimbra email or password.",
            Self::InvalidTwoFactorCode => "The authenticator code is invalid.",
            Self::TwoFactorExpired => "The two-factor session expired. Sign in again.",
            Self::TwoFactorSetupRequired => {
                "Complete two-factor authentication setup in Zimbra before signing in."
            }
            Self::Unavailable => "Zimbra is unavailable. Please try again.",
            Self::Unexpected => "Zimbra authentication failed. Please try again.",
        }
    }
}

#[derive(Clone, Debug)]
pub enum LoginResult {
    Authenticated(ZimbraSession),
    TwoFactorRequired {
        temporary_token: String,
        lifetime_ms: u64,
    },
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
pub fn encrypt_secret(config: &Config, value: &str) -> Result<String, String> {
    let key = credential_key(config)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| "Invalid credential key.".to_owned())?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), value.as_bytes())
        .map_err(|_| "Unable to encrypt Zimbra credentials.".to_owned())?;
    let mut payload = nonce.to_vec();
    payload.extend(encrypted);
    Ok(STANDARD.encode(payload))
}

pub fn decrypt_secret(config: &Config, value: &str) -> Result<String, String> {
    let key = credential_key(config)?;
    let payload = STANDARD
        .decode(value)
        .map_err(|_| "Stored Zimbra credential is invalid.".to_owned())?;
    if payload.len() < 12 {
        return Err("Stored Zimbra credential is invalid.".into());
    }
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| "Invalid credential key.".to_owned())?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&payload[..12]), &payload[12..])
        .map_err(|_| "Stored Zimbra credential cannot be decrypted.".to_owned())?;
    String::from_utf8(plaintext).map_err(|_| "Stored Zimbra credential is invalid.".to_owned())
}

pub fn encrypt_password(config: &Config, password: &str) -> Result<String, String> {
    encrypt_secret(config, password)
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
fn token_from_xml(xml: &str) -> Option<String> {
    Regex::new(r#"(?is)<(?:\w+:)?authToken[^>]*>([^<]+)</(?:\w+:)?authToken>"#)
        .ok()?
        .captures(xml)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_owned())
}
fn element_from_xml(xml: &str, name: &str) -> Option<String> {
    let escaped = regex::escape(name);
    Regex::new(&format!(
        r#"(?is)<(?:\w+:)?{escaped}[^>]*>([^<]+)</(?:\w+:)?{escaped}>"#
    ))
    .ok()?
    .captures(xml)
    .and_then(|captures| captures.get(1))
    .map(|value| value.as_str().trim().to_owned())
}
fn soap_fault_code(xml: &str) -> Option<String> {
    let re = Regex::new(r#"(?is)<(?:\w+:)?Code[^>]*>([^<]+)</(?:\w+:)?Code>"#).ok()?;
    re.captures_iter(xml)
        .filter_map(|captures| captures.get(1).map(|value| value.as_str().trim()))
        .find(|value| value.starts_with("account.") || value.starts_with("service."))
        .map(str::to_owned)
}
fn auth_failure(xml: &str) -> AuthFailure {
    match soap_fault_code(xml).as_deref() {
        Some("account.TWO_FACTOR_AUTH_FAILED") => AuthFailure::InvalidTwoFactorCode,
        Some("account.TWO_FACTOR_SETUP_REQUIRED") => AuthFailure::TwoFactorSetupRequired,
        Some("account.AUTH_FAILED")
        | Some("account.NO_SUCH_ACCOUNT")
        | Some("account.ACCOUNT_INACTIVE") => AuthFailure::InvalidCredentials,
        Some("service.TEMPORARILY_UNAVAILABLE") => AuthFailure::Unavailable,
        _ => AuthFailure::Unexpected,
    }
}
fn two_factor_auth_failure(xml: &str) -> AuthFailure {
    let normalized = xml.to_ascii_lowercase();
    if normalized.contains("bad auth token")
        || normalized.contains("auth token expired")
        || normalized.contains("auth_token_expired")
        || normalized.contains("service.auth_required")
    {
        return AuthFailure::TwoFactorExpired;
    }
    match auth_failure(xml) {
        AuthFailure::InvalidCredentials => AuthFailure::InvalidTwoFactorCode,
        failure => failure,
    }
}
fn password_auth_body(email: &str, password: &str) -> String {
    soap(&format!(
        r#"<AuthRequest xmlns="urn:zimbraAccount"><account by="name">{}</account><password>{}</password></AuthRequest>"#,
        xml_escape(email.trim()),
        xml_escape(password)
    ))
}
fn two_factor_auth_body(temporary_token: &str, code: &str) -> String {
    soap(&format!(
        r#"<AuthRequest xmlns="urn:zimbraAccount"><authToken>{}</authToken><twoFactorCode>{}</twoFactorCode></AuthRequest>"#,
        xml_escape(temporary_token),
        xml_escape(code)
    ))
}
fn parse_login_response(xml: &str) -> Result<LoginResult, AuthFailure> {
    let token = token_from_xml(xml).ok_or_else(|| auth_failure(xml))?;
    if element_from_xml(xml, "twoFactorAuthRequired")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    {
        let lifetime_ms = element_from_xml(xml, "lifetime")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(300_000);
        return Ok(LoginResult::TwoFactorRequired {
            temporary_token: token,
            lifetime_ms,
        });
    }
    Ok(LoginResult::Authenticated(ZimbraSession { token }))
}
fn parse_two_factor_response(xml: &str) -> Result<ZimbraSession, AuthFailure> {
    let token = token_from_xml(xml).ok_or_else(|| two_factor_auth_failure(xml))?;
    if element_from_xml(xml, "twoFactorAuthRequired")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    {
        return Err(AuthFailure::InvalidTwoFactorCode);
    }
    Ok(ZimbraSession { token })
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
    pub async fn login(
        config: &Config,
        email: &str,
        password: &str,
    ) -> Result<LoginResult, AuthFailure> {
        if !crate::auth::valid_email(email) || password.is_empty() {
            return Err(AuthFailure::InvalidCredentials);
        }
        let http = client(config).map_err(|_| AuthFailure::Unavailable)?;
        let response = http
            .post(endpoint(config, "service/soap"))
            .header(header::CONTENT_TYPE, "application/soap+xml; charset=utf-8")
            .body(password_auth_body(email, password))
            .send()
            .await
            .map_err(|_| AuthFailure::Unavailable)?;
        let status = response.status();
        let xml = response
            .text()
            .await
            .map_err(|_| AuthFailure::Unavailable)?;
        if !status.is_success() {
            return Err(auth_failure(&xml));
        }
        parse_login_response(&xml)
    }

    pub async fn complete_two_factor(
        config: &Config,
        temporary_token: &str,
        code: &str,
    ) -> Result<Self, AuthFailure> {
        let http = client(config).map_err(|_| AuthFailure::Unavailable)?;
        let response = http
            .post(endpoint(config, "service/soap"))
            .header(header::CONTENT_TYPE, "application/soap+xml; charset=utf-8")
            .body(two_factor_auth_body(temporary_token, code))
            .send()
            .await
            .map_err(|_| AuthFailure::Unavailable)?;
        let status = response.status();
        let xml = response
            .text()
            .await
            .map_err(|_| AuthFailure::Unavailable)?;
        if !status.is_success() {
            return Err(two_factor_auth_failure(&xml));
        }
        parse_two_factor_response(&xml)
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
            vulnerabilities_collection: "news".into(),
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
            port: 9100,
        }
    }
    #[test]
    fn credentials_round_trip_without_exposing_plaintext() {
        let cfg = config();
        let encrypted = encrypt_password(&cfg, "secret").unwrap();
        assert_ne!(encrypted, "secret");
        assert_eq!(decrypt_secret(&cfg, &encrypted).unwrap(), "secret");
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
    }

    #[test]
    fn parses_two_factor_challenge_before_mailbox_access() {
        let result = parse_login_response(
            "<AuthResponse><authToken>temporary</authToken><lifetime>240000</lifetime><twoFactorAuthRequired>true</twoFactorAuthRequired></AuthResponse>",
        )
        .unwrap();
        match result {
            LoginResult::TwoFactorRequired {
                temporary_token,
                lifetime_ms,
            } => {
                assert_eq!(temporary_token, "temporary");
                assert_eq!(lifetime_ms, 240_000);
            }
            LoginResult::Authenticated(_) => panic!("temporary token treated as authenticated"),
        }
    }

    #[test]
    fn two_factor_completion_uses_token_and_code_without_password() {
        let body = two_factor_auth_body("temporary", "123456");
        assert!(body.contains("<authToken>temporary</authToken>"));
        assert!(body.contains("<twoFactorCode>123456</twoFactorCode>"));
        assert!(!body.contains("<password>"));
    }

    #[test]
    fn maps_two_factor_faults_to_safe_errors() {
        let xml = "<soap:Fault><Detail><Error><Code>account.TWO_FACTOR_AUTH_FAILED</Code></Error></Detail></soap:Fault>";
        assert_eq!(auth_failure(xml), AuthFailure::InvalidTwoFactorCode);
        assert_eq!(
            two_factor_auth_failure(
                "<Error><Code>account.AUTH_FAILED</Code><Trace>incorrect code</Trace></Error>"
            ),
            AuthFailure::InvalidTwoFactorCode
        );
        assert!(matches!(
            parse_two_factor_response(
                "<Error><Code>account.AUTH_FAILED</Code><Trace>incorrect code</Trace></Error>"
            ),
            Err(AuthFailure::InvalidTwoFactorCode)
        ));
        assert_eq!(
            two_factor_auth_failure(
                "<Error><Code>service.AUTH_REQUIRED</Code><Trace>auth token expired</Trace></Error>"
            ),
            AuthFailure::TwoFactorExpired
        );
        assert_eq!(
            auth_failure("<Error><Code>account.TWO_FACTOR_SETUP_REQUIRED</Code></Error>"),
            AuthFailure::TwoFactorSetupRequired
        );
    }
}
