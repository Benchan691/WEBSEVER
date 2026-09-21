use serde_json::Value;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub struct Config {
    pub root: PathBuf,
    pub file: Value,
    pub mongo_uri: String,
    pub web_database: String,
    pub vulnerabilities_database: String,
    pub secret: String,
    pub bootstrap_username: String,
    pub bootstrap_password: String,
    pub zimbra_base_url: String,
    pub zimbra_folder_name: String,
    pub zimbra_timeout_seconds: u64,
    pub zimbra_verify_tls: bool,
    pub zimbra_credential_key: String,
    pub account_collection: String,
    pub newsletter_root: PathBuf,
    pub review_view_suffix: String,
    pub port: u16,
}

impl Config {
    pub fn load(root: &Path) -> Result<Self, String> {
        let _ = dotenvy::from_path(root.join(".env"));
        let path = env::var("APP_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| root.join("config/config.json"));
        let file = if path.exists() {
            serde_json::from_slice::<Value>(&fs::read(&path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?
        } else {
            Value::Object(Default::default())
        };
        if !file.is_object() {
            return Err("Application config must be a JSON object".into());
        }
        let get = |key: &str, pointer: &str, default: &str| -> String {
            env::var(key)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .or_else(|| {
                    file.pointer(pointer)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| default.to_owned())
        };
        let get_u64 = |key: &str, pointer: &str, default: u64| -> u64 {
            env::var(key)
                .ok()
                .or_else(|| {
                    file.pointer(pointer).and_then(|v| {
                        v.as_u64()
                            .map(|n| n.to_string())
                            .or_else(|| v.as_str().map(str::to_owned))
                    })
                })
                .and_then(|v| v.parse().ok())
                .filter(|v: &u64| *v > 0)
                .unwrap_or(default)
        };
        let get_bool = |key: &str, pointer: &str, default: bool| -> bool {
            env::var(key)
                .ok()
                .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
                .or_else(|| file.pointer(pointer).and_then(Value::as_bool))
                .unwrap_or(default)
        };
        let mongo_uri = env::var("MONGO_URI")
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| env::var("LOCAL_MONGO_URI").ok())
            .unwrap_or_default();
        let secret = env::var("FLASK_SECRET_KEY").unwrap_or_default();
        if mongo_uri.is_empty() || secret.is_empty() {
            return Err("LOCAL_MONGO_URI (or MONGO_URI) and FLASK_SECRET_KEY are required".into());
        }
        let newsletter = get("NEWSLETTER_ROOT", "/newsletter_root", "newsletters");
        let newsletter_root = if Path::new(&newsletter).is_absolute() {
            PathBuf::from(newsletter)
        } else {
            root.join(newsletter)
        };
        Ok(Self {
            root: root.to_path_buf(),
            file: file.clone(),
            mongo_uri,
            web_database: get("WEB_DATABASE", "/mongodb/web_database", "web"),
            vulnerabilities_database: get(
                "VULNERABILITIES_DATABASE",
                "/mongodb/vulnerabilities_database",
                "vulnerabilities",
            ),
            secret,
            bootstrap_username: get(
                "WEB_AUTH_BOOTSTRAP_USERNAME",
                "/web_auth/bootstrap_username",
                "admin",
            ),
            bootstrap_password: env::var("WEB_AUTH_BOOTSTRAP_PASSWORD").unwrap_or_default(),
            zimbra_base_url: get(
                "ZIMBRA_BASE_URL",
                "/zimbra/base_url",
                "https://zmailbox.citictel-cpc.com",
            ),
            zimbra_folder_name: get("ZIMBRA_FOLDER_NAME", "/zimbra/folder_name", "news"),
            zimbra_timeout_seconds: get_u64(
                "ZIMBRA_TIMEOUT_SECONDS",
                "/zimbra/timeout_seconds",
                10,
            ),
            zimbra_verify_tls: get_bool("ZIMBRA_VERIFY_TLS", "/zimbra/verify_tls", true),
            zimbra_credential_key: env::var("ZIMBRA_CREDENTIAL_KEY").unwrap_or_default(),
            account_collection: get("ACCOUNT_COLLECTION", "/account_collection", "accounts"),
            newsletter_root,
            review_view_suffix: get(
                "REVIEW_VIEW_SUFFIX",
                "/mongodb/review_view_suffix",
                "_review",
            ),
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(9100),
        })
    }
    pub fn value(&self, key: &str, pointer: &str, default: Value) -> Value {
        env::var(key)
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| serde_json::from_str(&v).unwrap_or(Value::String(v)))
            .or_else(|| self.file.pointer(pointer).cloned())
            .unwrap_or(default)
    }
}
