mod auth;
mod config;
mod cron_schedule;
mod db;
mod mail;
mod management;
mod newsletter_normalizer;
mod newsletter_statistics;
mod newsletters;
mod operations;
mod rbac;
mod reports;
mod reviews;
mod scheduler;
mod subscriptions;
mod vendor_matcher;
mod view;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use minijinja::Environment;
use mongodb::{Client, Database};
use serde_json::{Map, Value, json};
use std::{collections::HashMap, env, path::PathBuf, sync::Arc};
use tower_http::services::ServeDir;

#[derive(Clone)]
pub struct AppState {
    pub cfg: config::Config,
    pub web: Database,
    pub vuln: Database,
    pub templates: Arc<Environment<'static>>,
    pub http: reqwest::Client,
}

pub struct ReqCtx {
    pub method: Method,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub json: Value,
    pub form: HashMap<String, String>,
    pub user: Option<mongodb::bson::Document>,
}

impl ReqCtx {
    pub fn arg(&self, key: &str) -> String {
        self.query
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    }
    pub fn args(&self, key: &str) -> Vec<String> {
        self.query
            .iter()
            .filter(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
            .collect()
    }
    pub fn field(&self, key: &str) -> String {
        self.form
            .get(key)
            .cloned()
            .or_else(|| {
                self.json
                    .get(key)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default()
    }
    pub fn json_field(&self, key: &str) -> Value {
        self.json.get(key).cloned().unwrap_or(Value::Null)
    }
    pub fn is_api(&self) -> bool {
        self.path.starts_with("/api/")
    }
    pub fn can(&self, permission: &str) -> bool {
        rbac::allowed(self, permission)
    }
    pub fn is_superadmin(&self) -> bool {
        self.user.as_ref().is_some_and(rbac::is_superadmin)
    }
    pub fn user_id(&self) -> Option<mongodb::bson::oid::ObjectId> {
        self.user
            .as_ref()
            .and_then(|user| user.get_object_id("_id").ok())
    }
    pub fn owner_filter(&self, _state: &AppState) -> mongodb::bson::Document {
        rbac::scope(self.user.as_ref())
    }
}

fn request_context(ctx: &ReqCtx) -> Value {
    let mut args = Map::new();
    for (key, value) in &ctx.query {
        args.entry(key.clone()).or_insert_with(|| json!(value));
    }
    json!({
        "path": ctx.path,
        "full_path": if ctx.query.is_empty() {
            ctx.path.clone()
        } else {
            format!(
                "{}?{}",
                ctx.path,
                serde_urlencoded::to_string(&ctx.query).unwrap_or_default()
            )
        },
        "args": args,
        "next": ctx.arg("next"),
        "blueprint": if ctx.path.starts_with("/subscriptions") {
            "subscription"
        } else if ctx.path.starts_with("/reviews") {
            "review"
        } else if ctx.path.starts_with("/reports") {
            "report"
        } else if ctx.path.starts_with("/operations") {
            "operations"
        } else {
            "auth"
        },
        "endpoint": ""
    })
}

fn page_context(ctx: &ReqCtx, _state: &AppState, extras: Value) -> Value {
    // This branch serves the portal in English. Ignore any legacy language
    // cookie so an existing browser session cannot switch the interface back
    // to Chinese.
    let locale = "en".to_owned();
    let mut base = json!({
        "locale": locale, "html_lang": "en",
        "i18n_catalog": serde_json::from_str::<Value>(include_str!("../config/translations.json")).unwrap_or(json!({})).get(&locale).cloned().unwrap_or(json!({})),
        "current_user": ctx.user.as_ref().map(auth::public_user),
        "permissions": rbac::CATALOG.iter().map(|p| (p.id, ctx.can(p.id))).collect::<std::collections::BTreeMap<_,_>>(),
        "is_superadmin": ctx.is_superadmin(),
        "request": request_context(ctx)
    });
    if let (Some(dst), Some(src)) = (base.as_object_mut(), extras.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    base
}

pub fn render(state: &AppState, ctx: &ReqCtx, name: &str, extras: Value) -> Response {
    view::render(&state.templates, name, page_context(ctx, state, extras))
}

fn guard(state: &AppState, ctx: &ReqCtx) -> Option<Response> {
    if !matches!(ctx.method, Method::GET | Method::HEAD | Method::OPTIONS) {
        let origin = ctx.headers.get("origin").and_then(|v| v.to_str().ok());
        let host = ctx.headers.get("host").and_then(|v| v.to_str().ok());
        let expected = format!(
            "{}://{}",
            if state.cfg.cookie_secure {
                "https"
            } else {
                "http"
            },
            host.unwrap_or("")
        );
        if origin.is_some_and(|value| value != expected)
            || ctx
                .headers
                .get("sec-fetch-site")
                .is_some_and(|v| v == "cross-site")
        {
            return Some(view::error(
                StatusCode::FORBIDDEN,
                "Same-origin request required.",
            ));
        }
        if ctx.is_api() && !ctx.body.is_empty() {
            let content = ctx
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let upload = matches!(
                ctx.path.as_str(),
                "/api/reports"
                    | "/api/subscriptions/vendor-product-import"
                    | "/api/reviews/vendor-product-import"
            );
            if !(content.starts_with("application/json")
                || upload && content.starts_with("multipart/form-data;"))
            {
                return Some(view::error(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Use application/json or a supported upload.",
                ));
            }
        }
    }
    if matches!(
        (ctx.method.as_str(), ctx.path.as_str()),
        ("GET" | "POST", "/login")
    ) || (ctx.method == Method::GET && ctx.path.starts_with("/image/"))
    {
        return None;
    }
    if ctx.user.is_none() {
        return Some(if ctx.is_api() {
            view::error(StatusCode::UNAUTHORIZED, "Authentication required")
        } else {
            view::redirect(&format!("/login?next={}", urlencoding::encode(&ctx.path)))
        });
    }
    if matches!(
        (ctx.method.as_str(), ctx.path.as_str()),
        ("POST", "/logout") | ("GET", "/settings") | ("POST", "/api/auth/password")
    ) {
        return None;
    }
    if ctx
        .user
        .as_ref()
        .is_some_and(|u| db::bool_field(u, "must_change_password"))
    {
        return Some(if ctx.is_api() {
            view::error(
                StatusCode::FORBIDDEN,
                "Change your temporary password first.",
            )
        } else {
            view::redirect("/settings")
        });
    }
    let allowed = match (ctx.method.as_str(), ctx.path.as_str()) {
        ("GET", "/") => true,
        ("PUT", "/api/auth/profile") => true,
        ("GET", "/management") => ["users.view", "roles.view", "organizations.view"]
            .iter()
            .any(|p| ctx.can(p)),
        _ => rbac::required(&ctx.method, &ctx.path).is_some_and(|p| ctx.can(p)),
    };
    if allowed {
        None
    } else {
        Some(if ctx.is_api() {
            view::error(StatusCode::FORBIDDEN, "Permission denied.")
        } else {
            render(state, ctx, "errors/403.html", json!({})).with_status(StatusCode::FORBIDDEN)
        })
    }
}

trait ResponseStatus {
    fn with_status(self, status: StatusCode) -> Response;
}
impl ResponseStatus for Response {
    fn with_status(mut self, status: StatusCode) -> Response {
        *self.status_mut() = status;
        self
    }
}

async fn dispatch(state: State<AppState>, request: Request<Body>) -> Response {
    let mut response = dispatch_request(state, request).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        "no-store".parse().unwrap(),
    );
    response
}
async fn dispatch_request(State(state): State<AppState>, request: Request<Body>) -> Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_owned();
    let query =
        serde_urlencoded::from_str::<Vec<(String, String)>>(parts.uri.query().unwrap_or(""))
            .unwrap_or_default();
    let body = match to_bytes(body, 25 * 1024 * 1024).await {
        Ok(b) => b.to_vec(),
        Err(_) => return view::error(StatusCode::PAYLOAD_TOO_LARGE, "Request is too large."),
    };
    let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let form = serde_urlencoded::from_bytes::<HashMap<String, String>>(&body).unwrap_or_default();
    let user = auth::current_user(&state, &parts.headers).await;
    let ctx = ReqCtx {
        method: parts.method,
        path,
        query,
        headers: parts.headers,
        body,
        json,
        form,
        user,
    };
    if let Some(response) = guard(&state, &ctx) {
        return response;
    }
    if ctx.path == "/" {
        return view::redirect(if ctx.can("subscriptions.view") {
            "/subscriptions"
        } else if ["users.view", "roles.view", "organizations.view"]
            .iter()
            .any(|p| ctx.can(p))
        {
            "/management"
        } else if ctx.can("reviews.view") {
            "/reviews"
        } else if ctx.can("reports.view") {
            "/reports"
        } else {
            "/settings"
        });
    }
    if let Some(response) = auth::handle(&state, &ctx).await {
        return response;
    }
    if let Some(response) = management::handle(&state, &ctx).await {
        return response;
    }
    if let Some(response) = subscriptions::handle(&state, &ctx).await {
        return response;
    }
    if let Some(response) = reviews::handle(&state, &ctx).await {
        return response;
    }
    if let Some(response) = reports::handle(&state, &ctx).await {
        return response;
    }
    if let Some(response) = operations::handle(&state, &ctx).await {
        return response;
    }
    if let Some(response) = newsletters::handle(&state, &ctx).await {
        return response;
    }
    if let Some(filename) = ctx.path.strip_prefix("/image/") {
        if filename.contains('/') || filename.contains("..") {
            return view::error(StatusCode::NOT_FOUND, "Not found");
        }
        if let Ok(bytes) =
            tokio::fs::read(state.cfg.root.join("static/images").join(filename)).await
        {
            return ([(axum::http::header::CONTENT_TYPE, "image/gif")], bytes).into_response();
        }
    }
    render(
        &state,
        &ctx,
        "errors/404.html",
        json!({"image_filename":"67.gif"}),
    )
    .with_status(StatusCode::NOT_FOUND)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "webserver_rust=info,tower_http=info".into()),
        )
        .init();
    if env::args().nth(1).as_deref() == Some("--local-password-hash") {
        let mut password = String::new();
        std::io::stdin().read_line(&mut password)?;
        while password.ends_with(['\n', '\r']) {
            password.pop();
        }
        println!("{}", auth::password_hash(password).await?);
        return Ok(());
    }
    let root = env::var("WEBSERVER_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let cfg = config::Config::load(&root)?;
    let client = Client::with_uri_str(&cfg.mongo_uri).await?;
    let state = AppState {
        web: client.database(&cfg.web_database),
        vuln: client.database(&cfg.vulnerabilities_database),
        templates: Arc::new(view::environment(&root)),
        http: reqwest::Client::new(),
        cfg,
    };
    auth::ensure_bootstrap(&state).await?;
    if env::var("RUST_SCHEDULER_ENABLED")
        .ok()
        .is_some_and(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
    {
        scheduler::start(state.clone());
    }
    let address = format!("0.0.0.0:{}", state.cfg.port);
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!("Rust server listening on {address}");
    let app = Router::new()
        .nest_service("/static", ServeDir::new(root.join("static")))
        .fallback(any(dispatch))
        .with_state(state);
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod rbac_tests;

#[cfg(test)]
mod rbac_integration_tests;
