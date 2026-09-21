mod auth;
mod config;
mod db;
mod mail;
mod newsletter_normalizer;
mod newsletters;
mod operations;
mod reports;
mod reviews;
mod scheduler;
mod subscriptions;
mod vendor_matcher;
mod view;
mod zimbra;

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
    pub fn is_admin(&self, state: &AppState) -> bool {
        self.user
            .as_ref()
            .is_some_and(|user| auth::is_admin(user, &state.cfg))
    }
    pub fn is_top_admin(&self, state: &AppState) -> bool {
        self.user
            .as_ref()
            .is_some_and(|user| auth::is_top_admin(user, &state.cfg))
    }
    pub fn is_organization_admin(&self, state: &AppState) -> bool {
        self.user
            .as_ref()
            .is_some_and(|user| auth::is_organization_admin(user, &state.cfg))
    }
    pub fn user_id(&self) -> Option<mongodb::bson::oid::ObjectId> {
        self.user
            .as_ref()
            .and_then(|user| user.get_object_id("_id").ok())
    }
    pub fn owner_filter(&self, state: &AppState) -> mongodb::bson::Document {
        if self.is_top_admin(state) {
            mongodb::bson::doc! {}
        } else if let Some(id) = self.user_id() {
            mongodb::bson::doc! {"managed_by_user_id": id}
        } else {
            mongodb::bson::doc! {"_id": mongodb::bson::Bson::Null}
        }
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

fn page_context(ctx: &ReqCtx, state: &AppState, extras: Value) -> Value {
    // The portal is intentionally Chinese-only. Ignore any legacy `lang=en`
    // cookie so an existing browser session cannot switch the interface back
    // to English.
    let locale = "ch".to_owned();
    let mut base = json!({
        "locale": locale, "html_lang": if locale == "ch" { "zh-Hans" } else { "en" },
        "i18n_catalog": serde_json::from_str::<Value>(include_str!("../config/translations.json")).unwrap_or(json!({})).get(&locale).cloned().unwrap_or(json!({})),
        "current_user": ctx.user.as_ref().map(auth::public_user),
        "is_admin": ctx.is_admin(state), "is_top_admin": ctx.is_top_admin(state),
        "is_organization_admin": ctx.is_organization_admin(state),
        "config": {"ZIMBRA_ENABLED": true},
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
    let public = matches!(
        ctx.path.as_str(),
        "/login" | "/login/local" | "/logout" | "/en" | "/zh" | "/cn"
    ) || ctx.path.starts_with("/locale/")
        || ctx.path.starts_with("/image/");
    if public {
        return None;
    }
    if ctx.user.is_none() {
        return Some(if ctx.is_api() {
            view::error(StatusCode::UNAUTHORIZED, "Authentication required")
        } else {
            let target = format!("/login?next={}", urlencoding::encode(&ctx.path));
            view::redirect(&target)
        });
    }
    if ctx
        .user
        .as_ref()
        .is_some_and(|u| db::bool_field(u, "must_change_password"))
        && !matches!(
            ctx.path.as_str(),
            "/settings" | "/api/auth/password" | "/logout"
        )
    {
        return Some(if ctx.is_api() {
            view::json_response(
                StatusCode::FORBIDDEN,
                json!({"error":"Password change required.","code":"password_change_required"}),
            )
        } else {
            view::redirect("/settings")
        });
    }
    let admin = ctx.path.starts_with("/api/reviews")
        || ctx.path.starts_with("/reviews")
        || ctx.path.starts_with("/api/reports")
        || ctx.path.starts_with("/reports")
        || ctx.path.starts_with("/api/operations")
        || ctx.path.starts_with("/generated-newsletters/");
    let top = matches!(
        ctx.path.as_str(),
        "/admin/sub-admins" | "/operations" | "/set-news"
    ) || (ctx.path.starts_with("/api/admin/")
        && !ctx.path.starts_with("/api/admin/account-users"))
        || ctx.path.starts_with("/api/reports/evidence-cache/")
        || ctx.path.starts_with("/api/reports/search-cache/")
        || ctx.path.starts_with("/api/operations/newsletter-")
        || ctx.path == "/api/operations/source-list";
    if top && !ctx.is_top_admin(state) || admin && !ctx.is_admin(state) {
        return Some(if ctx.is_api() {
            view::error(StatusCode::FORBIDDEN, "Administrator access required.")
        } else {
            render(state, ctx, "errors/403.html", json!({})).with_status(StatusCode::FORBIDDEN)
        });
    }
    None
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

async fn dispatch(State(state): State<AppState>, request: Request<Body>) -> Response {
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
        return view::redirect("/subscriptions");
    }
    if let Some(response) = auth::handle(&state, &ctx).await {
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
    if ctx.path.strip_prefix("/locale/").is_some() {
        // Keep the old endpoint working for bookmarks, but always select the
        // only supported portal language.
        let locale = "ch";
        let next = ctx.arg("next");
        let next = if next.starts_with('/') && !next.starts_with("//") {
            next
        } else {
            "/subscriptions".into()
        };
        let mut response = view::redirect(&next);
        response.headers_mut().insert(
            axum::http::header::SET_COOKIE,
            format!("lang={locale}; Max-Age=31536000; Path=/; SameSite=Lax")
                .parse()
                .unwrap(),
        );
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
mod tests {
    use super::*;
    use std::{collections::HashMap, path::Path};

    #[test]
    fn zimbra_login_renders_query_next() {
        let ctx = ReqCtx {
            method: Method::GET,
            path: "/login".into(),
            query: vec![("next".into(), "/subscriptions".into())],
            headers: HeaderMap::new(),
            body: vec![],
            json: Value::Null,
            form: HashMap::new(),
            user: None,
        };
        let request = request_context(&ctx);
        assert_eq!(request["args"]["next"], "/subscriptions");

        let env = view::environment(Path::new(env!("CARGO_MANIFEST_DIR")));
        let html = env
            .get_template("auth/login.html")
            .unwrap()
            .render(json!({
                "locale": "ch",
                "html_lang": "zh-Hans",
                "i18n_catalog": {},
                "config": {"ZIMBRA_ENABLED": true},
                "request": request,
                "local_login": false,
            }))
            .unwrap();
        assert!(html.contains("name=\"next\""));
        assert!(html.contains("subscriptions"));
    }
}
