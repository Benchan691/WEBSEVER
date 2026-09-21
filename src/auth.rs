use crate::{AppState, ReqCtx, db, render, view, zimbra};
use axum::{
    http::{HeaderMap, Method, StatusCode, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use mongodb::{
    IndexModel,
    bson::{self, Document, doc, oid::ObjectId},
    options::IndexOptions,
};
use serde_json::{Value, json};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const COOKIE: &str = "rust_session";

pub fn key(value: &str) -> String {
    value.trim().to_lowercase()
}
pub(crate) fn valid_email(email: &str) -> bool {
    let e = email.trim();
    !e.is_empty()
        && e.len() <= 320
        && e.contains('@')
        && e.rsplit('@').next().is_some_and(|d| d.contains('.'))
        && !e.contains(char::is_whitespace)
}
fn valid_password(password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("Password is required.".into());
    }
    if password.chars().count() > 256 || password.len() > 72 {
        return Err("Password must be 72 bytes or fewer.".into());
    }
    Ok(())
}
fn accounts(state: &AppState) -> mongodb::Collection<Document> {
    db::collection(&state.web, &state.cfg.account_collection)
}

fn session_cookie(state: &AppState, user: &Document) -> String {
    let expiry = chrono::Utc::now().timestamp() + 12 * 3600;
    let payload = format!(
        "{}:{}:{}",
        db::id_string(user),
        db::string(user, "auth_source"),
        expiry
    );
    let mut mac = HmacSha256::new_from_slice(state.cfg.secret.as_bytes()).expect("HMAC key");
    mac.update(payload.as_bytes());
    format!(
        "{COOKIE}={}.{}; Path=/; Max-Age=43200; HttpOnly; SameSite=Lax",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}
fn session_from_cookie(state: &AppState, headers: &HeaderMap) -> Option<(ObjectId, String)> {
    let raw = view::cookie(headers, COOKIE)?;
    let (message, signature) = raw.split_once('.')?;
    let payload = URL_SAFE_NO_PAD.decode(message).ok()?;
    let sig = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let mut mac = HmacSha256::new_from_slice(state.cfg.secret.as_bytes()).ok()?;
    mac.update(&payload);
    mac.verify_slice(&sig).ok()?;
    let payload = String::from_utf8(payload).ok()?;
    let mut parts = payload.splitn(3, ':');
    let id = db::object_id(parts.next()?)?;
    let source = parts.next()?.to_owned();
    let expiry = parts.next()?.parse::<i64>().ok()?;
    (expiry > chrono::Utc::now().timestamp()).then_some((id, source))
}

pub async fn current_user(state: &AppState, headers: &HeaderMap) -> Option<Document> {
    let (id, source) = session_from_cookie(state, headers)?;
    let user = accounts(state).find_one(doc! {"_id":id}).await.ok()??;
    if db::bool_field(&user, "disabled") || db::string(&user, "auth_source") != source {
        return None;
    }
    Some(user)
}
pub fn is_top_admin(user: &Document, cfg: &crate::config::Config) -> bool {
    db::string(user, "auth_source") == "local"
        && db::string(user, "role") == "admin"
        && key(&db::string(user, "username")) == key(&cfg.bootstrap_username)
}
pub fn is_admin(user: &Document, cfg: &crate::config::Config) -> bool {
    is_top_admin(user, cfg)
}
pub fn is_organization_admin(_user: &Document, _cfg: &crate::config::Config) -> bool {
    false
}
pub(crate) fn zimbra_email(user: &Document) -> Option<String> {
    let email = db::string(user, "email").trim().to_lowercase();
    (db::string(user, "auth_source") == "zimbra" && valid_email(&email)).then_some(email)
}
pub(crate) fn organization_filter(user: &Document) -> Option<Document> {
    let id = db::string(user, "organization_id");
    if !id.is_empty() {
        return Some(doc! {"organization_id": id});
    }
    let name = db::string(user, "organization");
    (!name.is_empty()).then(|| doc! {"organization":name})
}
pub(crate) fn same_organization(manager: &Document, member: &Document) -> bool {
    let left = db::string(manager, "organization_id");
    let right = db::string(member, "organization_id");
    if !left.is_empty() || !right.is_empty() {
        return !left.is_empty() && left == right;
    }
    let left = db::string(manager, "organization");
    let right = db::string(member, "organization");
    !left.is_empty() && key(&left) == key(&right)
}

pub fn public_user(user: &Document) -> Value {
    json!({
        "id": db::id_string(user), "username": db::string(user,"username"),
        "email": db::string(user,"email"), "role": db::string(user,"role"),
        "auth_source": db::string(user,"auth_source"), "disabled": db::bool_field(user,"disabled"),
        "must_change_password": db::bool_field(user,"must_change_password"),
        "zimbra_email": if db::string(user,"auth_source")=="zimbra" { db::string(user,"email") } else { String::new() },
        "zimbra_folder_id": db::string(user,"zimbra_folder_id"),
        "zimbra_folder_path": db::string(user,"zimbra_folder_path"),
        "organization": db::string(user,"organization"), "organization_id": db::string(user,"organization_id"),
        "account_hub_email": "", "account_hub_bound": false, "organization_admin": false,
        "account_hub_roles": [], "account_hub_system_roles": [], "role_source": "local"
    })
}

pub async fn ensure_bootstrap(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    let coll = accounts(state);
    coll.create_index(
        IndexModel::builder()
            .keys(doc! {"username_key":1})
            .options(
                IndexOptions::builder()
                    .unique(true)
                    .name(Some("accounts_username_unique".to_owned()))
                    .build(),
            )
            .build(),
    )
    .await?;
    coll.create_index(
        IndexModel::builder()
            .keys(doc! {"email_key":1})
            .options(
                IndexOptions::builder()
                    .unique(true)
                    .sparse(true)
                    .name(Some("accounts_email_unique".to_owned()))
                    .build(),
            )
            .build(),
    )
    .await?;
    let username = state.cfg.bootstrap_username.trim();
    if username.is_empty() || state.cfg.bootstrap_password.is_empty() {
        return Err("WEB_AUTH_BOOTSTRAP_USERNAME and WEB_AUTH_BOOTSTRAP_PASSWORD are required for the local administrator.".into());
    }
    valid_password(&state.cfg.bootstrap_password)?;
    let now = bson::DateTime::now();
    let hash = bcrypt::hash(&state.cfg.bootstrap_password, bcrypt::DEFAULT_COST)?;
    coll.update_one(doc! {"username_key":key(username), "auth_source":"local"}, doc! {"$set":{"username":username,"username_key":key(username),"password":hash,"role":"admin","auth_source":"local","disabled":false,"must_change_password":false,"updated_at":now},"$setOnInsert":{"created_at":now}}).upsert(true).await?;
    Ok(())
}

async fn local_login(state: &AppState, ctx: &ReqCtx) -> Response {
    let username = ctx.field("username");
    let password = ctx.field("password");
    let user = accounts(state)
        .find_one(doc! {"username_key":key(&username),"auth_source":"local"})
        .await
        .ok()
        .flatten();
    if let Some(user) = user
        && !db::bool_field(&user, "disabled")
        && bcrypt::verify(password, user.get_str("password").unwrap_or("")).unwrap_or(false)
    {
        let next = ctx.field("next");
        let target = if db::bool_field(&user, "must_change_password") {
            "/settings"
        } else {
            safe_next(&next)
        };
        let mut response = view::redirect(target);
        response.headers_mut().insert(
            header::SET_COOKIE,
            session_cookie(state, &user).parse().unwrap(),
        );
        return response;
    }
    let mut response = render(
        state,
        ctx,
        "auth/login.html",
        json!({"local_login":true,"error":"Invalid username or password."}),
    );
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
}
fn safe_next(next: &str) -> &str {
    if next.starts_with('/') && !next.starts_with("//") {
        next
    } else {
        "/subscriptions"
    }
}

async fn zimbra_login(state: &AppState, ctx: &ReqCtx) -> Response {
    let email = ctx.field("username").trim().to_lowercase();
    let password = ctx.field("password");
    if !valid_email(&email) || password.is_empty() {
        let mut r = render(
            state,
            ctx,
            "auth/login.html",
            json!({"error":"Enter your full Zimbra email address and password."}),
        );
        *r.status_mut() = StatusCode::UNAUTHORIZED;
        return r;
    }
    let (_session, folder_id, folder_path) =
        match zimbra::login_and_prepare(state, &email, &password).await {
            Ok(v) => v,
            Err(error) => {
                let mut r = render(state, ctx, "auth/login.html", json!({"error":error}));
                *r.status_mut() = StatusCode::UNAUTHORIZED;
                return r;
            }
        };
    let encrypted = match zimbra::encrypt_password(&state.cfg, &password) {
        Ok(v) => v,
        Err(e) => return view::error(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    let now = bson::DateTime::now();
    let coll = accounts(state);
    let existing = coll
        .find_one(doc! {"email_key":&email,"auth_source":"zimbra"})
        .await
        .ok()
        .flatten();
    let set = doc! {"username":&email,"username_key":&email,"email":&email,"email_key":&email,"auth_source":"zimbra","role":"user","disabled":false,"must_change_password":false,"zimbra_password":encrypted,"zimbra_folder_id":folder_id,"zimbra_folder_path":folder_path,"last_login_at":now,"updated_at":now};
    let user = if let Some(old) = existing {
        let id = old.get_object_id("_id").unwrap();
        if coll
            .update_one(doc! {"_id":id}, doc! {"$set":set})
            .await
            .is_err()
        {
            return view::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unable to save the Zimbra account.",
            );
        }
        coll.find_one(doc! {"_id":id}).await.ok().flatten().unwrap()
    } else {
        let mut d = set;
        d.insert("created_at", now);
        let result = match coll.insert_one(d.clone()).await {
            Ok(v) => v,
            Err(_) => {
                return view::error(StatusCode::CONFLICT, "This email is already registered.");
            }
        };
        d.insert("_id", result.inserted_id);
        d
    };
    let mut response = view::redirect(safe_next(&ctx.field("next")));
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(state, &user).parse().unwrap(),
    );
    response
}

pub async fn handle(state: &AppState, ctx: &ReqCtx) -> Option<Response> {
    match (ctx.method.clone(), ctx.path.as_str()) {
        (Method::GET, "/login") => {
            return Some(render(
                state,
                ctx,
                "auth/login.html",
                json!({"local_login":false}),
            ));
        }
        (Method::POST, "/login") => return Some(zimbra_login(state, ctx).await),
        (Method::GET, "/login/local") => {
            return Some(render(
                state,
                ctx,
                "auth/login.html",
                json!({"local_login":true}),
            ));
        }
        (Method::POST, "/login/local") => return Some(local_login(state, ctx).await),
        (_, "/logout") => {
            let mut r = view::redirect("/login");
            r.headers_mut().insert(
                header::SET_COOKIE,
                format!("{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
                    .parse()
                    .unwrap(),
            );
            return Some(r);
        }
        (Method::GET, "/settings") => {
            return Some(render(state, ctx, "auth/settings.html", json!({})));
        }
        (Method::POST, "/api/auth/password") => return Some(change_password(state, ctx).await),
        (Method::PUT, "/api/auth/profile") => return Some(update_profile(state, ctx).await),
        (Method::GET, "/admin/sub-admins") => {
            return Some(view::redirect("/subscriptions"));
        }
        (Method::GET, "/organization/members") | (Method::GET, "/admin/account-users") => {
            return Some(view::error(
                StatusCode::GONE,
                "Account Hub organization management is no longer available.",
            ));
        }
        _ => {}
    }
    if ctx.path.starts_with("/api/admin/") || ctx.path.starts_with("/api/organization/members") {
        return Some(view::error(
            StatusCode::GONE,
            "Account Hub administration is no longer available.",
        ));
    }
    None
}
async fn change_password(state: &AppState, ctx: &ReqCtx) -> Response {
    let Some(user) = ctx.user.as_ref() else {
        return view::error(StatusCode::UNAUTHORIZED, "Authentication required");
    };
    if db::string(user, "auth_source") != "local" {
        return view::error(
            StatusCode::FORBIDDEN,
            "Zimbra passwords are managed by Zimbra.",
        );
    }
    let old = ctx.field("current_password");
    let new = ctx.field("new_password");
    if new != ctx.field("new_password_confirmation") {
        return view::error(StatusCode::BAD_REQUEST, "New passwords do not match.");
    }
    if !bcrypt::verify(old, user.get_str("password").unwrap_or("")).unwrap_or(false) {
        return view::error(StatusCode::BAD_REQUEST, "Current password is incorrect.");
    }
    if let Err(e) = valid_password(&new) {
        return view::error(StatusCode::BAD_REQUEST, &e);
    }
    let hash = match bcrypt::hash(new, bcrypt::DEFAULT_COST) {
        Ok(v) => v,
        Err(_) => {
            return view::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unable to change password.",
            );
        }
    };
    match accounts(state).update_one(doc!{"_id":ctx.user_id().unwrap()},doc!{"$set":{"password":hash,"must_change_password":false,"updated_at":bson::DateTime::now()}}).await{Ok(_)=>view::json_response(StatusCode::OK,json!({"success":true})),Err(_)=>view::error(StatusCode::SERVICE_UNAVAILABLE,"Unable to change password.")}
}
async fn update_profile(state: &AppState, ctx: &ReqCtx) -> Response {
    let Some(user) = ctx.user.as_ref() else {
        return view::error(StatusCode::UNAUTHORIZED, "Authentication required");
    };
    if db::string(user, "auth_source") != "local" {
        return view::error(StatusCode::FORBIDDEN, "Zimbra email is managed by Zimbra.");
    }
    if !ctx.json.is_object()
        || ctx
            .json
            .as_object()
            .is_some_and(|o| o.keys().any(|k| k != "email"))
    {
        return view::error(
            StatusCode::BAD_REQUEST,
            "Only your email address can be changed here.",
        );
    }
    let email = ctx
        .json
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if !email.is_empty() && !valid_email(&email) {
        return view::error(StatusCode::BAD_REQUEST, "Invalid email address.");
    }
    match accounts(state).update_one(doc!{"_id":ctx.user_id().unwrap()},doc!{"$set":{"email":&email,"email_key":if email.is_empty(){bson::Bson::Null}else{bson::Bson::String(email.clone())},"updated_at":bson::DateTime::now()}}).await{Ok(_)=>view::json_response(StatusCode::OK,json!({"data":public_user(&accounts(state).find_one(doc!{"_id":ctx.user_id().unwrap()}).await.ok().flatten().unwrap_or_else(||user.clone()))})),Err(_)=>view::error(StatusCode::CONFLICT,"Unable to update your profile.")}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalizes_account_keys() {
        assert_eq!(key(" User@Example.COM "), "user@example.com");
    }
    #[test]
    fn zimbra_users_cannot_be_local_admins() {
        let u = doc! {"auth_source":"zimbra","role":"user","username":"x@example.com"};
        assert!(!is_top_admin(&u, &dummy()));
    }
    fn dummy() -> crate::config::Config {
        crate::config::Config {
            root: Default::default(),
            file: json!({}),
            mongo_uri: String::new(),
            web_database: "web".into(),
            vulnerabilities_database: "vulnerabilities".into(),
            secret: "x".into(),
            bootstrap_username: "admin".into(),
            bootstrap_password: "pw".into(),
            zimbra_base_url: String::new(),
            zimbra_folder_name: "news".into(),
            zimbra_timeout_seconds: 10,
            zimbra_verify_tls: true,
            zimbra_credential_key: String::new(),
            account_collection: "accounts".into(),
            newsletter_root: Default::default(),
            review_view_suffix: "_review".into(),
            port: 9100,
        }
    }
}
