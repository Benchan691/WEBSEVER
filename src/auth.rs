use crate::{AppState, ReqCtx, db, render, view};
use axum::{
    http::{HeaderMap, Method, StatusCode, header},
    response::Response,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use mongodb::bson::{self, Document, doc, oid::ObjectId};
use serde_json::{Value, json};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const COOKIE: &str = "rust_session";

fn key(value: &str) -> String {
    value.trim().to_lowercase()
}
fn valid_password(password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("Password is required.".into());
    }
    if password.chars().count() > 256 {
        return Err("Password must be 256 characters or fewer.".into());
    }
    if password.len() > 72 {
        return Err("Password must be 72 bytes or fewer.".into());
    }
    Ok(())
}
fn valid_email(email: &str) -> bool {
    let e = email.trim();
    e.is_empty()
        || (e.contains('@')
            && e.rsplit('@')
                .next()
                .is_some_and(|domain| domain.contains('.'))
            && !e.contains(char::is_whitespace))
}
fn session_cookie(state: &AppState, user: &Document) -> String {
    let expiry = chrono::Utc::now().timestamp() + 12 * 3600;
    let payload = format!(
        "{}:{}:{}:{}",
        db::id_string(user),
        db::string(user, "auth_source"),
        db::string(user, "account_hub_uid"),
        expiry
    );
    let mut mac = HmacSha256::new_from_slice(state.cfg.secret.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    format!(
        "{COOKIE}={}.{}; Path=/; Max-Age=43200; HttpOnly; SameSite=Lax",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}
fn session_from_cookie(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<(ObjectId, String, String)> {
    let raw = view::cookie(headers, COOKIE)?;
    let (message, signature) = raw.split_once('.')?;
    let payload = URL_SAFE_NO_PAD.decode(message).ok()?;
    let sig = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let mut mac = HmacSha256::new_from_slice(state.cfg.secret.as_bytes()).ok()?;
    mac.update(&payload);
    mac.verify_slice(&sig).ok()?;
    let payload = String::from_utf8(payload).ok()?;
    let mut parts = payload.splitn(4, ':');
    let id = db::object_id(parts.next()?)?;
    let source = parts.next()?.to_owned();
    let uid = parts.next()?.to_owned();
    let expiry = parts.next()?.parse::<i64>().ok()?;
    if expiry <= chrono::Utc::now().timestamp() {
        return None;
    }
    Some((id, source, uid))
}

pub async fn current_user(state: &AppState, headers: &HeaderMap) -> Option<Document> {
    let (id, source, uid) = session_from_cookie(state, headers)?;
    let user = db::find_one(&state.web, "auth", doc! {"_id":id})
        .await
        .ok()??;
    if db::bool_field(&user, "disabled") {
        return None;
    }
    let actual_source = user.get_str("auth_source").unwrap_or("local");
    if source == "account_hub" {
        if !state.cfg.account_hub_enabled
            || actual_source != "account_hub"
            || uid.is_empty()
            || db::string(&user, "account_hub_uid") != uid
            || !matches!(user.get_str("role"), Ok("user" | "sub_admin"))
        {
            return None;
        }
    } else if state.cfg.account_hub_enabled && !is_top_admin(&user, &state.cfg) {
        return None;
    }
    Some(user)
}

pub fn is_top_admin(user: &Document, cfg: &crate::config::Config) -> bool {
    db::string(user, "role") == "admin"
        && matches!(user.get_str("auth_source"), Ok("local") | Err(_))
        && (!cfg.account_hub_enabled
            || key(&db::string(user, "username")) == key(&cfg.bootstrap_username))
}
pub fn is_admin(user: &Document, cfg: &crate::config::Config) -> bool {
    db::string(user, "role") == "sub_admin" || is_top_admin(user, cfg)
}
pub fn public_user(user: &Document) -> Value {
    json!({"id":db::id_string(user),"username":db::string(user,"username"),"email":db::string(user,"email"),
        "role":user.get_str("role").unwrap_or("user"),"must_change_password":db::bool_field(user,"must_change_password"),
        "disabled":db::bool_field(user,"disabled"),"pause_managed_subscriptions_when_disabled":db::bool_field(user,"pause_managed_subscriptions_when_disabled"),
        "auth_source":user.get_str("auth_source").unwrap_or("local"),"account_hub_uid":db::string(user,"account_hub_uid"),
        "account_hub_username":db::string(user,"account_hub_username"),"account_hub_bound":!db::string(user,"account_hub_uid").is_empty(),
        "role_source":"local"})
}
pub async fn ensure_bootstrap(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    let coll = db::collection(&state.web, "auth");
    let username = state.cfg.bootstrap_username.trim();
    if username.is_empty() {
        return Ok(());
    }
    let existing = coll.find_one(doc! {"username_key":key(username)}).await?;
    let now = bson::DateTime::now();
    if let Some(user) = existing {
        if !matches!(user.get_str("auth_source"), Ok("local") | Err(_)) {
            tracing::warn!("Bootstrap username belongs to a non-local user");
            return Ok(());
        }
        let id = user.get_object_id("_id")?;
        let mut set = doc! {"role":"admin","auth_source":"local","disabled":false,"must_change_password":false,"username_key":key(username),"updated_at":now};
        if user
            .get_str("password")
            .ok()
            .is_none_or(|v| !v.starts_with("$2"))
            && !state.cfg.bootstrap_password.is_empty()
        {
            set.insert(
                "password",
                bcrypt::hash(&state.cfg.bootstrap_password, bcrypt::DEFAULT_COST)?,
            );
        }
        coll.update_one(doc!{"_id":id},doc!{"$set":set,"$unset":{"account_hub_uid":"","account_hub_username":"","last_account_hub_sync_at":""}}).await?;
    } else if !state.cfg.bootstrap_password.is_empty() {
        valid_password(&state.cfg.bootstrap_password)?;
        let hash = bcrypt::hash(&state.cfg.bootstrap_password, bcrypt::DEFAULT_COST)?;
        coll.insert_one(doc!{"username":username,"username_key":key(username),"password":hash,"role":"admin","auth_source":"local","disabled":false,"must_change_password":false,"created_at":now,"updated_at":now}).await?;
    }
    Ok(())
}

async fn find_login(state: &AppState, username: &str) -> Option<Document> {
    let name = username.trim();
    if name.is_empty() {
        return None;
    }
    db::find_one(&state.web, "auth", doc! {"username_key":key(name)})
        .await
        .ok()
        .flatten()
        .or_else(|| None)
}
async fn local_login(state: &AppState, ctx: &ReqCtx, only_bootstrap: bool) -> Response {
    let username = ctx.field("username");
    let password = ctx.field("password");
    if let Some(user) = find_login(state, &username).await {
        let bootstrap = db::string(&user, "role") == "admin"
            && db::string(&user, "auth_source") == "local"
            && key(&db::string(&user, "username")) == key(&state.cfg.bootstrap_username);
        let allowed = !db::bool_field(&user, "disabled") && (!only_bootstrap || bootstrap);
        let hashed = user.get_str("password").unwrap_or("");
        if allowed && bcrypt::verify(&password, hashed).unwrap_or(false) {
            let target = if db::bool_field(&user, "must_change_password") {
                "/settings"
            } else {
                "/subscriptions"
            };
            let mut response = view::redirect(target);
            response.headers_mut().insert(
                header::SET_COOKIE,
                session_cookie(state, &user).parse().unwrap(),
            );
            return response;
        }
    }
    let mut response = render(
        state,
        ctx,
        "auth/login.html",
        json!({"local_login":only_bootstrap,"error":"Invalid username or password"}),
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
async fn hub_login(state: &AppState, ctx: &ReqCtx) -> Response {
    if state.cfg.account_hub_login_url.is_empty()
        || state.cfg.account_hub_token_check_url.is_empty()
    {
        let mut response = render(
            state,
            ctx,
            "auth/login.html",
            json!({"error":"Account Hub is not configured."}),
        );
        *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
        return response;
    }
    let username = ctx.field("username");
    let password = ctx.field("password");
    if username.trim().is_empty() || password.is_empty() {
        return hub_error(
            state,
            ctx,
            "Invalid username or password",
            StatusCode::UNAUTHORIZED,
        );
    }
    let encoded = STANDARD.encode(password.as_bytes());
    let captcha = ctx.field("captchaVerification");
    let mut payload = json!({"username":username,"password":encoded});
    if !captcha.is_empty() {
        payload["captchaVerification"] = json!(captcha);
    }
    let login = state
        .http
        .post(&state.cfg.account_hub_login_url)
        .header(header::ACCEPT, "application/json")
        .json(&payload)
        .send()
        .await;
    let Ok(login) = login else {
        return hub_error(
            state,
            ctx,
            "Account Hub is unavailable.",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    if !login.status().is_success() {
        return hub_error(
            state,
            ctx,
            "Invalid Account Hub username, password, or CAPTCHA.",
            StatusCode::UNAUTHORIZED,
        );
    }
    let cookie_header = login
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .collect::<Vec<_>>()
        .join("; ");
    let payload: Value = match login.json().await {
        Ok(v) => v,
        Err(_) => {
            return hub_error(
                state,
                ctx,
                "Account Hub returned invalid JSON.",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }
    };
    if !business_success(&payload) {
        return hub_error(
            state,
            ctx,
            "Invalid Account Hub username, password, or CAPTCHA.",
            StatusCode::UNAUTHORIZED,
        );
    }
    let data = payload
        .get("data")
        .filter(|v| v.is_object())
        .unwrap_or(&payload);
    let access = data
        .get("accessToken")
        .or_else(|| data.get("access_token"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let refresh = data
        .get("refreshToken")
        .or_else(|| data.get("refresh_token"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if access.is_empty() || refresh.is_empty() {
        return hub_error(
            state,
            ctx,
            "Account Hub did not return usable tokens.",
            StatusCode::UNAUTHORIZED,
        );
    }
    let mut check_request = state
        .http
        .get(&state.cfg.account_hub_token_check_url)
        .bearer_auth(access);
    if state
        .cfg
        .account_hub_token_check_url
        .contains("/token/check")
    {
        check_request = check_request.query(&[("accessToken", access), ("refreshToken", refresh)]);
    }
    if !cookie_header.is_empty() {
        check_request = check_request.header(header::COOKIE, cookie_header);
    }
    let check = check_request.send().await;
    let Ok(check) = check else {
        return hub_error(
            state,
            ctx,
            "Account Hub is unavailable.",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    if !check.status().is_success() {
        return hub_error(
            state,
            ctx,
            "Account Hub session is no longer valid.",
            StatusCode::UNAUTHORIZED,
        );
    }
    let claims: Value = match check.json().await {
        Ok(v) => v,
        Err(_) => {
            return hub_error(
                state,
                ctx,
                "Account Hub returned invalid JSON.",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }
    };
    if !business_success(&claims) {
        return hub_error(
            state,
            ctx,
            "Account Hub session is no longer valid.",
            StatusCode::UNAUTHORIZED,
        );
    }
    let data = claims
        .get("data")
        .filter(|v| v.is_object())
        .unwrap_or(&claims);
    let uid = data
        .get("uid")
        .or_else(|| data.get("userId"))
        .map(value_string)
        .unwrap_or_default();
    let hub_username = data
        .get("username")
        .or_else(|| data.get("userName"))
        .or_else(|| data.get("account"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let role_ok = has_required_role(data, &state.cfg.account_hub_required_role);
    if !role_ok {
        let message = format!("{} role is required.", state.cfg.account_hub_required_role);
        return hub_error(state, ctx, &message, StatusCode::FORBIDDEN);
    }
    if uid.is_empty()
        || hub_username.is_empty()
        || key(hub_username) == key(&state.cfg.bootstrap_username)
    {
        return hub_error(
            state,
            ctx,
            "Account Hub identity is incomplete.",
            StatusCode::FORBIDDEN,
        );
    }
    for name in [
        "accountNonExpired",
        "credentialsNonExpired",
        "accountNonLocked",
        "enabled",
    ] {
        if data.get(name).is_some_and(|v| v != &Value::Bool(true)) {
            return hub_error(
                state,
                ctx,
                "Account Hub account is not active.",
                StatusCode::UNAUTHORIZED,
            );
        }
    }
    if data
        .get("anonymousFlag")
        .is_some_and(|v| v != &Value::Bool(false))
    {
        return hub_error(
            state,
            ctx,
            "Anonymous Account Hub sessions are not allowed.",
            StatusCode::UNAUTHORIZED,
        );
    }
    let coll = db::collection(&state.web, "auth");
    let by_uid = coll
        .find_one(doc! {"account_hub_uid":&uid})
        .await
        .ok()
        .flatten();
    let by_name = find_login(state, hub_username).await;
    if by_uid
        .as_ref()
        .is_some_and(|u| db::string(u, "auth_source") != "account_hub")
        || by_name
            .as_ref()
            .is_some_and(|u| db::string(u, "auth_source") != "account_hub")
        || by_uid
            .as_ref()
            .zip(by_name.as_ref())
            .is_some_and(|(a, b)| a.get("_id") != b.get("_id"))
    {
        return hub_error(
            state,
            ctx,
            "Account Hub identity conflicts with a local user.",
            StatusCode::FORBIDDEN,
        );
    }
    let user = if let Some(user) = by_uid.or(by_name) {
        user
    } else {
        let now = bson::DateTime::now();
        let mut document = doc! {"username":hub_username,"username_key":key(hub_username),"auth_source":"account_hub","role":"user","disabled":false,"must_change_password":false,"created_at":now,"updated_at":now};
        if let Some(email) = data
            .get("email")
            .and_then(Value::as_str)
            .filter(|e| valid_email(e))
        {
            document.insert("email", email.trim().to_lowercase());
        }
        let inserted = match coll.insert_one(document).await {
            Ok(r) => r,
            Err(_) => {
                return hub_error(
                    state,
                    ctx,
                    "Unable to establish the Account Hub session.",
                    StatusCode::SERVICE_UNAVAILABLE,
                );
            }
        };
        match coll
            .find_one(doc! {"_id":inserted.inserted_id})
            .await
            .ok()
            .flatten()
        {
            Some(v) => v,
            None => {
                return hub_error(
                    state,
                    ctx,
                    "Unable to establish the Account Hub session.",
                    StatusCode::SERVICE_UNAVAILABLE,
                );
            }
        }
    };
    if db::bool_field(&user, "disabled") {
        return hub_error(
            state,
            ctx,
            "This portal account is disabled.",
            StatusCode::FORBIDDEN,
        );
    }
    if !db::string(&user, "account_hub_uid").is_empty()
        && db::string(&user, "account_hub_uid") != uid
    {
        return hub_error(
            state,
            ctx,
            "Account Hub identity does not match the local user.",
            StatusCode::FORBIDDEN,
        );
    }
    let id = user.get_object_id("_id").unwrap();
    let now = bson::DateTime::now();
    if coll.update_one(doc!{"_id":id},doc!{"$set":{"auth_source":"account_hub","account_hub_uid":&uid,"account_hub_username":hub_username,"role":if db::string(&user,"role")=="sub_admin"{"sub_admin"}else{"user"},"must_change_password":false,"last_account_hub_sync_at":now,"updated_at":now},"$unset":{"password":""}}).await.is_err(){return hub_error(state,ctx,"Unable to establish the Account Hub session.",StatusCode::SERVICE_UNAVAILABLE)}
    let Some(user) = coll.find_one(doc! {"_id":id}).await.ok().flatten() else {
        return hub_error(
            state,
            ctx,
            "Unable to establish the Account Hub session.",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    let mut response = view::redirect(safe_next(&ctx.field("next")));
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(state, &user).parse().unwrap(),
    );
    response
}
fn business_success(value: &Value) -> bool {
    matches!(value.get("code"), None | Some(Value::Null))
        || matches!(value.get("code"),Some(Value::Number(n)) if n.as_i64().is_some_and(|code| matches!(code, 0 | 200 | 1000)))
        || matches!(value.get("code"),Some(Value::String(s)) if matches!(s.as_str(), "0" | "200" | "1000"))
}
fn value_string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}
fn has_required_role(data: &Value, required: &str) -> bool {
    let required = required.trim();
    if required.is_empty() {
        return false;
    }
    ["roles", "role_names", "systemRole", "systemRoles"]
        .into_iter()
        .flat_map(|key| data.get(key).into_iter())
        .flat_map(|value| value.as_array().into_iter().flatten())
        .filter_map(|role| {
            role.as_str().map(str::to_owned).or_else(|| {
                role.get("roleName")
                    .or_else(|| role.get("name"))
                    .or_else(|| role.get("label"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
        })
        .map(|role| role.trim().to_owned())
        .any(|role| {
            role.eq_ignore_ascii_case(required)
                || role
                    .strip_prefix(required)
                    .is_some_and(|suffix| suffix.starts_with(['-', '_', '/', ' ']))
                || role
                    .split('/')
                    .any(|part| part.trim().eq_ignore_ascii_case(required))
        })
}
fn hub_error(state: &AppState, ctx: &ReqCtx, message: &str, status: StatusCode) -> Response {
    let mut r = render(state, ctx, "auth/login.html", json!({"error":message}));
    *r.status_mut() = status;
    r
}

pub async fn handle(state: &AppState, ctx: &ReqCtx) -> Option<Response> {
    match (ctx.method.clone(), ctx.path.as_str()) {
        (Method::GET, "/login") => return Some(render(state, ctx, "auth/login.html", json!({}))),
        (Method::POST, "/login") => {
            return Some(if state.cfg.account_hub_enabled {
                hub_login(state, ctx).await
            } else {
                local_login(state, ctx, false).await
            });
        }
        (Method::GET, "/login/local") => {
            return Some(render(
                state,
                ctx,
                "auth/login.html",
                json!({"local_login":true}),
            ));
        }
        (Method::POST, "/login/local") => return Some(local_login(state, ctx, true).await),
        (_, "/auth/account-hub/callback") => return Some(view::redirect("/login")),
        (_, "/logout") => {
            let mut response = view::redirect("/login");
            response.headers_mut().insert(
                header::SET_COOKIE,
                format!("{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
                    .parse()
                    .unwrap(),
            );
            return Some(response);
        }
        (Method::GET, "/settings") => {
            return Some(render(state, ctx, "auth/settings.html", json!({})));
        }
        (Method::GET, "/admin/sub-admins") => {
            return Some(if state.cfg.account_hub_enabled {
                view::redirect("/admin/account-users")
            } else {
                render(state, ctx, "auth/sub_admins_legacy.html", json!({}))
            });
        }
        (Method::GET, "/admin/account-users") => {
            return Some(if state.cfg.account_hub_enabled {
                render(
                    state,
                    ctx,
                    "auth/sub_admins.html",
                    json!({"account_hub_enabled":true}),
                )
            } else {
                view::redirect("/admin/sub-admins")
            });
        }
        (Method::POST, "/api/auth/password") => return Some(change_password(state, ctx).await),
        _ => {}
    }
    if ctx.path.starts_with("/api/admin/") {
        return Some(admin_api(state, ctx).await);
    }
    None
}
async fn change_password(state: &AppState, ctx: &ReqCtx) -> Response {
    let Some(user) = ctx.user.as_ref() else {
        return view::error(StatusCode::UNAUTHORIZED, "Authentication required");
    };
    if db::string(user, "auth_source") == "account_hub" {
        return view::error(
            StatusCode::FORBIDDEN,
            "Password changes are managed by Account Hub.",
        );
    }
    let old = ctx.field("current_password");
    let new = ctx.field("new_password");
    if new != ctx.field("new_password_confirmation") {
        return view::error(StatusCode::BAD_REQUEST, "New passwords do not match.");
    }
    if !bcrypt::verify(&old, user.get_str("password").unwrap_or("")).unwrap_or(false) {
        return view::error(StatusCode::BAD_REQUEST, "Current password is incorrect.");
    }
    if let Err(e) = valid_password(&new) {
        return view::error(StatusCode::BAD_REQUEST, &e);
    }
    let hash = match bcrypt::hash(&new, bcrypt::DEFAULT_COST) {
        Ok(v) => v,
        Err(_) => {
            return view::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to change password.",
            );
        }
    };
    if db::collection(&state.web,"auth").update_one(doc!{"_id":ctx.user_id().unwrap()},doc!{"$set":{"password":hash,"must_change_password":false,"updated_at":bson::DateTime::now()}}).await.is_err(){return view::error(StatusCode::SERVICE_UNAVAILABLE,"Unable to change password.")}
    view::json_response(StatusCode::OK, json!({"success":true}))
}

async fn admin_api(state: &AppState, ctx: &ReqCtx) -> Response {
    let hub = ctx.path.starts_with("/api/admin/account-users");
    if hub != state.cfg.account_hub_enabled {
        return view::error(
            StatusCode::GONE,
            if hub {
                "Account Hub is disabled."
            } else {
                "Account Hub user management has replaced sub-admin management."
            },
        );
    }
    let base = if hub {
        "/api/admin/account-users"
    } else {
        "/api/admin/sub-admins"
    };
    let coll = db::collection(&state.web, "auth");
    let id = ctx
        .path
        .strip_prefix(&format!("{base}/"))
        .and_then(db::object_id);
    if ctx.method == Method::GET && ctx.path == base {
        let filter = if hub {
            doc! {"auth_source":"account_hub"}
        } else {
            doc! {"role":"sub_admin"}
        };
        return match db::find_sorted(&state.web, "auth", filter, doc! {"username_key":1}, 500).await
        {
            Ok(rows) => view::json_response(
                StatusCode::OK,
                json!({"data":rows.iter().map(public_user).collect::<Vec<_>>()}),
            ),
            Err(_) => view::error(StatusCode::SERVICE_UNAVAILABLE, "Unable to load users."),
        };
    }
    if ctx.method == Method::POST && ctx.path == base {
        let username = ctx.field("username").trim().to_owned();
        let email = ctx.field("email").trim().to_lowercase();
        if username.is_empty() {
            return view::error(StatusCode::BAD_REQUEST, "Username is required.");
        }
        if key(&username) == key(&state.cfg.bootstrap_username) {
            return view::error(
                StatusCode::BAD_REQUEST,
                "Username is reserved for the local administrator.",
            );
        }
        if !valid_email(&email) {
            return view::error(StatusCode::BAD_REQUEST, "Invalid email address.");
        }
        if coll
            .find_one(doc! {"username_key":key(&username)})
            .await
            .ok()
            .flatten()
            .is_some()
        {
            return view::error(StatusCode::CONFLICT, "Username is already in use.");
        }
        let now = bson::DateTime::now();
        let mut document = doc! {"username":&username,"username_key":key(&username),"email":&email,"role":if hub{"user"}else{"sub_admin"},"auth_source":if hub{"account_hub"}else{"local"},"disabled":ctx.json_field("disabled").as_bool().unwrap_or(false),"pause_managed_subscriptions_when_disabled":ctx.json_field("pause_managed_subscriptions_when_disabled").as_bool().unwrap_or(false),"must_change_password":false,"created_at":now,"updated_at":now};
        if hub {
            if ctx.json.get("password").is_some() {
                return view::error(
                    StatusCode::BAD_REQUEST,
                    "Account Hub users do not use local passwords.",
                );
            }
            if ctx.json.get("role").is_some() {
                return view::error(
                    StatusCode::BAD_REQUEST,
                    "Assign a local role after creating the user.",
                );
            }
        } else {
            let password = ctx.field("password");
            if let Err(e) = valid_password(&password) {
                return view::error(StatusCode::BAD_REQUEST, &e);
            };
            document.insert(
                "password",
                bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap(),
            );
            if let Some(owner) = ctx.user_id() {
                document.insert("parent_admin_id", owner);
            }
        }
        return match coll.insert_one(document.clone()).await {
            Ok(result) => {
                document.insert("_id", result.inserted_id);
                view::json_response(StatusCode::CREATED, json!({"data":public_user(&document)}))
            }
            Err(_) => view::error(StatusCode::SERVICE_UNAVAILABLE, "Unable to create user."),
        };
    }
    let Some(id) = id else {
        return view::error(StatusCode::NOT_FOUND, "User not found.");
    };
    let Some(user) = coll.find_one(doc! {"_id":id}).await.ok().flatten() else {
        return view::error(StatusCode::NOT_FOUND, "User not found.");
    };
    if hub && db::string(&user, "auth_source") != "account_hub"
        || !hub && db::string(&user, "role") != "sub_admin"
    {
        return view::error(StatusCode::NOT_FOUND, "User not found.");
    }
    if ctx.method == Method::DELETE && !hub {
        if let Some(owner) = ctx.user_id() {
            for name in ["sub_account", "report_jobs", "newsletter_deliveries"] {
                let _ = db::collection(&state.web, name)
                    .update_many(
                        doc! {"managed_by_user_id":id},
                        doc! {"$set":{"managed_by_user_id":owner}},
                    )
                    .await;
            }
        }
        return match coll.delete_one(doc! {"_id":id}).await {
            Ok(_) => view::json_response(StatusCode::OK, json!({"success":true})),
            Err(_) => view::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unable to remove sub-admin.",
            ),
        };
    }
    if ctx.method == Method::PUT {
        if ctx.json.get("username").is_some()
            || hub
                && (ctx.json.get("password").is_some() || ctx.json.get("account_hub_uid").is_some())
        {
            return view::error(
                StatusCode::BAD_REQUEST,
                "Identity fields cannot be changed.",
            );
        }
        let mut update = doc! {"updated_at":bson::DateTime::now()};
        if let Some(email) = ctx.json.get("email").and_then(Value::as_str) {
            if !valid_email(email) {
                return view::error(StatusCode::BAD_REQUEST, "Invalid email address.");
            };
            update.insert("email", email.trim().to_lowercase());
        }
        for field in ["disabled", "pause_managed_subscriptions_when_disabled"] {
            if let Some(value) = ctx.json.get(field) {
                let Some(value) = value.as_bool() else {
                    return view::error(StatusCode::BAD_REQUEST, "Boolean field is invalid.");
                };
                update.insert(field, value);
            }
        }
        if hub {
            if let Some(role) = ctx.json.get("role").and_then(Value::as_str) {
                if !matches!(role, "user" | "sub_admin") {
                    return view::error(StatusCode::BAD_REQUEST, "Invalid user role.");
                };
                update.insert("role", role);
            }
        } else if let Some(password) = ctx
            .json
            .get("password")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        {
            if let Err(e) = valid_password(password) {
                return view::error(StatusCode::BAD_REQUEST, &e);
            };
            update.insert(
                "password",
                bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap(),
            );
            update.insert("must_change_password", false);
        }
        if coll
            .update_one(doc! {"_id":id}, doc! {"$set":update})
            .await
            .is_err()
        {
            return view::error(StatusCode::SERVICE_UNAVAILABLE, "Unable to update user.");
        }
        let updated = coll
            .find_one(doc! {"_id":id})
            .await
            .ok()
            .flatten()
            .unwrap_or(user);
        return view::json_response(StatusCode::OK, json!({"data":public_user(&updated)}));
    }
    view::error(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_hub_role_matches_system_role_suffix() {
        let data = json!({
            "roles": [{"roleName": "user"}],
            "systemRole": ["accounthub-user", "CVE-SYSTEM-admin"]
        });
        assert!(has_required_role(&data, "CVE-SYSTEM"));
        assert!(!has_required_role(&data, "OTHER-SYSTEM"));
    }

    #[test]
    fn account_hub_success_code_includes_current_api() {
        assert!(business_success(&json!({"code":1000})));
        assert!(!business_success(&json!({"code":2010})));
    }
}
