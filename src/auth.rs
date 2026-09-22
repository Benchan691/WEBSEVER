use crate::{AppState, ReqCtx, db, render, subscriptions, view, zimbra};
use axum::{
    http::{HeaderMap, Method, StatusCode, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use mongodb::{
    IndexModel,
    bson::{self, Document, doc, oid::ObjectId},
    options::{IndexOptions, ReturnDocument},
};
use rand::RngCore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;
const COOKIE: &str = "rust_session";
const TWO_FACTOR_COOKIE: &str = "zimbra_2fa_challenge";
const TWO_FACTOR_COLLECTION: &str = "zimbra_login_challenges";
const TWO_FACTOR_MAX_ATTEMPTS: i32 = 5;
const TWO_FACTOR_MAX_LIFETIME_SECONDS: u64 = 300;

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
fn two_factor_challenges(state: &AppState) -> mongodb::Collection<Document> {
    db::collection(&state.web, TWO_FACTOR_COLLECTION)
}

fn challenge_digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}
fn new_challenge_id() -> String {
    let mut value = [0_u8; 32];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}
fn challenge_cookie(value: &str, lifetime_seconds: u64) -> String {
    format!(
        "{TWO_FACTOR_COOKIE}={value}; Path=/login; Max-Age={lifetime_seconds}; HttpOnly; SameSite=Lax"
    )
}
fn clear_challenge_cookie() -> String {
    format!("{TWO_FACTOR_COOKIE}=; Path=/login; Max-Age=0; HttpOnly; SameSite=Lax")
}
fn challenge_lifetime_seconds(lifetime_ms: u64) -> u64 {
    if lifetime_ms == 0 {
        TWO_FACTOR_MAX_LIFETIME_SECONDS
    } else {
        lifetime_ms
            .div_ceil(1000)
            .clamp(1, TWO_FACTOR_MAX_LIFETIME_SECONDS)
    }
}
fn valid_two_factor_code(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|value| value.is_ascii_digit())
}
fn masked_email(value: &str) -> String {
    let Some((name, domain)) = value.split_once('@') else {
        return value.to_owned();
    };
    let first = name.chars().next().unwrap_or('*');
    format!("{first}***@{domain}")
}
fn challenge_attempts(challenge: &Document) -> i32 {
    challenge
        .get_i32("attempts")
        .or_else(|_| challenge.get_i64("attempts").map(|value| value as i32))
        .unwrap_or(0)
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
    two_factor_challenges(state)
        .create_index(
            IndexModel::builder()
                .keys(doc! {"expires_at":1})
                .options(
                    IndexOptions::builder()
                        .expire_after(Duration::from_secs(0))
                        .name(Some("zimbra_2fa_challenge_expiry".to_owned()))
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
    let target_filter = doc! {"username_key":key(username), "auth_source":"local"};
    if let Some(existing) = coll.find_one(target_filter.clone()).await? {
        coll.update_one(
            doc! {"_id": existing.get_object_id("_id")?},
            doc! {"$set":{"username":username,"username_key":key(username),"password":hash,"role":"admin","auth_source":"local","disabled":false,"must_change_password":false,"updated_at":now}},
        )
        .await?;
    } else if let Some(existing) = coll
        .find_one(doc! {"auth_source":"local","role":"admin"})
        .await?
    {
        // Keep one break-glass administrator when its configured username is
        // changed between deployments; do not create a second local admin.
        coll.update_one(
            doc! {"_id": existing.get_object_id("_id")?},
            doc! {"$set":{"username":username,"username_key":key(username),"password":hash,"role":"admin","auth_source":"local","disabled":false,"must_change_password":false,"updated_at":now}},
        )
        .await?;
    } else {
        let mut account = doc! {
            "username": username,
            "username_key": key(username),
            "password": hash,
            "role": "admin",
            "auth_source": "local",
            "disabled": false,
            "must_change_password": false,
            "updated_at": now,
            "created_at": now,
        };
        coll.insert_one(&mut account).await?;
    }
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

fn login_error(
    state: &AppState,
    ctx: &ReqCtx,
    email: &str,
    message: &str,
    status: StatusCode,
) -> Response {
    let mut response = render(
        state,
        ctx,
        "auth/login.html",
        json!({"local_login":false,"login_email":email,"error":message}),
    );
    *response.status_mut() = status;
    response
}

fn two_factor_page(
    state: &AppState,
    ctx: &ReqCtx,
    email: &str,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let mut response = render(
        state,
        ctx,
        "auth/login.html",
        json!({
            "local_login": false,
            "two_factor_required": true,
            "masked_email": masked_email(email),
            "error": error,
        }),
    );
    *response.status_mut() = status;
    response
}

async fn create_two_factor_challenge(
    state: &AppState,
    email: &str,
    encrypted_password: &str,
    temporary_token: &str,
    next: &str,
    lifetime_ms: u64,
) -> Result<(String, u64), String> {
    let challenge_id = new_challenge_id();
    let lifetime_seconds = challenge_lifetime_seconds(lifetime_ms);
    let expires_at = bson::DateTime::from_millis(
        bson::DateTime::now().timestamp_millis() + (lifetime_seconds as i64 * 1000),
    );
    let encrypted_token = zimbra::encrypt_secret(&state.cfg, temporary_token)?;
    two_factor_challenges(state)
        .insert_one(doc! {
            "_id": challenge_digest(&challenge_id),
            "email": email,
            "encrypted_password": encrypted_password,
            "encrypted_auth_token": encrypted_token,
            "next": safe_next(next),
            "attempts": 0,
            "created_at": bson::DateTime::now(),
            "expires_at": expires_at,
        })
        .await
        .map_err(|_| "Unable to start two-factor authentication.".to_owned())?;
    Ok((challenge_id, lifetime_seconds))
}

async fn active_two_factor_challenge(state: &AppState, ctx: &ReqCtx) -> Option<Document> {
    let challenge_id = view::cookie(&ctx.headers, TWO_FACTOR_COOKIE)?;
    two_factor_challenges(state)
        .find_one(doc! {
            "_id": challenge_digest(&challenge_id),
            "expires_at": {"$gt": bson::DateTime::now()},
        })
        .await
        .ok()
        .flatten()
}

async fn delete_two_factor_challenge(state: &AppState, ctx: &ReqCtx) {
    if let Some(challenge_id) = view::cookie(&ctx.headers, TWO_FACTOR_COOKIE) {
        let _ = two_factor_challenges(state)
            .delete_one(doc! {"_id":challenge_digest(&challenge_id)})
            .await;
    }
}

fn clear_two_factor_cookie(response: &mut Response) {
    response.headers_mut().append(
        header::SET_COOKIE,
        clear_challenge_cookie().parse().unwrap(),
    );
}

async fn record_failed_two_factor_attempt(state: &AppState, challenge: &Document) -> bool {
    let id = db::string(challenge, "_id");
    let attempts = two_factor_challenges(state)
        .find_one_and_update(
            doc! {"_id":&id,"attempts":{"$lt":TWO_FACTOR_MAX_ATTEMPTS}},
            doc! {"$inc":{"attempts":1},"$set":{"updated_at":bson::DateTime::now()}},
        )
        .return_document(ReturnDocument::After)
        .await
        .ok()
        .flatten()
        .as_ref()
        .map(challenge_attempts)
        .unwrap_or(TWO_FACTOR_MAX_ATTEMPTS);
    if attempts >= TWO_FACTOR_MAX_ATTEMPTS {
        let _ = two_factor_challenges(state)
            .delete_one(doc! {"_id":id})
            .await;
        true
    } else {
        false
    }
}

async fn finish_zimbra_login(
    state: &AppState,
    ctx: &ReqCtx,
    email: &str,
    encrypted_password: String,
    session: zimbra::ZimbraSession,
    next: &str,
) -> Response {
    let (folder_id, folder_path) = match session.ensure_folder(&state.cfg, email).await {
        Ok(folder) => folder,
        Err(error) => {
            tracing::warn!(email = %email, outcome = "folder_setup_failed", reason = %error, "Zimbra login");
            return login_error(
                state,
                ctx,
                email,
                "Zimbra authenticated, but mailbox setup failed. Please try again.",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }
    };
    let now = bson::DateTime::now();
    let coll = accounts(state);
    let existing = coll
        .find_one(doc! {"email_key":email,"auth_source":"zimbra"})
        .await
        .ok()
        .flatten();
    let set = doc! {"username":email,"username_key":email,"email":email,"email_key":email,"auth_source":"zimbra","role":"user","disabled":false,"must_change_password":false,"zimbra_password":encrypted_password,"zimbra_folder_id":folder_id,"zimbra_folder_path":folder_path,"last_login_at":now,"updated_at":now};
    let user = if let Some(old) = existing {
        let Ok(id) = old.get_object_id("_id") else {
            return login_error(
                state,
                ctx,
                email,
                "Unable to save the Zimbra account.",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        };
        if coll
            .update_one(doc! {"_id":id}, doc! {"$set":set})
            .await
            .is_err()
        {
            return login_error(
                state,
                ctx,
                email,
                "Unable to save the Zimbra account.",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }
        let Some(user) = coll.find_one(doc! {"_id":id}).await.ok().flatten() else {
            return login_error(
                state,
                ctx,
                email,
                "Unable to save the Zimbra account.",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        };
        user
    } else {
        let mut account = set;
        account.insert("created_at", now);
        let result = match coll.insert_one(account.clone()).await {
            Ok(result) => result,
            Err(_) => {
                return login_error(
                    state,
                    ctx,
                    email,
                    "This email is already registered.",
                    StatusCode::CONFLICT,
                );
            }
        };
        account.insert("_id", result.inserted_id);
        account
    };
    if let Err(error) = subscriptions::ensure_zimbra_subscription(state, &user).await {
        tracing::warn!(email = %email, outcome = "account_setup_failed", reason = %error, "Zimbra login");
        return login_error(
            state,
            ctx,
            email,
            "Zimbra authenticated, but portal account setup failed. Please try again.",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    tracing::info!(email = %email, outcome = "authenticated", "Zimbra login");
    let mut response = view::redirect(safe_next(next));
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(state, &user).parse().unwrap(),
    );
    response
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
    let outcome = match zimbra::ZimbraSession::login(&state.cfg, &email, &password).await {
        Ok(outcome) => outcome,
        Err(error) => {
            let outcome = if error == zimbra::AuthFailure::InvalidCredentials {
                "password_rejected"
            } else {
                "authentication_failed"
            };
            tracing::warn!(email = %email, outcome, failure = ?error, "Zimbra login");
            let status = if error == zimbra::AuthFailure::Unavailable {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::UNAUTHORIZED
            };
            return login_error(state, ctx, &email, error.message(), status);
        }
    };
    let encrypted_password = match zimbra::encrypt_password(&state.cfg, &password) {
        Ok(value) => value,
        Err(error) => {
            return login_error(state, ctx, &email, &error, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    match outcome {
        zimbra::LoginResult::Authenticated(session) => {
            delete_two_factor_challenge(state, ctx).await;
            let mut response = finish_zimbra_login(
                state,
                ctx,
                &email,
                encrypted_password,
                session,
                &ctx.field("next"),
            )
            .await;
            clear_two_factor_cookie(&mut response);
            response
        }
        zimbra::LoginResult::TwoFactorRequired {
            temporary_token,
            lifetime_ms,
        } => {
            delete_two_factor_challenge(state, ctx).await;
            let (challenge_id, lifetime_seconds) = match create_two_factor_challenge(
                state,
                &email,
                &encrypted_password,
                &temporary_token,
                &ctx.field("next"),
                lifetime_ms,
            )
            .await
            {
                Ok(challenge) => challenge,
                Err(error) => {
                    return login_error(
                        state,
                        ctx,
                        &email,
                        &error,
                        StatusCode::SERVICE_UNAVAILABLE,
                    );
                }
            };
            tracing::info!(email = %email, outcome = "two_factor_required", "Zimbra login");
            let mut response = two_factor_page(state, ctx, &email, None, StatusCode::OK);
            response.headers_mut().insert(
                header::SET_COOKIE,
                challenge_cookie(&challenge_id, lifetime_seconds)
                    .parse()
                    .unwrap(),
            );
            response
        }
    }
}

async fn show_two_factor_login(state: &AppState, ctx: &ReqCtx) -> Response {
    let Some(challenge) = active_two_factor_challenge(state, ctx).await else {
        let mut response = view::redirect("/login");
        clear_two_factor_cookie(&mut response);
        return response;
    };
    two_factor_page(
        state,
        ctx,
        &db::string(&challenge, "email"),
        None,
        StatusCode::OK,
    )
}

async fn complete_two_factor_login(state: &AppState, ctx: &ReqCtx) -> Response {
    let Some(challenge) = active_two_factor_challenge(state, ctx).await else {
        let mut response = view::redirect("/login");
        clear_two_factor_cookie(&mut response);
        return response;
    };
    let email = db::string(&challenge, "email");
    let code = ctx.field("two_factor_code").trim().to_owned();
    if !valid_two_factor_code(&code) {
        tracing::warn!(email = %email, outcome = "two_factor_failed", reason = "invalid_format", "Zimbra login");
        let exhausted = record_failed_two_factor_attempt(state, &challenge).await;
        let mut response = if exhausted {
            login_error(
                state,
                ctx,
                &email,
                "Too many incorrect authenticator codes. Sign in again.",
                StatusCode::UNAUTHORIZED,
            )
        } else {
            two_factor_page(
                state,
                ctx,
                &email,
                Some("Enter the six-digit code from your authenticator app."),
                StatusCode::UNAUTHORIZED,
            )
        };
        if exhausted {
            clear_two_factor_cookie(&mut response);
        }
        return response;
    }
    let temporary_token =
        match zimbra::decrypt_secret(&state.cfg, &db::string(&challenge, "encrypted_auth_token")) {
            Ok(token) => token,
            Err(_) => {
                delete_two_factor_challenge(state, ctx).await;
                let mut response = login_error(
                    state,
                    ctx,
                    &email,
                    "The two-factor session is invalid. Sign in again.",
                    StatusCode::UNAUTHORIZED,
                );
                clear_two_factor_cookie(&mut response);
                return response;
            }
        };
    let session = match zimbra::ZimbraSession::complete_two_factor(
        &state.cfg,
        &temporary_token,
        &code,
    )
    .await
    {
        Ok(session) => session,
        Err(zimbra::AuthFailure::InvalidTwoFactorCode) => {
            tracing::warn!(email = %email, outcome = "two_factor_failed", reason = "rejected", "Zimbra login");
            let exhausted = record_failed_two_factor_attempt(state, &challenge).await;
            let mut response = if exhausted {
                login_error(
                    state,
                    ctx,
                    &email,
                    "Too many incorrect authenticator codes. Sign in again.",
                    StatusCode::UNAUTHORIZED,
                )
            } else {
                two_factor_page(
                    state,
                    ctx,
                    &email,
                    Some("The authenticator code is invalid."),
                    StatusCode::UNAUTHORIZED,
                )
            };
            if exhausted {
                clear_two_factor_cookie(&mut response);
            }
            return response;
        }
        Err(error) => {
            tracing::warn!(email = %email, outcome = "two_factor_failed", failure = ?error, "Zimbra login");
            let status = if error == zimbra::AuthFailure::Unavailable {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::UNAUTHORIZED
            };
            if error != zimbra::AuthFailure::Unavailable {
                delete_two_factor_challenge(state, ctx).await;
            }
            let mut response = if error == zimbra::AuthFailure::Unavailable {
                two_factor_page(state, ctx, &email, Some(error.message()), status)
            } else {
                login_error(state, ctx, &email, error.message(), status)
            };
            if error != zimbra::AuthFailure::Unavailable {
                clear_two_factor_cookie(&mut response);
            }
            return response;
        }
    };
    delete_two_factor_challenge(state, ctx).await;
    let encrypted_password = db::string(&challenge, "encrypted_password");
    let next = db::string(&challenge, "next");
    let mut response =
        finish_zimbra_login(state, ctx, &email, encrypted_password, session, &next).await;
    clear_two_factor_cookie(&mut response);
    response
}

async fn cancel_two_factor_login(state: &AppState, ctx: &ReqCtx) -> Response {
    delete_two_factor_challenge(state, ctx).await;
    let mut response = view::redirect("/login");
    clear_two_factor_cookie(&mut response);
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
        (Method::GET, "/login/2fa") => return Some(show_two_factor_login(state, ctx).await),
        (Method::POST, "/login/2fa") => {
            return Some(complete_two_factor_login(state, ctx).await);
        }
        (Method::POST, "/login/2fa/cancel") => {
            return Some(cancel_two_factor_login(state, ctx).await);
        }
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
    #[test]
    fn two_factor_challenges_are_short_lived_and_codes_are_strict() {
        assert_eq!(challenge_lifetime_seconds(600_000), 300);
        assert_eq!(challenge_lifetime_seconds(90_001), 91);
        assert_eq!(challenge_lifetime_seconds(0), 300);
        assert!(valid_two_factor_code("012345"));
        assert!(!valid_two_factor_code("12345"));
        assert!(!valid_two_factor_code("12345a"));
    }
    #[test]
    fn two_factor_cookie_is_opaque_and_http_only() {
        let challenge_id = new_challenge_id();
        let cookie = challenge_cookie(&challenge_id, 300);
        assert!(cookie.contains(&format!("{TWO_FACTOR_COOKIE}={challenge_id}")));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(!cookie.contains('@'));
        assert_ne!(challenge_digest(&challenge_id), challenge_id);
    }
    #[test]
    fn two_factor_page_masks_the_account_address() {
        assert_eq!(
            masked_email("sunshine.wong@example.com"),
            "s***@example.com"
        );
    }
    fn dummy() -> crate::config::Config {
        crate::config::Config {
            root: Default::default(),
            file: json!({}),
            mongo_uri: String::new(),
            web_database: "web".into(),
            vulnerabilities_database: "vulnerabilities".into(),
            vulnerabilities_collection: "news".into(),
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
            port: 9100,
        }
    }
}
