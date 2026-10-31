use crate::{AppState, ReqCtx, db, rbac, render, view};
use axum::{
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use mongodb::{
    IndexModel,
    bson::{self, Bson, Document, doc, oid::ObjectId},
    options::IndexOptions,
};
use rand::RngCore;
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::BTreeSet;

type HmacSha256 = Hmac<Sha256>;
const COOKIE: &str = "rust_session";

pub fn key(value: &str) -> String {
    value.trim().to_lowercase()
}
pub(crate) fn valid_email(email: &str) -> bool {
    !email.trim().is_empty()
        && email.len() <= 320
        && !email.contains(char::is_whitespace)
        && email.parse::<lettre::Address>().is_ok()
}
pub fn valid_password(password: &str) -> Result<(), String> {
    if password.chars().count() < 12 || password.len() > 72 {
        return Err(
            "Use a new local password with at least 12 characters and at most 72 bytes.".into(),
        );
    }
    Ok(())
}
pub fn new_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub async fn password_hash(password: String) -> Result<String, String> {
    valid_password(&password)?;
    tokio::task::spawn_blocking(move || bcrypt::hash(password, bcrypt::DEFAULT_COST))
        .await
        .map_err(|_| "Password hashing failed.".to_owned())?
        .map_err(|_| "Password hashing failed.".to_owned())
}
async fn verify(password: String, hash: String) -> bool {
    if password.len() > 72 {
        return false;
    }
    tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false))
        .await
        .unwrap_or(false)
}
pub fn accounts(state: &AppState) -> mongodb::Collection<Document> {
    db::collection(&state.web, &state.cfg.account_collection)
}
pub fn public_user(user: &Document) -> Value {
    json!({"id":db::id_string(user),"username":db::string(user,"username"),
        "email":db::string(user,"email"),"role":db::string(user,"role"),
        "role_id":user.get_object_id("role_id").ok().map(|id|id.to_hex()),
        "organization_id":rbac::organization(user).map(|id|id.to_hex()),
        "organization":db::string(user,"organization"),"disabled":db::bool_field(user,"disabled"),
        "deleted":user.contains_key("deleted_at"),
        "reserved":db::bool_field(user,"reserved_bootstrap"),
        "must_change_password":db::bool_field(user,"must_change_password"),
        "migration_required":db::string(user,"auth_source")!="local" || user.get_i32("rbac_schema").ok()!=Some(1),
        "permissions":rbac::CATALOG.iter().filter(|p|rbac::has(user,p.id)).map(|p|p.id).collect::<Vec<_>>()})
}

/// Resolve every request from current records. Delegations are intersected with
/// the creator's *current* role, so revocation propagates down the delegation tree.
/// Missing/disabled/cyclic/foreign/malformed ancestors grant no permissions.
pub async fn principal(state: &AppState, mut user: Document) -> Option<Document> {
    if db::string(&user, "auth_source") != "local"
        || db::bool_field(&user, "disabled")
        || user.contains_key("deleted_at")
        || user.get_i32("rbac_schema").ok() != Some(1)
    {
        return None;
    }
    user.remove("effective_permissions");
    user.remove("authorization_roles");
    if rbac::is_superadmin(&user) {
        return Some(user);
    }
    if db::bool_field(&user, "reserved_bootstrap") || db::string(&user, "role") == "superadmin" {
        return None;
    }
    let org_id = rbac::organization(&user)?;
    let org = db::find_one(
        &state.web,
        "organizations",
        doc! {"_id":org_id,"disabled":{"$ne":true}},
    )
    .await
    .ok()??;
    user.insert("organization", db::string(&org, "name"));
    Some(
        resolve_role_chain(
            user,
            org,
            |id| async move {
                db::find_one(&state.web, "roles", doc! {"_id":id})
                    .await
                    .ok()
                    .flatten()
            },
            |id| async move {
                accounts(state)
                    .find_one(doc! {"_id":id})
                    .await
                    .ok()
                    .flatten()
            },
        )
        .await,
    )
}

pub(crate) async fn resolve_role_chain<R, A, RF, AF>(
    mut user: Document,
    org: Document,
    role_lookup: R,
    account_lookup: A,
) -> Document
where
    R: Fn(ObjectId) -> RF,
    A: Fn(ObjectId) -> AF,
    RF: std::future::Future<Output = Option<Document>>,
    AF: std::future::Future<Output = Option<Document>>,
{
    let org_id = org.get_object_id("_id").expect("resolved organization");
    let mut permissions: BTreeSet<String> = rbac::tenant_permissions().into_iter().collect();
    let mut seen_users = BTreeSet::new();
    let mut chain = Vec::<Bson>::new();
    let mut cursor = user.clone();
    let mut valid = false;
    for _ in 0..32 {
        if !seen_users.insert(db::id_string(&cursor)) {
            break;
        }
        let Ok(role_id) = cursor.get_object_id("role_id") else {
            break;
        };
        let Some(role) = role_lookup(role_id).await.filter(|role| {
            rbac::organization(role) == Some(org_id) && !db::bool_field(role, "disabled")
        }) else {
            break;
        };
        chain.push(Bson::ObjectId(role_id));
        if chain.len() == 1 {
            user.insert("role", db::string(&role, "name"));
        }
        if db::string(&role, "type") == "organization_admin" {
            valid = org.get_object_id("administrator_role_id").ok() == Some(role_id)
                && db::bool_field(&role, "reserved");
            break;
        }
        let Some(grants) = rbac::custom_permissions(&role) else {
            break;
        };
        permissions = permissions.intersection(&grants).cloned().collect();
        let Ok(creator_id) = role.get_object_id("delegated_by_user_id") else {
            break;
        };
        let Some(creator) = account_lookup(creator_id).await else {
            break;
        };
        if rbac::is_superadmin(&creator) {
            valid = true;
            break;
        }
        if db::string(&creator, "auth_source") != "local"
            || db::bool_field(&creator, "disabled")
            || creator.contains_key("deleted_at")
            || creator.get_i32("rbac_schema").ok() != Some(1)
            || rbac::organization(&creator) != Some(org_id)
        {
            break;
        }
        cursor = creator;
    }
    user.insert(
        "effective_permissions",
        if valid {
            permissions.into_iter().collect::<Vec<_>>()
        } else {
            vec![]
        },
    );
    user.insert("authorization_roles", chain);
    user.insert("authorization_valid", valid);
    user
}

fn session_cookie(state: &AppState, user: &Document) -> String {
    let expiry = chrono::Utc::now().timestamp() + 12 * 3600;
    let payload = format!(
        "local-v2:{}:{}:{}",
        db::id_string(user),
        db::string(user, "session_version"),
        expiry
    );
    let mut mac = HmacSha256::new_from_slice(state.cfg.secret.as_bytes()).expect("HMAC");
    mac.update(payload.as_bytes());
    format!(
        "{COOKIE}={}.{}; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
        if state.cfg.cookie_secure {
            "; Secure"
        } else {
            ""
        }
    )
}
fn session_from_cookie(state: &AppState, headers: &HeaderMap) -> Option<(ObjectId, String)> {
    let raw = view::cookie(headers, COOKIE)?;
    let (message, signature) = raw.split_once('.')?;
    let payload = URL_SAFE_NO_PAD.decode(message).ok()?;
    let mut mac = HmacSha256::new_from_slice(state.cfg.secret.as_bytes()).ok()?;
    mac.update(&payload);
    mac.verify_slice(&URL_SAFE_NO_PAD.decode(signature).ok()?)
        .ok()?;
    let payload = String::from_utf8(payload).ok()?;
    let parts = payload.split(':').collect::<Vec<_>>();
    if parts.len() != 4
        || parts[0] != "local-v2"
        || parts[2].is_empty()
        || parts[3].parse::<i64>().ok()? <= chrono::Utc::now().timestamp()
    {
        return None;
    }
    Some((db::object_id(parts[1])?, parts[2].to_owned()))
}
pub async fn current_user(state: &AppState, headers: &HeaderMap) -> Option<Document> {
    let (id, version) = session_from_cookie(state, headers)?;
    let user = accounts(state)
        .find_one(doc! {"_id":id,"auth_source":"local","session_version":version})
        .await
        .ok()??;
    if temporary_expired(&user) {
        return None;
    }
    principal(state, user).await
}
fn temporary_expired(user: &Document) -> bool {
    db::bool_field(user, "must_change_password")
        && user
            .get_datetime("temporary_password_expires_at")
            .ok()
            .is_none_or(|expiry| {
                expiry.timestamp_millis() <= bson::DateTime::now().timestamp_millis()
            })
}

/// Only this explicit bootstrap transition may promote the pre-existing local
/// bootstrap administrator. It preserves the password hash across restarts.
pub fn bootstrap_update(existing: &Document, username: &str) -> Result<Document, String> {
    if db::string(existing, "auth_source") != "local"
        || key(&db::string(existing, "username")) != key(username)
        || !matches!(
            db::string(existing, "role").as_str(),
            "admin" | "superadmin"
        )
    {
        return Err("Bootstrap identity conflict. Restore the reserved local account from backup; startup will not rename or take over another account.".into());
    }
    if db::string(existing, "password").is_empty() {
        return Err(
            "Bootstrap password hash is missing; use the documented offline recovery.".into(),
        );
    }
    let mut set = doc! {"role":"superadmin","reserved_bootstrap":true,"auth_source":"local","rbac_schema":1,"disabled":false,"must_change_password":false,"updated_at":bson::DateTime::now()};
    if db::string(existing, "session_version").is_empty() {
        set.insert("session_version", new_secret());
    }
    Ok(
        doc! {"$set":set,"$unset":{"organization_id":"","role_id":"","deleted_at":"","temporary_password_expires_at":""}},
    )
}
pub async fn ensure_bootstrap(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    let coll = accounts(state);
    for (name, keys) in [
        (
            state.cfg.account_collection.as_str(),
            doc! {"organization_id":1,"username_key":1},
        ),
        (
            "sub_account",
            doc! {"organization_id":1,"created_at":1,"_id":1},
        ),
        ("report_jobs", doc! {"organization_id":1,"created_at":-1}),
    ] {
        db::collection(&state.web, name)
            .create_index(IndexModel::builder().keys(keys).build())
            .await?;
    }
    let username = state.cfg.bootstrap_username.trim();
    if username.is_empty() {
        return Err("WEB_AUTH_BOOTSTRAP_USERNAME is required".into());
    }
    coll.create_index(
        IndexModel::builder()
            .keys(doc! {"username_key":1})
            .options(
                IndexOptions::builder()
                    .unique(true)
                    .name("accounts_username_unique".to_owned())
                    .build(),
            )
            .build(),
    )
    .await?;
    coll.create_index(
        IndexModel::builder()
            .keys(doc! {"reserved_bootstrap":1})
            .options(
                IndexOptions::builder()
                    .unique(true)
                    .partial_filter_expression(doc! {"reserved_bootstrap":true})
                    .name("reserved_bootstrap_unique".to_owned())
                    .build(),
            )
            .build(),
    )
    .await?;
    for name in ["organizations", "roles"] {
        let keys = if name == "roles" {
            doc! {"organization_id":1,"name_key":1}
        } else {
            doc! {"name_key":1}
        };
        db::collection(&state.web, name)
            .create_index(
                IndexModel::builder()
                    .keys(keys)
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
    }
    let existing = coll
        .find_one(doc! {"$or":[{"reserved_bootstrap":true},{"username_key":key(username)}]})
        .await?;
    if let Some(existing) = existing {
        let update = bootstrap_update(&existing, username)?;
        coll.update_one(doc! {"_id":existing.get_object_id("_id")?}, update)
            .await?;
    } else {
        // Never create a second reserved identity if the configured name changed.
        if coll.count_documents(doc! {"role":"superadmin"}).await? > 0 {
            return Err(
                "A reserved administrator already exists. Restore its configured username.".into(),
            );
        }
        let hash = password_hash(state.cfg.bootstrap_password.clone()).await?;
        coll.insert_one(doc!{"username":username,"username_key":key(username),"password":hash,"role":"superadmin","reserved_bootstrap":true,"auth_source":"local","rbac_schema":1,"disabled":false,"must_change_password":false,"session_version":new_secret(),"created_at":bson::DateTime::now()}).await?;
    }
    Ok(())
}

fn safe_next(next: &str) -> &str {
    if next.starts_with('/') && !next.starts_with("//") && !next.contains(['\\', '\r', '\n']) {
        next
    } else {
        "/"
    }
}
async fn login(state: &AppState, ctx: &ReqCtx) -> Response {
    let user = accounts(state)
        .find_one(
            doc! {"username_key":key(&ctx.field("username")),"auth_source":"local","rbac_schema":1},
        )
        .await
        .ok()
        .flatten();
    // Unknown accounts still pay a bcrypt verification cost.
    let hash = user
        .as_ref()
        .map(|u| db::string(u, "password"))
        .unwrap_or_else(|| "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW".into());
    let verified = verify(ctx.field("password"), hash).await;
    if verified
        && let Some(user) = user.filter(|u| !temporary_expired(u))
        && let Some(user) = principal(state, user).await
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
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        return response;
    }
    let mut response = render(
        state,
        ctx,
        "auth/login.html",
        json!({"error":"Invalid username or password, or account requires local provisioning."}),
    );
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
}
pub async fn handle(state: &AppState, ctx: &ReqCtx) -> Option<Response> {
    match (ctx.method.as_str(), ctx.path.as_str()) {
        ("GET", "/login") => Some(render(state, ctx, "auth/login.html", json!({}))),
        ("POST", "/login") => Some(login(state, ctx).await),
        ("POST", "/logout") => {
            let mut response = view::redirect("/login");
            response.headers_mut().insert(
                header::SET_COOKIE,
                format!(
                    "{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict{}",
                    if state.cfg.cookie_secure {
                        "; Secure"
                    } else {
                        ""
                    }
                )
                .parse()
                .unwrap(),
            );
            Some(response)
        }
        ("GET", "/settings") => Some(render(state, ctx, "auth/settings.html", json!({}))),
        ("POST", "/api/auth/password") => Some(change_password(state, ctx).await),
        ("PUT", "/api/auth/profile") => Some(update_profile(state, ctx).await),
        _ => None,
    }
}
async fn change_password(state: &AppState, ctx: &ReqCtx) -> Response {
    let Some(user) = ctx.user.as_ref() else {
        return view::error(StatusCode::UNAUTHORIZED, "Authentication required");
    };
    let new = ctx.field("new_password");
    if new != ctx.field("new_password_confirmation") {
        return view::error(StatusCode::BAD_REQUEST, "New passwords do not match.");
    }
    if new == ctx.field("current_password") {
        return view::error(
            StatusCode::BAD_REQUEST,
            "Choose a different local password.",
        );
    }
    if !verify(ctx.field("current_password"), db::string(user, "password")).await {
        return view::error(StatusCode::BAD_REQUEST, "Current password is incorrect.");
    }
    let hash = match password_hash(new).await {
        Ok(hash) => hash,
        Err(error) => return view::error(StatusCode::BAD_REQUEST, &error),
    };
    let mut changed = user.clone();
    let version = new_secret();
    changed.insert("session_version", &version);
    let filter = doc! {"_id":ctx.user_id().unwrap(),"session_version":db::string(user,"session_version"),"auth_source":"local"};
    match accounts(state).update_one(filter,doc!{"$set":{"password":hash,"must_change_password":false,"session_version":version,"updated_at":bson::DateTime::now()},"$unset":{"temporary_password_expires_at":""}}).await {
        Ok(result) if result.matched_count==1=>{
            let mut response=view::json_response(StatusCode::OK,json!({"success":true}));
            response.headers_mut().insert(header::SET_COOKIE,session_cookie(state,&changed).parse().unwrap());
            response
        },
        _=>view::error(StatusCode::CONFLICT,"Account changed; sign in again."),
    }
}
async fn update_profile(state: &AppState, ctx: &ReqCtx) -> Response {
    let Some(user) = ctx.user.as_ref() else {
        return view::error(StatusCode::UNAUTHORIZED, "Authentication required");
    };
    if !ctx
        .json
        .as_object()
        .is_some_and(|o| o.len() == 1 && o.contains_key("email"))
    {
        return view::error(
            StatusCode::BAD_REQUEST,
            "Only your email address can be changed here.",
        );
    }
    if ctx.json.get("email").and_then(Value::as_str).is_none() {
        return view::error(StatusCode::BAD_REQUEST, "Email must be text.");
    }
    let email = key(&ctx.field("email"));
    if !valid_email(&email) {
        return view::error(
            StatusCode::BAD_REQUEST,
            "A valid email address is required.",
        );
    }
    let update =
        doc! {"$set":{"email":&email,"email_key":&email,"updated_at":bson::DateTime::now()}};
    match accounts(state)
        .update_one(doc! {"_id":ctx.user_id().unwrap()}, update)
        .await
    {
        Ok(_) => view::json_response(
            StatusCode::OK,
            json!({"success":true,"username":db::string(user,"username")}),
        ),
        Err(_) => view::error(StatusCode::CONFLICT, "Unable to save profile email."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn session_cookie_requires_signature_local_format_and_version() {
        let state = crate::rbac_tests::state().await;
        let id = ObjectId::new();
        let user = doc! {"_id":id,"session_version":"random-version"};
        let cookie = session_cookie(&state, &user);
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            cookie.split(';').next().unwrap().parse().unwrap(),
        );
        assert_eq!(
            session_from_cookie(&state, &headers),
            Some((id, "random-version".into()))
        );
        let mut altered = cookie.split(';').next().unwrap().to_owned();
        altered.push('x');
        headers.insert(header::COOKIE, altered.parse().unwrap());
        assert!(session_from_cookie(&state, &headers).is_none());
        let legacy = format!(
            "{id}:external-provider:{}",
            chrono::Utc::now().timestamp() + 3600
        );
        let mut mac = HmacSha256::new_from_slice(state.cfg.secret.as_bytes()).unwrap();
        mac.update(legacy.as_bytes());
        headers.insert(
            header::COOKIE,
            format!(
                "{COOKIE}={}.{}",
                URL_SAFE_NO_PAD.encode(legacy),
                URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
            )
            .parse()
            .unwrap(),
        );
        assert!(session_from_cookie(&state, &headers).is_none());
    }
    #[test]
    fn temporary_passwords_require_a_future_expiry_and_strong_replacement() {
        assert!(valid_password("short").is_err());
        assert!(valid_password(&"a".repeat(73)).is_err());
        assert!(valid_password("unique-local-password").is_ok());
        assert!(temporary_expired(&doc! {"must_change_password":true}));
        assert!(temporary_expired(
            &doc! {"must_change_password":true,"temporary_password_expires_at":bson::DateTime::from_millis(1)}
        ));
        assert!(!temporary_expired(
            &doc! {"must_change_password":true,"temporary_password_expires_at":bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis()+60000)}
        ));
        assert!(!temporary_expired(&doc! {"must_change_password":false}));
        for path in [
            "//external.example",
            "/\\external.example",
            "/\r\nLocation:evil",
            "https://external.example",
        ] {
            assert_eq!(safe_next(path), "/");
        }
    }
}
