use crate::{AppState, auth, db};
use mongodb::bson::{Bson, Document, doc, oid::ObjectId};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

const DIRECTORY_PAGE_SIZE: u64 = 500;
const MAX_DIRECTORY_PAGES: usize = 1000;

#[derive(Debug, Clone, PartialEq)]
struct DirectoryUser {
    uid: String,
    username: String,
    email: Option<String>,
    organization: String,
    organization_id: String,
    roles: Vec<String>,
    system_roles: Vec<String>,
    enabled: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncSummary {
    pub synced: i64,
    pub deleted: i64,
}

#[derive(Debug)]
struct DirectoryPage {
    users: Vec<DirectoryUser>,
    has_more: bool,
    next_page: Option<u64>,
    current_page: Option<u64>,
}

fn key(value: &str) -> String {
    value.trim().to_lowercase()
}

fn scalar_text(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_i64().map(|value| value.to_string()))
        .or_else(|| value.as_u64().map(|value| value.to_string()))
        .or_else(|| value.as_f64().map(|value| value.to_string()))
}

fn first_value(value: &Value, fields: &[&str]) -> Option<Value> {
    fields.iter().find_map(|field| value.get(*field).cloned())
}

fn first_text(value: &Value, fields: &[&str]) -> Option<String> {
    first_value(value, fields)
        .and_then(|value| scalar_text(&value))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn role_name(value: &Value) -> Option<String> {
    scalar_text(value).or_else(|| {
        value
            .get("roleName")
            .or_else(|| value.get("name"))
            .or_else(|| value.get("label"))
            .and_then(scalar_text)
    })
}

fn role_names(value: &Value, fields: &[&str]) -> Vec<String> {
    fields
        .iter()
        .filter_map(|field| value.get(*field))
        .flat_map(|value| value.as_array().into_iter().flatten())
        .filter_map(role_name)
        .map(|role| role.trim().to_owned())
        .filter(|role| !role.is_empty())
        .collect()
}

fn bool_value(value: &Value) -> Option<bool> {
    value.as_bool().or_else(|| {
        value
            .as_i64()
            .and_then(|value| match value {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            })
            .or_else(|| {
                value
                    .as_str()
                    .and_then(|value| match value.trim().to_lowercase().as_str() {
                        "1" | "true" | "yes" | "on" | "active" | "enabled" => Some(true),
                        "0" | "false" | "no" | "off" | "inactive" | "disabled" | "deleted"
                        | "locked" => Some(false),
                        _ => None,
                    })
            })
    })
}

fn status_value(value: &Value) -> Option<bool> {
    value
        .as_bool()
        .or_else(|| {
            value.as_i64().and_then(|value| match value {
                1 => Some(true),
                0 | 2 => Some(false),
                _ => None,
            })
        })
        .or_else(|| {
            value
                .as_str()
                .and_then(|value| match value.trim().to_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" | "active" | "enabled" => Some(true),
                    "0" | "2" | "false" | "no" | "off" | "inactive" | "disabled" | "deleted"
                    | "locked" => Some(false),
                    _ => None,
                })
        })
}

fn enabled(value: &Value) -> Result<bool, String> {
    for field in ["enabled", "active", "isEnabled", "accountEnabled"] {
        if let Some(raw) = value.get(field) {
            return bool_value(raw).ok_or_else(|| format!("Account Hub field {field} is invalid."));
        }
    }
    if let Some(raw) = value.get("status") {
        return status_value(raw).ok_or_else(|| "Account Hub user status is invalid.".to_owned());
    }
    for field in [
        "accountNonExpired",
        "credentialsNonExpired",
        "accountNonLocked",
    ] {
        if value
            .get(field)
            .is_some_and(|raw| bool_value(raw) == Some(false))
        {
            return Ok(false);
        }
    }
    Err("Account Hub user status is missing.".to_owned())
}

fn organization(value: &Value) -> (String, String) {
    let nested = value.get("organization").filter(|value| value.is_object());
    let name = nested
        .and_then(|value| first_text(value, &["name", "organizationName", "orgName", "org"]))
        .or_else(|| first_text(value, &["organizationName", "orgName", "org"]))
        .or_else(|| {
            value
                .get("organization")
                .and_then(scalar_text)
                .map(|value| value.trim().to_owned())
        })
        .unwrap_or_default();
    let id = nested
        .and_then(|value| first_text(value, &["id", "organizationId", "orgId", "org_id"]))
        .or_else(|| {
            first_text(
                value,
                &["organizationId", "organizationID", "orgId", "org_id"],
            )
        })
        .unwrap_or_default();
    (name, id)
}

fn parse_user(value: &Value, _required_role: &str) -> Result<DirectoryUser, String> {
    let uid = first_text(value, &["uid", "userId", "id"])
        .ok_or_else(|| "Account Hub directory user has no UID.".to_owned())?;
    let username = first_text(value, &["username", "userName", "account", "loginName"])
        .ok_or_else(|| "Account Hub directory user has no username.".to_owned())?;
    let email = first_text(
        value,
        &["email", "userEmail", "user_email", "mail", "emailAddress"],
    )
    .map(|email| email.to_lowercase())
    .map(|email| {
        if auth::valid_email(&email) && !email.is_empty() {
            Ok(email)
        } else {
            Err("Account Hub directory returned an invalid email.".to_owned())
        }
    })
    .transpose()?;
    let (organization, organization_id) = organization(value);
    if organization.is_empty() && organization_id.is_empty() {
        return Err("Account Hub directory user has no organization.".to_owned());
    }
    let roles = role_names(value, &["roles", "role_names"]);
    let system_roles = role_names(value, &["systemRole", "systemRoles"]);
    Ok(DirectoryUser {
        uid,
        username,
        email,
        organization,
        organization_id,
        roles,
        system_roles,
        enabled: enabled(value)?,
    })
}

fn list_and_metadata(payload: &Value) -> Option<(Vec<Value>, Value, bool)> {
    let mut candidates = vec![payload];
    if let Some(data) = payload.get("data") {
        candidates.push(data);
    }
    for candidate in candidates {
        if let Some(items) = candidate.as_array() {
            return Some((items.clone(), json!({}), true));
        }
        let Some(object) = candidate.as_object() else {
            continue;
        };
        for field in ["users", "records", "items", "list", "rows", "content"] {
            if let Some(items) = object.get(field).and_then(Value::as_array) {
                return Some((items.clone(), Value::Object(object.clone()), false));
            }
        }
    }
    None
}

fn metadata_value(payload: &Value, metadata: &Value, fields: &[&str]) -> Option<Value> {
    fields
        .iter()
        .find_map(|field| {
            metadata
                .get(*field)
                .or_else(|| payload.get(*field))
                .cloned()
        })
        .or_else(|| {
            metadata
                .get("pageInfo")
                .or_else(|| payload.get("pageInfo"))
                .and_then(|page| first_value(page, fields))
        })
}

fn metadata_bool(payload: &Value, metadata: &Value, fields: &[&str]) -> Option<bool> {
    metadata_value(payload, metadata, fields).and_then(|value| bool_value(&value))
}

fn metadata_u64(payload: &Value, metadata: &Value, fields: &[&str]) -> Option<u64> {
    metadata_value(payload, metadata, fields).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
            .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
    })
}

fn business_success(value: &Value) -> bool {
    matches!(value.get("code"), None | Some(Value::Null))
        || matches!(value.get("code"), Some(Value::Number(number)) if number.as_i64().is_some_and(|code| matches!(code, 0 | 200 | 1000)))
        || matches!(value.get("code"), Some(Value::String(code)) if matches!(code.as_str(), "0" | "200" | "1000"))
}

fn parse_page(payload: &Value, required_role: &str) -> Result<DirectoryPage, String> {
    if !business_success(payload) {
        return Err("Account Hub directory returned an unsuccessful response.".to_owned());
    }
    let Some((items, metadata, array_response)) = list_and_metadata(payload) else {
        return Err("Account Hub directory response has no user list.".to_owned());
    };
    if items.is_empty() {
        return Err("Account Hub directory returned an empty user list.".to_owned());
    }
    let users = items
        .iter()
        .map(|item| {
            if !item.is_object() {
                return Err("Account Hub directory user must be an object.".to_owned());
            }
            parse_user(item, required_role)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let complete = metadata_bool(payload, &metadata, &["complete", "isComplete", "all"]);
    let has_next = metadata_bool(payload, &metadata, &["hasNext", "has_next", "more"]);
    let page = metadata_u64(payload, &metadata, &["page", "current", "pageNum"]);
    let pages = metadata_u64(payload, &metadata, &["pages", "pageCount", "totalPages"]);
    let total = metadata_u64(payload, &metadata, &["total", "totalCount", "count"]);
    let size = metadata_u64(payload, &metadata, &["size", "pageSize", "limit"])
        .unwrap_or(users.len() as u64);
    let next_page = metadata_u64(payload, &metadata, &["nextPage", "next_page"]);
    if !array_response
        && complete.is_none()
        && has_next.is_none()
        && page.is_none()
        && pages.is_none()
        && total.is_none()
        && next_page.is_none()
    {
        return Err(
            "Account Hub directory response does not prove that the list is complete.".to_owned(),
        );
    }
    let calculated_more = pages.zip(page).is_some_and(|(pages, page)| pages > page)
        || total.is_some_and(|total| page.unwrap_or(1).saturating_mul(size.max(1)) < total);
    let has_more = match complete {
        Some(true) => false,
        Some(false) => has_next.unwrap_or(true) || calculated_more || next_page.is_some(),
        None => has_next.unwrap_or(false) || calculated_more || next_page.is_some(),
    };
    if complete == Some(false) && !has_more {
        return Err("Account Hub directory response is not complete.".to_owned());
    }
    Ok(DirectoryPage {
        users,
        has_more,
        next_page,
        current_page: page,
    })
}

async fn fetch_directory(state: &AppState) -> Result<Vec<DirectoryUser>, String> {
    if !state.cfg.account_hub_enabled {
        return Err("Account Hub is disabled.".to_owned());
    }
    if state.cfg.account_hub_directory_url.trim().is_empty()
        || state.cfg.account_hub_directory_token.trim().is_empty()
    {
        return Err("Account Hub directory sync is not configured.".to_owned());
    }
    let mut users = Vec::new();
    let mut next_page = None;
    for _ in 0..MAX_DIRECTORY_PAGES {
        let request = directory_request(
            &state.http,
            &state.cfg.account_hub_directory_url,
            &state.cfg.account_hub_directory_token,
            state.cfg.account_hub_timeout_seconds,
            next_page,
        );
        let response = request
            .send()
            .await
            .map_err(|_| "Account Hub directory is unavailable.".to_owned())?;
        if !response.status().is_success() {
            return Err(if response.status().is_client_error() {
                "Account Hub directory authorization failed.".to_owned()
            } else {
                "Account Hub directory is unavailable.".to_owned()
            });
        }
        let payload: Value = response
            .json()
            .await
            .map_err(|_| "Account Hub directory returned invalid JSON.".to_owned())?;
        let page = parse_page(&payload, &state.cfg.account_hub_required_role)?;
        users.extend(page.users);
        if !page.has_more {
            break;
        }
        let current = next_page.or(page.current_page).unwrap_or(1);
        let next = page.next_page.unwrap_or(current.saturating_add(1));
        if next <= current {
            return Err("Account Hub directory pagination did not advance.".to_owned());
        }
        next_page = Some(next);
    }
    if next_page.is_some() {
        return Err("Account Hub directory pagination is incomplete.".to_owned());
    }
    if users.is_empty() {
        return Err("Account Hub directory returned an empty user list.".to_owned());
    }
    let mut ids = HashSet::new();
    for user in &users {
        if !ids.insert(user.uid.clone()) {
            return Err("Account Hub directory returned duplicate user IDs.".to_owned());
        }
    }
    Ok(users)
}

fn directory_request(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    timeout_seconds: u64,
    page: Option<u64>,
) -> reqwest::RequestBuilder {
    let mut request = client
        .get(url)
        .bearer_auth(token)
        .header(reqwest::header::ACCEPT, "application/json")
        .timeout(Duration::from_secs(timeout_seconds.max(1)));
    if let Some(page) = page {
        request = request.query(&[
            ("page", page),
            ("current", page),
            ("size", DIRECTORY_PAGE_SIZE),
        ]);
    }
    request
}

fn bson_strings(values: &[String]) -> Bson {
    Bson::Array(values.iter().cloned().map(Bson::String).collect())
}

fn user_id(user: &Document) -> Result<ObjectId, String> {
    user.get_object_id("_id")
        .map_err(|_| "Account Hub user has an invalid local ID.".to_owned())
}

async fn sync_active_user(
    state: &AppState,
    user: &Document,
    remote: &DirectoryUser,
) -> Result<(), String> {
    let id = user_id(user)?;
    let now = mongodb::bson::DateTime::now();
    let mut update = doc! {
        "username": &remote.username,
        "username_key": key(&remote.username),
        "account_hub_uid": &remote.uid,
        "account_hub_username": &remote.username,
        "account_hub_organization": &remote.organization,
        "account_hub_organization_id": &remote.organization_id,
        "account_hub_roles": bson_strings(&remote.roles),
        "account_hub_system_roles": bson_strings(&remote.system_roles),
        "account_hub_is_organization_admin": remote
            .system_roles
            .iter()
            .chain(remote.roles.iter())
            .any(|role| {
            let role = key(role);
            let required = key(&state.cfg.account_hub_required_role);
            [
                format!("{required}-admin"),
                format!("{required}_admin"),
                format!("{required}/admin"),
                format!("{required}:admin"),
            ]
            .iter()
            .any(|candidate| role == *candidate)
        }),
        "last_account_hub_sync_at": now,
        "updated_at": now,
    };
    if let Some(email) = remote.email.as_ref() {
        update.insert("email", email.clone());
        update.insert("account_hub_email", email.clone());
    }
    let users = db::collection(&state.web, "auth");
    users
        .update_one(doc! {"_id": id}, doc! {"$set": update})
        .await
        .map_err(|_| "Unable to update Account Hub user.".to_owned())?;

    let mut subscription_update = doc! {
        "username": &remote.username,
        "organization": &remote.organization,
        "organization_id": &remote.organization_id,
        "updated_at": now,
    };
    if let Some(email) = remote.email.as_ref() {
        subscription_update.insert("email", email.clone());
        subscription_update.insert("emails", vec![email.clone()]);
        subscription_update.insert("account_hub_email", email.clone());
        let updated = users
            .find_one(doc! {"_id": id})
            .await
            .map_err(|_| "Unable to reload Account Hub user.".to_owned())?
            .ok_or_else(|| "Unable to reload Account Hub user.".to_owned())?;
        auth::sync_account_hub_subscription_email(state, &updated, email).await;
    }
    db::collection(&state.web, "sub_account")
        .update_many(
            doc! {"owner_user_id": id},
            doc! {"$set": subscription_update},
        )
        .await
        .map_err(|_| "Unable to update Account Hub subscriptions.".to_owned())?;
    Ok(())
}

async fn delete_account_hub_user(state: &AppState, user: &Document) -> Result<(), String> {
    let id = user_id(user)?;
    let subscriptions = db::find_many(
        &state.web,
        "sub_account",
        doc! {"$or":[{"owner_user_id":id},{"managed_by_user_id":id}]},
        5000,
    )
    .await
    .map_err(|_| "Unable to load subscriptions for deleted Account Hub user.".to_owned())?;
    let mut job_ids = HashSet::new();
    let mut manager_ids = HashSet::from([id]);
    let mut emails = HashSet::new();
    for subscription in &subscriptions {
        if let Ok(manager) = subscription.get_object_id("managed_by_user_id") {
            manager_ids.insert(manager);
        }
        if let Some(email) = subscription
            .get_str("email")
            .ok()
            .filter(|email| !email.is_empty())
        {
            emails.insert(email.to_lowercase());
        }
        if let Ok(values) = subscription.get_array("emails") {
            for email in values.iter().filter_map(Bson::as_str) {
                emails.insert(email.to_lowercase());
            }
        }
        if let Ok(profile) = subscription.get_document("report_profile") {
            if let Some(job) = profile.get_str("last_job_id").ok().and_then(db::object_id) {
                job_ids.insert(job);
            }
        }
    }
    let owned_jobs = db::find_many(
        &state.web,
        "report_jobs",
        doc! {"managed_by_user_id":id},
        5000,
    )
    .await
    .map_err(|_| "Unable to load reports for deleted Account Hub user.".to_owned())?;
    for job in owned_jobs {
        if let Ok(job_id) = job.get_object_id("_id") {
            job_ids.insert(job_id);
        }
    }
    let job_values: Vec<Bson> = job_ids.iter().copied().map(Bson::ObjectId).collect();
    if !job_values.is_empty() {
        let job_filter = doc! {"_id":{"$in":job_values.clone()}};
        let _ = db::collection(&state.web, "report_jobs")
            .update_many(
                job_filter.clone(),
                doc! {"$set":{"status":"cancelled","updated_at":mongodb::bson::DateTime::now()}},
            )
            .await;
        db::collection(&state.web, "report_job_inputs")
            .delete_many(doc! {"job_id":{"$in":job_values.clone()}})
            .await
            .map_err(|_| {
                "Unable to delete report inputs for deleted Account Hub user.".to_owned()
            })?;
        db::collection(&state.web, "report_job_results")
            .delete_many(doc! {"job_id":{"$in":job_values}})
            .await
            .map_err(|_| {
                "Unable to delete report results for deleted Account Hub user.".to_owned()
            })?;
        db::collection(&state.web, "report_jobs")
            .delete_many(job_filter)
            .await
            .map_err(|_| "Unable to delete reports for deleted Account Hub user.".to_owned())?;
    }
    let manager_values: Vec<Bson> = manager_ids.into_iter().map(Bson::ObjectId).collect();
    let mut delivery_or = vec![doc! {"managed_by_user_id":{"$in":manager_values}}];
    if !emails.is_empty() {
        delivery_or.push(doc! {"email":{"$in":emails.into_iter().collect::<Vec<_>>()}});
    }
    db::collection(&state.web, "newsletter_deliveries")
        .delete_many(doc! {"$or":delivery_or})
        .await
        .map_err(|_| "Unable to delete deliveries for deleted Account Hub user.".to_owned())?;
    db::collection(&state.web, "sub_account")
        .delete_many(doc! {"$or":[{"owner_user_id":id},{"managed_by_user_id":id}]})
        .await
        .map_err(|_| "Unable to delete subscriptions for deleted Account Hub user.".to_owned())?;
    db::collection(&state.web, "auth")
        .delete_one(doc! {"_id":id})
        .await
        .map_err(|_| "Unable to delete Account Hub user.".to_owned())?;
    Ok(())
}

pub async fn run(state: &AppState) -> Result<SyncSummary, String> {
    let remote = fetch_directory(state).await?;
    let local = db::find_many(&state.web, "auth", doc! {"auth_source":"account_hub"}, 5000)
        .await
        .map_err(|_| "Unable to load local Account Hub users.".to_owned())?;
    let all_accounts = db::find_many(&state.web, "auth", doc! {}, 10000)
        .await
        .map_err(|_| "Unable to validate Account Hub identities.".to_owned())?;
    let mut local_by_uid = HashMap::new();
    let mut local_by_username = HashMap::new();
    for user in &local {
        let uid = db::string(user, "account_hub_uid");
        if uid.is_empty() {
            return Err(
                "A local Account Hub user has no UID; refusing destructive sync.".to_owned(),
            );
        }
        if local_by_uid.insert(uid, user.clone()).is_some() {
            return Err("Local Account Hub users contain duplicate UIDs.".to_owned());
        }
        local_by_username.insert(key(&db::string(user, "username")), user.clone());
    }
    let mut remote_by_uid = HashMap::new();
    for user in remote {
        if remote_by_uid.insert(user.uid.clone(), user).is_some() {
            return Err("Account Hub directory returned duplicate user IDs.".to_owned());
        }
    }
    let mut remote_usernames = HashSet::new();
    let mut accounts_by_username = HashMap::new();
    for account in &all_accounts {
        let username = key(&db::string(account, "username"));
        if !username.is_empty() {
            accounts_by_username.insert(username, account.clone());
        }
    }
    for remote_user in remote_by_uid.values() {
        if !remote_usernames.insert(key(&remote_user.username)) {
            return Err("Account Hub directory returned duplicate usernames.".to_owned());
        }
        if key(&remote_user.username) == key(&state.cfg.bootstrap_username) {
            return Err(
                "Account Hub directory contains the local administrator username.".to_owned(),
            );
        }
        if let Some(existing) = accounts_by_username.get(&key(&remote_user.username)) {
            let same_identity = db::string(existing, "auth_source") == "account_hub"
                && db::string(existing, "account_hub_uid") == remote_user.uid;
            if !same_identity {
                return Err(format!(
                    "Account Hub username {} conflicts with a local account.",
                    remote_user.username
                ));
            }
        }
    }
    let mut updates = Vec::new();
    let mut deletes = Vec::new();
    for (uid, local_user) in &local_by_uid {
        let Some(remote_user) = remote_by_uid.get(uid) else {
            deletes.push(local_user.clone());
            continue;
        };
        if !remote_user.enabled {
            deletes.push(local_user.clone());
            continue;
        }
        let username_key = key(&remote_user.username);
        let local_id = local_user.get_object_id("_id").ok();
        if local_by_username
            .get(&username_key)
            .is_some_and(|other| other.get_object_id("_id").ok() != local_id)
        {
            return Err(format!(
                "Account Hub username {} conflicts with another local account.",
                remote_user.username
            ));
        }
        updates.push((local_user.clone(), remote_user.clone()));
    }
    for (user, remote_user) in updates {
        sync_active_user(state, &user, &remote_user).await?;
    }
    let mut deleted = 0;
    for user in deletes {
        delete_account_hub_user(state, &user).await?;
        deleted += 1;
    }
    Ok(SyncSummary {
        synced: local_by_uid.len() as i64 - deleted,
        deleted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(overrides: Value) -> Value {
        let mut value = json!({
            "uid": "1",
            "username": "s1234",
            "email": "user@example.com",
            "organization": "SW-ENG",
            "organizationId": 7,
            "roles": ["CVE-SYSTEM"],
            "enabled": true
        });
        if let (Some(base), Some(extra)) = (value.as_object_mut(), overrides.as_object()) {
            for (key, value) in extra {
                base.insert(key.clone(), value.clone());
            }
        }
        value
    }

    #[test]
    fn parses_data_list_and_account_status() {
        let payload = json!({"code":0,"data":[user(json!({}))]});
        let page = parse_page(&payload, "CVE-SYSTEM").unwrap();
        assert_eq!(page.users[0].uid, "1");
        assert!(page.users[0].enabled);
        assert_eq!(page.users[0].organization_id, "7");
        let disabled = parse_user(&user(json!({"enabled":false})), "CVE-SYSTEM").unwrap();
        assert!(!disabled.enabled);
        let mut status_disabled = user(json!({
            "status": "2",
            "userEmail": "other@example.com"
        }));
        status_disabled.as_object_mut().unwrap().remove("enabled");
        status_disabled.as_object_mut().unwrap().remove("email");
        let disabled = parse_user(&status_disabled, "CVE-SYSTEM").unwrap();
        assert!(!disabled.enabled);
        assert_eq!(disabled.email.as_deref(), Some("other@example.com"));
    }

    #[test]
    fn parses_nested_list_and_pagination() {
        let payload = json!({
            "code": 200,
            "data": {"records": [user(json!({}))], "page": 1, "pages": 2, "size": 1}
        });
        let page = parse_page(&payload, "CVE-SYSTEM").unwrap();
        assert!(page.has_more);
        assert_eq!(page.next_page, None);
        assert_eq!(page.current_page, Some(1));
    }

    #[test]
    fn rejects_empty_or_incomplete_directory_responses() {
        assert!(parse_page(&json!({"code":0,"data":[]}), "CVE-SYSTEM").is_err());
        assert!(
            parse_page(
                &json!({"code":0,"data":{"items":[user(json!({}))],"complete":false}}),
                "CVE-SYSTEM"
            )
            .is_ok()
        );
        assert!(
            parse_page(
                &json!({"code":0,"data":{"items":[user(json!({}))]}}),
                "CVE-SYSTEM"
            )
            .is_err()
        );
        assert!(parse_page(
            &json!({"code":0,"data":{"items":[user(json!({}))],"complete":false,"hasNext":false}}),
            "CVE-SYSTEM"
        )
        .is_err());
    }

    #[test]
    fn rejects_invalid_identity_and_status() {
        assert!(parse_user(&user(json!({"uid":""})), "CVE-SYSTEM").is_err());
        assert!(parse_user(&user(json!({"enabled":"unknown"})), "CVE-SYSTEM").is_err());
    }

    #[test]
    fn directory_requests_use_bearer_auth_and_page_parameters() {
        let request = directory_request(
            &reqwest::Client::new(),
            "https://directory.example.test/users",
            "directory-secret",
            5,
            Some(2),
        )
        .build()
        .unwrap();
        assert_eq!(
            request.headers().get(reqwest::header::AUTHORIZATION),
            Some(&"Bearer directory-secret".parse().unwrap())
        );
        assert_eq!(request.url().query(), Some("page=2&current=2&size=500"));
    }
}
