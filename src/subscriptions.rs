use crate::{
    AppState, ReqCtx, auth, db, mail, newsletter_statistics, render, reviews, vendor_matcher, view,
};
use axum::{
    body::Bytes,
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures::{TryStreamExt, stream};
use mongodb::bson::{self, Bson, Document, doc};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

fn default_filters() -> Value {
    json!({"collections":[],"collections_mode":"selected","sources":[],"search":"","code":"","title":"","impact":"","affected":"","status":[],"severity_threshold":"","include_unknown":false,"source":"","keywords":[],"vendor_product_filter":{"enabled":false,"schema_version":1,"include_possible_matches":false,"rows":[]},"time_window":"all","start":"","end":"","source_timestamp":{},"report_scope":{}})
}
fn default_profile(kind: &str) -> Value {
    if kind == "newsletter" {
        json!({"enabled":false,"filters":default_filters(),"delivery_cursor":"","cve_delivery_cutoff":"","statistic_schedule_enabled":false})
    } else {
        let mut filters = default_filters();
        filters["collections"] = json!(["cve"]);
        filters["sources"] = json!(["cve"]);
        json!({"enabled":false,"filters":filters,"generation_mode":"template","report_language":"en","search_prompt":"","schedule_enabled":false,"schedule_weekday":"mon","schedule_time":"09:00"})
    }
}
fn canonical_provider_name(value: &str) -> String {
    value
        .trim()
        .strip_suffix("_review")
        .unwrap_or(value.trim())
        .to_owned()
}
fn logical_collection_names(filters: &Value) -> Vec<String> {
    let sources = filters["sources"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(canonical_provider_name)
        .filter(|source| !source.is_empty())
        .collect::<Vec<_>>();
    if !sources.is_empty() {
        return sources;
    }
    filters["collections"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(canonical_provider_name)
        .filter(|name| !name.is_empty() && name != "news")
        .collect()
}

pub(crate) async fn source_providers(state: &AppState) -> Result<Vec<String>, String> {
    let catalog = db::find_one(&state.vuln, "source_catalog", doc! {"_id":"active"})
        .await
        .map_err(|error| {
            tracing::error!(%error, "Unable to read Cyberclawer source catalog");
            "Unable to load the Cyberclawer source catalog.".to_owned()
        })?
        .ok_or_else(|| {
            "Cyberclawer source catalog is not initialized. Run `vuln-scrape sync-source-catalog`."
                .to_owned()
        })?;
    parse_source_catalog(&catalog)
}

fn parse_source_catalog(catalog: &Document) -> Result<Vec<String>, String> {
    let values = catalog
        .get_array("providers")
        .map_err(|_| "Cyberclawer source catalog has an invalid provider list.".to_owned())?;
    let mut providers = Vec::with_capacity(values.len());
    let mut seen = HashSet::new();
    for value in values {
        let Bson::String(provider) = value else {
            return Err("Cyberclawer source catalog has an invalid provider list.".to_owned());
        };
        let provider = provider.trim();
        if provider.is_empty() || !seen.insert(provider.to_owned()) {
            return Err("Cyberclawer source catalog has an invalid provider list.".to_owned());
        }
        providers.push(provider.to_owned());
    }
    Ok(providers)
}

pub(crate) fn selected_provider_names(filters: &Value, physical_collection: &str) -> Vec<String> {
    let collection_sources = filters["collections"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty() && *name != physical_collection && *name != "news")
        .map(canonical_provider_name)
        .collect::<Vec<_>>();
    let values = if collection_sources.is_empty() {
        filters["sources"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(canonical_provider_name)
            .collect::<Vec<_>>()
    } else {
        collection_sources
    };
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| !value.is_empty() && seen.insert(value.clone()))
        .collect()
}
fn report_filters(profile: &Value, physical_collection: &str) -> Value {
    let mut filters = profile["filters"].clone();
    // Reports have no source picker. Repair empty selections saved by the old
    // template form, and apply the same scope to preview and scheduled reports.
    if matches!(
        profile["generation_mode"].as_str(),
        Some("enriched_weekly" | "ai" | "company_ai")
    ) || (filters["collections_mode"] == "selected"
        && selected_provider_names(&filters, physical_collection).is_empty())
    {
        filters["collections"] = json!([physical_collection]);
        filters["sources"] = json!(["cve"]);
    }
    filters
}

fn merge(into: &mut Value, from: &Value) {
    if let (Some(dst), Some(src)) = (into.as_object_mut(), from.as_object()) {
        for (k, v) in src {
            if let Some(existing) = dst.get_mut(k) {
                if existing.is_object() && v.is_object() {
                    merge(existing, v);
                    continue;
                }
            }
            dst.insert(k.clone(), v.clone());
        }
    }
}
async fn profile(state: &AppState, kind: &str, input: &Value) -> Result<Value, String> {
    if !input.is_null() && !input.is_object() {
        return Err(format!(
            "{} profile must be an object.",
            if kind == "newsletter" {
                "Newsletter"
            } else {
                "Report"
            }
        ));
    }
    let mut profile = default_profile(kind);
    merge(&mut profile, input);
    if kind == "newsletter" && !profile["statistic_schedule_enabled"].is_boolean() {
        return Err("Monthly statistics schedule must be true or false.".into());
    }
    let filters = profile["filters"].clone();
    if !filters.is_object() {
        return Err("Filters must be an object.".into());
    }
    vendor_matcher::validate(&filters["vendor_product_filter"])?;
    let collections = filters["collections"]
        .as_array()
        .ok_or("Filter collections must be a list.")?;
    let providers = source_providers(state).await?;
    let unified_collection = state.cfg.vulnerabilities_collection.as_str();
    if collections.iter().any(|value| value.as_str().is_none()) {
        return Err("Filter collections must contain provider names.".into());
    }
    if profile["filters"]["sources"]
        .as_array()
        .is_none_or(|values| values.iter().any(|value| value.as_str().is_none()))
    {
        return Err("Filter sources must be a list of source names.".into());
    }
    let selected_sources = selected_provider_names(&filters, unified_collection);
    if selected_sources
        .iter()
        .any(|source| !providers.iter().any(|provider| provider == source))
    {
        return Err("Filters contain a source that is not in the Cyberclawer catalog.".into());
    }
    profile["filters"]["sources"] = json!(selected_sources);
    profile["filters"]["collections"] = if profile["filters"]["sources"]
        .as_array()
        .is_some_and(|sources| !sources.is_empty())
    {
        json!([unified_collection])
    } else {
        json!([])
    };
    for field in ["search", "code", "title", "impact", "affected", "source"] {
        if !filters[field].is_string() {
            return Err(format!("Filter {field} must be text."));
        }
    }
    let statuses = filters["status"]
        .as_array()
        .ok_or("Severity/status must be Critical, High, Medium, or Low.")?;
    if statuses.iter().any(|v| {
        v.as_str()
            .is_none_or(|s| !matches!(s, "Critical" | "High" | "Medium" | "Low"))
    }) {
        return Err("Severity/status must be Critical, High, Medium, or Low.".into());
    }
    if !matches!(
        filters["severity_threshold"].as_str(),
        Some("" | "Critical" | "High" | "Medium" | "Low")
    ) {
        return Err("Severity threshold must be Critical, High, Medium, or Low.".into());
    }
    if !matches!(
        filters["time_window"].as_str(),
        Some("all" | "daily" | "week" | "custom")
    ) {
        return Err("Invalid filter time window.".into());
    }
    if kind == "report" {
        let mode = profile["generation_mode"].as_str().unwrap_or("");
        if mode == "ai" || mode == "company_ai" {
            profile["generation_mode"] = json!("enriched_weekly")
        }
        if !matches!(
            profile["generation_mode"].as_str(),
            Some("template" | "enriched_weekly")
        ) {
            return Err("Invalid report generation mode.".into());
        }
        if !matches!(
            profile["report_language"].as_str(),
            Some("en" | "zh" | "ch")
        ) {
            return Err("Invalid report language.".into());
        }
        if profile["generation_mode"] == "template" {
            profile["report_language"] = json!("en");
            profile["search_prompt"] = json!("")
        }
        profile["filters"] = report_filters(&profile, unified_collection);
        if !matches!(
            profile["schedule_weekday"].as_str(),
            Some("mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun")
        ) {
            return Err("Invalid report schedule weekday.".into());
        }
        let time = profile["schedule_time"].as_str().unwrap_or("");
        let valid = time.split_once(':').is_some_and(|(h, m)| {
            h.len() == 2
                && m.len() == 2
                && h.parse::<u8>().is_ok_and(|v| v < 24)
                && m.parse::<u8>().is_ok_and(|v| v < 60)
        });
        if !valid {
            return Err("Invalid report schedule time.".into());
        }
        if profile["enabled"] == true
            && profile["filters"]["vendor_product_filter"]["enabled"] != true
            && profile["filters"]["keywords"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        {
            return Err("Report keyword filters are no longer supported. Import a vendor/product CSV instead.".into());
        }
    }
    let normalized_sources = selected_provider_names(&profile["filters"], unified_collection);
    if normalized_sources
        .iter()
        .any(|source| !providers.iter().any(|provider| provider == source))
    {
        return Err("Filters contain a source that is not in the Cyberclawer catalog.".into());
    }
    Ok(profile)
}
fn public(document: &Document) -> Value {
    let mut value = db::public_id(db::bson_json(document));
    if let Some(obj) = value.as_object_mut() {
        let organization = obj
            .get("organization")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                obj.get("team")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
            })
            .unwrap_or("")
            .to_owned();
        obj.insert("organization".into(), json!(organization));
        obj.insert("delivery_mode".into(), json!("individual"));
        for key in ["cc", "bcc"] {
            if obj.get(key).is_none_or(Value::is_null) {
                obj.insert(key.into(), json!([]));
            }
        }
        obj.remove("team");
        for key in [
            "owner_user_id",
            "managed_by_user_id",
            "organization_id",
            "password",
            "password_hash",
            "zimbra_password",
            "schedule_claim_until",
            "schedule_claim_owner",
            "statistic_schedule_claim_until",
            "statistic_schedule_claim_owner",
        ] {
            obj.remove(key);
        }
        for profile_name in ["newsletter_profile", "report_profile"] {
            let collections = obj
                .get(profile_name)
                .and_then(|profile| profile.get("filters"))
                .map(logical_collection_names)
                .unwrap_or_default();
            if let Some(filters) = obj
                .get_mut(profile_name)
                .and_then(|profile| profile.get_mut("filters"))
                .and_then(Value::as_object_mut)
            {
                filters.insert("collections".to_owned(), json!(collections));
            }
        }
    }
    if let Some(obj) = value
        .get_mut("newsletter_profile")
        .and_then(Value::as_object_mut)
    {
        obj.remove("cve_delivery_cutoff");
    }
    value
}
fn subscription_organization(value: &Value) -> &str {
    value
        .get("organization")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            value
                .get("team")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or("")
}

fn organization_name(user: &Document) -> String {
    db::string(user, "zimbra_organization").trim().to_owned()
}

fn local_subscription_scope(ctx: &ReqCtx) -> Option<Document> {
    let manager_id = ctx.user_id()?;
    Some(doc! {
        "local_subscription": true,
        "managed_by_user_id": manager_id,
    })
}
async fn organization_members(state: &AppState, ctx: &ReqCtx) -> Option<Vec<Document>> {
    let manager = ctx.user.as_ref()?;
    let mut filter = crate::auth::organization_filter(manager)?;
    filter.insert("auth_source", "zimbra");
    db::find_sorted(
        &state.web,
        &state.cfg.account_collection,
        filter,
        doc! {"username_key":1},
        5000,
    )
    .await
    .ok()
}

async fn organization_member_ids(
    state: &AppState,
    ctx: &ReqCtx,
) -> Option<Vec<mongodb::bson::oid::ObjectId>> {
    Some(
        organization_members(state, ctx)
            .await?
            .iter()
            .filter_map(|user| user.get_object_id("_id").ok())
            .collect(),
    )
}

fn can_manage_subscriptions(state: &AppState, ctx: &ReqCtx) -> bool {
    ctx.is_admin(state) || ctx.is_organization_admin(state)
}

fn is_zimbra_user(ctx: &ReqCtx) -> bool {
    ctx.user
        .as_ref()
        .is_some_and(|user| db::string(user, "auth_source") == "zimbra")
}

fn can_create_local_subscription(state: &AppState, ctx: &ReqCtx) -> bool {
    ctx.is_top_admin(state) || ctx.is_organization_admin(state) || is_zimbra_user(ctx)
}

fn owns_local_subscription(ctx: &ReqCtx, subscription: &Document) -> bool {
    ctx.user_id().is_some_and(|user_id| {
        subscription.get_object_id("managed_by_user_id").ok() == Some(user_id)
    })
}

fn is_self_manager(state: &AppState, ctx: &ReqCtx) -> bool {
    ctx.user.is_some() && !can_manage_subscriptions(state, ctx)
}

fn same_username(left: &str, right: &str) -> bool {
    !left.trim().is_empty() && left.trim().eq_ignore_ascii_case(right.trim())
}

fn same_email(left: &str, right: &str) -> bool {
    !left.trim().is_empty() && left.trim().eq_ignore_ascii_case(right.trim())
}

fn zimbra_recipient(user: &Document) -> Result<Option<String>, String> {
    if db::string(user, "auth_source") != "zimbra" {
        return Ok(None);
    }
    let email = {
        let value = db::string(user, "email");
        if value.is_empty() {
            db::string(user, "zimbra_email")
        } else {
            value
        }
    }
    .trim()
    .to_lowercase();
    if email.is_empty() || !auth::valid_email(&email) {
        return Err("Zimbra email is unavailable. Ask the user to sign in again.".into());
    }
    Ok(Some(email))
}

fn default_zimbra_subscription_document(
    user: &Document,
    owner_id: bson::oid::ObjectId,
    email: &str,
    now: bson::DateTime,
) -> Document {
    doc! {
        "owner_user_id": owner_id,
        "managed_by_user_id": owner_id,
        "username": db::string(user, "username"),
        "emails": [email],
        "cc": [],
        "bcc": [],
        "email": email,
        "zimbra_email": email,
        "organization": db::string(user, "organization"),
        "delivery_mode": "individual",
        "local_subscription": false,
        "auto_provisioned": true,
        "newsletter_profile": db::json_doc(&default_profile("newsletter")).unwrap_or_default(),
        "report_profile": db::json_doc(&default_profile("report")).unwrap_or_default(),
        "created_at": now,
        "updated_at": now,
    }
}

fn subscription_emails(document: &Document) -> Vec<String> {
    let mut emails = document
        .get_array("emails")
        .ok()
        .map(|values| {
            values
                .iter()
                .filter_map(Bson::as_str)
                .map(|value| value.trim().to_lowercase())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if emails.is_empty() {
        let email = db::string(document, "email").trim().to_lowercase();
        if !email.is_empty() {
            emails.push(email);
        }
    }
    emails.sort();
    emails
}

fn same_subscription_identity(left: &Document, right: &Document) -> bool {
    let left_organization = db::string(left, "organization");
    let right_organization = db::string(right, "organization");
    same_username(
        &db::string(left, "username"),
        &db::string(right, "username"),
    ) && subscription_emails(left) == subscription_emails(right)
        && left_organization
            .trim()
            .eq_ignore_ascii_case(right_organization.trim())
        && left.get("newsletter_profile") == right.get("newsletter_profile")
        && left.get("report_profile") == right.get("report_profile")
        && copy_recipients(&db::bson_json(left)).ok() == copy_recipients(&db::bson_json(right)).ok()
}

fn is_default_zimbra_subscription(document: &Document) -> bool {
    if ["cc", "bcc"].iter().any(|key| {
        document
            .get_array(*key)
            .is_ok_and(|items| !items.is_empty())
    }) {
        return false;
    }
    let newsletter = db::json_doc(&default_profile("newsletter")).ok();
    let report = db::json_doc(&default_profile("report")).ok();
    newsletter.is_some_and(|expected| {
        document
            .get_document("newsletter_profile")
            .ok()
            .is_some_and(|actual| actual == &expected)
    }) && report.is_some_and(|expected| {
        document
            .get_document("report_profile")
            .ok()
            .is_some_and(|actual| actual == &expected)
    })
}

fn is_legacy_subscription(document: &Document) -> bool {
    matches!(document.get("auto_provisioned"), None | Some(Bson::Null))
}

fn subscription_object_id(document: &Document) -> Option<bson::oid::ObjectId> {
    document.get_object_id("_id").ok()
}

/// Ensure that every Zimbra account has one owner-scoped subscription record.
/// The record is deliberately created with both delivery profiles disabled so
/// logging in never starts mail delivery without the user's action.
pub async fn ensure_zimbra_subscription(state: &AppState, user: &Document) -> Result<(), String> {
    if db::string(user, "auth_source") != "zimbra" {
        return Ok(());
    }
    let owner_id = user
        .get_object_id("_id")
        .map_err(|_| "Zimbra account has no valid owner id.".to_owned())?;
    let Some(email) = zimbra_recipient(user)? else {
        return Err("Zimbra email is unavailable. Ask the user to sign in again.".into());
    };
    let now = bson::DateTime::now();
    let coll = db::collection(&state.web, "sub_account");
    let identity = doc! {
        "owner_user_id": owner_id,
        "managed_by_user_id": owner_id,
        "username": db::string(user, "username"),
        "zimbra_email": &email,
        "organization": db::string(user, "organization"),
        "delivery_mode": "individual",
        "updated_at": now,
    };
    let owner_filter = doc! {
        "owner_user_id": owner_id,
        "local_subscription": {"$ne": true},
    };
    let mut owner_rows = db::find_sorted(
        &state.web,
        "sub_account",
        owner_filter.clone(),
        doc! {"auto_provisioned": -1, "created_at": 1, "_id": 1},
        5000,
    )
    .await
    .map_err(|_| "Unable to load the Zimbra subscriptions.".to_owned())?;

    // A deployment before auto_provisioned was introduced may have left the
    // user's default disabled subscription without the marker. Reuse it as
    // the canonical automatic row instead of creating a second row.
    let mut canonical_id = owner_rows
        .iter()
        .find(|row| db::bool_field(row, "auto_provisioned"))
        .and_then(subscription_object_id);
    if canonical_id.is_none()
        && let Some(legacy) = owner_rows
            .iter()
            .find(|row| is_legacy_subscription(row) && is_default_zimbra_subscription(row))
    {
        canonical_id = subscription_object_id(legacy);
        if let Some(id) = canonical_id {
            let mut set = identity.clone();
            set.insert("auto_provisioned", true);
            set.insert("local_subscription", false);
            coll.update_one(doc! {"_id": id}, doc! {"$set": set})
                .await
                .map_err(|_| "Unable to migrate the Zimbra subscription.".to_owned())?;
        }
    }

    // Adopt a prior Rust subscription created before owner_user_id was set,
    // but do not take over a local subscription or a configured manual row.
    if canonical_id.is_none() && owner_rows.is_empty() {
        let zimbra_pattern = format!("^{}$", regex::escape(&email));
        if let Some(existing) = coll
            .find_one(doc! {
                "local_subscription": {"$ne": true},
                "$or": [{"owner_user_id": {"$exists": false}}, {"owner_user_id": Bson::Null}],
                "zimbra_email": {"$regex": zimbra_pattern, "$options": "i"},
            })
            .await
            .map_err(|_| "Unable to inspect existing Zimbra subscriptions.".to_owned())?
        {
            let id = existing
                .get_object_id("_id")
                .map_err(|_| "Zimbra subscription has no valid id.".to_owned())?;
            let mut set = identity.clone();
            let default_row = is_default_zimbra_subscription(&existing);
            set.insert("auto_provisioned", default_row);
            set.insert("local_subscription", false);
            coll.update_one(doc! {"_id": id}, doc! {"$set": set})
                .await
                .map_err(|_| "Unable to claim the Zimbra subscription.".to_owned())?;
            if default_row {
                canonical_id = Some(id);
            }
            owner_rows = db::find_sorted(
                &state.web,
                "sub_account",
                owner_filter.clone(),
                doc! {"auto_provisioned": -1, "created_at": 1, "_id": 1},
                5000,
            )
            .await
            .map_err(|_| "Unable to reload the Zimbra subscriptions.".to_owned())?;
        }
    }

    if canonical_id.is_none() {
        let document = default_zimbra_subscription_document(user, owner_id, &email, now);
        canonical_id = match coll.insert_one(document).await {
            Ok(result) => result.inserted_id.as_object_id(),
            Err(_) => {
                // A concurrent login may have created the record. Re-check
                // the owner before reporting a failure to the caller.
                coll.find_one(doc! {"owner_user_id": owner_id, "auto_provisioned": true})
                    .await
                    .ok()
                    .flatten()
                    .and_then(|existing| existing.get_object_id("_id").ok())
            }
        };
        if canonical_id.is_none() {
            return Err("Zimbra subscription has no valid id.".into());
        }
    }

    let canonical_id = canonical_id.expect("canonical id set above");
    let mut canonical_set = identity;
    canonical_set.insert("auto_provisioned", true);
    canonical_set.insert("local_subscription", false);
    coll.update_one(doc! {"_id": canonical_id}, doc! {"$set": canonical_set})
        .await
        .map_err(|_| "Unable to update the Zimbra subscription.".to_owned())?;

    let Some(canonical) = coll
        .find_one(doc! {"_id": canonical_id})
        .await
        .ok()
        .flatten()
    else {
        return Err("Unable to reload the Zimbra subscription.".into());
    };
    // Remove exact copies of the automatic disabled row. A manually submitted
    // copy with the same identity and default profiles has no independent
    // meaning, while manual rows with different profiles remain available to
    // the owner.
    let rows = if owner_rows.is_empty() {
        db::find_sorted(
            &state.web,
            "sub_account",
            owner_filter,
            doc! {"created_at": 1, "_id": 1},
            5000,
        )
        .await
        .map_err(|_| "Unable to inspect duplicate Zimbra subscriptions.".to_owned())?
    } else {
        owner_rows
    };
    for row in rows {
        let Some(id) = subscription_object_id(&row) else {
            continue;
        };
        if id == canonical_id {
            continue;
        }
        let duplicate_auto = db::bool_field(&row, "auto_provisioned");
        let duplicate_default = !db::bool_field(&row, "auto_provisioned")
            && same_subscription_identity(&row, &canonical)
            && is_default_zimbra_subscription(&row);
        if duplicate_auto || duplicate_default {
            if let Err(error) = coll.delete_one(doc! {"_id": id}).await {
                tracing::warn!(%error, subscription_id = %id, "Unable to remove duplicate Zimbra subscription");
            }
        } else if is_legacy_subscription(&row) {
            let _ = coll
                .update_one(doc! {"_id": id}, doc! {"$set": {"auto_provisioned": false}})
                .await;
        }
    }
    Ok(())
}

/// Backfill active Zimbra accounts when the service starts. This keeps users
/// created by an earlier deployment on the same self-management path.
pub async fn ensure_zimbra_subscriptions(state: &AppState) -> Result<(), String> {
    let users = db::find_many(
        &state.web,
        &state.cfg.account_collection,
        doc! {"auth_source": "zimbra", "disabled": {"$ne": true}},
        5000,
    )
    .await
    .map_err(|_| "Unable to load Zimbra accounts for subscription setup.".to_owned())?;
    for user in users {
        if let Err(error) = ensure_zimbra_subscription(state, &user).await {
            tracing::warn!(username = %db::string(&user, "username"), %error, "Unable to initialize Zimbra subscription");
        }
    }
    Ok(())
}

fn self_recipient(user: &Document) -> Result<String, String> {
    if let Some(email) = zimbra_recipient(user)? {
        return Ok(email);
    }
    let email = db::string(user, "email").trim().to_lowercase();
    if email.is_empty() || !auth::valid_email(&email) {
        return Err("A valid profile email is required for this subscription.".into());
    }
    Ok(email)
}

fn self_subscription_owner_filter(ctx: &ReqCtx) -> Option<Document> {
    let owner_id = ctx.user_id()?;
    Some(doc! {"owner_user_id":owner_id})
}

async fn subscription_filter(state: &AppState, ctx: &ReqCtx, id: Option<&str>) -> Option<Document> {
    let owner = if ctx.is_top_admin(state) {
        doc! {}
    } else if ctx.is_organization_admin(state) {
        let ids = organization_member_ids(state, ctx).await?;
        let mut scopes = vec![Bson::Document(doc! {"owner_user_id":{"$in":ids}})];
        if let Some(local_scope) = local_subscription_scope(ctx) {
            scopes.push(Bson::Document(local_scope));
        }
        doc! {"$or":scopes}
    } else if ctx.is_admin(state) {
        doc! {"managed_by_user_id":ctx.user_id()?}
    } else {
        let owner_filter = self_subscription_owner_filter(ctx)?;
        if is_zimbra_user(ctx) {
            let mut scopes = vec![Bson::Document(owner_filter)];
            if let Some(local_scope) = local_subscription_scope(ctx) {
                scopes.push(Bson::Document(local_scope));
            }
            doc! {"$or":scopes}
        } else {
            owner_filter
        }
    };
    if let Some(id) = id {
        if id.is_empty() {
            return None;
        }
        let identifier = if let Some(oid) = db::object_id(id) {
            doc! {"_id":oid}
        } else {
            doc! {"$or":[{"email":id.to_lowercase()},{"emails":id.to_lowercase()}]}
        };
        if owner.is_empty() {
            Some(identifier)
        } else {
            Some(doc! {"$and":[identifier,owner]})
        }
    } else {
        Some(owner)
    }
}

fn public_organization_member(user: &Document, subscription: Option<&Document>) -> Value {
    let mut value = auth::public_user(user);
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "account_status".into(),
            json!(if db::bool_field(user, "disabled") {
                "disabled"
            } else {
                "active"
            }),
        );
        object.insert("has_subscription".into(), json!(subscription.is_some()));
        object.insert(
            "subscription".into(),
            subscription.map(public).unwrap_or(Value::Null),
        );
    }
    value
}

fn public_local_subscription(subscription: &Document) -> Value {
    let value = public(subscription);
    let emails = value.get("emails").cloned().unwrap_or_else(|| json!([]));
    json!({
        "id": value.get("id").cloned().unwrap_or(Value::Null),
        "username": value.get("username").cloned().unwrap_or(json!("")),
        "email": value.get("email").cloned().unwrap_or(json!("")),
        "emails": emails,
        "organization": value.get("organization").cloned().unwrap_or(json!("")),
        "organization_admin": false,
        "account_status": "local",
        "disabled": false,
        "auth_source": "local",
        "local_subscription": true,
        "has_subscription": true,
        "subscription": value,
    })
}

async fn organization_subscription_rows(
    state: &AppState,
    ctx: &ReqCtx,
) -> Result<Vec<Value>, String> {
    let members = organization_members(state, ctx)
        .await
        .ok_or_else(|| "Your Account Hub organization is not available.".to_owned())?;
    let ids: Vec<Bson> = members
        .iter()
        .filter_map(|user| user.get_object_id("_id").ok().map(Bson::ObjectId))
        .collect();
    let subscriptions = if ids.is_empty() {
        Vec::new()
    } else {
        db::find_many(
            &state.web,
            "sub_account",
            doc! {"owner_user_id":{"$in":ids}},
            5000,
        )
        .await
        .map_err(|_| "Unable to load subscriptions.".to_owned())?
    };
    let mut by_owner = HashMap::new();
    for subscription in subscriptions {
        if let Ok(owner_id) = subscription.get_object_id("owner_user_id") {
            by_owner.insert(owner_id, subscription);
        }
    }
    let mut rows: Vec<Value> = members
        .iter()
        .map(|member| {
            let subscription = member
                .get_object_id("_id")
                .ok()
                .and_then(|owner_id| by_owner.get(&owner_id));
            public_organization_member(member, subscription)
        })
        .collect();
    if let Some(local_scope) = local_subscription_scope(ctx) {
        let local_subscriptions = db::find_many(&state.web, "sub_account", local_scope, 5000)
            .await
            .map_err(|_| "Unable to load subscriptions.".to_owned())?;
        rows.extend(local_subscriptions.iter().map(public_local_subscription));
    }
    Ok(rows)
}
pub(crate) fn recipients(data: &Value) -> Result<Vec<String>, String> {
    let raw = if let Some(items) = data.get("emails") {
        items.clone()
    } else if let Some(email) = data.get("email") {
        json!([email])
    } else {
        return Err("At least one email recipient is required.".into());
    };
    let items = raw.as_array().ok_or("Email recipients must be an array.")?;
    if items.is_empty() || items.len() > 50 {
        return Err("Email recipient count must be between 1 and 50.".into());
    }
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for item in items {
        let email = item
            .as_str()
            .ok_or("Email recipients must be non-empty text values.")?
            .trim()
            .to_lowercase();
        if !auth::valid_email(&email) || email.parse::<lettre::Address>().is_err() {
            return Err(format!("Invalid email address: {email}"));
        }
        if seen.insert(email.clone()) {
            output.push(email)
        }
    }
    Ok(output)
}

pub(crate) fn copy_recipients(data: &Value) -> Result<mail::CopyRecipients, String> {
    let to = recipients(data)?;
    let mut seen = to.into_iter().collect::<HashSet<_>>();
    let mut output = mail::CopyRecipients::default();
    for (key, target) in [("cc", &mut output.cc), ("bcc", &mut output.bcc)] {
        let Some(raw) = data.get(key).filter(|value| !value.is_null()) else {
            continue;
        };
        let items = raw
            .as_array()
            .ok_or_else(|| format!("{key} recipients must be an array."))?;
        if items.len() > 50 {
            return Err("At most 50 recipients are allowed across To, CC, and BCC.".into());
        }
        for item in items {
            let email = item
                .as_str()
                .ok_or_else(|| format!("{key} recipients must be email addresses."))?
                .trim()
                .to_lowercase();
            if !auth::valid_email(&email) || email.parse::<lettre::Address>().is_err() {
                return Err(format!("Invalid {key} email address: {email}"));
            }
            if seen.insert(email.clone()) {
                target.push(email);
            }
        }
    }
    if seen.len() > 50 {
        return Err("At most 50 recipients are allowed across To, CC, and BCC.".into());
    }
    Ok(output)
}
fn json_error(status: StatusCode, message: &str) -> Option<Response> {
    Some(view::error(status, message))
}
fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
async fn notify(
    state: &AppState,
    emails: &[String],
    copies: &mail::CopyRecipients,
    kind: &str,
    username: &str,
    organization: &str,
    newsletter: &Value,
    report: &Value,
) -> Result<(), String> {
    let (kind, subject, heading, badge, intro) = match kind {
        "created" => (
            "created",
            "Security portal subscription confirmed",
            "Subscription confirmed",
            "Confirmed",
            "Your Security Portal subscription has been created successfully.",
        ),
        "updated" => (
            "updated",
            "Security portal subscription updated",
            "Subscription updated",
            "Updated",
            "Your Security Portal subscription settings were updated successfully.",
        ),
        _ => (
            "cancelled",
            "Security portal subscription cancelled",
            "Subscription cancelled",
            "Cancelled",
            "Your Security Portal subscription was cancelled and scheduled deliveries will stop.",
        ),
    };
    let recipient_text = if emails.is_empty() {
        "No recipients".to_owned()
    } else {
        emails
            .iter()
            .map(|email| escape_html(email))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let organization = if organization.trim().is_empty() {
        "Not specified"
    } else {
        organization.trim()
    };
    let event_time = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let newsletter_enabled = newsletter["enabled"].as_bool().unwrap_or(false);
    let report_enabled = report["enabled"].as_bool().unwrap_or(false);
    let changes = vec![
        format!(
            "Newsletter feed: {}",
            if newsletter_enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        ),
        format!(
            "Report profile: {}",
            if report_enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        ),
        format!("Recipients: {recipient_text}"),
    ];
    let details = json!({
        "subject": subject,
        "heading": heading,
        "badge": badge,
        "intro": intro,
        "username": escape_html(username.trim()),
        "organization": escape_html(organization),
        "recipients": recipient_text,
        "event_time": event_time,
        "footer": "Automated subscription notification from Security Portal.",
    });
    let cards = vec![
        notification_profile_card("Newsletter feed", newsletter, true),
        notification_profile_card("Report profile", report, false),
    ];
    let body = state
        .templates
        .get_template("subscriptions/notification_email.html")
        .map_err(|error| error.to_string())?
        .render(json!({
            "details": details,
            "kind": kind,
            "changes": changes,
            "cards": cards,
        }))
        .map_err(|error| error.to_string())?;
    for email in emails {
        mail::send(
            state,
            std::slice::from_ref(email),
            copies,
            "individual",
            subject,
            &body,
        )
        .await
        .map_err(|error| format!("{email}: {error}"))?;
    }
    Ok(())
}

fn notification_delivery_error(action: &str, error: &str) -> Response {
    tracing::error!(action, error, "Subscription notification delivery failed");
    view::error(
        StatusCode::SERVICE_UNAVAILABLE,
        &format!(
            "Subscription was {action}, but the notification email could not be sent: {error}"
        ),
    )
}

fn notification_profile_card(name: &str, profile: &Value, newsletter: bool) -> Value {
    let enabled = profile["enabled"].as_bool().unwrap_or(false);
    let mut summary_lines = Vec::new();
    let filters = &profile["filters"];
    let collections = logical_collection_names(filters)
        .iter()
        .map(|value| escape_html(value))
        .collect::<Vec<_>>()
        .join(", ");
    let collections = (!collections.is_empty())
        .then_some(collections)
        .unwrap_or_else(|| "No sources selected".to_owned());
    summary_lines.push(format!("Sources: {collections}"));

    if newsletter {
        if profile["statistic_schedule_enabled"] == true {
            summary_lines.push("Monthly delivery statistics: Enabled".to_owned());
        } else {
            summary_lines.push("Monthly delivery statistics: Disabled".to_owned());
        }
    } else {
        let generation = match profile["generation_mode"].as_str().unwrap_or("template") {
            "enriched_weekly" => "Enriched Weekly",
            _ => "Fixed Template",
        };
        let language = match profile["report_language"].as_str().unwrap_or("en") {
            "zh" => "Traditional Chinese",
            "ch" => "Simplified Chinese",
            _ => "English",
        };
        summary_lines.push(format!("Generation: {generation}"));
        summary_lines.push(format!("Language: {language}"));
        if profile["schedule_enabled"] == true {
            let weekday = match profile["schedule_weekday"].as_str().unwrap_or("mon") {
                "tue" => "Tuesday",
                "wed" => "Wednesday",
                "thu" => "Thursday",
                "fri" => "Friday",
                "sat" => "Saturday",
                "sun" => "Sunday",
                _ => "Monday",
            };
            let time = profile["schedule_time"].as_str().unwrap_or("09:00");
            summary_lines.push(format!(
                "Schedule: Every {weekday} at {} HKT",
                escape_html(time)
            ));
        } else {
            summary_lines.push("Schedule: Disabled".to_owned());
        }
    }
    json!({
        "name": name,
        "enabled": enabled,
        "status": if enabled { "Enabled" } else { "Disabled" },
        "summary_lines": summary_lines,
    })
}
async fn vendor_import(ctx: &ReqCtx) -> Response {
    let content_type = ctx
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let boundary = match multer::parse_boundary(content_type) {
        Ok(v) => v,
        Err(_) => return view::error(StatusCode::BAD_REQUEST, "Choose a vendor/product CSV file."),
    };
    let bytes = Bytes::from(ctx.body.clone());
    let body = stream::once(async move { Ok::<Bytes, std::io::Error>(bytes) });
    let mut multipart = multer::Multipart::new(body, boundary);
    let mut csv_bytes = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") {
            csv_bytes = field.bytes().await.ok();
            break;
        }
    }
    let Some(bytes) = csv_bytes else {
        return view::error(StatusCode::BAD_REQUEST, "Choose a vendor/product CSV file.");
    };
    if bytes.len() > 1024 * 1024 {
        return view::error(StatusCode::BAD_REQUEST, "CSV file is too large.");
    }
    let mut reader = csv::ReaderBuilder::new()
        .flexible(false)
        .from_reader(bytes.as_ref());
    let headers = match reader.headers() {
        Ok(v) => v.clone(),
        Err(_) => return view::error(StatusCode::BAD_REQUEST, "CSV is invalid."),
    };
    if headers.iter().collect::<Vec<_>>()
        != vec!["vendor", "product", "vendor_aliases", "product_aliases"]
    {
        return view::error(
            StatusCode::BAD_REQUEST,
            "CSV columns must be vendor, product, vendor_aliases, product_aliases.",
        );
    }
    let mut rows = Vec::new();
    for (i, result) in reader.records().enumerate() {
        let Ok(record) = result else {
            return view::error(StatusCode::BAD_REQUEST, "CSV row is invalid.");
        };
        if i >= 500 {
            return view::error(
                StatusCode::BAD_REQUEST,
                "CSV must contain at most 500 data rows.",
            );
        };
        let vendor = record.get(0).unwrap_or("").trim();
        let product = record.get(1).unwrap_or("").trim();
        if vendor.is_empty() || product.is_empty() {
            return view::error(StatusCode::BAD_REQUEST, "Vendor and product are required.");
        }
        let aliases = |v: &str| {
            v.split('|')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        rows.push(json!({"vendor":vendor,"product":product,"vendor_aliases":aliases(record.get(2).unwrap_or("")),"product_aliases":aliases(record.get(3).unwrap_or("")),"row_number":i+2}));
    }
    if rows.is_empty() {
        return view::error(
            StatusCode::BAD_REQUEST,
            "CSV must contain at least one data row.",
        );
    }
    view::json_response(
        StatusCode::OK,
        json!({"vendor_product_filter":{"enabled":true,"schema_version":1,"include_possible_matches":false,"rows":rows},"warnings":[]}),
    )
}

fn vendor_product_csv(subscription: &Value, profile_name: &str) -> Result<String, String> {
    let profile_key = match profile_name {
        "newsletter" => "newsletter_profile",
        "report" => "report_profile",
        _ => return Err("Inventory profile must be newsletter or report.".into()),
    };
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record(["vendor", "product", "vendor_aliases", "product_aliases"])
        .map_err(|error| error.to_string())?;
    if let Some(rows) =
        subscription[profile_key]["filters"]["vendor_product_filter"]["rows"].as_array()
    {
        for row in rows {
            let aliases = |key: &str| {
                row[key]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("|")
            };
            writer
                .write_record([
                    row["vendor"].as_str().unwrap_or(""),
                    row["product"].as_str().unwrap_or(""),
                    &aliases("vendor_aliases"),
                    &aliases("product_aliases"),
                ])
                .map_err(|error| error.to_string())?;
        }
    }
    String::from_utf8(writer.into_inner().map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}
async fn collection_rows(state: &AppState) -> Result<Vec<Value>, String> {
    let collection = db::collection(&state.vuln, &state.cfg.vulnerabilities_collection);
    let providers = source_providers(state).await?;
    let mut data = Vec::with_capacity(providers.len());
    for provider in providers {
        let count = collection
            .count_documents(doc! {"source.provider":&provider})
            .await
            .map_err(|error| {
                tracing::error!(%error, provider, "Unable to count provider documents");
                "Unable to load provider document counts.".to_owned()
            })?;
        data.push(json!({
            "name":provider,
            "source":provider,
            "count":count,
        }));
    }
    Ok(data)
}
fn profile_filter(filters: &Value, physical_collection: &str) -> Document {
    let mut clauses: Vec<Bson> = Vec::new();
    let mapping: [(&str, &[&str]); 6] = [
        (
            "search",
            &[
                "code",
                "cve",
                "cve_ids",
                "title",
                "description",
                "details.description",
                "details.descriptions.value",
                "details.summary",
                "impacts",
                "details.impact",
                "details.impacts",
                "affected",
                "details.affected",
                "details.affected_products",
                "details.affected_software",
                "details.systems_affected",
                "recommendation",
                "details.recommendation",
                "details.recommendations",
                "details.solutions",
                "related_link",
            ],
        ),
        (
            "code",
            &[
                "code",
                "cve",
                "cve_ids",
                "details.cve_id",
                "details.cve_ids",
                "details.cveCode",
                "details.cveId",
            ],
        ),
        (
            "title",
            &["title", "details.title", "details.advisory_title"],
        ),
        ("impact", &["impacts", "details.impact", "details.impacts"]),
        (
            "affected",
            &[
                "affected",
                "details.affected",
                "details.affected_products",
                "details.affected_software",
                "details.systems_affected",
                "details.affected_systems",
            ],
        ),
        (
            "source",
            &["source.provider", "source.url", "source.detail_url"],
        ),
    ];
    for (name, fields) in mapping {
        let Some(value) = filters[name].as_str().filter(|v| !v.trim().is_empty()) else {
            continue;
        };
        for term in value.split_whitespace() {
            let options: Vec<Bson> = fields
                .iter()
                .map(|field| {
                    let mut d = Document::new();
                    d.insert(*field, doc! {"$regex":regex::escape(term),"$options":"i"});
                    Bson::Document(d)
                })
                .collect();
            clauses.push(Bson::Document(doc! {"$or":options}));
        }
    }
    let sources = selected_provider_names(filters, physical_collection);
    if !sources.is_empty() || filters["collections_mode"].as_str() == Some("selected") {
        clauses.push(Bson::Document(doc! {
            "source.provider": {"$in": sources.clone()}
        }));
    }

    let status = filters["status"].as_array().cloned().unwrap_or_default();
    let threshold = filters["severity_threshold"].as_str().unwrap_or("");
    let include_unknown = filters["include_unknown"] == true;
    let mut accepted = status
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !threshold.is_empty() {
        for severity in ["Critical", "High", "Medium", "Low"] {
            if !accepted.iter().any(|v| v == severity) {
                accepted.push(severity.into())
            }
            if severity == threshold {
                break;
            }
        }
    }
    let zimbra_only = sources.len() == 1 && sources[0] == "zimbra";
    if accepted.is_empty() && !include_unknown && !zimbra_only {
        accepted = ["Critical", "High", "Medium", "Low"]
            .iter()
            .map(|v| v.to_string())
            .collect()
    }
    if !accepted.is_empty() {
        let mut ors=accepted.iter().map(|s|Bson::Document(doc!{"severity":{"$regex":format!("^{}(?:\\s+Risk)?$",regex::escape(s)),"$options":"i"}})).collect::<Vec<_>>();
        if include_unknown {
            ors.push(Bson::Document(doc! {"severity":{"$exists":false}}));
            ors.push(Bson::Document(doc! {"severity":Bson::Null}));
            ors.push(Bson::Document(doc! {"severity":""}));
        } else if sources.is_empty() || sources.iter().any(|value| value == "zimbra") {
            // The legacy Zimbra feed has no severity. It was always included
            // when all providers were selected, so preserve that behavior in
            // the unified collection.
            ors.push(Bson::Document(doc! {"source.provider":"zimbra"}));
        }
        clauses.push(Bson::Document(doc! {"$or":ors}));
    }
    let window = filters["time_window"].as_str().unwrap_or("all");
    let now = chrono::Utc::now();
    let start = match window {
        "daily" => {
            let hk = now + chrono::Duration::hours(8);
            let midnight = hk.date_naive().and_hms_opt(0, 0, 0).unwrap();
            Some((midnight - chrono::Duration::hours(8)).and_utc())
        }
        "week" => Some(now - chrono::Duration::days(7)),
        _ => None,
    };
    if let Some(start) = start {
        clauses.push(Bson::Document(
            doc! {"observed_at":{"$gte":bson::DateTime::from_millis(start.timestamp_millis())}},
        ));
    }
    if filters["report_scope"]["kev_only"] == true {
        clauses.push(Bson::Document(doc!{"$or":[{"cisa_kev":true},{"kev":true},{"details.cisa_kev":true},{"details.kev":true}]}));
    }
    if clauses.is_empty() {
        doc! {}
    } else if clauses.len() == 1 {
        clauses.remove(0).as_document().cloned().unwrap_or_default()
    } else {
        doc! {"$and":clauses}
    }
}
fn inventory_match(document: &Document, filters: &Value) -> bool {
    let inventory = &filters["vendor_product_filter"];
    if inventory["enabled"] != true {
        return true;
    }
    vendor_matcher::classify(&db::bson_json(document), inventory).is_some()
}

async fn profile_has_collection_scope(state: &AppState, filters: &Value) -> bool {
    if !selected_provider_names(filters, &state.cfg.vulnerabilities_collection).is_empty() {
        return true;
    }
    if filters["collections_mode"].as_str() == Some("selected") {
        return false;
    }
    source_providers(state)
        .await
        .is_ok_and(|providers| !providers.is_empty())
}

pub(crate) struct ProfileMatchBatch {
    pub items: Vec<Value>,
    pub last_scanned_at: Option<String>,
}

fn observed_at(document: &Document) -> Option<chrono::DateTime<chrono::Utc>> {
    match document.get("observed_at") {
        Some(Bson::DateTime(value)) => {
            chrono::DateTime::<chrono::Utc>::from_timestamp_millis(value.timestamp_millis())
        }
        Some(Bson::String(value)) => chrono::DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|value| value.with_timezone(&chrono::Utc)),
        _ => None,
    }
}

/// Return the next matching newsletter records after a delivery cursor.
///
/// Records are scanned oldest first. Once `limit` matching records have been
/// found, every remaining record with the same timestamp is included before
/// stopping. This makes a timestamp-only cursor safe even when several
/// documents were inserted at exactly the same instant.
pub(crate) async fn match_profile_after(
    state: &AppState,
    profile: &Value,
    after: chrono::DateTime<chrono::Utc>,
    limit: usize,
) -> Result<ProfileMatchBatch, String> {
    let filters = &profile["filters"];
    if limit == 0 || !profile_has_collection_scope(state, filters).await {
        return Ok(ProfileMatchBatch {
            items: Vec::new(),
            last_scanned_at: None,
        });
    }

    let collection = db::collection(&state.vuln, &state.cfg.vulnerabilities_collection);
    let high_watermark = collection
        .find_one(doc! {
            "observed_at": {
                "$gt": bson::DateTime::from_millis(after.timestamp_millis())
            }
        })
        .sort(doc! {"observed_at": -1, "_id": -1})
        .await
        .map_err(|error| format!("Unable to query the newsletter watermark: {error}"))?
        .as_ref()
        .and_then(observed_at);
    let Some(high_watermark) = high_watermark else {
        return Ok(ProfileMatchBatch {
            items: Vec::new(),
            last_scanned_at: None,
        });
    };

    let base_filter = profile_filter(filters, &state.cfg.vulnerabilities_collection);
    let after_filter = doc! {
        "observed_at": {
            "$gt": bson::DateTime::from_millis(after.timestamp_millis()),
            "$lte": bson::DateTime::from_millis(high_watermark.timestamp_millis()),
        }
    };
    let filter = if base_filter.is_empty() {
        after_filter
    } else {
        doc! {"$and": [base_filter, after_filter]}
    };
    let mut cursor = collection
        .find(filter)
        .sort(doc! {"observed_at": 1, "_id": 1})
        .await
        .map_err(|error| format!("Unable to query newsletter records: {error}"))?;

    let mut items = Vec::new();
    let mut last_scanned_at = None;
    let mut cutoff_millis = None;
    while let Some(document) = cursor
        .try_next()
        .await
        .map_err(|error| format!("Unable to read newsletter records: {error}"))?
    {
        let Some(observed) = observed_at(&document) else {
            continue;
        };
        let observed_millis = observed.timestamp_millis();
        if cutoff_millis.is_some_and(|cutoff| observed_millis > cutoff) {
            break;
        }
        last_scanned_at = Some(observed.to_rfc3339());

        if !inventory_match(&document, filters) {
            continue;
        }
        let value = db::bson_json(&document);
        let source = value
            .pointer("/source/provider")
            .and_then(Value::as_str)
            .filter(|source| !source.trim().is_empty())
            .unwrap_or("unknown")
            .to_owned();
        items.push(json!({
            "collection": state.cfg.vulnerabilities_collection,
            "source_collection": source,
            "selection_id": db::id_string(&document),
            "document": value,
        }));
        if items.len() >= limit && cutoff_millis.is_none() {
            cutoff_millis = Some(observed_millis);
        }
    }

    if cutoff_millis.is_none() {
        // The filtered cursor was exhausted. Advancing to the snapshot's high
        // watermark prevents permanently rescanning unrelated providers while
        // preserving records inserted after the snapshot for the next tick.
        last_scanned_at = Some(high_watermark.to_rfc3339());
    }
    Ok(ProfileMatchBatch {
        items,
        last_scanned_at,
    })
}

pub(crate) async fn match_profile(
    state: &AppState,
    profile: &Value,
    limit: i64,
) -> Result<Vec<Value>, String> {
    let mut output = Vec::new();
    if limit <= 0 {
        return Ok(output);
    }
    let filters = report_filters(profile, &state.cfg.vulnerabilities_collection);
    let name = &state.cfg.vulnerabilities_collection;
    let mut cursor = db::collection(&state.vuln, name)
        .find(profile_filter(&filters, name))
        .sort(doc! {"observed_at": -1, "_id": -1})
        .await
        .map_err(|error| {
            tracing::error!(%error, "Unable to query report records");
            "Unable to query the vulnerabilities database.".to_owned()
        })?;
    // Apply the limit to matches, not candidates: an inventory match may be
    // older than the newest 10,000 unrelated records.
    while let Some(doc) = cursor.try_next().await.map_err(|error| {
        tracing::error!(%error, "Unable to read report records");
        "Unable to read the vulnerabilities database.".to_owned()
    })? {
        let document = db::bson_json(&doc);
        let inventory = &filters["vendor_product_filter"];
        let matched = vendor_matcher::classify(&document, inventory);
        if inventory["enabled"] == true && matched.is_none() {
            continue;
        }
        let source = document
            .pointer("/source/provider")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        output.push(json!({"collection":name,"source_collection":source,"selection_id":db::id_string(&doc),"vendor_product_match":matched,"document":document}));
        if output.len() >= limit as usize {
            break;
        }
    }
    Ok(output)
}

fn report_preview(matches: &[Value], report: &Value) -> Value {
    let mut confirmed = 0;
    let mut probable = 0;
    let mut possible = 0;
    let mut top = Vec::new();
    let mut examples = Vec::new();
    for row in matches {
        let matched = &row["vendor_product_match"];
        match matched["confidence"].as_str() {
            Some("confirmed") => confirmed += 1,
            Some("probable") => probable += 1,
            Some("possible") => possible += 1,
            _ => (),
        }
        let document = db::json_doc(&row["document"]).unwrap_or_default();
        let cve = reviews::cve_id(&document);
        if !cve.is_empty() && top.len() < 3 && !top.contains(&cve) {
            top.push(cve.clone());
        }
        if !cve.is_empty() && matched.is_object() && examples.len() < 3 {
            let mut example = matched.clone();
            example["cve"] = json!(cve);
            examples.push(example);
        }
    }
    json!({
        "count": matches.len(),
        "confirmed_count": confirmed,
        "probable_count": probable,
        "possible_count": possible,
        "top_cves": top,
        "match_examples": examples,
        "vendor_product_filter_enabled": report["filters"]["vendor_product_filter"]["enabled"] == true,
    })
}
pub async fn handle(state: &AppState, ctx: &ReqCtx) -> Option<Response> {
    if ctx.path == "/subscriptions" && ctx.method == Method::GET {
        return Some(render(state, ctx, "subscriptions/index.html", json!({})));
    }
    if ctx.path == "/api/subscriptions/vendor-product-template.csv" && ctx.method == Method::GET {
        return Some(view::attachment("text/csv; charset=utf-8","vendor_product_filter_template.csv","vendor,product,vendor_aliases,product_aliases\nRed Hat,Enterprise Linux,\"Red Hat, Inc.|RedHat\",RHEL|Red Hat Enterprise Linux\nMicrosoft,Windows Server,Microsoft Corporation,Windows Server 2019|Windows Server 2022\nApache Software Foundation,HTTP Server,Apache|ASF,Apache HTTPD|httpd\n".into()));
    }
    if ctx.path == "/api/subscriptions/vendor-product-import" && ctx.method == Method::POST {
        return Some(vendor_import(ctx).await);
    }
    if ctx.path == "/api/subscriptions/collections" && ctx.method == Method::GET {
        return Some(match collection_rows(state).await {
            Ok(rows) => view::json_response(StatusCode::OK, json!({"data":rows})),
            Err(error) => view::error(StatusCode::SERVICE_UNAVAILABLE, &error),
        });
    }
    if ctx.path == "/api/subscriptions/schema" && ctx.method == Method::GET {
        let rows = match collection_rows(state).await {
            Ok(rows) => rows,
            Err(error) => return Some(view::error(StatusCode::SERVICE_UNAVAILABLE, &error)),
        };
        let names = rows
            .into_iter()
            .filter_map(|row| row["name"].as_str().map(str::to_owned))
            .collect::<Vec<_>>();
        return Some(view::json_response(
            StatusCode::OK,
            json!({"schema_version":1,"subscription":{"fields":["username","emails","cc","bcc","organization"],"delivery_mode":"individual"},"profile_types":["newsletter","report"],"source_providers":names.clone(),"review_collections":names,"filters":{"defaults":default_filters()},"profiles":{"newsletter":{"defaults":default_profile("newsletter")},"report":{"defaults":default_profile("report")}},"vendor_product_filter":{"schema_version":1,"defaults":{"enabled":false,"schema_version":1,"include_possible_matches":false,"rows":[]}},"allowed_values":{"severity":["Critical","High","Medium","Low"],"time_window":["all","daily","week","custom"],"generation_mode":["template","enriched_weekly"],"report_language":["en","zh","ch"]},"limits":{"report_scope_max_count":500,"email_recipients_max_count":50}}),
        ));
    }
    if ctx.path == "/api/organization/subscriptions" && ctx.method == Method::GET {
        if !ctx.is_organization_admin(state) {
            return json_error(
                StatusCode::FORBIDDEN,
                "Organization administrator access required.",
            );
        }
        return Some(match organization_subscription_rows(state, ctx).await {
            Ok(rows) => view::json_response(StatusCode::OK, json!({"data":rows})),
            Err(error) => view::error(StatusCode::SERVICE_UNAVAILABLE, &error),
        });
    }
    if ctx.path == "/api/subscriptions" && ctx.method == Method::GET {
        let Some(filter) = subscription_filter(state, ctx, None).await else {
            return json_error(StatusCode::FORBIDDEN, "Access denied.");
        };
        return Some(
            match db::find_sorted(
                &state.web,
                "sub_account",
                filter,
                doc! {"auto_provisioned": -1, "created_at": 1, "_id": 1},
                5000,
            )
            .await
            {
                Ok(rows) => view::json_response(
                    StatusCode::OK,
                    json!({"data":rows.iter().map(|row| public(row)).collect::<Vec<_>>()}),
                ),
                Err(_) => view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to load subscriptions.",
                ),
            },
        );
    }
    if ctx.path == "/api/subscriptions/preview" && ctx.method == Method::POST {
        let mode = ctx.field("mode");
        if !matches!(mode.as_str(), "create" | "update") {
            return json_error(
                StatusCode::BAD_REQUEST,
                "Preview mode must be create or update.",
            );
        }
        if mode == "create" && !can_manage_subscriptions(state, ctx) && !is_self_manager(state, ctx)
        {
            return json_error(StatusCode::FORBIDDEN, "Access denied.");
        }
        let mut data = ctx.json.clone();
        let mut identifier = String::new();
        if mode == "update" {
            identifier = ctx.field("subscription_id");
            if identifier.is_empty() {
                identifier = ctx.field("id")
            }
            if identifier.is_empty() {
                identifier = ctx.field("email")
            }
            let Some(filter) = subscription_filter(state, ctx, Some(&identifier)).await else {
                return json_error(StatusCode::FORBIDDEN, "Access denied.");
            };
            let Some(existing) = db::find_one(&state.web, "sub_account", filter)
                .await
                .ok()
                .flatten()
            else {
                return json_error(StatusCode::NOT_FOUND, "Subscription not found.");
            };
            let old = db::bson_json(&existing);
            for name in ["newsletter_profile", "report_profile"] {
                if data.get(name).is_none() {
                    data[name] = old.get(name).cloned().unwrap_or(Value::Null)
                }
            }
        }
        let newsletter = match profile(state, "newsletter", &data["newsletter_profile"]).await {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
        };
        let report = match profile(state, "report", &data["report_profile"]).await {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
        };
        return Some(view::json_response(
            StatusCode::OK,
            json!({"valid":true,"mode":mode,"normalized_profiles":{"newsletter_profile":newsletter,"report_profile":report},"newsletter_profile":newsletter,"report_profile":report,"applied_defaults":[],"warnings":[],"subscription_id":identifier}),
        ));
    }
    if ctx.path == "/api/subscriptions/report-preview" && ctx.method == Method::POST {
        let report = match profile(state, "report", &ctx.json["report_profile"]).await {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
        };
        let matches = match match_profile(state, &report, 100).await {
            Ok(matches) => matches,
            Err(error) => return json_error(StatusCode::SERVICE_UNAVAILABLE, &error),
        };
        return Some(view::json_response(
            StatusCode::OK,
            report_preview(&matches, &report),
        ));
    }
    if ctx.path == "/api/subscriptions" && ctx.method == Method::POST {
        let local_subscription = ctx
            .json
            .get("local_subscription")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let self_only = is_self_manager(state, ctx) && !local_subscription;
        if local_subscription && !can_create_local_subscription(state, ctx) {
            return json_error(
                StatusCode::FORBIDDEN,
                "Only an administrator or Zimbra user can create local subscriptions.",
            );
        }
        if !can_manage_subscriptions(state, ctx) && !self_only && !local_subscription {
            return json_error(
                StatusCode::FORBIDDEN,
                "You can only manage your own subscription.",
            );
        }
        if ctx
            .user
            .as_ref()
            .is_some_and(|u| db::string(u, "auth_source") == "zimbra")
            && ctx
                .json
                .get("password")
                .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "Zimbra users do not use local passwords.",
            );
        }
        let self_email = if self_only {
            let Some(user) = ctx.user.as_ref() else {
                return json_error(StatusCode::UNAUTHORIZED, "Authentication required.");
            };
            Some(match self_recipient(user) {
                Ok(email) => email,
                Err(error) => return json_error(StatusCode::BAD_REQUEST, &error),
            })
        } else {
            None
        };
        let submitted_emails = match recipients(&ctx.json) {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
        };
        let copies = match copy_recipients(&ctx.json) {
            Ok(value) => value,
            Err(error) => return json_error(StatusCode::BAD_REQUEST, &error),
        };
        let submitted_username = ctx.field("username");
        let mut username = if local_subscription {
            submitted_username
        } else if submitted_username.trim().is_empty() {
            ctx.field("email")
        } else {
            submitted_username
        };
        let emails = if self_only {
            let Some(user) = ctx.user.as_ref() else {
                return json_error(StatusCode::UNAUTHORIZED, "Authentication required.");
            };
            let current_username = db::string(user, "username");
            if !same_username(&username, &current_username) {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "You can only manage your own subscription.",
                );
            }
            let current_email = self_email.as_deref().unwrap_or("");
            if !is_zimbra_user(ctx)
                && (current_email.is_empty()
                    || submitted_emails.len() != 1
                    || !same_email(&submitted_emails[0], current_email))
            {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "You can only manage your own subscription.",
                );
            }
            username = current_username;
            submitted_emails
        } else {
            submitted_emails
        };
        let submitted_organization = {
            let value = ctx.field("organization");
            if value.trim().is_empty() {
                ctx.field("team")
            } else {
                value
            }
        };
        let organization = if self_only && submitted_organization.trim().is_empty() {
            ctx.user
                .as_ref()
                .map(|user| db::string(user, "zimbra_organization"))
                .unwrap_or_default()
        } else {
            submitted_organization
        };
        if username.trim().is_empty()
            || (!self_only && !local_subscription && organization.trim().is_empty())
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "Username, email, and organization are required.",
            );
        }
        let mode = "individual";
        let newsletter = match profile(state, "newsletter", &ctx.json["newsletter_profile"]).await {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
        };
        let report = match profile(state, "report", &ctx.json["report_profile"]).await {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
        };
        if self_only {
            let Some(owner_id) = ctx.user_id() else {
                return json_error(StatusCode::UNAUTHORIZED, "Authentication required.");
            };
            let duplicate_filter = doc! {
                "owner_user_id": owner_id,
                "local_subscription": {"$ne": true},
                "emails": emails.clone(),
                "newsletter_profile": db::json_doc(&newsletter).unwrap_or_default(),
                "report_profile": db::json_doc(&report).unwrap_or_default(),
            };
            match db::collection(&state.web, "sub_account")
                .find_one(duplicate_filter)
                .await
            {
                Ok(Some(_)) => {
                    return json_error(
                        StatusCode::CONFLICT,
                        "An identical subscription already exists. Edit the existing subscription instead.",
                    );
                }
                Ok(None) => {}
                Err(_) => {
                    return json_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Unable to check existing subscriptions.",
                    );
                }
            }
        }
        if local_subscription {
            let Some(manager) = ctx.user.as_ref() else {
                return json_error(StatusCode::UNAUTHORIZED, "Authentication required.");
            };
            // Local subscriptions are owned by the account that creates them.
            // Keep the organization as optional display metadata only; it is
            // not used to authorize or scope the subscription.
            let local_organization = if organization.trim().is_empty() {
                let value = organization_name(manager);
                if value.is_empty() {
                    "local".to_owned()
                } else {
                    value
                }
            } else {
                organization.trim().to_owned()
            };
            let existing = db::find_one(
                &state.web,
                "sub_account",
                doc! {
                    "username": {
                        "$regex": format!("^{}$", regex::escape(username.trim())),
                        "$options": "i"
                    }
                },
            )
            .await
            .ok()
            .flatten();
            if existing.is_some() {
                return json_error(
                    StatusCode::CONFLICT,
                    "A subscription already exists for this username.",
                );
            }
            let now = bson::DateTime::now();
            let document = doc! {
                "managed_by_user_id": ctx.user_id().unwrap(),
                "local_subscription": true,
                "username": username.trim(),
                "emails": emails.clone(),
                "email": &emails[0],
                "cc": copies.cc.clone(),
                "bcc": copies.bcc.clone(),
                "organization": &local_organization,
                "delivery_mode": "individual",
                "auto_provisioned": false,
                "newsletter_profile": db::json_doc(&newsletter).unwrap(),
                "report_profile": db::json_doc(&report).unwrap(),
                "created_at": now,
                "updated_at": now,
            };
            return Some(
                match db::collection(&state.web, "sub_account")
                    .insert_one(document)
                    .await
                {
                    Ok(v) => {
                        if let Err(error) = notify(
                            state,
                            &emails,
                            &copies,
                            "created",
                            username.trim(),
                            &local_organization,
                            &newsletter,
                            &report,
                        )
                        .await
                        {
                            notification_delivery_error("saved", &error)
                        } else {
                            view::json_response(
                                StatusCode::CREATED,
                                json!({"success":true,"id":v.inserted_id.as_object_id().map(|id|id.to_hex()).unwrap_or_default()}),
                            )
                        }
                    }
                    Err(_) => view::error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Unable to add subscription.",
                    ),
                },
            );
        }
        let users = db::collection(&state.web, &state.cfg.account_collection);
        let owner = users
            .find_one(doc! {"username_key":username.trim().to_lowercase()})
            .await
            .ok()
            .flatten();
        if self_only && owner.is_none() {
            return json_error(
                StatusCode::FORBIDDEN,
                "You can only manage your own subscription.",
            );
        }
        if ctx.is_organization_admin(state) {
            let Some(member) = owner.as_ref() else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "Zimbra user must be approved before creating a subscription.",
                );
            };
            if db::string(member, "auth_source") != "zimbra"
                || !ctx
                    .user
                    .as_ref()
                    .is_some_and(|manager| crate::auth::same_organization(manager, member))
            {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "You can only manage members of your organization.",
                );
            }
        }
        if let Some(owner) = owner.as_ref() {
            if let Err(error) = zimbra_recipient(owner) {
                return json_error(StatusCode::BAD_REQUEST, &error);
            }
        }
        let existing=db::find_one(&state.web,"sub_account",doc!{"username":{"$regex":format!("^{}$",regex::escape(username.trim())),"$options":"i"}}).await.ok().flatten();
        if existing.is_some() && !self_only {
            return json_error(
                StatusCode::CONFLICT,
                "A subscription already exists for this username.",
            );
        }
        let owner_zimbra_email = owner.as_ref().and_then(auth::zimbra_email);
        let owner_id = if let Some(owner) = owner {
            if self_only && ctx.user_id() != owner.get_object_id("_id").ok() {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "You can only manage your own subscription.",
                );
            }
            let zimbra_member =
                ctx.is_organization_admin(state) && db::string(&owner, "auth_source") == "zimbra";
            if db::string(&owner, "role") != "user" && !zimbra_member {
                return json_error(
                    StatusCode::CONFLICT,
                    "Username is already used by the administrator.",
                );
            }
            owner.get_object_id("_id").unwrap()
        } else {
            return json_error(
                StatusCode::BAD_REQUEST,
                "The recipient must first sign in with Zimbra.",
            );
        };
        let now = bson::DateTime::now();
        let mut document = doc! {"owner_user_id":owner_id,"managed_by_user_id":ctx.user_id().unwrap(),"username":username.trim(),"emails":emails.clone(),"email":&emails[0],"organization":organization.trim(),"delivery_mode":mode,"auto_provisioned":false,"newsletter_profile":db::json_doc(&newsletter).unwrap(),"report_profile":db::json_doc(&report).unwrap(),"created_at":now,"updated_at":now};
        document.insert("cc", copies.cc.clone());
        document.insert("bcc", copies.bcc.clone());
        if let Some(email) = owner_zimbra_email {
            document.insert("zimbra_email", email);
        }
        return Some(
            match db::collection(&state.web, "sub_account")
                .insert_one(document)
                .await
            {
                Ok(v) => {
                    if let Err(error) = notify(
                        state,
                        &emails,
                        &copies,
                        "created",
                        &username,
                        &organization,
                        &newsletter,
                        &report,
                    )
                    .await
                    {
                        notification_delivery_error("saved", &error)
                    } else {
                        view::json_response(
                            StatusCode::CREATED,
                            json!({"success":true,"id":v.inserted_id.as_object_id().map(|id|id.to_hex()).unwrap_or_default()}),
                        )
                    }
                }
                Err(_) => view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to add subscription.",
                ),
            },
        );
    }
    if let Some(tail) = ctx.path.strip_prefix("/api/subscriptions/") {
        let (identifier, action) = tail.split_once('/').unwrap_or((tail, ""));
        let Some(filter) = subscription_filter(state, ctx, Some(identifier)).await else {
            return json_error(StatusCode::FORBIDDEN, "Access denied.");
        };
        let coll = db::collection(&state.web, "sub_account");
        let Some(existing) = coll.find_one(filter).await.ok().flatten() else {
            return json_error(StatusCode::NOT_FOUND, "Subscription not found.");
        };
        let id = existing.get_object_id("_id").unwrap();
        if action == "vendor-products.csv" && ctx.method == Method::GET {
            let requested = ctx.arg("profile");
            let profile_name = if requested.is_empty() {
                "report"
            } else {
                &requested
            };
            return Some(
                match vendor_product_csv(&db::bson_json(&existing), profile_name) {
                    Ok(csv) => {
                        let filename =
                            format!("subscription_{}_{profile_name}_inventory.csv", id.to_hex());
                        let mut response =
                            view::attachment("text/csv; charset=utf-8", &filename, csv);
                        response
                            .headers_mut()
                            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
                        response
                    }
                    Err(error) => view::error(StatusCode::BAD_REQUEST, &error),
                },
            );
        }
        if action == "run" && ctx.method == Method::POST {
            let old = db::bson_json(&existing);
            if old["report_profile"]["enabled"] != true {
                return json_error(StatusCode::BAD_REQUEST, "Report profile is disabled.");
            };
            let matches = match match_profile(state, &old["report_profile"], 500).await {
                Ok(matches) => matches,
                Err(error) => return json_error(StatusCode::SERVICE_UNAVAILABLE, &error),
            };
            let selections: Vec<Value> = matches
                .iter()
                .map(|v| json!({"collection":v["collection"],"selection_id":v["selection_id"]}))
                .collect();
            return Some(view::json_response(
                StatusCode::OK,
                json!({"selections":selections,"count":selections.len()}),
            ));
        }
        if action == "statistic-preview" && ctx.method == Method::GET {
            return Some(
                match newsletter_statistics::preview(state, &existing).await {
                    Ok(html) => {
                        let mut response = axum::response::Html(html).into_response();
                        response
                            .headers_mut()
                            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
                        response
                    }
                    Err(error) => view::error(StatusCode::SERVICE_UNAVAILABLE, &error),
                },
            );
        }
        if action == "send-statistic" && ctx.method == Method::POST {
            let sub = db::bson_json(&existing);
            if sub["newsletter_profile"]["enabled"] != true {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "Newsletter feed is disabled for this subscription.",
                );
            }
            return Some(
                match newsletter_statistics::send(state, &existing, false).await {
                    Ok(stats) => view::json_response(
                        StatusCode::OK,
                        json!({"success":true,"message":"Monthly newsletter statistics email sent.","statistics":stats}),
                    ),
                    Err(e) => view::error(StatusCode::BAD_GATEWAY, &e),
                },
            );
        }
        if action.is_empty() && ctx.method == Method::DELETE {
            if is_self_manager(state, ctx) && db::bool_field(&existing, "auto_provisioned") {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "The automatic Zimbra subscription cannot be deleted.",
                );
            }
            if ctx.is_organization_admin(state) && !db::bool_field(&existing, "local_subscription")
            {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "Zimbra subscriptions cannot be deleted by an organization administrator.",
                );
            }
            let old = db::bson_json(&existing);
            let emails = recipients(&old).unwrap_or_default();
            let copies = match copy_recipients(&old) {
                Ok(value) => value,
                Err(error) => return json_error(StatusCode::BAD_REQUEST, &error),
            };
            let username = old["username"].as_str().unwrap_or("");
            let organization = subscription_organization(&old);
            return Some(match coll.delete_one(doc! {"_id":id}).await {
                Ok(_) => {
                    if let Err(error) = notify(
                        state,
                        &emails,
                        &copies,
                        "cancelled",
                        username,
                        organization,
                        &old["newsletter_profile"],
                        &old["report_profile"],
                    )
                    .await
                    {
                        notification_delivery_error("cancelled", &error)
                    } else {
                        view::json_response(StatusCode::OK, json!({"success":true}))
                    }
                }
                Err(_) => view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to remove subscription.",
                ),
            });
        }
        if action.is_empty() && ctx.method == Method::PUT {
            let local_subscription = db::bool_field(&existing, "local_subscription");
            if ctx
                .json
                .get("local_subscription")
                .and_then(Value::as_bool)
                .is_some_and(|value| value)
                && !local_subscription
            {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "Zimbra subscriptions cannot be converted to local subscriptions.",
                );
            }
            if local_subscription
                && !ctx.is_top_admin(state)
                && !owns_local_subscription(ctx, &existing)
            {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "Only the administrator or Zimbra user who created this subscription can edit it.",
                );
            }
            if !can_manage_subscriptions(state, ctx)
                && !local_subscription
                && (["username", "password"]
                    .iter()
                    .any(|key| ctx.json.get(*key).is_some())
                    || (!is_zimbra_user(ctx)
                        && ["emails", "email"]
                            .iter()
                            .any(|key| ctx.json.get(*key).is_some())))
            {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "Only an administrator can edit subscription identity fields.",
                );
            }
            let owner = if local_subscription {
                None
            } else if let Ok(owner_id) = existing.get_object_id("owner_user_id") {
                db::find_one(
                    &state.web,
                    &state.cfg.account_collection,
                    doc! {"_id":owner_id},
                )
                .await
                .ok()
                .flatten()
            } else if is_self_manager(state, ctx) {
                ctx.user.clone()
            } else {
                let username = db::string(&existing, "username");
                if username.trim().is_empty() {
                    None
                } else {
                    db::find_one(
                        &state.web,
                        &state.cfg.account_collection,
                        doc! {"username_key":username.trim().to_lowercase()},
                    )
                    .await
                    .ok()
                    .flatten()
                }
            };
            let mut data = db::bson_json(&existing);
            merge(&mut data, &ctx.json);
            if ctx.json.get("emails").is_none()
                && let Some(email) = ctx.json.get("email").and_then(Value::as_str)
            {
                data["emails"] = json!([email]);
            }
            if ctx.json.get("organization").is_none()
                && let Some(organization) = ctx.json.get("team").and_then(Value::as_str)
            {
                data["organization"] = json!(organization);
            }
            if data
                .get("organization")
                .and_then(Value::as_str)
                .is_none_or(|value| value.trim().is_empty())
                && let Some(organization) = data.get("team").and_then(Value::as_str)
            {
                data["organization"] = json!(organization);
            }
            let emails = match recipients(&data) {
                Ok(v) => v,
                Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
            };
            let copies = match copy_recipients(&data) {
                Ok(value) => value,
                Err(error) => return json_error(StatusCode::BAD_REQUEST, &error),
            };
            let newsletter = match profile(state, "newsletter", &data["newsletter_profile"]).await {
                Ok(v) => v,
                Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
            };
            let report = match profile(state, "report", &data["report_profile"]).await {
                Ok(v) => v,
                Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
            };
            let username = data["username"].as_str().unwrap_or("").trim();
            let organization = data["organization"].as_str().unwrap_or("").trim();
            if username.is_empty()
                || (!local_subscription && !is_self_manager(state, ctx) && organization.is_empty())
            {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "Username and organization are required.",
                );
            }
            let mode = "individual";
            let identity_change = !local_subscription
                && ctx.is_organization_admin(state)
                && ctx.json.get("username").is_some();
            let current_owner_hub_email = if identity_change {
                None
            } else if let Some(owner) = owner.as_ref() {
                match zimbra_recipient(owner) {
                    Ok(email) => email,
                    Err(error) => return json_error(StatusCode::BAD_REQUEST, &error),
                }
            } else {
                None
            };
            if is_self_manager(state, ctx) && !local_subscription {
                let Some(owner_id) = ctx.user_id() else {
                    return json_error(StatusCode::UNAUTHORIZED, "Authentication required.");
                };
                let duplicate_filter = doc! {
                    "owner_user_id": owner_id,
                    "_id": {"$ne": id},
                    "local_subscription": {"$ne": true},
                    "emails": emails.clone(),
                    "newsletter_profile": db::json_doc(&newsletter).unwrap_or_default(),
                    "report_profile": db::json_doc(&report).unwrap_or_default(),
                };
                match coll.find_one(duplicate_filter).await {
                    Ok(Some(_)) => {
                        return json_error(
                            StatusCode::CONFLICT,
                            "An identical subscription already exists. Edit the existing subscription instead.",
                        );
                    }
                    Ok(None) => {}
                    Err(_) => {
                        return json_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Unable to check existing subscriptions.",
                        );
                    }
                }
            }
            let mut update = doc! {"username":username,"email":&emails[0],"emails":emails.clone(),"organization":organization,"delivery_mode":mode,"newsletter_profile":db::json_doc(&newsletter).unwrap(),"report_profile":db::json_doc(&report).unwrap(),"updated_at":bson::DateTime::now()};
            update.insert("cc", copies.cc.clone());
            update.insert("bcc", copies.bcc.clone());
            if let Some(zimbra_email) = current_owner_hub_email.as_ref() {
                update.insert("zimbra_email", zimbra_email.clone());
            }
            if identity_change {
                let Some(manager) = ctx.user.as_ref() else {
                    return json_error(StatusCode::UNAUTHORIZED, "Authentication required.");
                };
                let Some(member) = db::find_one(
                    &state.web,
                    &state.cfg.account_collection,
                    doc! {"username_key":username.to_lowercase()},
                )
                .await
                .ok()
                .flatten() else {
                    return json_error(
                        StatusCode::FORBIDDEN,
                        "You can only manage members of your organization.",
                    );
                };
                let Some(member_id) = member.get_object_id("_id").ok() else {
                    return json_error(StatusCode::FORBIDDEN, "Subscription owner is invalid.");
                };
                if db::string(&member, "auth_source") != "zimbra"
                    || !crate::auth::same_organization(manager, &member)
                {
                    return json_error(
                        StatusCode::FORBIDDEN,
                        "You can only manage members of your organization.",
                    );
                }
                let current_owner = existing.get_object_id("owner_user_id").ok();
                if current_owner != Some(member_id)
                    && coll
                        .find_one(doc! {"owner_user_id":member_id})
                        .await
                        .ok()
                        .flatten()
                        .is_some()
                {
                    return json_error(
                        StatusCode::CONFLICT,
                        "A subscription already exists for this username.",
                    );
                }
                let zimbra_email = match zimbra_recipient(&member) {
                    Ok(email) => email,
                    Err(error) => return json_error(StatusCode::BAD_REQUEST, &error),
                };
                let Some(zimbra_email) = zimbra_email else {
                    return json_error(
                        StatusCode::BAD_REQUEST,
                        "Zimbra email is unavailable. Ask the user to sign in again.",
                    );
                };
                update.insert("owner_user_id", member_id);
                update.insert("username", db::string(&member, "username"));
                update.insert("zimbra_email", zimbra_email);
            }
            let mut unset = doc! {"team":""};
            if local_subscription {
                update.insert("local_subscription", true);
                update.insert("managed_by_user_id", ctx.user_id().unwrap());
                // Ownership is the creator account. An organization value is
                // optional display metadata and must never restrict access.
                unset.insert("organization_id", "");
                unset.insert("owner_user_id", "");
                unset.insert("zimbra_email", "");
            } else if current_owner_hub_email.is_none() && !identity_change {
                unset.insert("zimbra_email", "");
            }
            return Some(
                match coll
                    .update_one(doc! {"_id":id}, doc! {"$set":update,"$unset":unset})
                    .await
                {
                    Ok(_) => {
                        let changed = ctx.json.get("username").is_some()
                            || ctx.json.get("email").is_some()
                            || ctx.json.get("newsletter_profile").is_some()
                            || ctx.json.get("report_profile").is_some()
                            || ctx.json.get("emails").is_some()
                            || ctx.json.get("cc").is_some()
                            || ctx.json.get("bcc").is_some()
                            || ctx.json.get("organization").is_some()
                            || ctx.json.get("team").is_some();
                        let notification_error = if changed {
                            notify(
                                state,
                                &emails,
                                &copies,
                                "updated",
                                username,
                                organization,
                                &newsletter,
                                &report,
                            )
                            .await
                            .err()
                        } else {
                            None
                        };
                        if let Some(error) = notification_error {
                            notification_delivery_error("updated", &error)
                        } else {
                            view::json_response(StatusCode::OK, json!({"success":true}))
                        }
                    }
                    Err(_) => view::error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Unable to update subscription.",
                    ),
                },
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::oid::ObjectId;

    #[test]
    fn copy_recipients_default_empty_and_normalize_across_recipient_groups() {
        assert_eq!(
            copy_recipients(&json!({"email":"owner@example.com"})).unwrap(),
            mail::CopyRecipients::default()
        );
        let copies = copy_recipients(&json!({
            "emails":["Owner@Example.com"],
            "cc":[" owner@example.com ","COPY@example.com","copy@example.com"],
            "bcc":["copy@example.com"," Hidden@Example.com "]
        }))
        .unwrap();
        assert_eq!(copies.cc, ["copy@example.com"]);
        assert_eq!(copies.bcc, ["hidden@example.com"]);
    }

    #[test]
    fn invalid_copy_recipients_are_rejected_before_saving() {
        for invalid in [
            json!("copy@example.com"),
            json!([7]),
            json!([""]),
            json!(["bad"]),
            json!(["copy@example.com\r\nBcc: bad@example.com"]),
        ] {
            for key in ["cc", "bcc"] {
                let mut data = json!({"emails":["owner@example.com"]});
                data[key] = invalid.clone();
                assert!(copy_recipients(&data).is_err(), "{key}: {invalid}");
            }
        }
        let mut data = json!({"emails":["owner@example.com"], "cc":[]});
        data["bcc"] = json!(
            (0..50)
                .map(|n| format!("copy{n}@example.com"))
                .collect::<Vec<_>>()
        );
        assert!(copy_recipients(&data).is_err());
    }

    #[test]
    fn copy_updates_preserve_omitted_lists_and_allow_clearing() {
        let mut data = json!({"emails":["owner@example.com"],"cc":["copy@example.com"],"bcc":["hidden@example.com"]});
        merge(&mut data, &json!({"cc":[]}));
        let copies = copy_recipients(&data).unwrap();
        assert!(copies.cc.is_empty());
        assert_eq!(copies.bcc, ["hidden@example.com"]);
    }

    #[test]
    fn configured_copy_recipients_prevent_default_subscription_cleanup() {
        let owner = ObjectId::new();
        let mut row = default_zimbra_subscription_document(
            &doc! {"username":"owner"},
            owner,
            "owner@example.com",
            bson::DateTime::now(),
        );
        assert!(is_default_zimbra_subscription(&row));
        let default = row.clone();
        row.insert("cc", vec!["copy@example.com"]);
        assert!(!is_default_zimbra_subscription(&row));
        assert!(!same_subscription_identity(&row, &default));
    }

    #[test]
    fn inventory_csv_preserves_quotes_unicode_aliases_and_profile_scope() {
        let data = json!({
            "newsletter_profile":{"filters":{"vendor_product_filter":{"rows":[{"vendor":"Newsletter vendor","product":"Other","vendor_aliases":[],"product_aliases":[]}]}}},
            "report_profile":{"filters":{"vendor_product_filter":{"rows":[{"vendor":"Acme, Inc.","product":"安全 \"Server\"\nEdition","vendor_aliases":["Acme","Acme Corp"],"product_aliases":["Server 2026"]}]}}}
        });
        let output = vendor_product_csv(&data, "report").unwrap();
        let mut csv = csv::Reader::from_reader(output.as_bytes());
        assert_eq!(
            csv.headers().unwrap().iter().collect::<Vec<_>>(),
            ["vendor", "product", "vendor_aliases", "product_aliases"]
        );
        let rows = csv.records().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(&rows[0][0], "Acme, Inc.");
        assert_eq!(&rows[0][1], "安全 \"Server\"\nEdition");
        assert_eq!(&rows[0][2], "Acme|Acme Corp");
        assert!(!output.contains("Newsletter vendor"));
        assert!(
            vendor_product_csv(&data, "newsletter")
                .unwrap()
                .contains("Newsletter vendor")
        );
        assert!(vendor_product_csv(&data, "other").is_err());
        assert_eq!(
            vendor_product_csv(&json!({}), "report").unwrap(),
            "vendor,product,vendor_aliases,product_aliases\n"
        );
    }

    #[tokio::test]
    #[ignore = "requires SUBSCRIPTION_TEST_MONGO_URI for a disposable database"]
    async fn inventory_download_is_scoped_to_subscription_owner() {
        use std::{path::PathBuf, sync::Arc};
        let uri = std::env::var("SUBSCRIPTION_TEST_MONGO_URI").unwrap();
        let client = mongodb::Client::with_uri_str(&uri).await.unwrap();
        let database = client.database(&format!(
            "subscription_download_test_{}",
            ObjectId::new().to_hex()
        ));
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cfg = crate::config::Config {
            root: root.clone(),
            file: json!({}),
            mongo_uri: uri,
            web_database: database.name().into(),
            vulnerabilities_database: database.name().into(),
            vulnerabilities_collection: "test_news".into(),
            secret: "test".into(),
            bootstrap_username: "test-admin".into(),
            bootstrap_password: String::new(),
            zimbra_base_url: String::new(),
            zimbra_folder_name: "news".into(),
            zimbra_timeout_seconds: 1,
            zimbra_verify_tls: true,
            zimbra_credential_key: String::new(),
            account_collection: "accounts".into(),
            newsletter_root: root.join("newsletters"),
            port: 0,
        };
        let state = AppState {
            cfg,
            web: database.clone(),
            vuln: database.clone(),
            templates: Arc::new(crate::view::environment(&root)),
            http: reqwest::Client::new(),
        };
        let owner = ObjectId::new();
        let stranger = ObjectId::new();
        let id = ObjectId::new();
        db::collection(&database,"sub_account").insert_one(doc!{
            "_id":id, "owner_user_id":owner, "emails":["owner@example.com"],
            "report_profile":{"filters":{"vendor_product_filter":{"rows":[{"vendor":"Owner vendor","product":"Private product"}]}}}
        }).await.unwrap();
        let mut ctx = ReqCtx {
            method: Method::GET,
            path: format!("/api/subscriptions/{}/vendor-products.csv", id.to_hex()),
            query: vec![("profile".into(), "report".into())],
            headers: Default::default(),
            body: vec![],
            json: Value::Null,
            form: Default::default(),
            user: Some(doc! {"_id":owner,"username":"owner","auth_source":"zimbra","role":"user"}),
        };
        let response = handle(&state, &ctx).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/csv; charset=utf-8"
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(
            response.headers()[header::CONTENT_DISPOSITION]
                .to_str()
                .unwrap()
                .contains("_report_inventory.csv")
        );
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert!(
            String::from_utf8(body.to_vec())
                .unwrap()
                .contains("Private product")
        );
        ctx.user =
            Some(doc! {"_id":stranger,"username":"stranger","auth_source":"zimbra","role":"user"});
        assert_eq!(
            handle(&state, &ctx).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        ctx.user = None;
        assert_eq!(
            handle(&state, &ctx).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        database.drop().await.unwrap();
    }

    #[test]
    fn new_profiles_start_without_selected_collections() {
        let filters = default_filters();
        assert_eq!(filters["collections"], json!([]));
        assert_eq!(filters["collections_mode"], "selected");
    }

    #[tokio::test]
    #[ignore = "requires SUBSCRIPTION_TEST_MONGO_URI and no SMTP_HOST"]
    async fn zimbra_owner_can_change_delivery_recipients_and_login_preserves_them() {
        use std::{path::PathBuf, sync::Arc};
        // Subscription writes still report notification errors. Keep this test
        // offline for SMTP, and inspect the saved data after that expected error.
        assert!(std::env::var_os("SMTP_HOST").is_none());
        let uri = std::env::var("SUBSCRIPTION_TEST_MONGO_URI").unwrap();
        let client = mongodb::Client::with_uri_str(&uri).await.unwrap();
        let database = client.database(&format!(
            "zimbra_recipients_test_{}",
            ObjectId::new().to_hex()
        ));
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cfg = crate::config::Config {
            root: root.clone(),
            file: json!({}),
            mongo_uri: uri,
            web_database: database.name().into(),
            vulnerabilities_database: database.name().into(),
            vulnerabilities_collection: "test_news".into(),
            secret: "test".into(),
            bootstrap_username: "test-admin".into(),
            bootstrap_password: String::new(),
            zimbra_base_url: String::new(),
            zimbra_folder_name: "news".into(),
            zimbra_timeout_seconds: 1,
            zimbra_verify_tls: true,
            zimbra_credential_key: String::new(),
            account_collection: "accounts".into(),
            newsletter_root: root.join("newsletters"),
            port: 0,
        };
        let state = AppState {
            cfg,
            web: database.clone(),
            vuln: database.clone(),
            templates: Arc::new(crate::view::environment(&root)),
            http: reqwest::Client::new(),
        };
        let owner = ObjectId::new();
        let user = doc! {"_id":owner,"username":"owner","username_key":"owner","email":"owner@example.test","zimbra_email":"owner@example.test","auth_source":"zimbra","role":"user","organization":"Team"};
        db::collection(&database, "accounts")
            .insert_one(user.clone())
            .await
            .unwrap();
        db::collection(&database, "source_catalog")
            .insert_one(doc! {"_id":"active","providers":["cve"]})
            .await
            .unwrap();
        ensure_zimbra_subscription(&state, &user).await.unwrap();
        let subscriptions = db::collection(&database, "sub_account");
        let automatic = subscriptions
            .find_one(doc! {"owner_user_id":owner,"auto_provisioned":true})
            .await
            .unwrap()
            .unwrap();
        let id = automatic.get_object_id("_id").unwrap();
        let mut ctx = ReqCtx {
            method: Method::PUT,
            path: format!("/api/subscriptions/{}", id.to_hex()),
            query: vec![],
            headers: Default::default(),
            body: vec![],
            form: Default::default(),
            user: Some(user.clone()),
            json: json!({"emails":["External@Example.test","team@example.test"],"cc":["copy@example.test"],"bcc":["hidden@example.test"]}),
        };
        let response = handle(&state, &ctx).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let response_body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert!(
            String::from_utf8(response_body.to_vec())
                .unwrap()
                .contains("SMTP_HOST is required")
        );
        ensure_zimbra_subscription(&state, &user).await.unwrap();
        ensure_zimbra_subscriptions(&state).await.unwrap();
        let saved = subscriptions
            .find_one(doc! {"_id":id})
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            recipients(&db::bson_json(&saved)).unwrap(),
            ["external@example.test", "team@example.test"]
        );
        assert_eq!(saved.get_str("zimbra_email").unwrap(), "owner@example.test");
        assert_eq!(saved.get_object_id("owner_user_id").unwrap(), owner);
        assert_eq!(
            copy_recipients(&db::bson_json(&saved)).unwrap().bcc,
            ["hidden@example.test"]
        );

        ctx.json = json!({"emails":[]});
        assert_eq!(
            handle(&state, &ctx).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        ctx.json = json!({"username":"different-owner","emails":["other@example.test"]});
        assert_eq!(
            handle(&state, &ctx).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        ctx.json = json!({"email":"replacement@example.test"});
        assert_eq!(
            handle(&state, &ctx).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let saved = subscriptions
            .find_one(doc! {"_id":id})
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            recipients(&db::bson_json(&saved)).unwrap(),
            ["replacement@example.test"]
        );

        ctx.user = Some(
            doc! {"_id":ObjectId::new(),"username":"stranger","auth_source":"zimbra","role":"user"},
        );
        ctx.json = json!({"emails":["stranger@example.test"]});
        assert_eq!(
            handle(&state, &ctx).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        ctx.user = Some(user.clone());
        ctx.method = Method::POST;
        ctx.path = "/api/subscriptions".into();
        ctx.json = json!({"username":"owner","emails":["new.external@example.test"],"newsletter_profile":default_profile("newsletter"),"report_profile":default_profile("report")});
        assert_eq!(
            handle(&state, &ctx).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        ensure_zimbra_subscription(&state, &user).await.unwrap();
        assert_eq!(
            subscriptions
                .count_documents(
                    doc! {"owner_user_id":owner,"emails":["new.external@example.test"]}
                )
                .await
                .unwrap(),
            1
        );
        database.drop().await.unwrap();
    }

    #[test]
    fn reports_default_to_cve_without_changing_newsletter_selection() {
        let report = default_profile("report");
        assert_eq!(
            selected_provider_names(&report["filters"], "news"),
            vec!["cve"]
        );
        assert_eq!(
            default_profile("newsletter")["filters"]["collections"],
            json!([])
        );
    }

    #[test]
    fn report_scope_repairs_saved_empty_template_selection() {
        let mut report = default_profile("report");
        report["filters"] = default_filters();
        let filters = report_filters(&report, "custom_news");
        assert_eq!(filters["collections"], json!(["custom_news"]));
        assert_eq!(filters["sources"], json!(["cve"]));
        let query = profile_filter(&filters, "custom_news");
        let clauses = query.get_array("$and").unwrap();
        assert_eq!(
            clauses[0],
            Bson::Document(doc! {"source.provider":{"$in":["cve"]}})
        );
    }

    #[test]
    fn template_preserves_explicit_scope_and_enriched_reports_use_cve() {
        let mut report = default_profile("report");
        report["filters"]["collections"] = json!(["nvd_review"]);
        assert_eq!(
            selected_provider_names(&report_filters(&report, "news"), "news"),
            vec!["nvd"]
        );
        report["generation_mode"] = json!("enriched_weekly");
        assert_eq!(
            selected_provider_names(&report_filters(&report, "news"), "news"),
            vec!["cve"]
        );
    }

    fn inventory_report() -> Value {
        let mut report = default_profile("report");
        report["enabled"] = json!(true);
        report["filters"]["vendor_product_filter"] = json!({
            "enabled": true,
            "schema_version": 1,
            "include_possible_matches": true,
            "rows": [{"vendor":"Acme","product":"Widget","vendor_aliases":[],"product_aliases":[],"row_number":2}]
        });
        report
    }

    #[test]
    fn preview_returns_real_cve_ids_counts_and_inventory_evidence() {
        let report = inventory_report();
        let documents = [
            json!({"_id":{"$oid":"000000000000000000000001"},"code":"2026-10001","details":{"affected":[{"vendor":"Acme","product":"Widget"}]}}),
            json!({"_id":"provider:2","cve_ids":["CVE-2026-10002"],"description":"Acme Widget has a vulnerability"}),
            json!({"_id":"provider:3","details":{"cve_id":"CVE-2026-10003","affected":[{"product":"Widget"}]}}),
        ];
        let matches = documents.iter().map(|document| json!({
            "selection_id": document["_id"],
            "document": document,
            "vendor_product_match": vendor_matcher::classify(document, &report["filters"]["vendor_product_filter"]),
        })).collect::<Vec<_>>();
        let preview = report_preview(&matches, &report);
        assert_eq!(preview["count"], 3);
        assert_eq!(preview["confirmed_count"], 1);
        assert_eq!(preview["probable_count"], 1);
        assert_eq!(preview["possible_count"], 1);
        assert_eq!(
            preview["top_cves"],
            json!(["CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10003"])
        );
        assert_eq!(preview["match_examples"].as_array().unwrap().len(), 3);
        assert_eq!(preview["match_examples"][0]["matched_vendor"], "Acme");
        assert_eq!(
            preview["match_examples"][0]["evidence"]["source"],
            "details.affected[0]"
        );
        assert_eq!(preview["match_examples"][0]["row_number"], 2);
        assert_eq!(report_preview(&[], &report)["confirmed_count"], 0);
    }

    #[tokio::test]
    #[ignore = "requires REPORT_TEST_MONGO_URI pointing to a disposable local MongoDB"]
    async fn preview_matches_inventory_beyond_ten_thousand_candidates() {
        use std::{path::PathBuf, sync::Arc};
        let uri = std::env::var("REPORT_TEST_MONGO_URI").expect("Set REPORT_TEST_MONGO_URI");
        let client = mongodb::Client::with_uri_str(&uri).await.unwrap();
        let database =
            client.database(&format!("report_preview_test_{}", ObjectId::new().to_hex()));
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cfg = crate::config::Config {
            root: root.clone(),
            file: json!({}),
            mongo_uri: uri,
            web_database: database.name().into(),
            vulnerabilities_database: database.name().into(),
            vulnerabilities_collection: "test_news".into(),
            secret: "test".into(),
            bootstrap_username: "test".into(),
            bootstrap_password: String::new(),
            zimbra_base_url: String::new(),
            zimbra_folder_name: "news".into(),
            zimbra_timeout_seconds: 1,
            zimbra_verify_tls: true,
            zimbra_credential_key: String::new(),
            account_collection: "accounts".into(),
            newsletter_root: root.join("newsletters"),
            port: 0,
        };
        let state = AppState {
            cfg,
            web: database.clone(),
            vuln: database.clone(),
            templates: Arc::new(view::environment(&root)),
            http: reqwest::Client::new(),
        };
        db::collection(&database, "source_catalog")
            .insert_one(doc! {"_id":"active","providers":["nvd","cve"]})
            .await
            .unwrap();
        let news = db::collection(&database, "test_news");
        let unrelated = (0..10_001).map(|index| doc! {
            "code":format!("CVE-2026-{}", 20000 + index), "severity":"High", "source":{"provider":"cve"},
            "observed_at":bson::DateTime::from_millis(2000),
            "details":{"affected":[{"vendor":"Other","product":"Unrelated"}]},
        });
        news.insert_many(unrelated).await.unwrap();
        news.insert_many([
            doc! {"code":"CVE-2026-10001","severity":"High","source":{"provider":"cve"},"observed_at":bson::DateTime::from_millis(1000),"details":{"affected":[{"vendor":"Acme","product":"Widget"}]}},
            doc! {"code":"CVE-2026-10002","severity":"High","source":{"provider":"cve"},"observed_at":bson::DateTime::from_millis(999),"description":"Acme Widget has a vulnerability"},
            doc! {"code":"CVE-2026-10003","severity":"High","source":{"provider":"cve"},"observed_at":bson::DateTime::from_millis(998),"details":{"affected":[{"product":"Widget"}]}},
            doc! {"code":"CVE-2026-10004","severity":"High","source":{"provider":"nvd"},"observed_at":bson::DateTime::from_millis(3000),"details":{"affected":[{"vendor":"Acme","product":"Widget"}]}},
        ]).await.unwrap();

        // Reproduce both the old form payload (no source) and an already-saved
        // profile with an explicit empty selection.
        let mut report = inventory_report();
        report["filters"]["collections"] = json!([]);
        report["filters"]["sources"] = json!([]);
        assert_eq!(match_profile(&state, &report, 100).await.unwrap().len(), 3);
        assert_eq!(match_profile(&state, &report, 1).await.unwrap().len(), 1);
        report["filters"]
            .as_object_mut()
            .unwrap()
            .remove("collections");
        report["filters"].as_object_mut().unwrap().remove("sources");
        for mode in ["template", "enriched_weekly"] {
            let mut ctx = ReqCtx {
                method: Method::POST,
                path: "/api/subscriptions/report-preview".into(),
                query: vec![],
                headers: Default::default(),
                body: vec![],
                json: json!({"report_profile":report}),
                form: Default::default(),
                user: None,
            };
            ctx.json["report_profile"]["generation_mode"] = json!(mode);
            let response = handle(&state, &ctx).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let preview: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(preview["count"], 3, "mode={mode}");
            assert_eq!(preview["confirmed_count"], 1);
            assert_eq!(preview["probable_count"], 1);
            assert_eq!(preview["possible_count"], 1);
            assert_eq!(preview["top_cves"][0], "CVE-2026-10001");
        }
        report["filters"]["vendor_product_filter"]["include_possible_matches"] = json!(false);
        assert_eq!(match_profile(&state, &report, 100).await.unwrap().len(), 2);

        // A failed database read must be distinguishable from no CVE matches.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let unavailable = mongodb::Client::with_uri_str(format!(
            "mongodb://{}/?serverSelectionTimeoutMS=100&connectTimeoutMS=100",
            listener.local_addr().unwrap()
        ))
        .await
        .unwrap();
        let mut unavailable_state = state.clone();
        unavailable_state.vuln = unavailable.database(database.name());
        assert!(
            match_profile(&unavailable_state, &report, 100)
                .await
                .is_err()
        );
        database.drop().await.unwrap();
    }

    #[test]
    fn organization_member_rows_include_account_status_and_subscription() {
        let owner_id = ObjectId::new();
        let user = doc! {
            "_id": owner_id,
            "username": "member",
            "email": "member@example.com",
            "zimbra_email": "hub@example.com",
            "role": "user",
            "auth_source": "zimbra",
            "zimbra_organization": "SW-ENG",
            "zimbra_organization_id": "1",
            "zimbra_is_organization_admin": false,
            "disabled": false,
        };
        let subscription = doc! {
            "_id": ObjectId::new(),
            "owner_user_id": owner_id,
            "username": "member",
            "email": "member@example.com",
            "emails": ["member@example.com"],
            "zimbra_email": "hub@example.com",
            "organization": "SW-ENG",
            "newsletter_profile": {"enabled": true},
            "report_profile": {"enabled": false},
        };
        let row = public_organization_member(&user, Some(&subscription));
        assert_eq!(row["username"], "member");
        assert_eq!(row["account_status"], "active");
        assert_eq!(row["has_subscription"], true);
        assert!(row["subscription"]["id"].as_str().is_some());
        assert_eq!(row["subscription"]["organization"], "SW-ENG");
        assert_eq!(row["subscription"]["zimbra_email"], "hub@example.com");
        assert!(row["subscription"].get("team").is_none());
    }

    #[test]
    fn legacy_team_subscription_is_publicized_as_organization() {
        let subscription = doc! {
            "_id": ObjectId::new(),
            "username": "legacy",
            "email": "legacy@example.com",
            "team": "SW-ENG",
            "delivery_mode": "grouped",
        };
        let value = public(&subscription);
        assert_eq!(value["organization"], "SW-ENG");
        assert_eq!(value["delivery_mode"], "individual");
        assert!(value.get("team").is_none());
    }

    #[test]
    fn organization_member_rows_keep_disabled_members_without_subscription() {
        let user = doc! {
            "_id": ObjectId::new(),
            "username": "disabled-member",
            "email": "disabled@example.com",
            "role": "user",
            "auth_source": "zimbra",
            "zimbra_organization": "SW-ENG",
            "zimbra_organization_id": "1",
            "disabled": true,
        };
        let row = public_organization_member(&user, None);
        assert_eq!(row["account_status"], "disabled");
        assert_eq!(row["has_subscription"], false);
        assert!(row["subscription"].is_null());
    }

    #[test]
    fn local_subscription_rows_keep_manual_recipients_and_scope_marker() {
        let subscription = doc! {
            "_id": ObjectId::new(),
            "local_subscription": true,
            "username": "local-report",
            "email": "one@example.com",
            "emails": ["one@example.com", "two@example.com"],
            "organization": "SW-ENG",
            "newsletter_profile": {"enabled": false},
            "report_profile": {"enabled": true},
        };
        let row = public_local_subscription(&subscription);
        assert_eq!(row["local_subscription"], true);
        assert_eq!(row["account_status"], "local");
        assert_eq!(row["organization"], "SW-ENG");
        assert_eq!(row["emails"][1], "two@example.com");
        assert_eq!(row["subscription"]["local_subscription"], true);
        assert_eq!(row["subscription"]["emails"][0], "one@example.com");
        assert!(row["subscription"].get("managed_by_user_id").is_none());
    }

    #[test]
    fn self_subscription_filter_uses_only_the_new_account_owner() {
        let owner_id = ObjectId::new();
        let ctx = ReqCtx {
            method: Method::GET,
            path: "/api/subscriptions".into(),
            query: Vec::new(),
            headers: axum::http::HeaderMap::new(),
            body: Vec::new(),
            json: Value::Null,
            form: std::collections::HashMap::new(),
            user: Some(doc! {
                "_id": owner_id,
                "username": "member",
                "email": "member@example.com",
            }),
        };
        let filter = self_subscription_owner_filter(&ctx).unwrap();
        assert_eq!(filter.get_object_id("owner_user_id").unwrap(), owner_id);
    }

    #[test]
    fn local_subscriptions_scope_only_to_their_creator() {
        let manager_id = ObjectId::new();
        let ctx = ReqCtx {
            method: Method::GET,
            path: "/api/subscriptions".into(),
            query: Vec::new(),
            headers: axum::http::HeaderMap::new(),
            body: Vec::new(),
            json: Value::Null,
            form: std::collections::HashMap::new(),
            user: Some(doc! {
                "_id": manager_id,
                "username": "member@example.com",
                "auth_source": "zimbra",
                "zimbra_organization": "SW-ENG",
                "zimbra_organization_id": "organization-a",
            }),
        };
        assert!(is_zimbra_user(&ctx));
        let scope = local_subscription_scope(&ctx).expect("manager scope");
        assert_eq!(scope.get_bool("local_subscription"), Ok(true));
        assert_eq!(scope.get_object_id("managed_by_user_id"), Ok(manager_id));
        assert!(scope.get("organization").is_none());
        assert!(scope.get("organization_id").is_none());
        assert!(owns_local_subscription(
            &ctx,
            &doc! {"managed_by_user_id": manager_id}
        ));
        assert!(!owns_local_subscription(
            &ctx,
            &doc! {"managed_by_user_id": ObjectId::new()}
        ));
    }

    #[test]
    fn zimbra_recipient_requires_the_synced_email() {
        let user = doc! {
            "auth_source": "zimbra",
            "zimbra_email": "Hub@Example.com",
        };
        assert_eq!(
            zimbra_recipient(&user).unwrap(),
            Some("hub@example.com".into())
        );
        let missing = doc! {"auth_source":"zimbra"};
        assert!(zimbra_recipient(&missing).is_err());
        let local = doc! {"auth_source":"local","email":"local@example.com"};
        assert_eq!(zimbra_recipient(&local).unwrap(), None);
    }

    #[test]
    fn new_zimbra_subscription_starts_with_both_profiles_disabled() {
        let owner_id = ObjectId::new();
        let user = doc! {
            "_id": owner_id,
            "username": "user@example.com",
            "auth_source": "zimbra",
            "organization": "",
        };
        let document = default_zimbra_subscription_document(
            &user,
            owner_id,
            "user@example.com",
            bson::DateTime::now(),
        );
        assert_eq!(document.get_object_id("owner_user_id").unwrap(), owner_id);
        assert_eq!(
            document.get_object_id("managed_by_user_id").unwrap(),
            owner_id
        );
        assert_eq!(document["email"], "user@example.com".into());
        assert_eq!(document["emails"].as_array().unwrap().len(), 1);
        assert_eq!(document["newsletter_profile"]["enabled"], false.into());
        assert_eq!(document["report_profile"]["enabled"], false.into());
        assert_eq!(document["local_subscription"], false.into());
    }

    #[test]
    fn legacy_default_subscription_is_identified_for_migration() {
        let owner_id = ObjectId::new();
        let user = doc! {
            "_id": owner_id,
            "username": "user@example.com",
            "auth_source": "zimbra",
            "organization": "SW-ENG",
        };
        let mut legacy = default_zimbra_subscription_document(
            &user,
            owner_id,
            "user@example.com",
            bson::DateTime::now(),
        );
        legacy.remove("auto_provisioned");
        let current = default_zimbra_subscription_document(
            &user,
            owner_id,
            "user@example.com",
            bson::DateTime::now(),
        );
        assert!(is_legacy_subscription(&legacy));
        assert!(is_default_zimbra_subscription(&legacy));
        assert!(same_subscription_identity(&legacy, &current));
    }

    #[test]
    fn configured_manual_subscription_is_not_treated_as_automatic() {
        let owner_id = ObjectId::new();
        let user = doc! {
            "_id": owner_id,
            "username": "user@example.com",
            "auth_source": "zimbra",
            "organization": "SW-ENG",
        };
        let mut manual = default_zimbra_subscription_document(
            &user,
            owner_id,
            "user@example.com",
            bson::DateTime::now(),
        );
        manual.remove("auto_provisioned");
        manual
            .get_document_mut("newsletter_profile")
            .unwrap()
            .insert("enabled", true);
        assert!(is_legacy_subscription(&manual));
        assert!(!is_default_zimbra_subscription(&manual));
    }

    #[test]
    fn unified_profile_filter_preserves_legacy_provider_scope() {
        let mut filters = default_filters();
        filters["collections"] = json!(["cve_review", "cisco_review"]);
        let query = profile_filter(&filters, "news");
        let rendered = format!("{query:?}");
        assert!(rendered.contains("source.provider"));
        assert!(rendered.contains("cve"));
        assert!(rendered.contains("cisco"));
    }

    #[test]
    fn unified_profile_filter_accepts_plain_provider_names() {
        let mut filters = default_filters();
        filters["collections"] = json!(["fortiguard", "cve"]);
        let query = profile_filter(&filters, "news");
        let rendered = format!("{query:?}");
        assert!(rendered.contains("source.provider"));
        assert!(rendered.contains("fortiguard"));
        assert!(rendered.contains("cve"));
        assert!(!rendered.contains("_review"));
    }

    #[test]
    fn clear_all_source_selection_matches_no_documents() {
        let filters = default_filters();
        let query = profile_filter(&filters, "news");
        let rendered = format!("{query:?}");
        assert!(rendered.contains("source.provider"));
        assert!(rendered.contains("Array([])"));
    }

    #[test]
    fn source_catalog_accepts_provider_without_news_documents() {
        let catalog = doc! {"_id":"active","providers":["fortiguard","cve"]};
        assert_eq!(
            parse_source_catalog(&catalog).unwrap(),
            vec!["fortiguard", "cve"]
        );
    }

    #[test]
    fn enriched_source_filter_can_be_restricted_to_cve() {
        let mut filters = default_filters();
        filters["collections"] = json!(["news"]);
        filters["sources"] = json!(["cve"]);
        let query = profile_filter(&filters, "news");
        let rendered = format!("{query:?}");
        assert!(rendered.contains("source.provider"));
        assert!(rendered.contains("cve"));
        assert!(!rendered.contains("zimbra"));
    }

    #[test]
    fn public_subscription_returns_plain_selected_provider_names() {
        let subscription = doc! {
            "_id": ObjectId::new(),
            "newsletter_profile": {
                "enabled": true,
                "filters": {
                    "collections": ["news"],
                    "sources": ["cve", "hkcert", "zimbra"],
                },
            },
        };
        let value = public(&subscription);
        assert_eq!(
            value["newsletter_profile"]["filters"]["collections"],
            json!(["cve", "hkcert", "zimbra"])
        );
        assert!(!value.to_string().contains("_review"));
    }
}
