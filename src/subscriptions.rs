use crate::{
    AppState, ReqCtx, auth, db, mail, newsletter_statistics, rbac, render, reviews, vendor_matcher,
    view,
};
use axum::{
    body::Bytes,
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures::{TryStreamExt, stream};
use mongodb::bson::{self, Bson, Document, doc};
use serde_json::{Value, json};
use std::collections::HashSet;

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
        json!({"enabled":false,"filters":filters,"generation_mode":"template","report_language":"en","search_prompt":"","schedule_enabled":false,"cron_expression":"0 9 * * 1"})
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
            if let Some(existing) = dst.get_mut(k)
                && existing.is_object()
                && v.is_object()
            {
                merge(existing, v);
                continue;
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
        if !profile["schedule_enabled"].is_boolean() {
            return Err("Report schedule must be true or false.".into());
        }
        let cron_expression = if input["cron_expression"]
            .as_str()
            .is_some_and(|expression| !expression.trim().is_empty())
        {
            crate::cron_schedule::expression(&profile)
        } else {
            let mut legacy_profile = profile.clone();
            legacy_profile["cron_expression"] = Value::Null;
            crate::cron_schedule::expression(&legacy_profile)
        };
        crate::cron_schedule::validate(&cron_expression)
            .map_err(|error| format!("Invalid report cron expression: {error}"))?;
        profile["cron_expression"] = json!(cron_expression);
        profile.as_object_mut().unwrap().remove("schedule_weekday");
        profile.as_object_mut().unwrap().remove("schedule_time");
        if profile["enabled"] == true && profile["schedule_enabled"] == true {
            let next_run_at = crate::cron_schedule::next_after(
                profile["cron_expression"].as_str().unwrap_or_default(),
                chrono::Utc::now(),
            )
            .map_err(|error| format!("Invalid report cron expression: {error}"))?;
            profile["next_run_at"] = json!(next_run_at.to_rfc3339());
        } else if let Some(profile) = profile.as_object_mut() {
            profile.remove("next_run_at");
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
        obj.insert(
            "organization_id".into(),
            json!(
                document
                    .get_object_id("organization_id")
                    .ok()
                    .map(|id| id.to_hex())
            ),
        );
        if let Some(profile) = obj
            .get_mut("report_profile")
            .filter(|profile| profile.is_object())
        {
            profile["cron_expression"] = json!(crate::cron_schedule::expression(profile));
            if let Some(profile) = profile.as_object_mut() {
                profile.remove("schedule_weekday");
                profile.remove("schedule_time");
            }
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
    // Public data is an allowlist; preserved legacy tokens and future private
    // fields must never leak after an explicitly approved scope migration.
    if let Some(obj) = value.as_object_mut() {
        obj.retain(|key, _| {
            matches!(
                key.as_str(),
                "id" | "username"
                    | "email"
                    | "emails"
                    | "cc"
                    | "bcc"
                    | "organization"
                    | "organization_id"
                    | "delivery_mode"
                    | "newsletter_profile"
                    | "report_profile"
                    | "auto_provisioned"
                    | "created_at"
                    | "updated_at"
            )
        });
    }
    value
}
fn subscription_filter(ctx: &ReqCtx, id: Option<&str>) -> Option<Document> {
    let scope = rbac::scope(Some(ctx.user.as_ref()?));
    match id {
        Some(id) => Some(doc! {"$and":[scope,{"_id":db::object_id(id)?}]}),
        None => Some(scope),
    }
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
    profiles: (&Value, &Value),
) -> Result<(), String> {
    let (newsletter, report) = profiles;
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

fn notification_profile_card(name: &str, profile: &Value, newsletter: bool) -> Value {
    let enabled = profile["enabled"].as_bool().unwrap_or(false);
    let mut summary_lines = Vec::new();
    let filters = &profile["filters"];
    let collections = logical_collection_names(filters)
        .iter()
        .map(|value| escape_html(value))
        .collect::<Vec<_>>()
        .join(", ");
    let collections = if !collections.is_empty() {
        collections
    } else {
        "No sources selected".to_owned()
    };
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
            summary_lines.push(format!(
                "Schedule: {} HKT",
                escape_html(&crate::cron_schedule::expression(profile))
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
    if matches!(
        ctx.path.as_str(),
        "/api/subscriptions/vendor-product-template.csv"
            | "/api/reviews/vendor-product-template.csv"
    ) && ctx.method == Method::GET
    {
        return Some(view::attachment("text/csv; charset=utf-8","vendor_product_filter_template.csv","vendor,product,vendor_aliases,product_aliases\nRed Hat,Enterprise Linux,\"Red Hat, Inc.|RedHat\",RHEL|Red Hat Enterprise Linux\nMicrosoft,Windows Server,Microsoft Corporation,Windows Server 2019|Windows Server 2022\nApache Software Foundation,HTTP Server,Apache|ASF,Apache HTTPD|httpd\n".into()));
    }
    if matches!(
        ctx.path.as_str(),
        "/api/subscriptions/vendor-product-import" | "/api/reviews/vendor-product-import"
    ) && ctx.method == Method::POST
    {
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
    if ctx.path == "/api/subscriptions" && ctx.method == Method::GET {
        let Some(filter) = subscription_filter(ctx, None) else {
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
                    json!({"data":rows.iter().map(public).collect::<Vec<_>>()}),
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
            let Some(filter) = subscription_filter(ctx, Some(&identifier)) else {
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
        return Some(save_subscription(state, ctx, None).await);
    }
    if let Some(tail) = ctx.path.strip_prefix("/api/subscriptions/") {
        let (identifier, action) = tail.split_once('/').unwrap_or((tail, ""));
        let Some(filter) = subscription_filter(ctx, Some(identifier)) else {
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
        if action.is_empty() && ctx.method == Method::GET {
            return Some(view::json_response(StatusCode::OK, public(&existing)));
        }
        if action.is_empty() && ctx.method == Method::DELETE {
            return Some(
                match coll
                    .delete_one(subscription_filter(ctx, Some(identifier)).unwrap())
                    .await
                {
                    Ok(_) => view::json_response(StatusCode::OK, json!({"success":true})),
                    Err(_) => view::error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Unable to delete subscription.",
                    ),
                },
            );
        }
        if action.is_empty() && ctx.method == Method::PUT {
            return Some(save_subscription(state, ctx, Some(&existing)).await);
        }
    }

    None
}

fn valid_subscription_fields(data: &Value) -> bool {
    data.as_object().is_some_and(|o| {
        o.keys().all(|k| {
            matches!(
                k.as_str(),
                "username"
                    | "organization_id"
                    | "organization"
                    | "email"
                    | "emails"
                    | "cc"
                    | "bcc"
                    | "newsletter_profile"
                    | "report_profile"
                    | "delivery_mode"
            )
        })
    })
}
async fn save_subscription(
    state: &AppState,
    ctx: &ReqCtx,
    existing: Option<&Document>,
) -> Response {
    if !valid_subscription_fields(&ctx.json) {
        return view::error(
            StatusCode::BAD_REQUEST,
            "Unknown subscription field; credentials and scope/ownership changes are not accepted.",
        );
    }
    let actor = ctx.user.as_ref().unwrap();
    let org = if let Some(old) = existing {
        old.get_object_id("organization_id").ok()
    } else if ctx.is_superadmin() {
        db::object_id(&ctx.field("organization_id"))
    } else {
        rbac::organization(actor)
    };
    let Some(org) = org.filter(|id| rbac::within_scope(actor, *id)) else {
        return view::error(
            StatusCode::FORBIDDEN,
            "Select an organization within your permitted scope.",
        );
    };
    if ctx.json.get("organization_id").is_some()
        && db::object_id(&ctx.field("organization_id")) != Some(org)
    {
        return view::error(
            StatusCode::FORBIDDEN,
            "Organization membership is immutable.",
        );
    }
    let Some(organization) = db::find_one(
        &state.web,
        "organizations",
        doc! {"_id":org,"disabled":{"$ne":true}},
    )
    .await
    .ok()
    .flatten() else {
        return view::error(StatusCode::BAD_REQUEST, "Active organization not found.");
    };
    let mut data = existing.map(db::bson_json).unwrap_or(json!({}));
    merge(&mut data, &ctx.json);
    let username = data["username"].as_str().unwrap_or("").trim();
    let Some(owner)=auth::accounts(state).find_one(doc!{"organization_id":org,"username_key":auth::key(username),"auth_source":"local","rbac_schema":1,"disabled":false,"deleted_at":{"$exists":false}}).await.ok().flatten() else {return view::error(StatusCode::BAD_REQUEST,"The owner must be an active local user in this organization.");};
    let owner_id = owner.get_object_id("_id").unwrap();
    if existing.is_some_and(|old| old.get_object_id("owner_user_id").ok() != Some(owner_id)) {
        return view::error(
            StatusCode::FORBIDDEN,
            "Subscription ownership is immutable. Create a new subscription for a different owner.",
        );
    }
    let emails = match recipients(&data) {
        Ok(values) => values,
        Err(error) => return view::error(StatusCode::BAD_REQUEST, &error),
    };
    let copies = match copy_recipients(&data) {
        Ok(values) => values,
        Err(error) => return view::error(StatusCode::BAD_REQUEST, &error),
    };
    let newsletter = match profile(state, "newsletter", &data["newsletter_profile"]).await {
        Ok(value) => value,
        Err(error) => return view::error(StatusCode::BAD_REQUEST, &error),
    };
    let report = match profile(state, "report", &data["report_profile"]).await {
        Ok(value) => value,
        Err(error) => return view::error(StatusCode::BAD_REQUEST, &error),
    };
    if (newsletter["enabled"] == true || report["schedule_enabled"] == true)
        && !ctx.can("subscriptions.send")
    {
        return view::error(
            StatusCode::FORBIDDEN,
            "Scheduled delivery requires subscriptions.send.",
        );
    }
    if report["schedule_enabled"] == true && !ctx.can("reports.create") {
        return view::error(
            StatusCode::FORBIDDEN,
            "Scheduled reports require reports.create.",
        );
    }
    let mut values = doc! {"username":db::string(&owner,"username"),"organization_id":org,"organization":db::string(&organization,"name"),"owner_user_id":owner_id,"email":&emails[0],"emails":emails.clone(),"cc":copies.cc.clone(),"bcc":copies.bcc.clone(),"delivery_mode":"individual","newsletter_profile":db::json_doc(&newsletter).unwrap(),"report_profile":db::json_doc(&report).unwrap(),"updated_at":bson::DateTime::now()};
    let coll = db::collection(&state.web, "sub_account");
    let result = if let Some(old) = existing {
        coll.update_one(
            subscription_filter(ctx, Some(&db::id_string(old))).unwrap(),
            doc! {"$set":values},
        )
        .await
        .map(|_| old.get_object_id("_id").unwrap())
    } else {
        values.insert("managed_by_user_id", ctx.user_id().unwrap());
        values.insert("created_at", bson::DateTime::now());
        coll.insert_one(values)
            .await
            .map(|result| result.inserted_id.as_object_id().unwrap())
    };
    match result {
        Ok(id) => {
            let warning = if ctx.can("subscriptions.send") {
                notify(
                    state,
                    &emails,
                    &copies,
                    if existing.is_some() {
                        "updated"
                    } else {
                        "created"
                    },
                    username,
                    &db::string(&organization, "name"),
                    (&newsletter, &report),
                )
                .await
                .err()
            } else {
                None
            };
            view::json_response(
                StatusCode::OK,
                json!({"success":true,"id":id.to_hex(),"notification_warning":warning}),
            )
        }
        Err(_) => view::error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Unable to save subscription.",
        ),
    }
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
    async fn inventory_download_is_scoped_to_organization() {
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
            cookie_secure: false,
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
        let organization = ObjectId::new();
        let id = ObjectId::new();
        db::collection(&database,"sub_account").insert_one(doc!{
            "_id":id, "organization_id":organization,"owner_user_id":owner, "emails":["owner@example.com"],
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
            user: Some(
                doc! {"_id":owner,"username":"owner","auth_source":"local","rbac_schema":1,"role":"user","organization_id":organization},
            ),
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
        ctx.user = Some(
            doc! {"_id":stranger,"username":"stranger","auth_source":"local","rbac_schema":1,"role":"user","organization_id":ObjectId::new()},
        );
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
            cookie_secure: false,
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
    #[test]
    fn subscription_scope_and_public_projection_do_not_trust_legacy_fields() {
        let organization = bson::oid::ObjectId::new();
        let id = bson::oid::ObjectId::new();
        let ctx = ReqCtx {
            method: Method::GET,
            path: "/api/subscriptions".into(),
            query: vec![],
            headers: Default::default(),
            body: vec![],
            json: Value::Null,
            form: Default::default(),
            user: Some(
                doc! {"_id":bson::oid::ObjectId::new(),"organization_id":organization,"rbac_schema":1,"auth_source":"local"},
            ),
        };
        assert_eq!(
            subscription_filter(&ctx, None).unwrap(),
            doc! {"organization_id":organization}
        );
        assert_eq!(
            subscription_filter(&ctx, Some(&id.to_hex())).unwrap(),
            doc! {"$and":[{"organization_id":organization},{"_id":id}]}
        );
        let row = public(
            &doc! {"_id":id,"organization_id":organization,"username":"member","email":"member@example.test","password":"private","legacy_access_token":"private","private_future_field":"private"},
        );
        assert_eq!(row["organization_id"], organization.to_hex());
        assert!(!row.to_string().contains("private"));
    }
}
