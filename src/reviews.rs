use crate::{AppState, ReqCtx, db, render, vendor_matcher, view};
use axum::{
    http::{Method, StatusCode},
    response::Response,
};
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use futures::TryStreamExt;
use mongodb::bson::{Bson, Document, doc};
use regex::Regex;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

pub async fn views(state: &AppState) -> Result<Vec<String>, mongodb::error::Error> {
    let mut cursor = state
        .vuln
        .list_collections()
        .filter(doc! {"type":"view"})
        .await?;
    let mut names = Vec::new();
    while let Some(spec) = cursor.try_next().await? {
        if spec.name.ends_with(&state.cfg.review_view_suffix) {
            names.push(spec.name)
        }
    }
    names.sort();
    Ok(names)
}
fn source<'a>(state: &AppState, name: &'a str) -> &'a str {
    name.strip_suffix(&state.cfg.review_view_suffix)
        .unwrap_or(name)
}
async fn view_spec(
    state: &AppState,
    name: &str,
) -> Result<Option<(String, Vec<Document>)>, mongodb::error::Error> {
    let mut cursor = state
        .vuln
        .list_collections()
        .filter(doc! {"type":"view","name":name})
        .await?;
    Ok(cursor.try_next().await?.and_then(|spec| {
        spec.options
            .view_on
            .map(|source| (source, spec.options.pipeline.unwrap_or_default()))
    }))
}
pub async fn resolve(state: &AppState, source_name: &str, id: &str) -> Option<Document> {
    if id.trim().is_empty() {
        return None;
    }
    db::find_one(&state.vuln, source_name, doc! {"_id": id})
        .await
        .ok()
        .flatten()
}
fn regex_clause(field: &str, value: &str) -> Bson {
    let mut result = Document::new();
    result.insert(
        field,
        doc! {"$regex": regex::escape(value), "$options": "i"},
    );
    Bson::Document(result)
}

fn parse_review_datetime(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Some(parsed.with_timezone(&Utc));
    }
    let hong_kong = FixedOffset::east_opt(8 * 3600)?;
    ["%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"]
        .iter()
        .find_map(|format| {
            NaiveDateTime::parse_from_str(value, format)
                .ok()
                .and_then(|parsed| hong_kong.from_local_datetime(&parsed).single())
                .map(|parsed| parsed.with_timezone(&Utc))
        })
}

fn filter_arg(ctx: &ReqCtx, key: &str) -> String {
    if ctx.method == Method::GET {
        return ctx.arg(key);
    }
    ctx.json
        .get(key)
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .or_else(|| value.as_i64().map(|number| number.to_string()))
                .or_else(|| value.as_u64().map(|number| number.to_string()))
        })
        .unwrap_or_default()
}

fn filter_args(ctx: &ReqCtx, key: &str) -> Vec<String> {
    if ctx.method == Method::GET {
        return ctx.args(key);
    }
    match ctx.json.get(key) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(value)) if !value.trim().is_empty() => vec![value.clone()],
        _ => Vec::new(),
    }
}

fn required_vendor_product_filter(ctx: &ReqCtx) -> Result<Value, String> {
    let value = if ctx.method == Method::GET {
        let raw = ctx.arg("vendor_product_filter");
        if raw.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str::<Value>(&raw)
                .map_err(|_| "Vendor/product CSV filter is invalid JSON.".to_owned())?
        }
    } else {
        ctx.json
            .get("vendor_product_filter")
            .cloned()
            .unwrap_or(Value::Null)
    };
    vendor_matcher::validate(&value)?;
    let rows = value
        .get("rows")
        .and_then(Value::as_array)
        .filter(|rows| !rows.is_empty());
    if value.get("enabled") != Some(&Value::Bool(true)) || rows.is_none() {
        return Err("Upload a vendor/product CSV filter before searching review documents.".into());
    }
    Ok(value)
}

fn reject_keyword_search(ctx: &ReqCtx) -> Result<(), String> {
    if !filter_arg(ctx, "search").trim().is_empty() {
        return Err(
            "Keyword search has been replaced by the required vendor/product CSV filter.".into(),
        );
    }
    Ok(())
}

fn filter(ctx: &ReqCtx) -> Result<Document, String> {
    let mut clauses = Vec::<Bson>::new();
    for (arg, fields) in [
        ("code", &["code", "cve", "cve_ids"][..]),
        ("title", &["title"][..]),
        ("affected", &["affected", "affected_products"][..]),
    ] {
        let value = filter_arg(ctx, arg);
        if !value.trim().is_empty() {
            clauses.push(Bson::Document(doc! {"$or": fields.iter().map(|field| regex_clause(field, value.trim())).collect::<Vec<_>>() }));
        }
    }
    let statuses = filter_args(ctx, "status");
    if statuses
        .iter()
        .any(|s| !matches!(s.as_str(), "Critical" | "High" | "Medium" | "Low"))
    {
        return Err("Severity must be Critical, High, Medium, or Low.".into());
    }
    if !statuses.is_empty() {
        clauses.push(Bson::Document(
            doc! {"$or": statuses.iter().map(|s| regex_clause("severity",s)).collect::<Vec<_>>() },
        ));
    }
    let window = filter_arg(ctx, "time_window");
    let now = Utc::now();
    let hong_kong = FixedOffset::east_opt(8 * 3600).unwrap();
    let bounds = match window.as_str() {
        "" | "all" => None,
        "daily" => {
            let local_now = now.with_timezone(&hong_kong);
            let start = local_now
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .and_then(|value| hong_kong.from_local_datetime(&value).single())
                .map(|value| value.with_timezone(&Utc))
                .expect("midnight is a valid local time");
            Some((start, now))
        }
        "week" => Some((now - chrono::Duration::days(7), now)),
        "24h" => Some((now - chrono::Duration::hours(24), now)),
        "7d" => Some((now - chrono::Duration::days(7), now)),
        "30d" => Some((now - chrono::Duration::days(30), now)),
        "custom" => {
            let start = parse_review_datetime(&filter_arg(ctx, "start"));
            let end = parse_review_datetime(&filter_arg(ctx, "end"));
            if start.is_none_or(|start| end.is_none_or(|end| start >= end)) {
                return Err("Custom scrape time requires a valid start before end.".into());
            }
            Some((start.unwrap(), end.unwrap()))
        }
        _ => return Err("Invalid time window.".into()),
    };
    if let Some((start, end)) = bounds {
        clauses.push(Bson::Document(doc! {"observed_at": {
            "$gte": mongodb::bson::DateTime::from_millis(start.timestamp_millis()),
            "$lt": mongodb::bson::DateTime::from_millis(end.timestamp_millis()),
        }}));
    }
    if clauses.is_empty() {
        Ok(doc! {})
    } else if clauses.len() == 1 {
        Ok(clauses.remove(0).as_document().cloned().unwrap())
    } else {
        Ok(doc! {"$and": clauses})
    }
}
fn flatten(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(flatten).collect::<Vec<_>>().join(" "),
        Value::Object(m) => m.values().map(flatten).collect::<Vec<_>>().join(" "),
        Value::Null => String::new(),
        _ => value.to_string(),
    }
}
fn severity(document: &Document) -> String {
    let value = db::bson_json(document);
    let text = ["severity", "impacts"]
        .iter()
        .filter_map(|key| value.get(*key))
        .map(flatten)
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    for (match_text, label) in [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
    ] {
        if text.contains(match_text) {
            return label.into();
        }
    }
    "Unknown".into()
}
fn cve_id(document: &Document) -> String {
    let value = db::bson_json(document);
    let re = Regex::new(r"(?i)\b(?:CVE-)?(\d{4}-\d{4,})\b").unwrap();
    for key in ["code", "_id", "title", "cve", "cve_ids"] {
        if let Some(v) = value.get(key) {
            if let Some(caps) = re.captures(&flatten(v)) {
                return format!("CVE-{}", caps.get(1).unwrap().as_str().to_uppercase());
            }
        }
    }
    String::new()
}
fn score(document: &Document) -> (i64, String, String, String) {
    let sev = severity(document);
    let value = db::bson_json(document);
    let details = value.get("details").cloned().unwrap_or(json!({}));
    let kev = [
        value.get("cisa_kev"),
        value.get("kev"),
        details.get("cisa_kev"),
        details.get("kev"),
    ]
    .iter()
    .flatten()
    .any(|v| **v == Value::Bool(true));
    let mut points = match sev.as_str() {
        "Critical" => 45,
        "High" => 35,
        "Medium" => 22,
        "Low" => 10,
        _ => 8,
    };
    if kev {
        points += 25;
    }
    let text = flatten(&value).to_lowercase();
    if ["exploited", "in the wild", "active exploitation", "kev"]
        .iter()
        .any(|term| text.contains(term))
    {
        points += 12;
    } else if ["proof of concept", "poc", "public exploit"]
        .iter()
        .any(|term| text.contains(term))
    {
        points += 6;
    }
    if ["remote code", "ransomware", "internet-facing", "privilege"]
        .iter()
        .any(|term| text.contains(term))
    {
        points += 8;
    }
    let points = points.clamp(0, 100);
    let priority = if kev || points >= 80 || sev == "Critical" {
        "Critical"
    } else if points >= 60 || sev == "High" {
        "High"
    } else if points >= 35 || sev == "Medium" {
        "Medium"
    } else {
        "Low"
    };
    (points, priority.into(), sev, cve_id(document))
}

fn is_blank(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(value)) => value.trim().is_empty(),
        Some(Value::Array(values)) => values.is_empty(),
        Some(Value::Object(values)) => values.is_empty(),
        Some(_) => false,
    }
}

fn text_value(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) => {
            let value = value.trim();
            (!value.is_empty()).then(|| value.to_owned())
        }
        Some(Value::Number(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn unique_join(values: impl IntoIterator<Item = String>) -> Option<String> {
    let mut seen = HashSet::new();
    let values = values
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .filter(|value| seen.insert(value.clone()))
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.join(", "))
}

fn normalized_document(document: &Document) -> Value {
    let mut data = db::bson_json(document);
    let Some(object) = data.as_object_mut() else {
        return data;
    };
    object.remove("_id");

    let details = object.get("details").cloned().unwrap_or(Value::Null);
    let affected_items = details
        .get("affected")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut vendors = Vec::new();
    let mut products = Vec::new();
    let mut affected = Vec::new();
    for item in &affected_items {
        if let Some(item) = item.as_object() {
            let vendor = text_value(item.get("vendor"));
            let product = text_value(item.get("product"));
            if let Some(value) = vendor.clone() {
                vendors.push(value);
            }
            if let Some(value) = product.clone() {
                products.push(value);
            }
            let combined = [vendor, product]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            if !combined.is_empty() {
                affected.push(combined);
            } else if let Some(package) = text_value(item.get("packageName")) {
                affected.push(package);
            }
        } else if let Some(value) = text_value(Some(item)) {
            affected.push(value);
        }
    }
    if let Some(values) = details.get("affected_products").and_then(Value::as_array) {
        affected.extend(values.iter().filter_map(|value| text_value(Some(value))));
    }

    if is_blank(object.get("description")) {
        let description = details
            .get("descriptions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| text_value(item.get("value").or_else(|| item.get("description"))))
            .collect::<Vec<_>>();
        let description = if description.is_empty() {
            ["description", "summary", "overview"]
                .iter()
                .filter_map(|key| text_value(details.get(*key)))
                .collect::<Vec<_>>()
        } else {
            description
        };
        if !description.is_empty() {
            object.insert("description".into(), Value::String(description.join("\n")));
        }
    }
    if is_blank(object.get("vendor")) {
        if let Some(vendor) = unique_join(vendors) {
            object.insert("vendor".into(), Value::String(vendor));
        }
    }
    if is_blank(object.get("product")) {
        if let Some(product) = unique_join(products) {
            object.insert("product".into(), Value::String(product));
        }
    }
    if is_blank(object.get("affected")) {
        let mut seen = HashSet::new();
        affected.retain(|value| seen.insert(value.clone()));
        if !affected.is_empty() {
            object.insert("affected".into(), json!(affected));
        }
    }
    if is_blank(object.get("cve")) {
        if let Some(code) = text_value(object.get("code")) {
            let cve = if code.to_ascii_uppercase().starts_with("CVE-") {
                code.to_ascii_uppercase()
            } else {
                format!("CVE-{code}")
            };
            object.insert("cve".into(), Value::String(cve));
        }
    }
    data
}

fn response_row(name: &str, document: &Document) -> Value {
    let data = normalized_document(document);
    let (selection_score, patch_priority, _, _) = score(document);
    json!({"collection":name,"selection_id":db::id_string(document),"document":data,"selection_score":selection_score,"patch_priority":patch_priority})
}
pub(crate) async fn query_rows(
    state: &AppState,
    name: &str,
    filter: Document,
    skip: u64,
    limit: i64,
) -> Result<(u64, Vec<Document>), mongodb::error::Error> {
    let Some((source_name, mut pipeline)) = view_spec(state, name).await? else {
        return Ok((0, Vec::new()));
    };
    if let Some(project) = pipeline
        .first_mut()
        .and_then(|stage| stage.get_document_mut("$project").ok())
    {
        for field in [
            "_id",
            "details",
            "observed_at",
            "published_at",
            "updated_at",
            "cve_ids",
            "code",
            "cve",
            "severity",
            "title",
            "summary",
            "description",
            "vendor",
            "product",
            "affected",
            "affected_products",
            "containers",
            "systems_affected",
            "products",
            "impacts",
            "source",
        ] {
            if source_name == "cve"
                && matches!(field, "description" | "affected" | "impacts" | "cve")
            {
                continue;
            }
            project.insert(field, 1);
        }
    }
    pipeline.push(doc! {"$match":filter});
    let mut count_pipeline = pipeline.clone();
    count_pipeline.push(doc! {"$count":"total"});
    let mut count_cursor = db::collection(&state.vuln, &source_name)
        .aggregate(count_pipeline)
        .await?;
    let count = count_cursor
        .try_next()
        .await?
        .and_then(|document| document.get("total").cloned())
        .and_then(|value| match value {
            Bson::Int32(value) => Some(value as u64),
            Bson::Int64(value) if value >= 0 => Some(value as u64),
            Bson::Double(value) if value >= 0.0 => Some(value as u64),
            _ => None,
        })
        .unwrap_or(0);

    pipeline.push(doc! {"$sort":{"observed_at":-1,"_id":-1}});
    pipeline.push(doc! {"$skip":skip.min(i64::MAX as u64) as i64});
    pipeline.push(doc! {"$limit":limit.max(0)});
    let mut cursor = db::collection(&state.vuln, &source_name)
        .aggregate(pipeline)
        .await?;
    let mut rows = Vec::new();
    while let Some(document) = cursor.try_next().await? {
        rows.push(document);
    }
    Ok((count, rows))
}

async fn filtered_rows(
    state: &AppState,
    names: &[String],
    filter: Document,
    vendor_product_filter: &Value,
) -> Result<Vec<(String, Document)>, mongodb::error::Error> {
    let mut rows = Vec::new();
    for name in names {
        let (total, _) = query_rows(state, name, filter.clone(), 0, 1).await?;
        if total == 0 {
            continue;
        }
        let limit = total.min(i64::MAX as u64) as i64;
        let (_, documents) = query_rows(state, name, filter.clone(), 0, limit).await?;
        for document in documents {
            if vendor_matcher::classify(&db::bson_json(&document), vendor_product_filter).is_some()
            {
                rows.push((name.clone(), document));
            }
        }
    }
    Ok(rows)
}

pub async fn handle(state: &AppState, ctx: &ReqCtx) -> Option<Response> {
    if ctx.path == "/reviews" && ctx.method == Method::GET {
        return Some(render(state, ctx, "reviews/index.html", json!({})));
    }
    if let Some(name) = ctx.path.strip_prefix("/reviews/") {
        if ctx.method == Method::GET {
            let exists = views(state)
                .await
                .ok()
                .is_some_and(|names| names.iter().any(|n| n == name));
            return Some(render(
                state,
                ctx,
                "reviews/collection.html",
                json!({"collection_name":name,"initial_error":if exists {Value::Null}else{json!("Review collection not found.")}}),
            ));
        }
    }
    if ctx.path == "/api/reviews" && ctx.method == Method::GET {
        let names = match views(state).await {
            Ok(v) => v,
            Err(_) => {
                return Some(view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to connect to the vulnerabilities database.",
                ));
            }
        };
        let mut data = Vec::new();
        for name in names {
            let count = db::collection(&state.vuln, &name)
                .count_documents(doc! {})
                .await
                .unwrap_or(0);
            data.push(json!({"name":name,"source":source(state,&name),"count":count}));
        }
        return Some(view::json_response(StatusCode::OK, json!({"data":data})));
    }
    if ctx.path == "/api/reviews/search" && matches!(ctx.method, Method::GET | Method::POST) {
        let vendor_product_filter = match required_vendor_product_filter(ctx) {
            Ok(value) => value,
            Err(error) => return Some(view::error(StatusCode::BAD_REQUEST, &error)),
        };
        if let Err(error) = reject_keyword_search(ctx) {
            return Some(view::error(StatusCode::BAD_REQUEST, &error));
        }
        let filter = match filter(ctx) {
            Ok(v) => v,
            Err(e) => return Some(view::error(StatusCode::BAD_REQUEST, &e)),
        };
        let names = views(state).await.unwrap_or_default();
        let page = filter_arg(ctx, "page").parse::<u64>().unwrap_or(1).max(1);
        let size = filter_arg(ctx, "page_size")
            .parse::<u64>()
            .unwrap_or(25)
            .clamp(1, 100);
        let offset = (page - 1).saturating_mul(size);
        let mut rows = match filtered_rows(state, &names, filter, &vendor_product_filter).await {
            Ok(rows) => rows,
            Err(_) => {
                return Some(view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to query the vulnerabilities database.",
                ));
            }
        };
        let total = rows.len() as u64;
        rows.sort_by(|a, b| {
            format!("{:?}", b.1.get("observed_at")).cmp(&format!("{:?}", a.1.get("observed_at")))
        });
        let data: Vec<Value> = rows
            .into_iter()
            .skip(offset as usize)
            .take(size as usize)
            .map(|(name, document)| response_row(&name, &document))
            .collect();
        return Some(view::json_response(
            StatusCode::OK,
            json!({"data":data,"page":page,"page_size":size,"total":total,"pages":((total+size-1)/size).max(1)}),
        ));
    }
    if ctx.path == "/api/reviews/auto-select" && ctx.method == Method::POST {
        let count = ctx.json.get("count").and_then(Value::as_i64).unwrap_or(0);
        if !(1..=500).contains(&count) {
            return Some(view::error(
                StatusCode::BAD_REQUEST,
                "Select between 1 and 500 vulnerability records.",
            ));
        }
        if let Err(error) = reject_keyword_search(ctx) {
            return Some(view::error(StatusCode::BAD_REQUEST, &error));
        }
        let filter = match filter(ctx) {
            Ok(v) => v,
            Err(e) => return Some(view::error(StatusCode::BAD_REQUEST, &e)),
        };
        let vendor_product_filter = match required_vendor_product_filter(ctx) {
            Ok(value) => value,
            Err(error) => return Some(view::error(StatusCode::BAD_REQUEST, &error)),
        };
        let names = views(state).await.unwrap_or_default();
        let mut rows = match filtered_rows(state, &names, filter, &vendor_product_filter).await {
            Ok(documents) => documents
                .into_iter()
                .map(|(name, document)| {
                    let (selection_score, patch_priority, severity, cve_id) = score(&document);
                    json!({"collection":name,"selection_id":db::id_string(&document),"selection_score":selection_score,"patch_priority":patch_priority,"severity":severity,"cve_id":cve_id})
                })
                .collect::<Vec<_>>(),
            Err(_) => {
                return Some(view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to query the vulnerabilities database.",
                ));
            }
        };
        if rows.len() > 2000 {
            return Some(view::error(
                StatusCode::BAD_REQUEST,
                "Filter matched too many documents. Narrow your filters and try again.",
            ));
        }
        let matched = rows.len();
        rows.sort_by(|a, b| {
            b["selection_score"]
                .as_i64()
                .cmp(&a["selection_score"].as_i64())
        });
        let mut seen = HashSet::new();
        let selected: Vec<Value> = rows
            .into_iter()
            .filter(|r| {
                let id = r["cve_id"].as_str().unwrap_or("");
                !id.is_empty() && seen.insert(id.to_owned())
            })
            .take(count as usize)
            .collect();
        let mut summary = HashMap::from([("Critical", 0), ("High", 0), ("Medium", 0), ("Low", 0)]);
        for row in &selected {
            if let Some(p) = row["patch_priority"].as_str() {
                if let Some(v) = summary.get_mut(p) {
                    *v += 1;
                }
            }
        }
        return Some(view::json_response(
            StatusCode::OK,
            json!({"selections":selected,"summary":summary,"matched":matched,"selected":selected.len()}),
        ));
    }
    if ctx.path == "/api/reviews/export-json" && ctx.method == Method::POST {
        let Some(selections) = ctx.json.get("selections").and_then(Value::as_array) else {
            return Some(view::error(
                StatusCode::BAD_REQUEST,
                "Select at least one document to export.",
            ));
        };
        if selections.is_empty() || selections.len() > 500 {
            return Some(view::error(
                StatusCode::BAD_REQUEST,
                "Export is limited to 500 documents.",
            ));
        }
        let names = views(state).await.unwrap_or_default();
        let mut documents = Vec::new();
        for selection in selections {
            let name = selection
                .get("collection")
                .and_then(Value::as_str)
                .unwrap_or("");
            let id = selection
                .get("selection_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !names.iter().any(|n| n == name) {
                return Some(view::error(
                    StatusCode::BAD_REQUEST,
                    "Invalid review collection.",
                ));
            }
            let Some(document) = resolve(state, source(state, name), id).await else {
                return Some(view::error(
                    StatusCode::NOT_FOUND,
                    "Selected document was not found.",
                ));
            };
            documents.push(db::bson_json(&document));
        }
        let filename = format!(
            "vulnerability-export-{}.json",
            chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
        );
        return Some(view::attachment(
            "application/json; charset=utf-8",
            &filename,
            serde_json::to_string_pretty(&documents).unwrap_or_default(),
        ));
    }
    if let Some(name) = ctx.path.strip_prefix("/api/reviews/") {
        if ctx.method == Method::GET {
            let names = views(state).await.unwrap_or_default();
            if !names.iter().any(|n| n == name) {
                return Some(view::error(
                    StatusCode::NOT_FOUND,
                    "Review collection not found.",
                ));
            }
            let filter = match filter(ctx) {
                Ok(v) => v,
                Err(e) => return Some(view::error(StatusCode::BAD_REQUEST, &e)),
            };
            let page = ctx.arg("page").parse::<u64>().unwrap_or(1).max(1);
            let size = ctx
                .arg("page_size")
                .parse::<u64>()
                .unwrap_or(25)
                .clamp(1, 100);
            return Some(
                match query_rows(state, name, filter, (page - 1) * size, size as i64).await {
                    Ok((total, documents)) => view::json_response(
                        StatusCode::OK,
                        json!({"data":documents.iter().map(|d|json!({"selection_id":db::id_string(d),"document":normalized_document(d)})).collect::<Vec<_>>(),"page":page,"page_size":size,"total":total,"pages":((total+size-1)/size).max(1)}),
                    ),
                    Err(_) => view::error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Unable to query the vulnerabilities database.",
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

    fn filter_context(query: Vec<(&str, &str)>) -> ReqCtx {
        ReqCtx {
            method: Method::GET,
            path: "/api/reviews/search".into(),
            query: query
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect(),
            headers: axum::http::HeaderMap::new(),
            body: Vec::new(),
            json: Value::Null,
            form: HashMap::new(),
            user: None,
        }
    }

    #[test]
    fn review_filter_accepts_frontend_time_windows() {
        for window in ["all", "daily", "week"] {
            assert!(filter(&filter_context(vec![("time_window", window)])).is_ok());
        }
        let custom = filter(&filter_context(vec![
            ("time_window", "custom"),
            ("start", "2026-06-01T08:30"),
            ("end", "2026-06-02T09:45"),
        ]))
        .expect("valid custom scrape time");
        assert!(custom.get("observed_at").is_some());
        assert!(filter(&filter_context(vec![("time_window", "invalid")])).is_err());
    }

    #[test]
    fn review_filter_rejects_keyword_search() {
        assert!(reject_keyword_search(&filter_context(vec![("search", "openssl")])).is_err());
    }

    #[test]
    fn review_search_requires_vendor_product_filter() {
        let missing = filter_context(Vec::new());
        assert!(required_vendor_product_filter(&missing).is_err());

        let mut valid = filter_context(Vec::new());
        valid.method = Method::POST;
        valid.json = json!({
            "vendor_product_filter": {
                "enabled": true,
                "schema_version": 1,
                "include_possible_matches": false,
                "rows": [{"vendor": "Acme", "product": "Widget", "vendor_aliases": [], "product_aliases": []}]
            }
        });
        assert!(required_vendor_product_filter(&valid).is_ok());
    }

    #[test]
    fn normalized_cve_document_restores_display_fields() {
        let document = doc! {
            "_id": "cve:2026-1234",
            "code": "2026-1234",
            "details": {
                "descriptions": vec![doc! {"value": "A useful description."}],
                "affected": vec![doc! {"vendor": "Acme", "product": "Widget"}],
            },
        };

        let normalized = normalized_document(&document);
        assert_eq!(normalized["description"], "A useful description.");
        assert_eq!(normalized["vendor"], "Acme");
        assert_eq!(normalized["product"], "Widget");
        assert_eq!(normalized["affected"], json!(["Acme Widget"]));
        assert_eq!(normalized["cve"], "CVE-2026-1234");
        assert!(normalized.get("_id").is_none());
    }

    #[test]
    fn normalized_cve_document_keeps_existing_view_fields() {
        let document = doc! {
            "code": "2026-1234",
            "description": "View description",
            "affected": ["View vendor View product"],
            "vendor": "View vendor",
            "product": "View product",
            "details": {
                "descriptions": vec![doc! {"value": "Raw description"}],
                "affected": vec![doc! {"vendor": "Raw vendor", "product": "Raw product"}],
            },
        };

        let normalized = normalized_document(&document);
        assert_eq!(normalized["description"], "View description");
        assert_eq!(normalized["affected"], json!(["View vendor View product"]));
        assert_eq!(normalized["vendor"], "View vendor");
        assert_eq!(normalized["product"], "View product");
    }
}
