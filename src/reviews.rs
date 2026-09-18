use crate::{AppState, ReqCtx, db, render, view};
use axum::{
    http::{Method, StatusCode},
    response::Response,
};
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
fn filter(ctx: &ReqCtx) -> Result<Document, String> {
    let mut clauses = Vec::<Bson>::new();
    for (arg, fields) in [
        ("code", &["code", "cve", "cve_ids"][..]),
        ("title", &["title"][..]),
        ("affected", &["affected", "affected_products"][..]),
    ] {
        let value = ctx.arg(arg);
        if !value.trim().is_empty() {
            clauses.push(Bson::Document(doc! {"$or": fields.iter().map(|field| regex_clause(field, value.trim())).collect::<Vec<_>>() }));
        }
    }
    let statuses = ctx.args("status");
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
    let search = ctx.arg("search");
    if !search.trim().is_empty() {
        let fields = [
            "code",
            "cve",
            "cve_ids",
            "title",
            "severity",
            "affected",
            "affected_products",
            "description",
            "impacts",
            "recommendation",
            "vendor",
            "product",
            "details.description",
            "details.summary",
            "details.affected.vendor",
            "details.affected.product",
            "details.vulnerability_identifiers.cve_id",
        ];
        clauses.push(Bson::Document(doc! {"$or": search.split_whitespace().flat_map(|term| fields.iter().map(move |field| regex_clause(field,term))).collect::<Vec<_>>() }));
    }
    let window = ctx.arg("time_window");
    let days = match window.as_str() {
        "24h" => 1,
        "7d" => 7,
        "30d" => 30,
        "" | "all" | "custom" => 0,
        _ => return Err("Invalid time window.".into()),
    };
    if days > 0 {
        let start = mongodb::bson::DateTime::from_millis(
            (chrono::Utc::now() - chrono::Duration::days(days)).timestamp_millis(),
        );
        clauses.push(Bson::Document(doc! {"observed_at": {"$gte": start}}));
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
fn response_row(name: &str, document: &Document) -> Value {
    let mut data = db::bson_json(document);
    if let Some(object) = data.as_object_mut() {
        object.remove("_id");
    }
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
    if source_name == "cve" {
        pipeline.clear();
    } else if let Some(project) = pipeline
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
            project.insert(field, 1);
        }
    }
    pipeline.push(doc! {"$match":filter});
    pipeline.push(doc! {"$sort":{"observed_at":-1,"_id":-1}});
    pipeline.push(doc!{"$facet":{"documents":[{"$skip":skip as i64},{"$limit":limit}],"metadata":[{"$count":"total"}]}});
    let mut cursor = db::collection(&state.vuln, &source_name)
        .aggregate(pipeline)
        .await?;
    let facet = cursor.try_next().await?.unwrap_or_default();
    let rows = facet
        .get_array("documents")
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_document().cloned())
                .collect()
        })
        .unwrap_or_default();
    let count = facet
        .get_array("metadata")
        .ok()
        .and_then(|items| items.first())
        .and_then(|v| v.as_document())
        .and_then(|d| d.get("total"))
        .and_then(|v| v.as_i64().or_else(|| v.as_i32().map(i64::from)))
        .unwrap_or(0) as u64;
    Ok((count, rows))
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
    if ctx.path == "/api/reviews/search" && ctx.method == Method::GET {
        let filter = match filter(ctx) {
            Ok(v) => v,
            Err(e) => return Some(view::error(StatusCode::BAD_REQUEST, &e)),
        };
        let names = views(state)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|n| source(state, n) == "cve")
            .collect::<Vec<_>>();
        let page = ctx.arg("page").parse::<u64>().unwrap_or(1).max(1);
        let size = ctx
            .arg("page_size")
            .parse::<u64>()
            .unwrap_or(25)
            .clamp(1, 100);
        let mut rows = Vec::new();
        for name in names {
            match query_rows(state, &name, filter.clone(), 0, 10_000).await {
                Ok((_, documents)) => {
                    for document in documents {
                        rows.push((name.clone(), document));
                    }
                }
                Err(_) => {
                    return Some(view::error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Unable to query the vulnerabilities database.",
                    ));
                }
            }
        }
        rows.sort_by(|a, b| {
            format!("{:?}", b.1.get("observed_at")).cmp(&format!("{:?}", a.1.get("observed_at")))
        });
        let total = rows.len();
        let data: Vec<Value> = rows
            .into_iter()
            .skip(((page - 1) * size) as usize)
            .take(size as usize)
            .map(|(name, document)| response_row(&name, &document))
            .collect();
        return Some(view::json_response(
            StatusCode::OK,
            json!({"data":data,"page":page,"page_size":size,"total":total,"pages":((total as u64+size-1)/size).max(1)}),
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
        let filter = match filter(ctx) {
            Ok(v) => v,
            Err(e) => return Some(view::error(StatusCode::BAD_REQUEST, &e)),
        };
        let names = views(state)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|n| source(state, n) == "cve")
            .collect::<Vec<_>>();
        let mut rows = Vec::new();
        for name in names {
            if let Ok((_, documents)) = query_rows(state, &name, filter.clone(), 0, 2001).await {
                for document in documents {
                    let (selection_score, patch_priority, severity, cve_id) = score(&document);
                    rows.push(json!({"collection":name,"selection_id":db::id_string(&document),"selection_score":selection_score,"patch_priority":patch_priority,"severity":severity,"cve_id":cve_id}));
                }
            }
        }
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
                        json!({"data":documents.iter().map(|d|json!({"selection_id":db::id_string(d),"document":db::bson_json(d)})).collect::<Vec<_>>(),"page":page,"page_size":size,"total":total,"pages":((total+size-1)/size).max(1)}),
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
