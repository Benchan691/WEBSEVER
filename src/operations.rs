use crate::{AppState, ReqCtx, db, newsletters, render, reviews, view};
use axum::{
    http::{Method, StatusCode},
    response::Response,
};
use mongodb::bson::{self, Bson, doc};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

const SOURCE_URL_FIELDS: &[&str] = &[
    "source",
    "source_url",
    "reference_links",
    "references",
    "related_links",
    "urls",
    "publication_url",
    "patch_installation_url",
    "open_source_repo_url",
    "details.references",
    "details.reference_links",
    "details.related_links",
    "details.urls",
    "details.publication_url",
    "details.patch_installation_url",
    "details.open_source_repo_url",
];

fn collect_source_urls(value: &Bson, urls: &mut HashSet<String>) {
    match value {
        Bson::String(text) => {
            for part in text.split_whitespace() {
                let candidate = part.trim_matches(|c: char| " ,;()[]<>\r\n\t".contains(c));
                let Some((scheme, host_and_path)) = candidate.split_once("://") else {
                    continue;
                };
                if !matches!(scheme, "http" | "https")
                    || host_and_path
                        .split('/')
                        .next()
                        .is_none_or(|host| host.is_empty())
                {
                    continue;
                }
                urls.insert(candidate.to_owned());
            }
        }
        Bson::Array(values) => {
            for value in values {
                collect_source_urls(value, urls);
            }
        }
        Bson::Document(document) => {
            for value in document.values() {
                collect_source_urls(value, urls);
            }
        }
        _ => {}
    }
}

const CATALOG: &[(&str, &str, &str)] = &[
    ("title", "Title", "The advisory or vulnerability title."),
    (
        "collection",
        "Source collection",
        "The collection that supplied this record.",
    ),
    ("overview", "Overview", "The source summary or description."),
    (
        "table",
        "Source table",
        "A structured table supplied by the source.",
    ),
    ("severity", "Severity", "Severity or risk rating."),
    (
        "cvss",
        "CVSS",
        "CVSS score or vector supplied by the source.",
    ),
    (
        "impacts",
        "Impacts",
        "The effects or consequences described by the source.",
    ),
    (
        "affected",
        "Affected systems",
        "Products, systems, or versions that are affected.",
    ),
    (
        "cves",
        "CVE identifiers",
        "CVE identifiers found in the record.",
    ),
    (
        "recommendations",
        "Recommendations",
        "Fixes, patches, or mitigation guidance.",
    ),
    (
        "references",
        "References",
        "Reference URLs from the source.",
    ),
    (
        "related_links",
        "Related links",
        "Additional source or related URLs.",
    ),
];
fn field_catalog() -> Vec<Value> {
    CATALOG
        .iter()
        .map(|(id, label, description)| json!({"id":id,"label":label,"description":description}))
        .collect()
}
async fn latest(state: &AppState) -> Vec<Value> {
    let names = reviews::views(state).await.unwrap_or_default();
    let mut by_source: HashMap<String, Vec<String>> = HashMap::new();
    for name in names {
        let source = name
            .strip_suffix(&state.cfg.review_view_suffix)
            .unwrap_or(&name);
        if source != "zimbra" {
            by_source.entry(source.into()).or_default().push(name)
        }
    }
    let mut rows = Vec::new();
    let mut sources: Vec<_> = by_source.into_iter().collect();
    sources.sort_by(|a, b| a.0.cmp(&b.0));
    for (source, names) in sources {
        let document = db::find_sorted(
            &state.vuln,
            &source,
            doc! {},
            doc! {"observed_at":-1,"_id":-1},
            1,
        )
        .await
        .ok()
        .and_then(|mut rows| rows.pop());
        let id = document.as_ref().map(db::id_string).unwrap_or_default();
        let timestamp = document
            .as_ref()
            .and_then(|d| d.get("observed_at"))
            .map(|v| format!("{v:?}"))
            .unwrap_or_default();
        rows.push(json!({"source_collection":source,"review_collections":names,"selection_id":id,"source_timestamp":timestamp}));
    }
    rows
}
async fn health(state: &AppState, ctx: &ReqCtx) -> Value {
    let heartbeat = db::find_one(
        &state.web,
        "scheduler_health",
        doc! {"_id":"email_scheduler"},
    )
    .await
    .ok()
    .flatten();
    let last = heartbeat
        .as_ref()
        .and_then(|v| v.get_datetime("last_tick_at").ok());
    let alive = last
        .is_some_and(|t| bson::DateTime::now().timestamp_millis() - t.timestamp_millis() < 120000);
    let filter = if ctx.is_top_admin(state) {
        doc! {}
    } else {
        doc! {"managed_by_user_id":ctx.user_id()}
    };
    let subs = db::find_many(&state.web, "sub_account", filter.clone(), 5000)
        .await
        .unwrap_or_default();
    let zimbra_status = json!({
        "base_url": state.cfg.zimbra_base_url,
        "folder": state.cfg.zimbra_folder_name,
        "direct_delivery": true,
        "smtp_fallback": true
    });
    let mut reports = Vec::new();
    let mut newsletters = Vec::new();
    for item in subs {
        let value = db::bson_json(&item);
        let emails = value["emails"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![value["email"].clone()]);
        let email = emails
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        let report = &value["report_profile"];
        let newsletter = &value["newsletter_profile"];
        let organization = value
            .get("organization")
            .and_then(Value::as_str)
            .filter(|organization| !organization.trim().is_empty())
            .or_else(|| {
                value
                    .get("team")
                    .and_then(Value::as_str)
                    .filter(|team| !team.trim().is_empty())
            })
            .unwrap_or("");
        let delivery_filter = match item.get("_id") {
            Some(Bson::ObjectId(id)) => doc! {
                "$or": [
                    {"subscription_id": id.to_owned()},
                    {"subscription_id": id.to_hex()},
                ]
            },
            Some(id) => doc! {"subscription_id": id.to_owned()},
            None => doc! {"subscription_id": Bson::Null},
        };
        let latest_delivery = db::find_sorted(
            &state.web,
            "newsletter_deliveries",
            delivery_filter.clone(),
            doc! {"sent_at": -1},
            1,
        )
        .await
        .ok()
        .and_then(|mut rows| rows.pop());
        let total_delivered = db::collection(&state.web, "newsletter_deliveries")
            .count_documents(delivery_filter)
            .await
            .unwrap_or(0);
        let latest_delivery = latest_delivery.map(|delivery| {
            let delivery_json = db::bson_json(&delivery);
            let source = db::string(&delivery, "source_collection");
            let selection_id = db::string(&delivery, "selection_id");
            let mut row = json!({
                "sent_at": delivery_json.get("sent_at").cloned().unwrap_or(Value::Null),
                "email": db::string(&delivery, "email"),
                "source_collection": source,
                "selection_id": selection_id,
                "title": db::string(&delivery, "title"),
            });
            if !source.is_empty() && !selection_id.is_empty() {
                row["preview_url"] = json!(reviews::preview_url(&source, &selection_id));
            }
            row
        });
        reports.push(json!({"username":value["username"],"emails":emails,"email":email,"organization":organization,"enabled":report["enabled"],"schedule_enabled":report["schedule_enabled"],"schedule_weekday":report["schedule_weekday"],"schedule_time":report["schedule_time"],"generation_mode":report["generation_mode"],"report_language":report["report_language"],"next_run_at":report["next_run_at"],"due":false,"last_run_at":report["last_run_at"],"last_error":report["last_error"],"last_job_id":report["last_job_id"],"last_match_count":report["last_match_count"],"delivery":{}}));
        newsletters.push(json!({"username":value["username"],"emails":emails,"email":email,"organization":organization,"enabled":newsletter["enabled"],"delivery_cursor":newsletter["delivery_cursor"],"cve_delivery_cutoff":newsletter["cve_delivery_cutoff"],"total_delivered":total_delivered,"by_collection":[],"latest_delivery":latest_delivery.unwrap_or(Value::Null)}));
    }
    json!({"generated_at":chrono::Utc::now().to_rfc3339(),"scheduler":{"alive":alive,"last_tick_at":last.map(|v|v.to_string()).unwrap_or_default(),"hostname":heartbeat.as_ref().map(|v|db::string(v,"hostname")).unwrap_or_default(),"pid":heartbeat.as_ref().and_then(|v|v.get_i64("pid").ok()),"retention":heartbeat.as_ref().and_then(|v|v.get_document("retention").ok()).map(db::bson_json).unwrap_or(json!({})),"zimbra":zimbra_status},"reports":reports,"newsletters":newsletters})
}
pub async fn handle(state: &AppState, ctx: &ReqCtx) -> Option<Response> {
    if ctx.path == "/operations" && ctx.method == Method::GET {
        return Some(render(state, ctx, "operations/index.html", json!({})));
    }
    if ctx.path == "/api/operations/health" && ctx.method == Method::GET {
        return Some(view::json_response(
            StatusCode::OK,
            health(state, ctx).await,
        ));
    }
    if ctx.path == "/api/operations/newsletter-templates" && ctx.method == Method::GET {
        return Some(view::json_response(
            StatusCode::OK,
            json!({"data":latest(state).await}),
        ));
    }
    if ctx.path == "/api/operations/source-list" && ctx.method == Method::GET {
        let mut data = Vec::new();
        for row in latest(state).await {
            let source = row["source_collection"].as_str().unwrap_or("");
            let coll = db::collection(&state.vuln, source);
            let mut urls = HashSet::new();
            for field in SOURCE_URL_FIELDS {
                if let Ok(values) = coll.distinct(*field, doc! {}).await {
                    for value in values {
                        collect_source_urls(&value, &mut urls);
                    }
                }
            }
            let mut urls: Vec<_> = urls.into_iter().collect();
            urls.sort();
            if !urls.is_empty() {
                data.push(json!({"collection":source,"urls":urls}))
            }
        }
        return Some(view::json_response(StatusCode::OK, json!({"data":data})));
    }
    if ctx.path == "/api/operations/newsletter-editor" && ctx.method == Method::GET {
        let config = newsletters::template_config(state).await;
        let mut rows = Vec::new();
        for row in latest(state).await {
            let source = row["source_collection"].as_str().unwrap_or("");
            let fields = config
                .pointer(&format!("/sources/{source}/fields"))
                .cloned()
                .unwrap_or(json!([
                    "title",
                    "collection",
                    "overview",
                    "table",
                    "severity",
                    "impacts",
                    "affected",
                    "cves",
                    "recommendations",
                    "references",
                    "related_links"
                ]));
            let mut item = row.clone();
            item["fields"] = fields;
            item["field_catalog"] = json!(field_catalog());
            rows.push(item)
        }
        return Some(view::json_response(
            StatusCode::OK,
            json!({"data":{"common":config["common"],"sources":rows,"field_catalog":field_catalog()}}),
        ));
    }
    if ctx.path == "/api/operations/newsletter-editor" && ctx.method == Method::PUT {
        let common = ctx
            .json
            .get("common")
            .filter(|v| v.is_object())
            .cloned()
            .unwrap_or(json!({}));
        let sources = ctx
            .json
            .get("sources")
            .filter(|v| v.is_object())
            .cloned()
            .unwrap_or(json!({}));
        let config = json!({"common":common,"sources":sources});
        let mut document = db::json_doc(&config).unwrap_or_default();
        document.insert("updated_at", bson::DateTime::now());
        let coll = db::collection(&state.web, "newsletter_template_config");
        return Some(
            match coll
                .update_one(doc! {"_id":"newsletter_default"}, doc! {"$set":document})
                .upsert(true)
                .await
            {
                Ok(_) => view::json_response(StatusCode::OK, json!({"data":config})),
                Err(_) => view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to save email templates.",
                ),
            },
        );
    }
    if ctx.path == "/api/operations/newsletter-editor/preview" && ctx.method == Method::POST {
        let source = ctx.field("source_collection");
        let id = ctx.field("selection_id");
        if source.is_empty() || id.is_empty() {
            return Some(view::error(
                StatusCode::BAD_REQUEST,
                "A source record is required for preview.",
            ));
        }
        let Some(document) = reviews::resolve(state, &source, &id).await else {
            return Some(view::error(
                StatusCode::NOT_FOUND,
                "Newsletter source document not found.",
            ));
        };
        let record = db::bson_json(&document);
        let config = ctx.json.get("config").cloned().unwrap_or(json!({}));
        let newsletter = newsletters::normalize(&record, &source, &config);
        let html = state
            .templates
            .get_template(newsletters::template_name(&source))
            .and_then(|t| t.render(json!({"newsletter":newsletter})))
            .unwrap_or_default();
        return Some(view::json_response(
            StatusCode::OK,
            json!({"html":html,"subject":newsletter["subject"]}),
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_all_safe_source_and_reference_urls() {
        let value = Bson::Document(doc! {
            "url": "https://vendor.example/advisory",
            "detail_url": "https://vendor.example/advisory/123",
            "references": [
                {"url": "https://tracker.example/CVE-2026-1234"},
                "https://patch.example/fix"
            ],
            "unsafe": "javascript:alert(1)",
        });
        let mut urls = HashSet::new();
        collect_source_urls(&value, &mut urls);
        assert_eq!(
            urls,
            HashSet::from([
                "https://vendor.example/advisory".to_owned(),
                "https://vendor.example/advisory/123".to_owned(),
                "https://tracker.example/CVE-2026-1234".to_owned(),
                "https://patch.example/fix".to_owned(),
            ])
        );
    }
}
