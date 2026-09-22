use crate::{AppState, ReqCtx, db, newsletters, render, reviews, view};
use axum::{
    http::{Method, StatusCode},
    response::Response,
};
use futures::TryStreamExt;
use mongodb::bson::{self, Bson, doc};
use serde_json::{Value, json};

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
fn canonical_source_url(document: &bson::Document) -> &str {
    document
        .get_document("source")
        .ok()
        .and_then(|source| source.get_str("url").ok())
        .unwrap_or("")
}
async fn latest(state: &AppState) -> Vec<Value> {
    let mut rows = Vec::new();
    let collection = db::collection(&state.vuln, &state.cfg.vulnerabilities_collection);
    let Ok(mut cursor) = collection
        .aggregate([
            doc! {"$match":{"source.provider":{"$type":"string","$ne":""}}},
            doc! {"$sort":{"observed_at":-1,"_id":-1}},
            doc! {"$group":{"_id":"$source.provider","document":{"$first":"$$ROOT"}}},
            doc! {"$sort":{"_id":1}},
        ])
        .await
    else {
        return rows;
    };
    while let Ok(Some(group)) = cursor.try_next().await {
        let source = db::string(&group, "_id");
        let Ok(document) = group.get_document("document") else {
            continue;
        };
        let id = db::id_string(&document);
        let timestamp = document
            .get("observed_at")
            .map(|v| format!("{v:?}"))
            .unwrap_or_default();
        let source_url = canonical_source_url(&document);
        rows.push(json!({"source_collection":source,"review_collections":[state.cfg.vulnerabilities_collection],"selection_id":id,"source_timestamp":timestamp,"source_url":source_url}));
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
        "direct_delivery": false,
        "smtp_delivery": true
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
        newsletters.push(json!({"username":value["username"],"emails":emails,"email":email,"organization":organization,"enabled":newsletter["enabled"],"delivery_cursor":newsletter["delivery_cursor"],"cve_delivery_cutoff":newsletter["cve_delivery_cutoff"],"last_error":newsletter["last_error"],"last_error_at":newsletter["last_error_at"],"last_success_at":newsletter["last_success_at"],"total_delivered":total_delivered,"by_collection":[],"latest_delivery":latest_delivery.unwrap_or(Value::Null)}));
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
        let data = latest(state)
            .await
            .into_iter()
            .filter_map(|row| {
                let collection = row["source_collection"].as_str()?.to_owned();
                let url = row["source_url"].as_str()?.trim();
                (!url.is_empty()).then(|| json!({"collection":collection,"url":url}))
            })
            .collect::<Vec<_>>();
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
        let source = record
            .pointer("/source/provider")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("unknown")
            .to_owned();
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
    fn source_list_uses_the_canonical_source_url_only() {
        let document = doc! {
            "source": {
                "provider": "cve",
                "url": "https://vendor.example/advisories",
                "detail_url": "https://vendor.example/advisories/CVE-2026-1234",
            },
            "details": {
                "references": ["https://tracker.example/CVE-2026-1234"],
            },
        };
        assert_eq!(
            canonical_source_url(&document),
            "https://vendor.example/advisories"
        );
    }
}
