use crate::{AppState, ReqCtx, db, newsletters, render, reviews, view};
use axum::{
    http::{Method, StatusCode},
    response::Response,
};
use chrono::{DateTime, Datelike, TimeZone, Utc};
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

fn record_month(now: DateTime<Utc>) -> (DateTime<Utc>, DateTime<Utc>) {
    let hong_kong = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
    let local = now.with_timezone(&hong_kong);
    let start = hong_kong
        .with_ymd_and_hms(local.year(), local.month(), 1, 0, 0, 0)
        .unwrap()
        .with_timezone(&Utc);
    let (year, month) = if local.month() == 12 {
        (local.year() + 1, 1)
    } else {
        (local.year(), local.month() + 1)
    };
    let next = hong_kong
        .with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .unwrap()
        .with_timezone(&Utc);
    (start, next)
}

fn monthly_record_reset(state: &AppState) -> bool {
    state
        .cfg
        .value(
            "NEWSLETTER_RECORDS_RESET_MONTHLY",
            "/newsletter_records/reset_monthly",
            json!(true),
        )
        .as_bool()
        .unwrap_or(true)
}

fn records_since(
    subscription: &bson::Document,
    now: DateTime<Utc>,
    monthly: bool,
) -> Option<(DateTime<Utc>, bool)> {
    let month = monthly.then(|| record_month(now).0);
    let manual = subscription
        .get_datetime("newsletter_records_reset_at")
        .ok()
        .and_then(|value| DateTime::from_timestamp_millis(value.timestamp_millis()));
    match (month, manual) {
        // A manual reset hides receipts at the reset instant as well.
        (Some(month), Some(manual)) if manual >= month => Some((manual, false)),
        (Some(month), _) => Some((month, true)),
        (None, Some(manual)) => Some((manual, false)),
        _ => None,
    }
}

fn displayed_delivery_filter(
    subscription: &bson::Document,
    since: Option<(DateTime<Utc>, bool)>,
) -> bson::Document {
    let mut filter = match subscription.get("_id") {
        Some(Bson::ObjectId(id)) => doc! {
            "$or": [
                {"subscription_id": id.to_owned()},
                {"subscription_id": id.to_hex()},
            ]
        },
        Some(id) => doc! {"subscription_id": id.to_owned()},
        None => doc! {"subscription_id": Bson::Null},
    };
    if let Some((since, inclusive)) = since {
        let mut boundary = bson::Document::new();
        boundary.insert(
            if inclusive { "$gte" } else { "$gt" },
            bson::DateTime::from_millis(since.timestamp_millis()),
        );
        filter.insert("sent_at", boundary);
    }
    filter
}

fn record_reset_scope(input: &Value) -> Result<bson::Document, &'static str> {
    if input.as_object().is_none_or(|object| object.len() != 1) {
        return Err("Choose one subscription or all newsletter records.");
    }
    match (input.get("all"), input.get("subscription_id")) {
        (Some(Value::Bool(true)), None) => Ok(doc! {"newsletter_profile":{"$type":"object"}}),
        (None, Some(Value::String(id))) => db::object_id(id)
            .map(|id| doc! {"_id":id,"newsletter_profile":{"$type":"object"}})
            .ok_or("Invalid subscription ID."),
        _ => Err("Choose one subscription or all newsletter records."),
    }
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
    let now = Utc::now();
    let monthly = monthly_record_reset(state);
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
        let since = records_since(&item, now, monthly);
        let delivery_filter = displayed_delivery_filter(&item, since);
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
        reports.push(json!({"username":value["username"],"emails":emails,"email":email,"organization":organization,"enabled":report["enabled"],"schedule_enabled":report["schedule_enabled"],"cron_expression":crate::cron_schedule::expression(report),"generation_mode":report["generation_mode"],"report_language":report["report_language"],"next_run_at":report["next_run_at"],"due":false,"last_run_at":report["last_run_at"],"last_error":report["last_error"],"last_job_id":report["last_job_id"],"last_match_count":report["last_match_count"],"delivery":{}}));
        newsletters.push(json!({"subscription_id":db::id_string(&item),"username":value["username"],"emails":emails,"email":email,"organization":organization,"enabled":newsletter["enabled"],"delivery_cursor":newsletter["delivery_cursor"],"cve_delivery_cutoff":newsletter["cve_delivery_cutoff"],"records_since":since.map(|(value, _)| value.to_rfc3339()),"last_error":newsletter["last_error"],"last_error_at":newsletter["last_error_at"],"last_success_at":newsletter["last_success_at"],"total_delivered":total_delivered,"by_collection":[],"latest_delivery":latest_delivery.unwrap_or(Value::Null)}));
    }
    json!({"generated_at":now.to_rfc3339(),"scheduler":{"alive":alive,"last_tick_at":last.map(|v|v.to_string()).unwrap_or_default(),"hostname":heartbeat.as_ref().map(|v|db::string(v,"hostname")).unwrap_or_default(),"pid":heartbeat.as_ref().and_then(|v|v.get_i64("pid").ok()),"retention":heartbeat.as_ref().and_then(|v|v.get_document("retention").ok()).map(db::bson_json).unwrap_or(json!({})),"zimbra":zimbra_status},"newsletter_records":{"monthly_reset_enabled":monthly,"next_reset_at":monthly.then(|| record_month(now).1.to_rfc3339()),"timezone":"Asia/Hong_Kong"},"reports":reports,"newsletters":newsletters})
}
pub async fn handle(state: &AppState, ctx: &ReqCtx) -> Option<Response> {
    if ctx.path == "/api/operations/newsletter-records/reset" && ctx.method == Method::POST {
        if !ctx.is_top_admin(state) {
            return Some(view::error(
                StatusCode::FORBIDDEN,
                "Administrator access required.",
            ));
        }
        let filter = match record_reset_scope(&ctx.json) {
            Ok(filter) => filter,
            Err(error) => return Some(view::error(StatusCode::BAD_REQUEST, error)),
        };
        let now = bson::DateTime::now();
        let mut reset = doc! {"newsletter_records_reset_at":now};
        if let Some(actor) = ctx.user_id() {
            reset.insert("newsletter_records_reset_by", actor);
        }
        let result = db::collection(&state.web, "sub_account")
            .update_many(filter, doc! {"$set":reset})
            .await;
        return Some(match result {
            Ok(result)
                if result.matched_count == 0 && ctx.json.get("subscription_id").is_some() =>
            {
                view::error(StatusCode::NOT_FOUND, "Newsletter subscription not found.")
            }
            Ok(result) => view::json_response(
                StatusCode::OK,
                json!({
                    "reset_count":result.matched_count,"reset_at":now,
                }),
            ),
            Err(error) => {
                tracing::error!(%error, "Unable to reset newsletter records");
                view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to reset newsletter records.",
                )
            }
        });
    }
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
        let record = db::news_json(&document);
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

    fn utc(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn records_roll_over_at_hong_kong_midnight_including_new_year_and_leap_year() {
        let before = record_month(utc("2026-11-30T15:59:59.999Z"));
        assert_eq!(before.0, utc("2026-10-31T16:00:00Z"));
        assert_eq!(before.1, utc("2026-11-30T16:00:00Z"));
        let after = record_month(utc("2026-11-30T16:00:00Z"));
        assert_eq!(after.0, before.1);
        assert_eq!(after.1, utc("2026-12-31T16:00:00Z"));
        let january = record_month(utc("2026-12-31T16:00:00Z"));
        assert_eq!(january.1, utc("2027-01-31T16:00:00Z"));
        let leap = record_month(utc("2024-02-29T00:00:00Z"));
        assert_eq!(leap.0, utc("2024-01-31T16:00:00Z"));
        assert_eq!(leap.1, utc("2024-02-29T16:00:00Z"));
    }

    #[test]
    fn manual_reset_hides_equal_timestamps_and_older_resets_yield_to_a_new_month() {
        let now = utc("2026-11-13T09:30:00Z");
        let mut sub = doc! {};
        assert_eq!(
            records_since(&sub, now, true),
            Some((utc("2026-10-31T16:00:00Z"), true))
        );
        assert_eq!(records_since(&sub, now, false), None);
        sub.insert(
            "newsletter_records_reset_at",
            bson::DateTime::from_millis(now.timestamp_millis()),
        );
        assert_eq!(records_since(&sub, now, true), Some((now, false)));
        assert_eq!(records_since(&sub, now, false), Some((now, false)));
        assert_eq!(
            records_since(&sub, utc("2026-11-30T16:00:00Z"), true),
            Some((utc("2026-11-30T16:00:00Z"), true))
        );
    }

    #[test]
    fn reset_requires_an_explicit_single_subscription_or_all_scope() {
        let id = bson::oid::ObjectId::new();
        assert_eq!(
            record_reset_scope(&json!({"subscription_id":id.to_hex()}))
                .unwrap()
                .get_object_id("_id")
                .unwrap(),
            id
        );
        assert!(record_reset_scope(&json!({"all":true})).is_ok());
        for value in [
            json!(null),
            json!({}),
            json!({"all":false}),
            json!({"all":"true"}),
            json!({"subscription_id":"invalid"}),
            json!({"all":true,"subscription_id":id.to_hex()}),
            json!({"all":true,"skip_queued":true}),
        ] {
            assert!(
                record_reset_scope(&value).is_err(),
                "Unexpected reset scope: {value}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires NEWSLETTER_RECORDS_TEST_MONGO_URI for a disposable database"]
    async fn display_reset_preserves_delivery_queues_receipts_and_other_subscriptions() {
        use axum::http::HeaderMap;
        use std::{collections::HashMap, path::PathBuf, sync::Arc};
        let uri = std::env::var("NEWSLETTER_RECORDS_TEST_MONGO_URI").unwrap();
        let client = mongodb::Client::with_uri_str(&uri).await.unwrap();
        let database = client.database(&format!(
            "newsletter_records_test_{}",
            bson::oid::ObjectId::new()
        ));
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let state = AppState {
            cfg: crate::config::Config {
                root: root.clone(),
                file: json!({}),
                mongo_uri: uri,
                web_database: database.name().into(),
                vulnerabilities_database: database.name().into(),
                vulnerabilities_collection: "test_news".into(),
                secret: "test".into(),
                bootstrap_username: "admin".into(),
                bootstrap_password: String::new(),
                zimbra_base_url: String::new(),
                zimbra_folder_name: "news".into(),
                zimbra_timeout_seconds: 1,
                zimbra_verify_tls: true,
                zimbra_credential_key: String::new(),
                account_collection: "accounts".into(),
                newsletter_root: root.join("newsletters"),
                port: 0,
            },
            web: database.clone(),
            vuln: database.clone(),
            templates: Arc::new(crate::view::environment(&root)),
            http: reqwest::Client::new(),
        };
        assert!(monthly_record_reset(&state));
        let admin_id = bson::oid::ObjectId::new();
        let id = bson::oid::ObjectId::new();
        let other_id = bson::oid::ObjectId::new();
        let profile = doc! {"enabled":true,"delivery_cursor":"2026-11-13T07:18:31.474+00:00","filters_hash":"existing","filters":{"sources":["govcert"]}};
        let report = doc! {"enabled":true,"schedule_enabled":true};
        let subscriptions = db::collection(&database, "sub_account");
        subscriptions
            .insert_many([
                doc! {"_id":id,"newsletter_profile":&profile,"report_profile":&report},
                doc! {"_id":other_id,"newsletter_profile":&profile},
            ])
            .await
            .unwrap();
        let receipts = db::collection(&database, "newsletter_deliveries");
        let now = Utc::now();
        let old = record_month(now).0 - chrono::Duration::milliseconds(1);
        let make_receipt = |sub, sent: DateTime<Utc>| doc! {"subscription_id":sub,"sent_at":bson::DateTime::from_millis(sent.timestamp_millis()),"source_collection":"govcert","selection_id":"govcert:1"};
        receipts
            .insert_many([
                make_receipt(Bson::ObjectId(id), old),
                make_receipt(Bson::ObjectId(id), record_month(now).0),
                make_receipt(
                    Bson::String(id.to_hex()),
                    now - chrono::Duration::milliseconds(1),
                ),
                make_receipt(Bson::ObjectId(other_id), now),
            ])
            .await
            .unwrap();
        let original = subscriptions
            .find_one(doc! {"_id":id})
            .await
            .unwrap()
            .unwrap();
        let visible = displayed_delivery_filter(&original, records_since(&original, now, true));
        assert_eq!(receipts.count_documents(visible).await.unwrap(), 2);
        let original_other = subscriptions
            .find_one(doc! {"_id":other_id})
            .await
            .unwrap()
            .unwrap();
        let mut ctx = ReqCtx {
            method: Method::POST,
            path: "/api/operations/newsletter-records/reset".into(),
            query: vec![],
            headers: HeaderMap::new(),
            body: vec![],
            json: json!({"subscription_id":id.to_hex()}),
            form: HashMap::new(),
            user: None,
        };
        assert_eq!(
            handle(&state, &ctx).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        ctx.user =
            Some(doc! {"_id":admin_id,"username":"admin","role":"admin","auth_source":"local"});
        assert_eq!(handle(&state, &ctx).await.unwrap().status(), StatusCode::OK);
        let changed = subscriptions
            .find_one(doc! {"_id":id})
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            changed.get_document("newsletter_profile").unwrap(),
            &profile
        );
        assert_eq!(changed.get_document("report_profile").unwrap(), &report);
        assert_eq!(
            subscriptions
                .find_one(doc! {"_id":other_id})
                .await
                .unwrap()
                .unwrap(),
            original_other
        );
        let reset = DateTime::from_timestamp_millis(
            changed
                .get_datetime("newsletter_records_reset_at")
                .unwrap()
                .timestamp_millis(),
        )
        .unwrap();
        // An equal-timestamp receipt remains hidden after reset.
        receipts
            .insert_one(make_receipt(Bson::ObjectId(id), reset))
            .await
            .unwrap();
        let filter = displayed_delivery_filter(&changed, records_since(&changed, Utc::now(), true));
        assert_eq!(receipts.count_documents(filter.clone()).await.unwrap(), 0);
        assert!(receipts.find_one(filter).await.unwrap().is_none());
        assert_eq!(receipts.count_documents(doc! {}).await.unwrap(), 5);
        assert!(receipts.find_one(doc! {"subscription_id":id,"source_collection":"govcert","selection_id":"govcert:1"}).await.unwrap().is_some());
        receipts
            .insert_one(make_receipt(
                Bson::ObjectId(id),
                reset + chrono::Duration::milliseconds(1),
            ))
            .await
            .unwrap();
        assert_eq!(
            receipts
                .count_documents(displayed_delivery_filter(
                    &changed,
                    records_since(&changed, Utc::now(), true)
                ))
                .await
                .unwrap(),
            1
        );
        ctx.json = json!({"all":true});
        assert_eq!(handle(&state, &ctx).await.unwrap().status(), StatusCode::OK);
        assert_eq!(
            subscriptions
                .count_documents(doc! {"newsletter_records_reset_at":{"$exists":true}})
                .await
                .unwrap(),
            2
        );
        ctx.json = json!({"subscription_id":bson::oid::ObjectId::new().to_hex()});
        assert_eq!(
            handle(&state, &ctx).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(receipts.count_documents(doc! {}).await.unwrap(), 6);
        database.drop().await.unwrap();
    }

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
