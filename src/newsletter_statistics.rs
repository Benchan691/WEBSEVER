use crate::{AppState, db, mail, subscriptions};
use chrono::{DateTime, Datelike, FixedOffset, TimeZone, Utc};
use futures::TryStreamExt;
use mongodb::bson::{self, Bson, Document, doc, oid::ObjectId};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const DELIVERY_LOG: &str = "newsletter_statistics_deliveries";

#[derive(Debug)]
struct MonthPeriod {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    due: DateTime<Utc>,
    key: String,
    label: String,
    date_range: String,
}

impl MonthPeriod {
    fn previous(now: DateTime<Utc>) -> Self {
        let hk = FixedOffset::east_opt(8 * 3600).unwrap();
        let local = now.with_timezone(&hk);
        let end = hk
            .with_ymd_and_hms(local.year(), local.month(), 1, 0, 0, 0)
            .single()
            .unwrap();
        let last_day = end - chrono::Duration::days(1);
        let start = hk
            .with_ymd_and_hms(last_day.year(), last_day.month(), 1, 0, 0, 0)
            .single()
            .unwrap();
        Self {
            start: start.with_timezone(&Utc),
            end: end.with_timezone(&Utc),
            due: (end + chrono::Duration::hours(9)).with_timezone(&Utc),
            key: start.format("%Y-%m").to_string(),
            label: start.format("%B %Y").to_string(),
            date_range: format!("1–{} {}", last_day.day(), start.format("%B %Y")),
        }
    }
}

fn source_name(source: &str) -> String {
    match source {
        "cve" => "CVE Program",
        "nvd" => "NVD",
        "hkcert" => "HKCERT",
        "msrc" => "Microsoft Security Response Center",
        "github_advisory" => "GitHub Security Advisories",
        "hpe" => "HPE",
        "cnvd" => "CNVD",
        "avd" => "AVD",
        "huawei_sa" => "Huawei Security Advisories",
        "juniper" => "Juniper Networks",
        "paloalto" => "Palo Alto Networks",
        "qianxin" => "QiAnXin",
        "splunk" => "Splunk",
        "zimbra" => "Zimbra",
        _ => source,
    }
    .to_owned()
}

fn display_count(count: u64) -> String {
    let digits = count.to_string();
    let mut display = String::new();
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            display.push(',');
        }
        display.push(character);
    }
    display
}

fn statistics(
    email: &str,
    subscription_name: &str,
    period: &MonthPeriod,
    sources: &[String],
    counts: &BTreeMap<String, u64>,
) -> Value {
    let sources: BTreeSet<&String> = sources.iter().chain(counts.keys()).collect();
    let total: u64 = counts.values().sum();
    let mut rows: Vec<Value> = sources
        .into_iter()
        .map(|source| {
            let count = counts.get(source).copied().unwrap_or(0);
            let share = if total == 0 {
                0.0
            } else {
                count as f64 * 100.0 / total as f64
            };
            json!({
                "source": source, "name": source_name(source), "count": count,
                "count_display": display_count(count), "share": share,
                "share_display": format!("{share:.1}%"),
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        b["count"]
            .as_u64()
            .cmp(&a["count"].as_u64())
            .then_with(|| a["source"].as_str().cmp(&b["source"].as_str()))
    });
    json!({
        "email": email, "subscription_name": subscription_name,
        "period": period.label, "period_key": period.key,
        "period_start": period.start.to_rfc3339(), "period_end": period.end.to_rfc3339(),
        "date_range": period.date_range, "timezone": "Asia/Hong_Kong",
        "total": total, "total_display": display_count(total),
        "active_sources": counts.values().filter(|count| **count > 0).count(),
        "source_count": rows.len(), "by_source": rows,
    })
}

fn aggregation_filter(id: ObjectId, emails: &[String], period: &MonthPeriod) -> Document {
    doc! {
        "subscription_id": id,
        "email": {"$in": emails},
        "sent_at": {
            "$gte": bson::DateTime::from_millis(period.start.timestamp_millis()),
            "$lt": bson::DateTime::from_millis(period.end.timestamp_millis()),
        },
    }
}

async fn prepare(
    state: &AppState,
    sub: &Document,
    period: &MonthPeriod,
) -> Result<Vec<Value>, String> {
    let id = sub
        .get_object_id("_id")
        .map_err(|_| "Subscription ID is missing.")?;
    let value = db::bson_json(sub);
    let emails = subscriptions::recipients(&value)?;
    let filters = &value["newsletter_profile"]["filters"];
    let mut sources =
        subscriptions::selected_provider_names(filters, &state.cfg.vulnerabilities_collection);
    if sources.is_empty() && filters["collections_mode"] != "selected" {
        sources = subscriptions::source_providers(state).await?;
    }
    // Delivery history retains provider IDs even though all news now lives in
    // one MongoDB collection. Never group newsletter statistics by "news".
    let mut cursor = db::collection(&state.web, "newsletter_deliveries")
        .aggregate([
            doc! {"$match": aggregation_filter(id, &emails, period)},
            doc! {"$group": {
                "_id": {
                    "email": "$email",
                    "source": {"$ifNull": ["$source_provider", "$source_collection"]},
                },
                "count": {"$sum": 1},
            }},
        ])
        .await
        .map_err(|error| format!("Unable to read monthly newsletter delivery history: {error}"))?;
    let mut by_recipient: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    while let Some(row) = cursor
        .try_next()
        .await
        .map_err(|error| format!("Unable to read monthly newsletter delivery history: {error}"))?
    {
        let identity = row
            .get_document("_id")
            .map_err(|_| "Invalid delivery statistics group.")?;
        let email = identity
            .get_str("email")
            .map_err(|_| "Delivery statistics recipient is missing.")?;
        let raw = identity.get_str("source").unwrap_or("").trim();
        let source = raw.strip_suffix("_review").unwrap_or(raw);
        let source = if source.is_empty() || source == state.cfg.vulnerabilities_collection {
            "Unspecified source"
        } else {
            source
        };
        let count = match row.get("count") {
            Some(Bson::Int32(count)) => u64::try_from(*count).ok(),
            Some(Bson::Int64(count)) => u64::try_from(*count).ok(),
            _ => None,
        }
        .ok_or("Invalid delivery statistics count.")?;
        *by_recipient
            .entry(email.to_owned())
            .or_default()
            .entry(source.to_owned())
            .or_default() += count;
    }
    Ok(emails
        .iter()
        .map(|email| {
            statistics(
                email,
                value["username"].as_str().unwrap_or(""),
                period,
                &sources,
                by_recipient.get(email).unwrap_or(&BTreeMap::new()),
            )
        })
        .collect())
}

fn render(state: &AppState, statistics: &Value) -> Result<String, String> {
    state
        .templates
        .get_template("subscriptions/statistics_email.html")
        .and_then(|template| template.render(statistics))
        .map_err(|error| format!("Unable to render monthly newsletter statistics: {error}"))
}

pub(crate) async fn preview(state: &AppState, sub: &Document) -> Result<String, String> {
    let period = MonthPeriod::previous(Utc::now());
    let snapshots = prepare(state, sub, &period).await?;
    render(
        state,
        snapshots
            .first()
            .ok_or("A statistics recipient is required.")?,
    )
}

fn schedule_due(sub: &Document, now: DateTime<Utc>, period: &MonthPeriod) -> bool {
    let Ok(profile) = sub.get_document("newsletter_profile") else {
        return false;
    };
    if !db::bool_field(profile, "enabled")
        || !db::bool_field(profile, "statistic_schedule_enabled")
        || now < period.due
        || sub.get_str("statistic_schedule_last_period").ok() == Some(&period.key)
    {
        return false;
    }
    // A new subscription starts with its own signup month, not a summary of
    // the month before it existed. Existing missed schedules catch up once.
    sub.get_datetime("created_at")
        .ok()
        .is_none_or(|created| created.timestamp_millis() < period.end.timestamp_millis())
}

async fn claim(
    state: &AppState,
    id: ObjectId,
    period: &MonthPeriod,
    scheduled: bool,
    now: DateTime<Utc>,
    owner: ObjectId,
) -> Result<bool, String> {
    let mut filter = doc! {
        "_id": id, "newsletter_profile.enabled": true,
        "$or": [
            {"statistic_schedule_claim_until": {"$exists": false}},
            {"statistic_schedule_claim_until": {"$lte": bson::DateTime::from_millis(now.timestamp_millis())}},
        ],
    };
    if scheduled {
        filter.insert("newsletter_profile.statistic_schedule_enabled", true);
        filter.insert("statistic_schedule_last_period", doc! {"$ne": &period.key});
    }
    db::collection(&state.web, "sub_account")
        .find_one_and_update(filter, doc! {"$set": {
            "statistic_schedule_claim_owner": owner,
            "statistic_schedule_claim_until": bson::DateTime::from_millis((now + chrono::Duration::minutes(10)).timestamp_millis()),
        }})
        .await
        .map(|sub| sub.is_some())
        .map_err(|error| format!("Unable to claim monthly statistics delivery: {error}"))
}

async fn deliver(
    state: &AppState,
    sub: &Document,
    period: &MonthPeriod,
    scheduled: bool,
    owner: ObjectId,
) -> Result<Vec<Value>, String> {
    let id = sub
        .get_object_id("_id")
        .map_err(|_| "Subscription ID is missing.")?;
    let snapshots = prepare(state, sub, period).await?;
    let html = snapshots
        .iter()
        .map(|stats| render(state, stats))
        .collect::<Result<Vec<_>, _>>()?;
    for (stats, html) in snapshots.iter().zip(&html) {
        let email = stats["email"]
            .as_str()
            .ok_or("Statistics recipient is missing.")?;
        let delivery_id = format!("{id}:{}:{email}", period.key);
        if scheduled
            && db::collection(&state.web, DELIVERY_LOG)
                .find_one(doc! {"_id": &delivery_id})
                .await
                .map_err(|error| format!("Unable to check monthly statistics delivery: {error}"))?
                .is_some()
        {
            continue;
        }
        let renewed = db::collection(&state.web, "sub_account").update_one(
            doc! {"_id": id, "statistic_schedule_claim_owner": owner},
            doc! {"$set": {"statistic_schedule_claim_until": bson::DateTime::from_millis((Utc::now() + chrono::Duration::minutes(10)).timestamp_millis())}},
        ).await.map_err(|error| format!("Unable to renew monthly statistics delivery: {error}"))?;
        if renewed.matched_count == 0 {
            return Err("Monthly statistics delivery claim was lost.".into());
        }
        mail::send(
            state,
            &[email.to_owned()],
            "individual",
            &format!("Newsletter delivery statistics: {}", period.label),
            html,
        )
        .await?;
        db::collection(&state.web, DELIVERY_LOG).update_one(
            doc! {"_id": delivery_id},
            doc! {"$set": {
                "subscription_id": id, "email": email, "period": &period.key,
                "sent_at": bson::DateTime::now(), "total": stats["total"].as_u64().unwrap_or(0) as i64,
                "mode": if scheduled { "scheduled" } else { "manual" },
            }},
        ).upsert(true).await.map_err(|error| format!("Statistics email was sent but delivery history could not be saved: {error}"))?;
    }
    Ok(snapshots)
}

pub(crate) async fn send(
    state: &AppState,
    sub: &Document,
    scheduled: bool,
) -> Result<Vec<Value>, String> {
    let now = Utc::now();
    let period = MonthPeriod::previous(now);
    let id = sub
        .get_object_id("_id")
        .map_err(|_| "Subscription ID is missing.")?;
    let owner = ObjectId::new();
    if !claim(state, id, &period, scheduled, now, owner).await? {
        return if scheduled {
            Ok(Vec::new())
        } else {
            Err("Monthly statistics are already being sent. Try again shortly.".into())
        };
    }
    let result = deliver(state, sub, &period, scheduled, owner).await;
    let update = match &result {
        Ok(_) => doc! {
            "$set": {"statistic_schedule_last_period": &period.key,
                "newsletter_profile.statistic_last_sent_at": bson::DateTime::now(),
                "newsletter_profile.statistic_last_period": &period.key},
            "$unset": {"statistic_schedule_claim_until": "", "statistic_schedule_claim_owner": "",
                "newsletter_profile.statistic_last_error": "", "newsletter_profile.statistic_last_error_at": ""},
        },
        Err(error) => {
            let mut update = doc! {
                "$set": {"newsletter_profile.statistic_last_error": error, "newsletter_profile.statistic_last_error_at": bson::DateTime::now()},
                "$unset": {"statistic_schedule_claim_owner": ""},
            };
            if scheduled {
                update.get_document_mut("$set").unwrap().insert(
                    "statistic_schedule_claim_until",
                    bson::DateTime::from_millis(
                        (Utc::now() + chrono::Duration::minutes(15)).timestamp_millis(),
                    ),
                );
            } else {
                update
                    .get_document_mut("$unset")
                    .unwrap()
                    .insert("statistic_schedule_claim_until", "");
            }
            update
        }
    };
    db::collection(&state.web, "sub_account")
        .update_one(
            doc! {"_id": id, "statistic_schedule_claim_owner": owner},
            update,
        )
        .await
        .map_err(|error| format!("Unable to save monthly statistics schedule status: {error}"))?;
    result
}

pub(crate) async fn scheduled_tick(state: &AppState, sub: &Document) {
    let now = Utc::now();
    let period = MonthPeriod::previous(now);
    if !schedule_due(sub, now, &period) {
        return;
    }
    match send(state, sub, true).await {
        Ok(statistics) if !statistics.is_empty() => {
            tracing::info!(subscription_id = %db::id_string(sub), period = %period.key, recipients = statistics.len(), "Monthly newsletter statistics delivered")
        }
        Err(error) => {
            tracing::error!(subscription_id = %db::id_string(sub), period = %period.key, %error, "Monthly newsletter statistics delivery failed")
        }
        _ => {}
    }
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
    fn reporting_month_uses_hong_kong_boundaries_and_leap_years() {
        let september = MonthPeriod::previous(utc("2026-09-30T16:00:00Z"));
        assert_eq!(september.key, "2026-09");
        assert_eq!(september.start, utc("2026-08-31T16:00:00Z"));
        assert_eq!(september.end, utc("2026-09-30T16:00:00Z"));
        let february = MonthPeriod::previous(utc("2024-03-01T01:00:00Z"));
        assert_eq!(february.date_range, "1–29 February 2024");
        assert_eq!(
            MonthPeriod::previous(utc("2027-01-01T01:00:00Z")).key,
            "2026-12"
        );
    }

    #[test]
    fn monthly_schedule_obeys_opt_in_due_time_and_signup_month() {
        let mut sub = doc! {"newsletter_profile": {"enabled": true, "statistic_schedule_enabled": true}, "created_at": bson::DateTime::from_millis(utc("2026-09-15T00:00:00Z").timestamp_millis())};
        let now = utc("2026-10-01T01:00:00Z");
        let period = MonthPeriod::previous(now);
        assert!(!schedule_due(
            &sub,
            now - chrono::Duration::seconds(1),
            &period
        ));
        assert!(schedule_due(&sub, now, &period));
        assert!(schedule_due(
            &sub,
            now + chrono::Duration::days(12),
            &period
        ));
        sub.insert("statistic_schedule_last_period", "2026-09");
        assert!(!schedule_due(&sub, now, &period));
        sub.remove("statistic_schedule_last_period");
        sub.insert(
            "created_at",
            bson::DateTime::from_millis(period.end.timestamp_millis()),
        );
        assert!(!schedule_due(&sub, now, &period));
        sub.remove("created_at");
        sub.get_document_mut("newsletter_profile")
            .unwrap()
            .insert("statistic_schedule_enabled", false);
        assert!(!schedule_due(&sub, now, &period));
    }

    #[test]
    fn source_summary_includes_zero_delivery_sources_and_escapes_email_html() {
        let period = MonthPeriod::previous(utc("2026-10-13T00:00:00Z"));
        let stats = statistics(
            "team@example.com",
            "Security team",
            &period,
            &["hkcert".into(), "msrc".into()],
            &BTreeMap::from([("cve".into(), 1248), ("hkcert".into(), 32)]),
        );
        assert_eq!(stats["total"], 1280);
        assert_eq!(stats["total_display"], "1,280");
        assert_eq!(stats["source_count"], 3);
        assert_eq!(stats["by_source"][0]["source"], "cve");
        assert_eq!(stats["by_source"][2]["count"], 0);
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let env = crate::view::environment(root);
        let template = env
            .get_template("subscriptions/statistics_email.html")
            .unwrap();
        let html = template.render(&stats).unwrap();
        assert!(html.contains("September 2026"));
        assert!(html.contains("CVE Program"));
        assert!(html.contains("Microsoft Security Response Center"));
        assert!(html.contains("1,280"));
        if let Ok(path) = std::env::var("STATISTICS_PREVIEW_PATH") {
            std::fs::write(path, &html).unwrap();
        }
        let unsafe_stats = statistics(
            "<img src=x>@example.com",
            "<script>alert(1)</script>",
            &period,
            &["<img src=x>".into()],
            &BTreeMap::new(),
        );
        let html = template.render(unsafe_stats).unwrap();
        assert!(!html.contains("<img src=x>"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("No successful newsletter deliveries"));
    }

    #[tokio::test]
    #[ignore = "requires STATISTICS_TEST_MONGO_URI for a disposable test database"]
    async fn monthly_statistics_isolate_subscriptions_dates_and_scheduler_claims() {
        use std::{path::PathBuf, sync::Arc};
        let uri =
            std::env::var("STATISTICS_TEST_MONGO_URI").expect("Set STATISTICS_TEST_MONGO_URI");
        let client = mongodb::Client::with_uri_str(&uri).await.unwrap();
        let database = client.database(&format!(
            "monthly_statistics_test_{}",
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
            templates: Arc::new(crate::view::environment(&root)),
            http: reqwest::Client::new(),
        };
        let id = ObjectId::new();
        let sub = doc! {"_id": id, "username": "Test", "emails": ["one@example.com", "two@example.com"], "newsletter_profile": {"enabled": true, "statistic_schedule_enabled": true, "filters": {"collections_mode": "selected", "sources": ["cve", "msrc", "nvd"]}}};
        db::collection(&database, "sub_account")
            .insert_one(sub.clone())
            .await
            .unwrap();
        let now = utc("2026-10-13T00:00:00Z");
        let period = MonthPeriod::previous(now);
        let delivery = |subscription_id, email: &str, source: &str, sent: i64| doc! {"subscription_id": subscription_id, "email": email, "source_collection": source, "sent_at": bson::DateTime::from_millis(sent)};
        let mut unified_delivery = delivery(
            id,
            "one@example.com",
            "test_news",
            period.start.timestamp_millis(),
        );
        unified_delivery.insert("source_provider", "msrc");
        db::collection(&database, "newsletter_deliveries")
            .insert_many([
                unified_delivery,
                delivery(
                    id,
                    "one@example.com",
                    "cve",
                    period.start.timestamp_millis(),
                ),
                delivery(
                    id,
                    "one@example.com",
                    "cve_review",
                    period.end.timestamp_millis() - 1,
                ),
                delivery(
                    id,
                    "two@example.com",
                    "hkcert",
                    period.start.timestamp_millis(),
                ),
                delivery(
                    ObjectId::new(),
                    "one@example.com",
                    "cve",
                    period.start.timestamp_millis(),
                ),
                delivery(
                    id,
                    "one@example.com",
                    "cve",
                    period.start.timestamp_millis() - 1,
                ),
                delivery(id, "one@example.com", "cve", period.end.timestamp_millis()),
            ])
            .await
            .unwrap();
        let stats = prepare(&state, &sub, &period).await.unwrap();
        assert_eq!(stats[0]["total"], 3);
        assert_eq!(stats[0]["by_source"][0]["source"], "cve");
        assert_eq!(stats[0]["by_source"][1]["source"], "msrc");
        assert_eq!(stats[0]["by_source"][1]["count"], 1);
        assert_eq!(stats[0]["by_source"][2]["source"], "nvd");
        assert_eq!(stats[0]["by_source"][2]["count"], 0);
        assert_eq!(stats[1]["total"], 1);
        assert_eq!(stats[1]["by_source"][0]["source"], "hkcert");
        let (a, b) = tokio::join!(
            claim(&state, id, &period, true, now, ObjectId::new()),
            claim(&state, id, &period, true, now, ObjectId::new())
        );
        assert_ne!(
            a.unwrap(),
            b.unwrap(),
            "Only one scheduler may claim a monthly delivery"
        );
        let claimed = db::collection(&database, "sub_account")
            .find_one(doc! {"_id": id})
            .await
            .unwrap()
            .unwrap();
        let owner = claimed
            .get_object_id("statistic_schedule_claim_owner")
            .unwrap();
        db::collection(&database, DELIVERY_LOG)
            .insert_many(
                ["one@example.com", "two@example.com"]
                    .map(|email| doc! {"_id": format!("{id}:{}:{email}", period.key)}),
            )
            .await
            .unwrap();
        assert_eq!(
            deliver(&state, &sub, &period, true, owner)
                .await
                .unwrap()
                .len(),
            2,
            "A restarted or retried scheduler skips recipients already sent this month's statistics"
        );
        assert_eq!(
            db::collection(&database, DELIVERY_LOG)
                .count_documents(doc! {})
                .await
                .unwrap(),
            2
        );
        db::collection(&database, "sub_account").update_one(doc! {"_id": id}, doc! {"$set": {"statistic_schedule_last_period": &period.key}, "$unset": {"statistic_schedule_claim_until": ""}}).await.unwrap();
        assert!(
            !claim(&state, id, &period, true, now, ObjectId::new())
                .await
                .unwrap()
        );
        database.drop().await.unwrap();
        let unavailable =
            mongodb::Client::with_uri_str("mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=500")
                .await
                .unwrap();
        let mut unavailable_state = state.clone();
        unavailable_state.web = unavailable.database("unavailable");
        assert!(
            prepare(&unavailable_state, &sub, &period).await.is_err(),
            "An unavailable database must not appear as zero deliveries"
        );
    }
}
