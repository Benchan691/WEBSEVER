use crate::{AppState, db, mail, newsletter_statistics, newsletters, reports, subscriptions};
use chrono::TimeZone;
use mongodb::bson::{self, Document, doc, oid::ObjectId};
use serde_json::{Value, json};
use tokio::time::{Duration, interval};

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}
fn recipients(value: &Value) -> Vec<String> {
    value["emails"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
fn text_hash(value: &Value) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.to_string().hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

fn bson_time(value: &mongodb::bson::Bson) -> Option<chrono::DateTime<chrono::Utc>> {
    match value {
        mongodb::bson::Bson::DateTime(dt) => chrono::Utc
            .timestamp_millis_opt(dt.timestamp_millis())
            .single(),
        mongodb::bson::Bson::String(s) => chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|d| d.with_timezone(&chrono::Utc)),
        _ => None,
    }
}
fn next_cron(profile: &Value, now: chrono::DateTime<chrono::Utc>) -> Option<bson::DateTime> {
    let expression = crate::cron_schedule::expression(profile);
    match crate::cron_schedule::next_after(&expression, now) {
        Ok(next) => Some(bson::DateTime::from_millis(next.timestamp_millis())),
        Err(error) => {
            tracing::error!(cron_expression = %expression, %error, "Invalid scheduled report cron expression");
            None
        }
    }
}
async fn heartbeat(state: &AppState) {
    let _=db::collection(&state.web,"scheduler_health").update_one(doc!{"_id":"email_scheduler"},doc!{"$set":{"last_tick_at":bson::DateTime::now(),"hostname":std::env::var("HOSTNAME").unwrap_or_default(),"pid":std::process::id() as i64,"updated_at":bson::DateTime::now()}}).upsert(true).await;
}

async fn newsletter_failure(state: &AppState, id: ObjectId, error: &str) {
    tracing::error!(subscription_id = %id, error, "Newsletter delivery failed");
    let now = bson::DateTime::now();
    let _ = db::collection(&state.web, "sub_account")
        .update_one(
            doc! {"_id":id},
            doc! {"$set":{
                "newsletter_profile.last_error":error,
                "newsletter_profile.last_error_at":now,
            }},
        )
        .await;
    let _ = db::collection(&state.web, "scheduler_health")
        .update_one(
            doc! {"_id":"email_scheduler"},
            doc! {"$set":{
                "newsletter.last_error":error,
                "newsletter.last_error_at":now,
                "newsletter.subscription_id":id,
            }},
        )
        .upsert(true)
        .await;
}

async fn newsletter_success(state: &AppState, id: ObjectId, cursor: &str, delivered: bool) {
    let now = bson::DateTime::now();
    let mut set = doc! {"newsletter_profile.delivery_cursor":cursor};
    if delivered {
        set.insert("newsletter_profile.last_success_at", now);
    }
    let _ = db::collection(&state.web, "sub_account")
        .update_one(
            doc! {"_id":id},
            doc! {
                "$set":set,
                "$unset":{
                    "newsletter_profile.last_error":"",
                    "newsletter_profile.last_error_at":"",
                }
            },
        )
        .await;
    if delivered {
        let _ = db::collection(&state.web, "scheduler_health")
            .update_one(
                doc! {"_id":"email_scheduler"},
                doc! {
                    "$set":{"newsletter.last_success_at":now},
                    "$unset":{
                        "newsletter.last_error":"",
                        "newsletter.last_error_at":"",
                        "newsletter.subscription_id":"",
                    }
                },
            )
            .upsert(true)
            .await;
    }
}
async fn manager_paused(state: &AppState, sub: &Document) -> bool {
    let Ok(id) = sub.get_object_id("managed_by_user_id") else {
        return false;
    };
    let manager = db::find_one(&state.web, &state.cfg.account_collection, doc! {"_id":id})
        .await
        .ok()
        .flatten();
    manager.is_some_and(|u| {
        db::bool_field(&u, "disabled")
            && db::bool_field(&u, "pause_managed_subscriptions_when_disabled")
    })
}
async fn scheduled_report(state: &AppState, sub: &Document) {
    let id = match sub.get_object_id("_id") {
        Ok(v) => v,
        Err(_) => return,
    };
    let value = db::bson_json(sub);
    let profile = &value["report_profile"];
    if profile["enabled"] != true || profile["schedule_enabled"] != true {
        return;
    }
    let now = chrono::Utc::now();
    let next = sub
        .get_document("report_profile")
        .ok()
        .and_then(|v| v.get("next_run_at"))
        .and_then(bson_time);
    if next.is_none() {
        let Some(next) = next_cron(profile, now) else {
            return;
        };
        let _ = db::collection(&state.web, "sub_account")
            .update_one(
                doc! {"_id":id},
                doc! {"$set":{"report_profile.next_run_at":next}},
            )
            .await;
        return;
    }
    if next.is_some_and(|v| v > now) {
        return;
    }
    let Some(next) = next_cron(profile, now) else {
        return;
    };
    let _=db::collection(&state.web,"sub_account").update_one(doc!{"_id":id},doc!{"$set":{"report_profile.next_run_at":next,"report_profile.last_run_at":bson::DateTime::now()}}).await;
    let mode = profile["generation_mode"].as_str().unwrap_or("template");
    let matches = match subscriptions::match_profile(state, profile, 500).await {
        Ok(matches) => matches,
        Err(error) => {
            tracing::error!(%error, subscription_id = %id, "Unable to match scheduled report records");
            return;
        }
    };
    let count = matches.len();
    if count == 0 {
        let _ = db::collection(&state.web, "sub_account")
            .update_one(
                doc! {"_id":id},
                doc! {"$set":{"report_profile.last_match_count":0}},
            )
            .await;
        return;
    }
    let now = bson::DateTime::now();
    let mut job = doc! {"generation_mode":mode,"effective_generation_mode":mode,"report_language":"en","effective_report_language":"en","search_prompt":text(profile,"search_prompt"),"input_source":"review_selections","source_count":count as i64,"processed_count":0,"current_position":0,"item_fallback_count":0,"status":"queued","created_at":now,"updated_at":now,"provider":if mode=="template"{"Fixed Template"}else{"Search API + llama-server"},"model":if mode=="template"{"Fixed Template"}else{"Enriched Weekly"},"progress_percent":0,"progress_current":0,"progress_total":count as i64,"pipeline_logs":[]};
    if let Ok(owner) = sub.get_object_id("managed_by_user_id") {
        job.insert("managed_by_user_id", owner);
    }
    let Ok(inserted) = db::collection(&state.web, "report_jobs")
        .insert_one(job)
        .await
    else {
        return;
    };
    let Some(job_id) = inserted.inserted_id.as_object_id() else {
        return;
    };
    let inputs:Vec<Document>=matches.iter().enumerate().map(|(position,item)|doc!{"job_id":job_id,"position":position as i64,"source_collection":item["source_collection"].as_str().unwrap_or(""),"selection_id":item["selection_id"].as_str().unwrap_or("")}).collect();
    if db::collection(&state.web, "report_job_inputs")
        .insert_many(inputs)
        .await
        .is_err()
    {
        return;
    }
    let _=db::collection(&state.web,"sub_account").update_one(doc!{"_id":id},doc!{"$set":{"report_profile.last_job_id":job_id.to_hex(),"report_profile.last_match_count":count as i64}}).await;
    tokio::spawn(reports::run(state.clone(), job_id));
    tokio::spawn(send_completed_report(state.clone(), job_id, sub.clone()));
}
async fn send_completed_report(state: AppState, id: ObjectId, sub: Document) {
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let Some(job) = db::find_one(&state.web, "report_jobs", doc! {"_id":id})
            .await
            .ok()
            .flatten()
        else {
            return;
        };
        match job.get_str("status").unwrap_or("") {
            "failed" | "cancelled" => return,
            "completed" => {
                let report = job
                    .get_document("report")
                    .map(db::bson_json)
                    .unwrap_or(json!({}));
                let title = report["title"].as_str().unwrap_or("Cybersecurity Report");
                let mut html = format!("<html><body><h1>{}</h1>", html_escape(title));
                if let Some(items) = report["highlights"].as_array() {
                    for item in items {
                        html.push_str(&format!(
                            "<h2>{}</h2><p>{}</p>",
                            html_escape(item["title"].as_str().unwrap_or("")),
                            html_escape(item["summary"].as_str().unwrap_or(""))
                        ));
                    }
                }
                if let Some(items) = report
                    .pointer("/vulnerability_detail_table/rows")
                    .and_then(Value::as_array)
                {
                    for item in items {
                        html.push_str(&format!(
                            "<h2>{}</h2><p>{}</p>",
                            html_escape(item["cve_id"].as_str().unwrap_or("")),
                            html_escape(item["what_happened"].as_str().unwrap_or(""))
                        ));
                    }
                }
                html.push_str("</body></html>");
                let value = db::bson_json(&sub);
                let emails = recipients(&value);
                let result = match subscriptions::copy_recipients(&value) {
                    Ok(copies) => {
                        mail::send(&state, &emails, &copies, "individual", title, &html).await
                    }
                    Err(error) => Err(error),
                };
                let status = if result.is_ok() { "sent" } else { "failed" };
                let error = result.err().unwrap_or_default();
                let _ = db::collection(&state.web, "report_jobs")
                    .update_one(
                        doc! {"_id":id},
                        doc! {"$set":{"delivery_status":status,"delivery_error":error}},
                    )
                    .await;
                return;
            }
            _ => {}
        }
    }
}
async fn newsletters_tick(state: &AppState, sub: &Document) {
    let id = match sub.get_object_id("_id") {
        Ok(v) => v,
        Err(_) => return,
    };
    let value = db::bson_json(sub);
    let profile = &value["newsletter_profile"];
    if profile["enabled"] != true {
        return;
    }
    // A subscription follows news from its last change onward: whenever the
    // subscription scope changes (filters, enabled state), the cursor
    // restarts at now and the historical backlog is intentionally skipped.
    let filters_hash =
        text_hash(&json!({"enabled":profile["enabled"],"filters":profile["filters"]}));
    if profile["filters_hash"].as_str().unwrap_or("") != filters_hash {
        let now = chrono::Utc::now().to_rfc3339();
        let _ = db::collection(&state.web, "sub_account")
            .update_one(
                doc! {"_id":id},
                doc! {"$set":{"newsletter_profile.delivery_cursor":now,"newsletter_profile.filters_hash":filters_hash}},
            )
            .await;
        return;
    }
    let cursor = profile["delivery_cursor"].as_str().unwrap_or("");
    if cursor.is_empty() {
        let now = chrono::Utc::now().to_rfc3339();
        let _ = db::collection(&state.web, "sub_account")
            .update_one(
                doc! {"_id":id},
                doc! {"$set":{"newsletter_profile.delivery_cursor":now}},
            )
            .await;
        return;
    }
    let emails = recipients(&value);
    if emails.is_empty() {
        newsletter_failure(state, id, "Newsletter subscription has no recipients.").await;
        return;
    }
    let copies = match subscriptions::copy_recipients(&value) {
        Ok(value) => value,
        Err(error) => {
            newsletter_failure(state, id, &error).await;
            return;
        }
    };
    let config = newsletters::template_config(state).await;
    let Some(cursor_time) = chrono::DateTime::parse_from_rfc3339(cursor)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
    else {
        newsletter_failure(state, id, "Newsletter delivery cursor is invalid.").await;
        return;
    };
    let batch = match subscriptions::match_profile_after(state, profile, cursor_time, 100).await {
        Ok(batch) => batch,
        Err(error) => {
            newsletter_failure(state, id, &error).await;
            return;
        }
    };
    let mut delivered = false;
    for item in batch.items {
        let source = item["source_collection"].as_str().unwrap_or("");
        let selection_id = item["selection_id"].as_str().unwrap_or("");
        let record = &item["document"];
        let mut pending = Vec::new();
        for email in &emails {
            let exists = db::find_one(
                &state.web,
                "newsletter_deliveries",
                doc! {"subscription_id":id,"email":email,"source_collection":source,"selection_id":selection_id},
            )
            .await
            .ok()
            .flatten()
            .is_some();
            if !exists {
                pending.push(email.clone())
            }
        }
        if pending.is_empty() {
            continue;
        }
        let newsletter = newsletters::normalize(record, source, &config);
        let html = match state
            .templates
            .get_template(newsletters::template_name(source))
            .and_then(|template| template.render(json!({"newsletter":newsletter})))
        {
            Ok(html) if !html.trim().is_empty() => html,
            Ok(_) => {
                newsletter_failure(state, id, "Newsletter template rendered an empty email.").await;
                return;
            }
            Err(error) => {
                newsletter_failure(
                    state,
                    id,
                    &format!("Unable to render newsletter email: {error}"),
                )
                .await;
                return;
            }
        };
        let subject = newsletter["subject"]
            .as_str()
            .unwrap_or("Security newsletter");
        for email in pending {
            if let Err(error) = mail::send(
                state,
                std::slice::from_ref(&email),
                &copies,
                "individual",
                subject,
                &html,
            )
            .await
            {
                newsletter_failure(state, id, &error).await;
                return;
            }
            let mut delivery = doc! {"subscription_id":id,"email":&email,"source_provider":source,"source_collection":source,"selection_id":selection_id,"title":newsletter["title"].as_str().unwrap_or(""),"database":&state.cfg.vulnerabilities_database,"sent_at":bson::DateTime::now()};
            if let Ok(owner) = sub.get_object_id("managed_by_user_id") {
                delivery.insert("managed_by_user_id", owner);
            }
            if let Err(error) = db::collection(&state.web, "newsletter_deliveries")
                .insert_one(delivery)
                .await
            {
                newsletter_failure(
                    state,
                    id,
                    &format!("Email was sent to {email}, but delivery history could not be saved: {error}"),
                )
                .await;
                return;
            }
            delivered = true;
        }
    }
    if let Some(cursor) = batch.last_scanned_at {
        newsletter_success(state, id, &cursor, delivered).await;
    }
}
async fn tick(state: &AppState) {
    heartbeat(state).await;
    let subscriptions = db::find_many(&state.web, "sub_account", doc! {}, 5000)
        .await
        .unwrap_or_default();
    for sub in subscriptions {
        if manager_paused(state, &sub).await {
            continue;
        }
        scheduled_report(state, &sub).await;
        newsletters_tick(state, &sub).await;
        newsletter_statistics::scheduled_tick(state, &sub).await;
    }
}
pub fn start(state: AppState) {
    tokio::spawn(async move {
        let mut timer = interval(Duration::from_secs(30));
        timer.tick().await;
        loop {
            timer.tick().await;
            tick(&state).await;
        }
    });
}
