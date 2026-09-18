use crate::{AppState, ReqCtx, db, render, reviews, view};
use axum::{
    body::Bytes,
    http::{Method, StatusCode, header},
    response::Response,
};
use futures::stream;
use mongodb::bson::{self, Document, doc, oid::ObjectId};
use serde_json::{Value, json};

fn job_public(document: &Document) -> Value {
    let mut job = db::public_id(db::bson_json(document));
    if let Some(obj) = job.as_object_mut() {
        for name in [
            "records",
            "managed_by_user_id",
            "report",
            "html",
            "html_path",
            "html_updated_at",
            "pipeline_logs",
            "company_ai_conversation_id",
        ] {
            obj.remove(name);
        }
        if let Some(translations) = obj.get_mut("translations").and_then(Value::as_object_mut) {
            for (_, translation) in translations {
                if let Some(t) = translation.as_object_mut() {
                    t.remove("report");
                }
            }
        }
    }
    job
}
fn job_filter(state: &AppState, ctx: &ReqCtx, id: ObjectId) -> Document {
    if ctx.is_top_admin(state) {
        doc! {"_id":id}
    } else {
        doc! {"_id":id,"managed_by_user_id":ctx.user_id()}
    }
}
async fn job(state: &AppState, ctx: &ReqCtx, id: &str) -> Option<Document> {
    let id = db::object_id(id)?;
    db::find_one(&state.web, "report_jobs", job_filter(state, ctx, id))
        .await
        .ok()
        .flatten()
}
async fn fields(ctx: &ReqCtx) -> Result<(Value, Option<Vec<u8>>), String> {
    let content_type = ctx
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with("multipart/form-data") {
        return Ok((ctx.json.clone(), None));
    }
    let boundary = multer::parse_boundary(content_type).map_err(|e| e.to_string())?;
    let bytes = Bytes::from(ctx.body.clone());
    let body = stream::once(async move { Ok::<Bytes, std::io::Error>(bytes) });
    let mut multipart = multer::Multipart::new(body, boundary);
    let mut map = serde_json::Map::new();
    let mut upload = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| e.to_string())? {
        let name = field.name().unwrap_or("").to_owned();
        let bytes = field.bytes().await.map_err(|e| e.to_string())?;
        if name == "json_file" {
            if bytes.len() > 20 * 1024 * 1024 {
                return Err("Uploaded JSON is limited to 20 MB.".into());
            }
            upload = Some(bytes.to_vec());
        } else {
            map.insert(
                name,
                Value::String(String::from_utf8_lossy(&bytes).to_string()),
            );
        }
    }
    Ok((Value::Object(map), upload))
}
fn first_text(value: &Value, fields: &[&str]) -> String {
    for key in fields {
        if let Some(v) = value.get(*key) {
            if let Some(s) = v.as_str() {
                if !s.trim().is_empty() {
                    return s.trim().to_owned();
                }
            }
            if let Some(a) = v.as_array() {
                if let Some(s) = a.iter().find_map(Value::as_str) {
                    if !s.trim().is_empty() {
                        return s.trim().to_owned();
                    }
                }
            }
        }
    }
    String::new()
}
fn strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => {
            if s.trim().is_empty() {
                vec![]
            } else {
                vec![s.trim().to_owned()]
            }
        }
        Value::Array(items) => items.iter().flat_map(strings).collect(),
        Value::Object(map) => map.values().flat_map(strings).collect(),
        _ => vec![],
    }
}
fn template_report(records: &[Value]) -> Value {
    let mut highlights = Vec::new();
    let mut recommendations = Vec::new();
    let mut with_severity = 0;
    let mut with_affected = 0;
    let mut with_recommendation = 0;
    let mut with_reference = 0;
    for (index, record) in records.iter().enumerate() {
        let details = &record["details"];
        let title = first_text(record, &["title", "vulName", "advisory_title"]);
        let title = if title.is_empty() {
            let v = first_text(
                details,
                &["title", "vulName", "advisory_title", "code", "cve"],
            );
            if v.is_empty() {
                format!("Vulnerability record {}", index + 1)
            } else {
                v
            }
        } else {
            title
        };
        let code = first_text(record, &["code", "cve", "cve_ids"]);
        let severity = first_text(record, &["severity", "risk", "priority"]);
        let severity = if severity.is_empty() {
            first_text(details, &["severity", "risk", "priority", "hazardLevel"])
        } else {
            severity
        };
        let summary = first_text(details, &["summary", "description", "overview", "impacts"]);
        let affected = [
            "affected",
            "affected_products",
            "systems_affected",
            "products",
        ]
        .iter()
        .flat_map(|key| strings(&details[*key]))
        .collect::<Vec<_>>();
        let refs = ["references", "reference_links", "related_links", "urls"]
            .iter()
            .flat_map(|key| strings(&details[*key]))
            .collect::<Vec<_>>();
        let recs = [
            "recommendation",
            "recommendations",
            "solution",
            "solutions",
            "remediation",
            "mitigation",
            "mitigations",
            "patch",
        ]
        .iter()
        .flat_map(|key| strings(&details[*key]))
        .collect::<Vec<_>>();
        if !severity.is_empty() {
            with_severity += 1
        }
        if !affected.is_empty() {
            with_affected += 1
        }
        if !recs.is_empty() {
            with_recommendation += 1
        }
        if !refs.is_empty() {
            with_reference += 1
        };
        recommendations.extend(recs.clone());
        highlights.push(json!({"title":title,"code":code,"severity":severity,"summary":summary,"affected":affected,"references":refs,"source_link":first_text(&record["source"],&["detail_url","url"]),"newsletter":{"overview":summary,"severity":if severity.is_empty(){vec![]}else{vec![severity.clone()]},"impacts":[],"affected":affected,"cves":if code.is_empty(){vec![]}else{vec![code.clone()]},"recommendations":recs,"references":refs,"related_links":[],"show_severity":!severity.is_empty(),"show_impacts":false,"show_affected":!affected.is_empty(),"show_recommendations":true,"labels":{"overview":"Overview:","severity":"Severity:","affected":"Affected system:","recommendations":"Recommendations:","references":"References:"}}}));
    }
    let n = records.len();
    let summary = format!(
        "This report contains {n} vulnerability {}. Severity or status data is available for {with_severity} of {n} records. Affected product or system data is available for {with_affected} of {n} records. Remediation guidance is available for {with_recommendation} of {n} records.",
        if n == 1 { "record" } else { "records" }
    );
    recommendations.sort();
    recommendations.dedup();
    if recommendations.is_empty() {
        recommendations.push("No recommendations were provided in the source records.".into())
    }
    json!({"title":"Cybersecurity Report","executive_summary":summary,"highlights":highlights,"trends":[format!("Severity or status coverage: {with_severity} of {n} records."),format!("Affected product or system coverage: {with_affected} of {n} records."),format!("Remediation guidance coverage: {with_recommendation} of {n} records."),format!("Reference coverage: {with_reference} of {n} records.")],"recommendations":recommendations,"template_mode":true})
}
async fn update(state: &AppState, id: ObjectId, values: Document) {
    let _ = db::collection(&state.web, "report_jobs")
        .update_one(
            doc! {"_id":id,"status":{"$ne":"cancelled"}},
            doc! {"$set":values},
        )
        .await;
}
async fn log(state: &AppState, id: ObjectId, message: &str) {
    let _ = db::collection(&state.web, "report_jobs")
        .update_one(
            doc! {"_id":id},
            doc! {"$push":{"pipeline_logs":{"timestamp":bson::DateTime::now(),"message":message}}},
        )
        .await;
}
pub(crate) async fn run(state: AppState, id: ObjectId) {
    let jobs = db::collection(&state.web, "report_jobs");
    let Some(job) = jobs.find_one(doc! {"_id":id}).await.ok().flatten() else {
        return;
    };
    let mode = db::string(&job, "generation_mode");
    let now = bson::DateTime::now();
    update(&state,id,doc!{"status":"running","started_at":now,"updated_at":now,"progress_label":"Loading sources"}).await;
    let mut inputs = match db::find_sorted(
        &state.web,
        "report_job_inputs",
        doc! {"job_id":id},
        doc! {"position":1},
        500,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            update(&state, id, doc! {"status":"failed","error":e.to_string()}).await;
            return;
        }
    };
    let mut records = Vec::new();
    let total = inputs.len();
    for (position, item) in inputs.drain(..).enumerate() {
        if jobs
            .find_one(doc! {"_id":id,"status":"cancelled"})
            .await
            .ok()
            .flatten()
            .is_some()
        {
            return;
        }
        let record = if let Ok(details) = item.get_document("details") {
            let mut v = db::bson_json(&item);
            v["details"] = db::bson_json(details);
            v
        } else {
            let source = db::string(&item, "source_collection");
            let selection_id = db::string(&item, "selection_id");
            match reviews::resolve(&state, &source, &selection_id).await {
                Some(v) => db::bson_json(&v),
                None => {
                    update(&state,id,doc!{"status":"failed","error":format!("Selected vulnerability not found: {selection_id}")}).await;
                    return;
                }
            }
        };
        if !record["details"].is_object() {
            update(
                &state,
                id,
                doc! {"status":"failed","error":"Selected vulnerability has no details object."},
            )
            .await;
            return;
        }
        records.push(record);
        update(&state,id,doc!{"processed_count":(position+1) as i64,"current_position":(position+1) as i64,"progress_current":(position+1) as i64,"progress_percent":((position+1)*80/total.max(1)) as i64,"updated_at":bson::DateTime::now()}).await;
    }
    let report = if mode == "template" {
        template_report(&records)
    } else {
        match enriched_report(&state, &records, &db::string(&job, "search_prompt")).await {
            Ok(v) => v,
            Err(e) => {
                update(&state,id,doc!{"status":"failed","error":&e,"status_message":&e,"updated_at":bson::DateTime::now()}).await;
                log(&state, id, &e).await;
                return;
            }
        }
    };
    if jobs
        .find_one(doc! {"_id":id,"status":"cancelled"})
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return;
    }
    let now = bson::DateTime::now();
    update(&state,id,doc!{"status":"completed","report":db::json_doc(&report).unwrap_or_default(),"progress_percent":100,"progress_current":total as i64,"progress_total":total as i64,"progress_label":"Completed","completed_at":now,"updated_at":now}).await;
    log(&state, id, "Report completed.").await;
    let _ = db::collection(&state.web, "report_job_inputs")
        .delete_many(doc! {"job_id":id})
        .await;
}

fn parse_json_content(content: &str) -> Result<Value, String> {
    if let Ok(v) = serde_json::from_str(content) {
        return Ok(v);
    }
    let start = content
        .find('{')
        .ok_or("AI response did not contain JSON.")?;
    let end = content
        .rfind('}')
        .ok_or("AI response did not contain JSON.")?;
    serde_json::from_str(&content[start..=end])
        .map_err(|_| "AI response contained invalid JSON.".into())
}
async fn llama(state: &AppState, prompt: &str) -> Result<Value, String> {
    let base = state.cfg.value(
        "ENRICHED_LLM_BASE_URL",
        "/enriched/llm_base_url",
        json!("http://localhost:9000/v1"),
    );
    let model = state
        .cfg
        .value("ENRICHED_LLM_MODEL", "/enriched/llm_model", json!(""));
    let url = format!(
        "{}/chat/completions",
        base.as_str().unwrap_or("").trim_end_matches('/')
    );
    let payload = json!({"model":model,"messages":[{"role":"system","content":"Return only valid JSON. Do not include markdown."},{"role":"user","content":prompt}],"temperature":0.1,"max_tokens":4096});
    let response = state
        .http
        .post(url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(300))
        .send()
        .await
        .map_err(|e| format!("llama-server request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("llama-server returned HTTP {}", response.status()));
    }
    let value: Value = response.json().await.map_err(|e| e.to_string())?;
    let content = value
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .ok_or("llama-server returned no message.")?;
    parse_json_content(content)
}
async fn enriched_report(
    state: &AppState,
    records: &[Value],
    extra_prompt: &str,
) -> Result<Value, String> {
    let keys = std::env::var("TAVILY_API_KEYS")
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_else(|| {
            std::env::var("TAVILY_API_KEY")
                .ok()
                .into_iter()
                .collect::<Vec<_>>()
        });
    let key = keys
        .first()
        .filter(|v| !v.is_empty())
        .ok_or("TAVILY_API_KEY is required for enriched reports.")?;
    let mut cards = Vec::new();
    for record in records {
        let identifier = first_text(record, &["code", "cve", "title"]);
        let identifier = if identifier.is_empty() {
            first_text(&record["details"], &["id", "cveId", "cve_id"])
        } else {
            identifier
        };
        let query = format!("{identifier} vulnerability vendor advisory patch");
        let search = state
            .http
            .post("https://api.tavily.com/search")
            .json(&json!({"api_key":key,"query":query,"search_depth":"advanced","max_results":6}))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("Tavily search failed: {e}"))?;
        if !search.status().is_success() {
            return Err(format!("Tavily search returned HTTP {}", search.status()));
        }
        let result: Value = search.json().await.map_err(|e| e.to_string())?;
        let sources = result["results"].as_array().cloned().unwrap_or_default();
        let evidence: Vec<Value> = sources
            .iter()
            .take(6)
            .map(|v| json!({"title":v["title"],"url":v["url"],"content":v["content"]}))
            .collect();
        let prompt = format!(
            "Create a factual vulnerability card as JSON with keys cve_id, vendor, product, severity, what_happened, why_matters, how_to_respond, source_urls. Use only the source record and search evidence. If unknown, say not confirmed. Additional user focus: {}\nSource record: {}\nSearch evidence: {}",
            extra_prompt,
            record,
            json!(evidence)
        );
        let mut card = llama(state, &prompt).await?;
        if !card.is_object() {
            return Err("AI card must be a JSON object.".into());
        }
        for field in [
            "cve_id",
            "vendor",
            "product",
            "severity",
            "what_happened",
            "why_matters",
            "how_to_respond",
        ] {
            if card.get(field).and_then(Value::as_str).is_none() {
                card[field] = json!(if field == "cve_id" {
                    identifier.as_str()
                } else {
                    "Not confirmed from available sources."
                })
            }
        }
        let urls: Vec<String> = sources
            .iter()
            .filter_map(|v| v["url"].as_str())
            .filter(|url| url.starts_with("https://") || url.starts_with("http://"))
            .map(str::to_owned)
            .collect();
        card["source_urls"] = json!(urls);
        cards.push(card);
    }
    let ids = cards
        .iter()
        .filter_map(|c| c["cve_id"].as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Ok(
        json!({"title":"Enriched Weekly Cybersecurity Report","executive_summary":{"key_findings":[format!("Reviewed {} CVE candidate(s): {ids}.",cards.len())]},"vulnerability_detail_table":{"rows":cards}}),
    )
}
async fn translate(
    state: AppState,
    translation_id: ObjectId,
    source_id: ObjectId,
    language: String,
) {
    let jobs = db::collection(&state.web, "report_jobs");
    let Some(source) = jobs.find_one(doc! {"_id":source_id}).await.ok().flatten() else {
        return;
    };
    let report = source
        .get_document("report")
        .map(db::bson_json)
        .unwrap_or(json!({}));
    update(
        &state,
        translation_id,
        doc! {"status":"running","started_at":bson::DateTime::now()},
    )
    .await;
    let target = if language == "zh" {
        "Traditional Chinese"
    } else {
        "Simplified Chinese"
    };
    let prompt = format!(
        "Translate all human-readable strings in this JSON report into {target}. Preserve keys, URLs, CVE identifiers, and structure exactly. Return valid JSON only. Report: {report}"
    );
    match llama(&state, &prompt).await {
        Ok(translated) => {
            update(&state,translation_id,doc!{"status":"completed","report":db::json_doc(&translated).unwrap_or_default(),"progress_percent":100,"completed_at":bson::DateTime::now(),"updated_at":bson::DateTime::now()}).await;
            log(&state, translation_id, "Translation completed.").await;
        }
        Err(error) => {
            update(
                &state,
                translation_id,
                doc! {"status":"failed","error":error,"updated_at":bson::DateTime::now()},
            )
            .await;
        }
    }
}
async fn report_html(
    state: &AppState,
    ctx: &ReqCtx,
    document: &Document,
    attachment: bool,
) -> Response {
    let language = ctx.arg("language");
    let language = if language.is_empty() {
        db::string(document, "report_language")
    } else {
        language
    };
    if !matches!(language.as_str(), "en" | "zh" | "ch") {
        return view::error(StatusCode::BAD_REQUEST, "Invalid report language.");
    }
    let mut report = document.get_document("report").map(db::bson_json).ok();
    if language != "en" && db::string(document, "input_source") != "translation" {
        let id = document.get_object_id("_id").unwrap();
        let translation = db::find_one(
            &state.web,
            "report_jobs",
            doc! {"translated_from_job_id":id,"report_language":&language,"status":"completed"},
        )
        .await
        .ok()
        .flatten();
        report = translation.and_then(|t| t.get_document("report").map(db::bson_json).ok());
    }
    let Some(report) = report else {
        return view::error(StatusCode::NOT_FOUND, "Completed report not found.");
    };
    let mode = db::string(document, "generation_mode");
    let count = document.get_i64("source_count").unwrap_or(0);
    let generated = format!(
        "Generated {} from {} source records.",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"),
        count
    );
    let labels = json!({"executive_summary":"Executive Summary","trends":"Trends","affected":"Affected","references":"References","recommended_actions":"Recommended Actions","strategic_recommendations":"Strategic Recommendations","high_priority_vulnerabilities":"High-Priority Vulnerabilities","vulnerability_cards":"Vulnerability Cards","severity":"Severity","vulnerability_overview":"Vulnerability Overview","risk_and_impact":"Risk and Impact","remediation_guidance":"Remediation Guidance","source_references":"Source References"});
    let template = if mode == "template" {
        "reports/generated.html"
    } else {
        "reports/enriched.html"
    };
    let mut response = render(
        state,
        ctx,
        template,
        json!({"report":report,"generated_label":generated,"source_count":count,"report_language":language,"html_language":if language=="en"{"en"}else if language=="zh"{"zh-Hant"}else{"zh-Hans"},"labels":labels}),
    );
    if attachment {
        let id = db::id_string(document);
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"report-{id}.html\"")
                .parse()
                .unwrap(),
        );
    }
    response
}

pub async fn handle(state: &AppState, ctx: &ReqCtx) -> Option<Response> {
    if ctx.path == "/reports" && ctx.method == Method::GET {
        return Some(render(state, ctx, "reports/index.html", json!({})));
    }
    if ctx.path == "/api/reports" && ctx.method == Method::GET {
        let filter = ctx.owner_filter(state);
        return Some(
            match db::find_sorted(
                &state.web,
                "report_jobs",
                filter,
                doc! {"created_at":-1},
                100,
            )
            .await
            {
                Ok(rows) => view::json_response(
                    StatusCode::OK,
                    json!({"data":rows.iter().map(job_public).collect::<Vec<_>>()}),
                ),
                Err(_) => view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to load report history.",
                ),
            },
        );
    }
    if ctx.path == "/api/reports" && ctx.method == Method::POST {
        let (data, upload) = match fields(ctx).await {
            Ok(v) => v,
            Err(e) => return Some(view::error(StatusCode::BAD_REQUEST, &e)),
        };
        let mode = first_text(&data, &["generation_mode"]);
        let mode = if mode.is_empty() {
            if upload.is_some() {
                "template"
            } else {
                "enriched_weekly"
            }
        } else {
            mode.as_str()
        };
        let mode = if matches!(mode, "ai" | "company_ai") {
            "enriched_weekly"
        } else {
            mode
        };
        if !matches!(mode, "template" | "enriched_weekly") {
            return Some(view::error(
                StatusCode::BAD_REQUEST,
                "Generation mode must be template or enriched_weekly.",
            ));
        }
        let language = first_text(&data, &["report_language"]);
        if !language.is_empty() && !matches!(language.as_str(), "en" | "zh" | "ch") {
            return Some(view::error(
                StatusCode::BAD_REQUEST,
                "Invalid report language.",
            ));
        }
        let (source, inputs) = if let Some(raw) = upload {
            let value: Value = match serde_json::from_slice(&raw) {
                Ok(v) => v,
                Err(_) => {
                    return Some(view::error(
                        StatusCode::BAD_REQUEST,
                        "Uploaded JSON is invalid.",
                    ));
                }
            };
            let Some(items) = value.as_array() else {
                return Some(view::error(
                    StatusCode::BAD_REQUEST,
                    "Uploaded JSON must be an array of documents.",
                ));
            };
            if items.iter().any(|v| !v["details"].is_object()) {
                return Some(view::error(
                    StatusCode::BAD_REQUEST,
                    "Each uploaded document must contain a details object.",
                ));
            }
            ("upload", items.clone())
        } else {
            let Some(selections) = data.get("selections").and_then(Value::as_array) else {
                return Some(view::error(
                    StatusCode::BAD_REQUEST,
                    "Select between 1 and 500 vulnerability records.",
                ));
            };
            if selections.is_empty() || selections.len() > 500 {
                return Some(view::error(
                    StatusCode::BAD_REQUEST,
                    "Select between 1 and 500 vulnerability records.",
                ));
            }
            let names = reviews::views(state).await.unwrap_or_default();
            let mut items = Vec::new();
            for s in selections {
                let collection = s["collection"].as_str().unwrap_or("");
                let id = s["selection_id"].as_str().unwrap_or("");
                if !names.iter().any(|n| n == collection) {
                    return Some(view::error(
                        StatusCode::BAD_REQUEST,
                        "Invalid Vulnerability Reviews selection.",
                    ));
                }
                let src = collection
                    .strip_suffix(&state.cfg.review_view_suffix)
                    .unwrap_or(collection);
                if mode == "enriched_weekly" && (collection != "cve_review" || src != "cve") {
                    return Some(view::error(
                        StatusCode::BAD_REQUEST,
                        "enriched_weekly reports only support cve_review selections.",
                    ));
                }
                if reviews::resolve(state, src, id).await.is_none() {
                    return Some(view::error(
                        StatusCode::BAD_REQUEST,
                        "Selected vulnerability not found.",
                    ));
                }
                items.push(json!({"source_collection":src,"selection_id":id,"identifier":id}));
            }
            ("review_selections", items)
        };
        if mode == "enriched_weekly" && source == "upload" {
            return Some(view::error(
                StatusCode::BAD_REQUEST,
                "enriched_weekly reports require cve_review selections, not uploaded JSON.",
            ));
        }
        if inputs.is_empty() || inputs.len() > 500 {
            return Some(view::error(
                StatusCode::BAD_REQUEST,
                "At least one vulnerability record is required.",
            ));
        }
        let now = bson::DateTime::now();
        let count = inputs.len() as i64;
        let mut document = doc! {"generation_mode":mode,"effective_generation_mode":mode,"report_language":"en","effective_report_language":"en","search_prompt":first_text(&data,&["search_prompt"]),"input_source":source,"source_count":count,"processed_count":0,"current_position":0,"item_fallback_count":0,"status":if mode=="template"{"running"}else{"queued"},"created_at":now,"updated_at":now,"provider":if mode=="template"{"Fixed Template"}else{"Search API + llama-server"},"model":if mode=="template"{"Fixed Template"}else{"Enriched Weekly"},"progress_percent":0,"progress_current":0,"progress_total":count,"progress_label":"Queued","pipeline_logs":[]};
        if let Some(owner) = ctx.user_id() {
            document.insert("managed_by_user_id", owner);
        }
        let inserted = match db::collection(&state.web, "report_jobs")
            .insert_one(document)
            .await
        {
            Ok(v) => v,
            Err(_) => {
                return Some(view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to create report job.",
                ));
            }
        };
        let id = inserted.inserted_id.as_object_id().unwrap();
        let input_documents: Vec<Document> = inputs
            .iter()
            .enumerate()
            .filter_map(|(position, value)| {
                let mut doc = db::json_doc(value).ok()?;
                doc.insert("job_id", id);
                doc.insert("position", position as i64);
                Some(doc)
            })
            .collect();
        if db::collection(&state.web, "report_job_inputs")
            .insert_many(input_documents)
            .await
            .is_err()
        {
            return Some(view::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unable to create report job.",
            ));
        }
        tokio::spawn(run(state.clone(), id));
        return Some(view::json_response(
            StatusCode::ACCEPTED,
            json!({"id":id.to_hex(),"status":if mode=="template"{"running"}else{"queued"}}),
        ));
    }
    for (path, collection) in [
        ("/api/reports/evidence-cache/purge", "source_evidence_cache"),
        ("/api/reports/search-cache/purge", "search_enrichment_cache"),
    ] {
        if ctx.path == path && ctx.method == Method::POST {
            return Some(
                match db::collection(&state.web, collection)
                    .delete_many(doc! {})
                    .await
                {
                    Ok(v) => view::json_response(
                        StatusCode::OK,
                        json!({"deleted_count":v.deleted_count}),
                    ),
                    Err(_) => {
                        view::error(StatusCode::SERVICE_UNAVAILABLE, "Unable to purge cache.")
                    }
                },
            );
        }
    }
    if let Some(rest) = ctx.path.strip_prefix("/api/reports/") {
        let (id, action) = rest.split_once('/').unwrap_or((rest, ""));
        let Some(document) = job(state, ctx, id).await else {
            return Some(view::error(StatusCode::NOT_FOUND, "Report job not found."));
        };
        let oid = document.get_object_id("_id").unwrap();
        if action.is_empty() && ctx.method == Method::GET {
            return Some(view::json_response(StatusCode::OK, job_public(&document)));
        }
        if action.is_empty() && ctx.method == Method::DELETE {
            if matches!(document.get_str("status"), Ok("queued" | "running")) {
                return Some(view::error(
                    StatusCode::BAD_REQUEST,
                    "Cancel the report job before deleting it.",
                ));
            }
            let _ = db::collection(&state.web, "report_job_inputs")
                .delete_many(doc! {"job_id":oid})
                .await;
            let _ = db::collection(&state.web, "report_job_results")
                .delete_many(doc! {"job_id":oid})
                .await;
            let _ = db::collection(&state.web, "report_jobs")
                .delete_one(doc! {"_id":oid})
                .await;
            return Some(view::json_response(
                StatusCode::OK,
                json!({"id":id,"deleted":true}),
            ));
        }
        if action == "cancel" && ctx.method == Method::POST {
            let changed = db::collection(&state.web, "report_jobs")
                .update_one(
                    doc! {"_id":oid,"status":{"$in":["queued","running"]}},
                    doc! {"$set":{"status":"cancelled","updated_at":bson::DateTime::now()}},
                )
                .await
                .ok()
                .is_some_and(|v| v.matched_count > 0);
            return Some(if changed {
                view::json_response(StatusCode::OK, json!({"id":id,"status":"cancelled"}))
            } else {
                view::error(StatusCode::BAD_REQUEST, "Report job cannot be cancelled.")
            });
        }
        if action == "logs" && ctx.method == Method::GET {
            return Some(view::json_response(
                StatusCode::OK,
                json!({"logs":document.get_array("pipeline_logs").map(|v|v.iter().map(|v|serde_json::to_value(v).unwrap_or(Value::Null)).collect::<Vec<_>>()).unwrap_or_default()}),
            ));
        }
        if action == "translations" && ctx.method == Method::POST {
            let language = ctx.field("language");
            if !matches!(language.as_str(), "zh" | "ch") {
                return Some(view::error(
                    StatusCode::BAD_REQUEST,
                    "Translation language must be zh or ch.",
                ));
            }
            if document.get_str("status") != Ok("completed") {
                return Some(view::error(
                    StatusCode::BAD_REQUEST,
                    "Only completed reports can be translated.",
                ));
            }
            let now = bson::DateTime::now();
            let mut translation = doc! {"job_type":"translation","input_source":"translation","translated_from_job_id":oid,"generation_mode":db::string(&document,"generation_mode"),"report_language":&language,"source_count":document.get_i64("source_count").unwrap_or(0),"status":"queued","created_at":now,"updated_at":now,"provider":"llama-server","model":format!("Translation ({language})"),"progress_percent":0,"pipeline_logs":[]};
            if let Ok(owner) = document.get_object_id("managed_by_user_id") {
                translation.insert("managed_by_user_id", owner);
            }
            let inserted = match db::collection(&state.web, "report_jobs")
                .insert_one(translation)
                .await
            {
                Ok(v) => v,
                Err(_) => {
                    return Some(view::error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Unable to start report translation.",
                    ));
                }
            };
            let translation_id = inserted.inserted_id.as_object_id().unwrap();
            tokio::spawn(translate(
                state.clone(),
                translation_id,
                oid,
                language.clone(),
            ));
            return Some(view::json_response(
                StatusCode::ACCEPTED,
                json!({"id":translation_id.to_hex(),"source_id":id,"language":language,"status":"queued"}),
            ));
        }
    }
    if let Some(rest) = ctx.path.strip_prefix("/reports/") {
        let Some((id, action)) = rest.split_once('/') else {
            return None;
        };
        if matches!(action, "preview" | "download") && ctx.method == Method::GET {
            let Some(document) = job(state, ctx, id).await else {
                return Some(view::error(
                    StatusCode::NOT_FOUND,
                    "Completed report not found.",
                ));
            };
            return Some(report_html(state, ctx, &document, action == "download").await);
        }
    }
    None
}
