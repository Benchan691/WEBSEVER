use crate::{AppState, ReqCtx, db, render, reviews, view};
use axum::{
    http::{Method, StatusCode},
    response::{Html, IntoResponse, Response},
};
use serde_json::{Value, json};

fn strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => {
            if s.trim().is_empty() {
                vec![]
            } else {
                vec![s.trim().to_owned()]
            }
        }
        Value::Array(a) => a.iter().flat_map(strings).collect(),
        Value::Object(m) => m.values().flat_map(strings).collect(),
        _ => vec![],
    }
}
fn first(record: &Value, details: &Value, keys: &[&str]) -> String {
    for root in [record, details] {
        for key in keys {
            if let Some(v) = strings(&root[*key]).into_iter().next() {
                return v;
            }
        }
    }
    String::new()
}
fn all(record: &Value, details: &Value, keys: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    for root in [record, details] {
        for key in keys {
            for item in strings(&root[*key]) {
                if !values
                    .iter()
                    .any(|v: &String| v.eq_ignore_ascii_case(&item))
                {
                    values.push(item)
                }
            }
        }
    }
    values
}
pub fn normalize(record: &Value, source: &str, config: &Value) -> Value {
    let details = record
        .get("details")
        .filter(|v| v.is_object())
        .unwrap_or(&Value::Null);
    let title = first(
        record,
        details,
        &["title", "vulName", "advisory_title", "code", "cve"],
    );
    let title = if title.is_empty() {
        "Security Advisory".into()
    } else {
        title
    };
    let overview = first(record, details, &["overview", "summary", "description"]);
    let severity = all(record, details, &["severity", "risk", "priority"]);
    let affected = all(
        record,
        details,
        &[
            "affected",
            "affected_products",
            "systems_affected",
            "products",
        ],
    );
    let impacts = all(record, details, &["impacts", "impact"]);
    let cves = all(record, details, &["cve_ids", "cve", "code"]);
    let recommendations = all(
        record,
        details,
        &[
            "recommendations",
            "recommendation",
            "solution",
            "solutions",
            "mitigation",
        ],
    );
    let references = all(record, details, &["references", "reference_links", "urls"]);
    let related_links = all(record, details, &["related_links", "related_link"]);
    let order = config
        .pointer(&format!("/sources/{source}/fields"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| {
            [
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
                "related_links",
            ]
            .iter()
            .map(|v| json!(v))
            .collect()
        });
    let subject = config
        .pointer("/common/subject")
        .and_then(Value::as_str)
        .unwrap_or("Security newsletter: {{title}}")
        .replace("{{title}}", &title);
    json!({"title":title,"subject":subject,"collection":source,"language":"en","overview":overview,"severity":severity,"affected":affected,"impacts":impacts,"cves":cves,"recommendations":recommendations,"references":references,"related_links":related_links,"cvss":"","field_order":order,"extra":config.pointer("/common/extra").and_then(Value::as_str).unwrap_or(""),"footer":config.pointer("/common/footer").and_then(Value::as_str).unwrap_or("Should you have any queries, please contact the Security Operation Centre. Thank you."),"show_severity":!severity.is_empty(),"show_affected":!affected.is_empty(),"show_impacts":!impacts.is_empty(),"show_recommendations":true,"labels":{"greeting":"Dear Valued Customer,","collection":"Source collection:","overview":"Overview:","severity":"Severity:","cvss":"CVSS:","impacts":"Impacts:","affected":"Affected system:","cves":"CVEs:","recommendations":"Recommendations:","references":"References:","related_links":"Related Links:","not_specified":"Not specified","default_recommendation":"Refer to the vendor guidance and apply available fixes."}})
}
pub async fn template_config(state: &AppState) -> Value {
    let saved = db::find_one(
        &state.web,
        "newsletter_template_config",
        mongodb::bson::doc! {"_id":"newsletter_default"},
    )
    .await
    .ok()
    .flatten()
    .map(|v| db::bson_json(&v))
    .unwrap_or(json!({}));
    let mut output = json!({"common":{"subject":"Security newsletter: {{title}}","extra":"","footer":""},"sources":{}});
    if let (Some(dst), Some(src)) = (output.as_object_mut(), saved.as_object()) {
        for (k, v) in src {
            if k != "_id" {
                dst.insert(k.clone(), v.clone());
            }
        }
    }
    output
}
pub async fn preview(
    state: &AppState,
    ctx: &ReqCtx,
    source: &str,
    id: &str,
    config: Option<Value>,
) -> Response {
    let Some(document) = reviews::resolve(state, source, id).await else {
        return view::error(
            StatusCode::NOT_FOUND,
            "Newsletter source document not found.",
        );
    };
    let record = db::bson_json(&document);
    let config = match config {
        Some(v) => v,
        None => template_config(state).await,
    };
    let newsletter = normalize(&record, source, &config);
    render(
        state,
        ctx,
        "newsletters/generated.html",
        json!({"newsletter":newsletter}),
    )
}
pub async fn handle(state: &AppState, ctx: &ReqCtx) -> Option<Response> {
    if matches!(ctx.path.as_str(), "/en" | "/zh" | "/cn") && ctx.method == Method::GET {
        let name = format!("news_{}.html", &ctx.path[1..]);
        let file = state.cfg.root.join("templates/newsletters").join(name);
        return Some(match tokio::fs::read_to_string(file).await {
            Ok(body) => Html(body).into_response(),
            Err(_) => view::error(StatusCode::NOT_FOUND, "Not found"),
        });
    }
    if ctx.path == "/set-news" && ctx.method == Method::POST {
        let lang = ctx.field("lang").to_lowercase();
        if !matches!(lang.as_str(), "en" | "zh" | "cn") {
            return Some(view::error(StatusCode::BAD_REQUEST, "Invalid language"));
        }
        let relative = ctx.field("path");
        let base = state.cfg.newsletter_root.canonicalize().ok();
        let Some(base) = base else {
            return Some(view::error(StatusCode::NOT_FOUND, "File not found"));
        };
        let source = base
            .join(relative.trim_start_matches('/'))
            .canonicalize()
            .ok();
        let Some(source) = source else {
            return Some(view::error(StatusCode::NOT_FOUND, "File not found"));
        };
        if !source.starts_with(&base) || !source.is_file() {
            return Some(view::error(StatusCode::FORBIDDEN, "Invalid path"));
        }
        let destination = state
            .cfg
            .root
            .join("templates/newsletters")
            .join(format!("news_{lang}.html"));
        return Some(match tokio::fs::copy(source, destination).await {
            Ok(_) => view::json_response(StatusCode::OK, json!({"success":true})),
            Err(_) => view::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to set newsletter",
            ),
        });
    }
    if let Some(rest) = ctx.path.strip_prefix("/generated-newsletters/") {
        if ctx.method == Method::GET {
            if let Some((source, tail)) = rest.split_once('/') {
                if let Some(id) = tail.strip_suffix("/preview") {
                    let decoded =
                        urlencoding::decode(id).unwrap_or_else(|_| std::borrow::Cow::Borrowed(id));
                    return Some(preview(state, ctx, source, &decoded, None).await);
                }
            }
        }
    }
    None
}
