use crate::{AppState, ReqCtx, db, render, reviews, view};
use axum::{
    http::{Method, StatusCode},
    response::{Html, IntoResponse, Response},
};
use serde_json::{Value, json};

pub fn normalize(record: &Value, source: &str, config: &Value) -> Value {
    crate::newsletter_normalizer::normalize(record, source, config)
}
pub fn template_name(source: &str) -> &'static str {
    crate::newsletter_normalizer::template_name(source)
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
        template_name(source),
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
                    let decoded_source = urlencoding::decode(source)
                        .unwrap_or_else(|_| std::borrow::Cow::Borrowed(source));
                    let decoded =
                        urlencoding::decode(id).unwrap_or_else(|_| std::borrow::Cow::Borrowed(id));
                    return Some(preview(state, ctx, &decoded_source, &decoded, None).await);
                }
            }
        }
    }
    None
}
