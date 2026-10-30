use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
};
use minijinja::{
    Environment, State,
    value::{Kwargs, Value},
};
use serde_json::{Value as Json, json};
use std::{path::Path, sync::Arc};

pub fn environment(root: &Path) -> Environment<'static> {
    let mut env = Environment::new();
    env.set_loader(minijinja::path_loader(root.join("templates")));
    let translations: Json =
        serde_json::from_str(include_str!("../config/translations.json")).unwrap_or(json!({}));
    let translations = Arc::new(translations);
    env.add_function(
        "t",
        move |state: &State, text: String, args: Kwargs| -> String {
            let locale = state
                .lookup("locale")
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default();
            let mut result = translations
                .get(locale)
                .and_then(|v| v.get(&text))
                .and_then(Json::as_str)
                .unwrap_or(&text)
                .to_owned();
            for name in args.args() {
                if let Ok(value) = args.peek::<Value>(name) {
                    result = result.replace(&format!("{{{name}}}"), &value.to_string());
                }
            }
            result
        },
    );
    env.add_function(
        "url_for",
        |endpoint: String, args: Kwargs| -> Result<String, minijinja::Error> {
            let get = |name: &str| -> String { args.peek::<String>(name).ok().unwrap_or_default() };
            let url = match endpoint.as_str() {
                "static" => format!("/static/{}", get("filename")),
                "serve_image" => format!("/image/{}", get("filename")),
                "set_locale" => format!(
                    "/locale/{}?next={}",
                    get("code"),
                    urlencoding::encode(&get("next"))
                ),
                "auth.login" => "/login".into(),
                "auth.settings" => "/settings".into(),
                "auth.change_password" => "/api/auth/password".into(),
                "auth.update_profile" => "/api/auth/profile".into(),
                "subscription.subscriptions" => "/subscriptions".into(),
                "subscription.get_subscriptions" => "/api/subscriptions".into(),
                "subscription.get_subscription_collections" => {
                    "/api/subscriptions/collections".into()
                }
                "subscription.import_vendor_products" => {
                    "/api/subscriptions/vendor-product-import".into()
                }
                "subscription.vendor_product_template" => {
                    "/api/subscriptions/vendor-product-template.csv".into()
                }
                "subscription.preview_subscription_report" => {
                    "/api/subscriptions/report-preview".into()
                }
                "review.reviews" => "/reviews".into(),
                "review.import_vendor_products" => "/api/reviews/vendor-product-import".into(),
                "review.vendor_product_template" => {
                    "/api/reviews/vendor-product-template.csv".into()
                }
                "review.get_review_documents" => format!("/api/reviews/{}", get("collection_name")),
                "review.search_review_documents" => "/api/reviews/search".into(),
                "review.auto_select_review_documents" => "/api/reviews/auto-select".into(),
                "review.export_review_documents" => "/api/reviews/export-json".into(),
                "report.reports" => "/reports".into(),
                "report.get_report_jobs" => "/api/reports".into(),
                "report.purge_report_evidence_cache" => "/api/reports/evidence-cache/purge".into(),
                "report.purge_report_search_cache" => "/api/reports/search-cache/purge".into(),
                "report.cancel_report_job" => format!("/api/reports/{}/cancel", get("job_id")),
                "report.delete_report_job" => format!("/api/reports/{}", get("job_id")),
                "report.get_report_job_logs" => format!("/api/reports/{}/logs", get("job_id")),
                "report.translate_report_job" => {
                    format!("/api/reports/{}/translations", get("job_id"))
                }
                "operations.operations" => "/operations".into(),
                "operations.get_operations_health" => "/api/operations/health".into(),
                "operations.get_newsletter_templates" => {
                    "/api/operations/newsletter-templates".into()
                }
                "operations.get_source_list" => "/api/operations/source-list".into(),
                "operations.get_newsletter_editor" => "/api/operations/newsletter-editor".into(),
                "operations.preview_newsletter_editor" => {
                    "/api/operations/newsletter-editor/preview".into()
                }
                _ => {
                    return Err(minijinja::Error::new(
                        minijinja::ErrorKind::InvalidOperation,
                        format!("Unknown endpoint: {endpoint}"),
                    ));
                }
            };
            let version = get("v");
            Ok(if version.is_empty() {
                url
            } else {
                format!("{url}?v={}", urlencoding::encode(&version))
            })
        },
    );
    env.add_filter("nl2br", |value: String| -> Value {
        let escaped = value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;");
        Value::from_safe_string(
            escaped
                .replace("\r\n", "\n")
                .replace('\r', "\n")
                .replace('\n', "<br>\n"),
        )
    });
    env
}

pub fn render(env: &Environment<'static>, name: &str, data: Json) -> Response {
    match env.get_template(name).and_then(|t| t.render(data)) {
        Ok(body) => Html(body).into_response(),
        Err(error) => {
            tracing::error!("template {name}: {error}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Unable to render page").into_response()
        }
    }
}

pub fn json_response(status: StatusCode, value: Json) -> Response {
    (status, axum::Json(value)).into_response()
}
pub fn error(status: StatusCode, message: &str) -> Response {
    json_response(status, json!({"error": message}))
}
pub fn redirect(path: &str) -> Response {
    (
        StatusCode::FOUND,
        [(axum::http::header::LOCATION, path.to_owned())],
    )
        .into_response()
}
pub fn attachment(content_type: &str, filename: &str, body: String) -> Response {
    let mut response = body.into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).unwrap(),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")).unwrap(),
    );
    response
}
pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_pages_render_and_management_uses_fixed_grouped_catalog() {
        let env = environment(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
        let permissions = crate::rbac::CATALOG
            .iter()
            .map(|p| (p.id, true))
            .collect::<std::collections::BTreeMap<_, _>>();
        let context = json!({"locale":"en","html_lang":"en","i18n_catalog":{},"permissions":permissions,"permission_catalog":crate::rbac::CATALOG,"is_superadmin":true,"current_user":{"username":"admin","role":"superadmin","email":"admin@example.test","organization":"Test","organization_id":"012345678901234567890123","must_change_password":false},"request":{"path":"/","next":"/subscriptions","args":{},"blueprint":"auth","endpoint":""},"collection_name":"news"});
        for template in [
            "auth/login.html",
            "auth/settings.html",
            "auth/management.html",
            "subscriptions/index.html",
            "reviews/index.html",
            "reviews/collection.html",
            "reports/index.html",
            "operations/index.html",
            "errors/403.html",
            "errors/404.html",
        ] {
            let html = env
                .get_template(template)
                .unwrap()
                .render(context.clone())
                .unwrap_or_else(|error| panic!("{template}: {error}"));
            assert!(!html.contains("Account Hub"));
            assert!(!html.contains("Sign in with Zimbra"));
        }
        let settings = env
            .get_template("auth/settings.html")
            .unwrap()
            .render(context.clone())
            .unwrap();
        assert!(settings.contains("id=\"password-form\""));
        assert!(settings.contains("id=\"profile-form\""));
        let management = env
            .get_template("auth/management.html")
            .unwrap()
            .render(context.clone())
            .unwrap();
        assert!(management.contains("permission-checkboxes"));
        assert!(management.contains("organizations.manage"));
        assert!(
            management.contains("id=\"new-email\" type=\"email\" class=\"form-control\" required")
        );
        assert!(management.contains("id=\"new-user-organization\" class=\"form-select\" required"));
        assert!(management.contains("emailed"));
        assert!(!management.contains("id=\"temporary-password\""));
        let mut first_login = context.clone();
        first_login["current_user"]["must_change_password"] = json!(true);
        let html = env
            .get_template("auth/settings.html")
            .unwrap()
            .render(first_login)
            .unwrap();
        assert!(html.contains("id=\"password-form\""));
        assert!(!html.contains("id=\"profile-form\""));
    }

    #[test]
    fn subscription_notification_email_renders_details_and_profiles() {
        let env = environment(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
        let html = env
            .get_template("subscriptions/notification_email.html")
            .unwrap()
            .render(json!({
                "details": {
                    "subject": "Security portal subscription updated",
                    "heading": "Subscription updated",
                    "badge": "Updated",
                    "intro": "Your subscription settings were updated successfully.",
                    "username": "member@example.com",
                    "organization": "SW-ENG",
                    "recipients": "member@example.com",
                    "event_time": "2026-09-21 15:00 UTC",
                    "footer": "Automated subscription notification from Security Portal."
                },
                "kind": "updated",
                "changes": ["Newsletter feed: Enabled", "Report profile: Disabled"],
                "cards": [
                    {"name":"Newsletter feed","enabled":true,"status":"Enabled","summary_lines":["Sources: cve"]},
                    {"name":"Report profile","enabled":false,"status":"Disabled","summary_lines":[]}
                ]
            }))
            .unwrap();
        assert!(html.contains("Subscription details"));
        assert!(html.contains("Configuration summary"));
        assert!(html.contains("Delivery profiles"));
        assert!(html.contains("details-table"));
        assert!(html.contains("member@example.com"));
        assert!(html.contains("badge-updated"));
    }

    #[test]
    fn report_templates_render() {
        let env = environment(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
        env.get_template("reports/generated.html").unwrap().render(json!({"html_language":"en","generated_label":"Generated now","source_count":1,"labels":{},"report":{"title":"Report","template_mode":true,"highlights":[],"trends":[],"recommendations":[],"executive_summary":""}})).unwrap();
        env.get_template("reports/enriched.html").unwrap().render(json!({"html_language":"en","generated_label":"Generated now","source_count":1,"labels":{},"report":{"title":"Report","executive_summary":{"key_findings":[]},"vulnerability_detail_table":{"rows":[]}}})).unwrap();
    }
    #[test]
    fn source_newsletter_templates_render() {
        let env = environment(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
        for (source, record, expected) in [
            (
                "hpe",
                json!({"title":"HPE Bulletin","severity":"Critical","details":{"bulletin_id":"HPESB1","cvss_text":"VULNERABILITY SUMMARY\nA security issue.","resolution":"RESOLUTION\nUpgrade now."}}),
                "Bulletin Information",
            ),
            (
                "zimbra",
                json!({"title":"Patch release","details":{"security_fixes":["Fixed injection"],"packages":{"zimbra-patch":"10.1"}}}),
                "Security Fixes",
            ),
            (
                "hkcert",
                json!({"title":"HKCERT Advisory","details":{"risk_level":"High","impact":["Remote execution"]}}),
                "Impacts:",
            ),
            (
                "github_advisory",
                json!({"title":"GitHub Advisory","source":{"url":"https://github.com/advisories","provider":"github_advisory"},"details":{"ghsa_id":"GHSA-1234","description":"## Summary\n\nA useful summary.\n\n- First item\n- Second item\n\n```shell\ncurl https://example.com\n```","vulnerabilities":[{"package":{"ecosystem":"npm","name":"demo"},"vulnerable_version_range":"< 1.2.3","first_patched_version":"1.2.3"}],"html_url":"https://github.com/advisories/GHSA-1234"}}),
                "GitHub Security Advisory",
            ),
        ] {
            let newsletter = crate::newsletters::normalize(&record, source, &json!({}));
            let html = env
                .get_template(crate::newsletters::template_name(source))
                .unwrap()
                .render(json!({"newsletter":newsletter}))
                .unwrap();
            assert!(html.contains(expected), "{source} missing {expected}");
        }
    }
}
