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
                "auth.local_login" => "/login/local".into(),
                "auth.logout" => "/logout".into(),
                "auth.settings" => "/settings".into(),
                "auth.sub_admins" => "/admin/sub-admins".into(),
                "auth.account_users" => "/admin/account-users".into(),
                "auth.organization_members" => "/organization/members".into(),
                "auth.get_sub_admins" => "/api/admin/sub-admins".into(),
                "auth.get_account_users" => "/api/admin/account-users".into(),
                "auth.get_organization_members" => "/api/organization/members".into(),
                "auth.change_password" => "/api/auth/password".into(),
                "auth.update_profile" => "/api/auth/profile".into(),
                "subscription.subscriptions" => "/subscriptions".into(),
                "subscription.get_subscriptions" => "/api/subscriptions".into(),
                "subscription.get_organization_subscriptions" => {
                    "/api/organization/subscriptions".into()
                }
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
    fn browser_pages_render_with_rust_template_functions() {
        let env = environment(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
        let context = json!({"locale":"ch","html_lang":"zh-Hans","i18n_catalog":{},"current_user":{"username":"admin","role":"admin","auth_source":"local","email":"","organization":""},"is_admin":true,"is_top_admin":true,"is_organization_admin":false,"config":{"ACCOUNT_HUB_ENABLED":false},"request":{"path":"/reviews","full_path":"/reviews","blueprint":"review","endpoint":""},"collection_name":"cve_review","initial_error":null});
        for name in [
            "auth/login.html",
            "auth/settings.html",
            "auth/organization_members.html",
            "auth/sub_admins_legacy.html",
            "subscriptions/index.html",
            "reviews/index.html",
            "reviews/collection.html",
            "reports/index.html",
            "operations/index.html",
            "errors/403.html",
            "errors/404.html",
        ] {
            env.get_template(name)
                .unwrap()
                .render(context.clone())
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
        let translated = env
            .render_str("{{ t('{n} per page', n=25) }}", json!({"locale":"en"}))
            .unwrap();
        assert_eq!(translated, "25 per page");
    }

    #[test]
    fn organization_subscription_dashboard_renders() {
        let env = environment(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
        let html = env
            .get_template("subscriptions/index.html")
            .unwrap()
            .render(json!({
                "locale":"ch",
                "html_lang":"zh-Hans",
                "i18n_catalog":{},
                "current_user":{"username":"manager","role":"user","auth_source":"account_hub","email":"manager@example.com","organization":"SW-ENG"},
                "is_admin":false,
                "is_top_admin":false,
                "is_organization_admin":true,
                "config":{"ACCOUNT_HUB_ENABLED":true},
                "request":{"path":"/subscriptions","full_path":"/subscriptions","blueprint":"subscription","endpoint":""}
            }))
            .unwrap();
        assert!(html.contains("组织订阅面板"));
        assert!(html.contains("organization/subscriptions"));
        assert!(html.contains("organizationDashboard"));
    }

    #[test]
    fn self_subscription_page_renders_self_management_controls() {
        let env = environment(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
        let html = env
            .get_template("subscriptions/index.html")
            .unwrap()
            .render(json!({
                "locale":"ch",
                "html_lang":"zh-Hans",
                "i18n_catalog":{},
                "current_user":{"username":"member","email":"member@example.com","role":"user","auth_source":"account_hub"},
                "is_admin":false,
                "is_top_admin":false,
                "is_organization_admin":false,
                "config":{"ACCOUNT_HUB_ENABLED":true},
                "request":{"path":"/subscriptions","full_path":"/subscriptions","blueprint":"subscription","endpoint":""}
            }))
            .unwrap();
        assert!(html.contains("我的订阅"));
        assert!(html.contains("仅管理您自己的订阅。"));
        assert!(!html.contains("for=\"team\""));
        assert!(html.contains("\"selfManagement\":true"));
        assert!(html.contains("\"currentUsername\":\"member\""));
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
