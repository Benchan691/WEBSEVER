use crate::{AppState, ReqCtx, auth, db, mail, render, reviews, vendor_matcher, view};
use axum::{
    body::Bytes,
    http::{Method, StatusCode, header},
    response::Response,
};
use futures::stream;
use mongodb::bson::{self, Bson, Document, doc};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

fn default_filters() -> Value {
    json!({"collections":[],"search":"","code":"","title":"","impact":"","affected":"","status":[],"severity_threshold":"","include_unknown":false,"source":"","keywords":[],"vendor_product_filter":{"enabled":false,"schema_version":1,"include_possible_matches":false,"rows":[]},"time_window":"all","start":"","end":"","source_timestamp":{},"report_scope":{}})
}
fn default_profile(kind: &str) -> Value {
    if kind == "newsletter" {
        json!({"enabled":false,"filters":default_filters(),"delivery_cursor":"","cve_delivery_cutoff":"","statistic_schedule_enabled":false})
    } else {
        json!({"enabled":false,"filters":default_filters(),"generation_mode":"template","report_language":"en","search_prompt":"","schedule_enabled":false,"schedule_weekday":"mon","schedule_time":"09:00"})
    }
}
fn merge(into: &mut Value, from: &Value) {
    if let (Some(dst), Some(src)) = (into.as_object_mut(), from.as_object()) {
        for (k, v) in src {
            if let Some(existing) = dst.get_mut(k) {
                if existing.is_object() && v.is_object() {
                    merge(existing, v);
                    continue;
                }
            }
            dst.insert(k.clone(), v.clone());
        }
    }
}
async fn profile(state: &AppState, kind: &str, input: &Value) -> Result<Value, String> {
    if !input.is_null() && !input.is_object() {
        return Err(format!(
            "{} profile must be an object.",
            if kind == "newsletter" {
                "Newsletter"
            } else {
                "Report"
            }
        ));
    }
    let mut profile = default_profile(kind);
    merge(&mut profile, input);
    let filters = profile["filters"].clone();
    if !filters.is_object() {
        return Err("Filters must be an object.".into());
    }
    vendor_matcher::validate(&filters["vendor_product_filter"])?;
    let collections = filters["collections"]
        .as_array()
        .ok_or("Filter collections must be a list.")?;
    let names = reviews::views(state)
        .await
        .map_err(|_| "Unable to load review collections.")?;
    if collections.iter().any(|v| {
        v.as_str()
            .is_none_or(|name| !names.iter().any(|n| n == name))
    }) {
        return Err("Filters contain an invalid review collection.".into());
    }
    for field in ["search", "code", "title", "impact", "affected", "source"] {
        if !filters[field].is_string() {
            return Err(format!("Filter {field} must be text."));
        }
    }
    let statuses = filters["status"]
        .as_array()
        .ok_or("Severity/status must be Critical, High, Medium, or Low.")?;
    if statuses.iter().any(|v| {
        v.as_str()
            .is_none_or(|s| !matches!(s, "Critical" | "High" | "Medium" | "Low"))
    }) {
        return Err("Severity/status must be Critical, High, Medium, or Low.".into());
    }
    if !matches!(
        filters["severity_threshold"].as_str(),
        Some("" | "Critical" | "High" | "Medium" | "Low")
    ) {
        return Err("Severity threshold must be Critical, High, Medium, or Low.".into());
    }
    if !matches!(
        filters["time_window"].as_str(),
        Some("all" | "daily" | "week" | "custom")
    ) {
        return Err("Invalid filter time window.".into());
    }
    if kind == "report" {
        let mode = profile["generation_mode"].as_str().unwrap_or("");
        if mode == "ai" || mode == "company_ai" {
            profile["generation_mode"] = json!("enriched_weekly")
        }
        if !matches!(
            profile["generation_mode"].as_str(),
            Some("template" | "enriched_weekly")
        ) {
            return Err("Invalid report generation mode.".into());
        }
        if !matches!(
            profile["report_language"].as_str(),
            Some("en" | "zh" | "ch")
        ) {
            return Err("Invalid report language.".into());
        }
        if profile["generation_mode"] == "template" {
            profile["report_language"] = json!("en");
            profile["search_prompt"] = json!("")
        } else {
            if collections.iter().any(|v| v != "cve_review") {
                return Err("enriched_weekly report profiles only support cve_review.".into());
            }
            profile["filters"]["collections"] = json!(["cve_review"])
        }
        if !matches!(
            profile["schedule_weekday"].as_str(),
            Some("mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun")
        ) {
            return Err("Invalid report schedule weekday.".into());
        }
        let time = profile["schedule_time"].as_str().unwrap_or("");
        let valid = time.split_once(':').is_some_and(|(h, m)| {
            h.len() == 2
                && m.len() == 2
                && h.parse::<u8>().is_ok_and(|v| v < 24)
                && m.parse::<u8>().is_ok_and(|v| v < 60)
        });
        if !valid {
            return Err("Invalid report schedule time.".into());
        }
        if profile["enabled"] == true
            && profile["filters"]["vendor_product_filter"]["enabled"] != true
            && profile["filters"]["keywords"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        {
            return Err("Report keyword filters are no longer supported. Import a vendor/product CSV instead.".into());
        }
    }
    Ok(profile)
}
fn public(document: &Document) -> Value {
    let mut value = db::public_id(db::bson_json(document));
    if let Some(obj) = value.as_object_mut() {
        for key in [
            "owner_user_id",
            "managed_by_user_id",
            "password",
            "password_hash",
            "schedule_claim_until",
            "schedule_claim_owner",
            "statistic_schedule_claim_until",
            "statistic_schedule_claim_owner",
        ] {
            obj.remove(key);
        }
    }
    if let Some(obj) = value
        .get_mut("newsletter_profile")
        .and_then(Value::as_object_mut)
    {
        obj.remove("cve_delivery_cutoff");
    }
    value
}
async fn organization_members(state: &AppState, ctx: &ReqCtx) -> Option<Vec<Document>> {
    let manager = ctx.user.as_ref()?;
    let mut filter = crate::auth::organization_filter(manager)?;
    filter.insert("auth_source", "account_hub");
    db::find_sorted(&state.web, "auth", filter, doc! {"username_key":1}, 5000)
        .await
        .ok()
}

async fn organization_member_ids(
    state: &AppState,
    ctx: &ReqCtx,
) -> Option<Vec<mongodb::bson::oid::ObjectId>> {
    Some(
        organization_members(state, ctx)
            .await?
            .iter()
            .filter_map(|user| user.get_object_id("_id").ok())
            .collect(),
    )
}

fn can_manage_subscriptions(state: &AppState, ctx: &ReqCtx) -> bool {
    ctx.is_admin(state) || ctx.is_organization_admin(state)
}

fn is_self_manager(state: &AppState, ctx: &ReqCtx) -> bool {
    ctx.user.is_some() && !can_manage_subscriptions(state, ctx)
}

fn same_username(left: &str, right: &str) -> bool {
    !left.trim().is_empty() && left.trim().eq_ignore_ascii_case(right.trim())
}

fn self_subscription_owner_filter(ctx: &ReqCtx) -> Option<Document> {
    let owner_id = ctx.user_id()?;
    let user = ctx.user.as_ref()?;
    let owner = doc! {"owner_user_id":owner_id};
    let mut legacy = Vec::new();
    let username = db::string(user, "username");
    if !username.trim().is_empty() {
        legacy.push(Bson::Document(doc! {
            "username":{"$regex":regex::escape(username.trim()),"$options":"i"}
        }));
    }
    let email = db::string(user, "email").trim().to_lowercase();
    if !email.is_empty() {
        let matcher = doc! {"$regex":regex::escape(&email),"$options":"i"};
        legacy.push(Bson::Document(doc! {"email":matcher.clone()}));
        legacy.push(Bson::Document(doc! {"emails":matcher}));
    }
    if legacy.is_empty() {
        return Some(owner);
    }
    let legacy_owner = doc! {
        "$and":[
            {"$or":[{"owner_user_id":{"$exists":false}},{"owner_user_id":Bson::Null}]},
            {"$or":legacy},
        ]
    };
    Some(doc! {"$or":[owner, legacy_owner]})
}

async fn subscription_filter(state: &AppState, ctx: &ReqCtx, id: Option<&str>) -> Option<Document> {
    let owner = if ctx.is_top_admin(state) {
        doc! {}
    } else if ctx.is_organization_admin(state) {
        let ids = organization_member_ids(state, ctx).await?;
        doc! {"owner_user_id":{"$in":ids}}
    } else if ctx.is_admin(state) {
        doc! {"managed_by_user_id":ctx.user_id()?}
    } else {
        self_subscription_owner_filter(ctx)?
    };
    if let Some(id) = id {
        if id.is_empty() {
            return None;
        }
        let identifier = if let Some(oid) = db::object_id(id) {
            doc! {"_id":oid}
        } else {
            doc! {"$or":[{"email":id.to_lowercase()},{"emails":id.to_lowercase()}]}
        };
        if owner.is_empty() {
            Some(identifier)
        } else {
            Some(doc! {"$and":[identifier,owner]})
        }
    } else {
        Some(owner)
    }
}

fn public_organization_member(user: &Document, subscription: Option<&Document>) -> Value {
    let mut value = auth::public_user(user);
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "account_status".into(),
            json!(if db::bool_field(user, "disabled") {
                "disabled"
            } else {
                "active"
            }),
        );
        object.insert("has_subscription".into(), json!(subscription.is_some()));
        object.insert(
            "subscription".into(),
            subscription.map(public).unwrap_or(Value::Null),
        );
    }
    value
}

async fn organization_subscription_rows(
    state: &AppState,
    ctx: &ReqCtx,
) -> Result<Vec<Value>, String> {
    let members = organization_members(state, ctx)
        .await
        .ok_or_else(|| "Your Account Hub organization is not available.".to_owned())?;
    let ids: Vec<Bson> = members
        .iter()
        .filter_map(|user| user.get_object_id("_id").ok().map(Bson::ObjectId))
        .collect();
    let subscriptions = if ids.is_empty() {
        Vec::new()
    } else {
        db::find_many(
            &state.web,
            "sub_account",
            doc! {"owner_user_id":{"$in":ids}},
            5000,
        )
        .await
        .map_err(|_| "Unable to load subscriptions.".to_owned())?
    };
    let mut by_owner = HashMap::new();
    for subscription in subscriptions {
        if let Ok(owner_id) = subscription.get_object_id("owner_user_id") {
            by_owner.insert(owner_id, subscription);
        }
    }
    Ok(members
        .iter()
        .map(|member| {
            let subscription = member
                .get_object_id("_id")
                .ok()
                .and_then(|owner_id| by_owner.get(&owner_id));
            public_organization_member(member, subscription)
        })
        .collect())
}
fn recipients(data: &Value) -> Result<Vec<String>, String> {
    let raw = if let Some(items) = data.get("emails") {
        items.clone()
    } else if let Some(email) = data.get("email") {
        json!([email])
    } else {
        return Err("At least one email recipient is required.".into());
    };
    let items = raw.as_array().ok_or("Email recipients must be an array.")?;
    if items.is_empty() || items.len() > 50 {
        return Err("Email recipient count must be between 1 and 50.".into());
    }
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for item in items {
        let email = item
            .as_str()
            .ok_or("Email recipients must be non-empty text values.")?
            .trim()
            .to_lowercase();
        if !email.contains('@')
            || !email
                .rsplit('@')
                .next()
                .is_some_and(|domain| domain.contains('.'))
        {
            return Err(format!("Invalid email address: {email}"));
        }
        if seen.insert(email.clone()) {
            output.push(email)
        }
    }
    Ok(output)
}
fn json_error(status: StatusCode, message: &str) -> Option<Response> {
    Some(view::error(status, message))
}
fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
async fn notify(
    state: &AppState,
    emails: &[String],
    mode: &str,
    kind: &str,
    username: &str,
    team: &str,
) -> Result<(), String> {
    let subject = match kind {
        "created" => "Security portal subscription confirmed",
        "updated" => "Security portal subscription updated",
        _ => "Security portal subscription cancelled",
    };
    let body = format!(
        "<html><body><h2>{subject}</h2><p>Username: {}</p><p>Team: {}</p></body></html>",
        escape_html(username),
        escape_html(team)
    );
    mail::send(state, emails, mode, subject, &body).await
}
async fn vendor_import(ctx: &ReqCtx) -> Response {
    let content_type = ctx
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let boundary = match multer::parse_boundary(content_type) {
        Ok(v) => v,
        Err(_) => return view::error(StatusCode::BAD_REQUEST, "Choose a vendor/product CSV file."),
    };
    let bytes = Bytes::from(ctx.body.clone());
    let body = stream::once(async move { Ok::<Bytes, std::io::Error>(bytes) });
    let mut multipart = multer::Multipart::new(body, boundary);
    let mut csv_bytes = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") {
            csv_bytes = field.bytes().await.ok();
            break;
        }
    }
    let Some(bytes) = csv_bytes else {
        return view::error(StatusCode::BAD_REQUEST, "Choose a vendor/product CSV file.");
    };
    if bytes.len() > 1024 * 1024 {
        return view::error(StatusCode::BAD_REQUEST, "CSV file is too large.");
    }
    let mut reader = csv::ReaderBuilder::new()
        .flexible(false)
        .from_reader(bytes.as_ref());
    let headers = match reader.headers() {
        Ok(v) => v.clone(),
        Err(_) => return view::error(StatusCode::BAD_REQUEST, "CSV is invalid."),
    };
    if headers.iter().collect::<Vec<_>>()
        != vec!["vendor", "product", "vendor_aliases", "product_aliases"]
    {
        return view::error(
            StatusCode::BAD_REQUEST,
            "CSV columns must be vendor, product, vendor_aliases, product_aliases.",
        );
    }
    let mut rows = Vec::new();
    for (i, result) in reader.records().enumerate() {
        let Ok(record) = result else {
            return view::error(StatusCode::BAD_REQUEST, "CSV row is invalid.");
        };
        if i >= 500 {
            return view::error(
                StatusCode::BAD_REQUEST,
                "CSV must contain at most 500 data rows.",
            );
        };
        let vendor = record.get(0).unwrap_or("").trim();
        let product = record.get(1).unwrap_or("").trim();
        if vendor.is_empty() || product.is_empty() {
            return view::error(StatusCode::BAD_REQUEST, "Vendor and product are required.");
        }
        let aliases = |v: &str| {
            v.split('|')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        rows.push(json!({"vendor":vendor,"product":product,"vendor_aliases":aliases(record.get(2).unwrap_or("")),"product_aliases":aliases(record.get(3).unwrap_or("")),"row_number":i+2}));
    }
    if rows.is_empty() {
        return view::error(
            StatusCode::BAD_REQUEST,
            "CSV must contain at least one data row.",
        );
    }
    view::json_response(
        StatusCode::OK,
        json!({"vendor_product_filter":{"enabled":true,"schema_version":1,"include_possible_matches":false,"rows":rows},"warnings":[]}),
    )
}
async fn collection_rows(state: &AppState) -> Vec<Value> {
    let mut data = Vec::new();
    if let Ok(names) = reviews::views(state).await {
        for name in names {
            let source = name
                .strip_suffix(&state.cfg.review_view_suffix)
                .unwrap_or(&name);
            let count = db::collection(&state.vuln, source)
                .count_documents(doc! {})
                .await
                .unwrap_or(0);
            data.push(json!({"name":name,"source":source,"count":count}));
        }
    }
    data
}
fn profile_filter(filters: &Value, source: &str) -> Document {
    let mut clauses: Vec<Bson> = Vec::new();
    let mapping: [(&str, &[&str]); 6] = [
        (
            "search",
            &[
                "code",
                "cve",
                "cve_ids",
                "title",
                "description",
                "impacts",
                "affected",
                "recommendation",
                "related_link",
            ],
        ),
        ("code", &["code", "cve", "cve_ids"]),
        ("title", &["title"]),
        ("impact", &["impacts"]),
        ("affected", &["affected"]),
        ("source", &["source.url", "source.detail_url"]),
    ];
    for (name, fields) in mapping {
        let Some(value) = filters[name].as_str().filter(|v| !v.trim().is_empty()) else {
            continue;
        };
        for term in value.split_whitespace() {
            let options: Vec<Bson> = fields
                .iter()
                .map(|field| {
                    let mut d = Document::new();
                    d.insert(*field, doc! {"$regex":regex::escape(term),"$options":"i"});
                    Bson::Document(d)
                })
                .collect();
            clauses.push(Bson::Document(doc! {"$or":options}));
        }
    }
    let status = filters["status"].as_array().cloned().unwrap_or_default();
    let threshold = filters["severity_threshold"].as_str().unwrap_or("");
    let include_unknown = filters["include_unknown"] == true;
    let mut accepted = status
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !threshold.is_empty() {
        for severity in ["Critical", "High", "Medium", "Low"] {
            if !accepted.iter().any(|v| v == severity) {
                accepted.push(severity.into())
            }
            if severity == threshold {
                break;
            }
        }
    }
    if accepted.is_empty() && !include_unknown && source != "zimbra" {
        accepted = ["Critical", "High", "Medium", "Low"]
            .iter()
            .map(|v| v.to_string())
            .collect()
    }
    if !accepted.is_empty() {
        let mut ors=accepted.iter().map(|s|Bson::Document(doc!{"severity":{"$regex":format!("^{}(?:\\s+Risk)?$",regex::escape(s)),"$options":"i"}})).collect::<Vec<_>>();
        if include_unknown {
            ors.push(Bson::Document(doc! {"severity":{"$exists":false}}));
            ors.push(Bson::Document(doc! {"severity":Bson::Null}));
            ors.push(Bson::Document(doc! {"severity":""}));
        }
        clauses.push(Bson::Document(doc! {"$or":ors}));
    }
    let window = filters["time_window"].as_str().unwrap_or("all");
    let now = chrono::Utc::now();
    let start = match window {
        "daily" => {
            let hk = now + chrono::Duration::hours(8);
            let midnight = hk.date_naive().and_hms_opt(0, 0, 0).unwrap();
            Some((midnight - chrono::Duration::hours(8)).and_utc())
        }
        "week" => Some(now - chrono::Duration::days(7)),
        _ => None,
    };
    if let Some(start) = start {
        clauses.push(Bson::Document(
            doc! {"observed_at":{"$gte":bson::DateTime::from_millis(start.timestamp_millis())}},
        ));
    }
    if filters["report_scope"]["kev_only"] == true {
        clauses.push(Bson::Document(doc!{"$or":[{"cisa_kev":true},{"kev":true},{"details.cisa_kev":true},{"details.kev":true}]}));
    }
    if clauses.is_empty() {
        doc! {}
    } else if clauses.len() == 1 {
        clauses.remove(0).as_document().cloned().unwrap_or_default()
    } else {
        doc! {"$and":clauses}
    }
}
fn inventory_match(document: &Document, filters: &Value) -> bool {
    let inventory = &filters["vendor_product_filter"];
    if inventory["enabled"] != true {
        return true;
    }
    vendor_matcher::classify(&db::bson_json(document), inventory).is_some()
}
pub(crate) async fn match_profile(state: &AppState, profile: &Value, limit: i64) -> Vec<Value> {
    let mut output = Vec::new();
    let filters = &profile["filters"];
    let mut names = filters["collections"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if names.is_empty() {
        names = reviews::views(state).await.unwrap_or_default()
    }
    for name in names {
        let source = name
            .strip_suffix(&state.cfg.review_view_suffix)
            .unwrap_or(&name);
        let filter = profile_filter(filters, source);
        let Ok((_, documents)) = reviews::query_rows(state, &name, filter, 0, 10_000).await else {
            continue;
        };
        for doc in documents {
            if !inventory_match(&doc, filters) {
                continue;
            }
            output.push(json!({"collection":name,"source_collection":source,"selection_id":db::id_string(&doc),"document":db::bson_json(&doc)}));
            if output.len() >= limit as usize {
                return output;
            }
        }
    }
    output
}
pub async fn handle(state: &AppState, ctx: &ReqCtx) -> Option<Response> {
    if ctx.path == "/subscriptions" && ctx.method == Method::GET {
        return Some(render(state, ctx, "subscriptions/index.html", json!({})));
    }
    if ctx.path == "/api/subscriptions/vendor-product-template.csv" && ctx.method == Method::GET {
        return Some(view::attachment("text/csv; charset=utf-8","vendor_product_filter_template.csv","vendor,product,vendor_aliases,product_aliases\nRed Hat,Enterprise Linux,\"Red Hat, Inc.|RedHat\",RHEL|Red Hat Enterprise Linux\nMicrosoft,Windows Server,Microsoft Corporation,Windows Server 2019|Windows Server 2022\nApache Software Foundation,HTTP Server,Apache|ASF,Apache HTTPD|httpd\n".into()));
    }
    if ctx.path == "/api/subscriptions/vendor-product-import" && ctx.method == Method::POST {
        return Some(vendor_import(ctx).await);
    }
    if ctx.path == "/api/subscriptions/collections" && ctx.method == Method::GET {
        return Some(view::json_response(
            StatusCode::OK,
            json!({"data":collection_rows(state).await}),
        ));
    }
    if ctx.path == "/api/subscriptions/schema" && ctx.method == Method::GET {
        let names = reviews::views(state).await.unwrap_or_default();
        return Some(view::json_response(
            StatusCode::OK,
            json!({"schema_version":1,"subscription":{"fields":["username","emails","team","delivery_mode"],"delivery_modes":["grouped","individual"],"default_delivery_mode":"individual"},"profile_types":["newsletter","report"],"review_collections":names,"filters":{"defaults":default_filters()},"profiles":{"newsletter":{"defaults":default_profile("newsletter")},"report":{"defaults":default_profile("report")}},"vendor_product_filter":{"schema_version":1,"defaults":{"enabled":false,"schema_version":1,"include_possible_matches":false,"rows":[]}},"allowed_values":{"severity":["Critical","High","Medium","Low"],"time_window":["all","daily","week","custom"],"generation_mode":["template","enriched_weekly"],"report_language":["en","zh","ch"]},"limits":{"report_scope_max_count":500}}),
        ));
    }
    if ctx.path == "/api/organization/subscriptions" && ctx.method == Method::GET {
        if !ctx.is_organization_admin(state) {
            return json_error(
                StatusCode::FORBIDDEN,
                "Organization administrator access required.",
            );
        }
        return Some(match organization_subscription_rows(state, ctx).await {
            Ok(rows) => view::json_response(StatusCode::OK, json!({"data":rows})),
            Err(error) => view::error(StatusCode::SERVICE_UNAVAILABLE, &error),
        });
    }
    if ctx.path == "/api/subscriptions" && ctx.method == Method::GET {
        let Some(filter) = subscription_filter(state, ctx, None).await else {
            return json_error(StatusCode::FORBIDDEN, "Access denied.");
        };
        return Some(
            match db::find_many(&state.web, "sub_account", filter, 5000).await {
                Ok(rows) => view::json_response(
                    StatusCode::OK,
                    json!({"data":rows.iter().map(public).collect::<Vec<_>>()}),
                ),
                Err(_) => view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to load subscriptions.",
                ),
            },
        );
    }
    if ctx.path == "/api/subscriptions/preview" && ctx.method == Method::POST {
        let mode = ctx.field("mode");
        if !matches!(mode.as_str(), "create" | "update") {
            return json_error(
                StatusCode::BAD_REQUEST,
                "Preview mode must be create or update.",
            );
        }
        if mode == "create" && !can_manage_subscriptions(state, ctx) && !is_self_manager(state, ctx)
        {
            return json_error(StatusCode::FORBIDDEN, "Access denied.");
        }
        let mut data = ctx.json.clone();
        let mut identifier = String::new();
        if mode == "update" {
            identifier = ctx.field("subscription_id");
            if identifier.is_empty() {
                identifier = ctx.field("id")
            }
            if identifier.is_empty() {
                identifier = ctx.field("email")
            }
            let Some(filter) = subscription_filter(state, ctx, Some(&identifier)).await else {
                return json_error(StatusCode::FORBIDDEN, "Access denied.");
            };
            let Some(existing) = db::find_one(&state.web, "sub_account", filter)
                .await
                .ok()
                .flatten()
            else {
                return json_error(StatusCode::NOT_FOUND, "Subscription not found.");
            };
            let old = db::bson_json(&existing);
            for name in ["newsletter_profile", "report_profile"] {
                if data.get(name).is_none() {
                    data[name] = old.get(name).cloned().unwrap_or(Value::Null)
                }
            }
        }
        let newsletter = match profile(state, "newsletter", &data["newsletter_profile"]).await {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
        };
        let report = match profile(state, "report", &data["report_profile"]).await {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
        };
        return Some(view::json_response(
            StatusCode::OK,
            json!({"valid":true,"mode":mode,"normalized_profiles":{"newsletter_profile":newsletter,"report_profile":report},"newsletter_profile":newsletter,"report_profile":report,"applied_defaults":[],"warnings":[],"subscription_id":identifier}),
        ));
    }
    if ctx.path == "/api/subscriptions/report-preview" && ctx.method == Method::POST {
        let report = match profile(state, "report", &ctx.json["report_profile"]).await {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
        };
        let matches = match_profile(state, &report, 100).await;
        let top: Vec<String> = matches
            .iter()
            .take(3)
            .map(|row| row["selection_id"].as_str().unwrap_or("").to_owned())
            .collect();
        return Some(view::json_response(
            StatusCode::OK,
            json!({"count":matches.len(),"top_cves":top,"match_examples":[],"vendor_product_filter_enabled":report["filters"]["vendor_product_filter"]["enabled"]==true}),
        ));
    }
    if ctx.path == "/api/subscriptions" && ctx.method == Method::POST {
        let self_only = is_self_manager(state, ctx);
        if !can_manage_subscriptions(state, ctx) && !self_only {
            return json_error(
                StatusCode::FORBIDDEN,
                "You can only manage your own subscription.",
            );
        }
        if state.cfg.account_hub_enabled
            && ctx
                .json
                .get("password")
                .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "Account Hub users do not use local passwords.",
            );
        }
        let submitted_emails = match recipients(&ctx.json) {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
        };
        let username = ctx.field("username");
        let mut username = if username.trim().is_empty() {
            ctx.field("email")
        } else {
            username
        };
        let emails = if self_only {
            let Some(user) = ctx.user.as_ref() else {
                return json_error(StatusCode::UNAUTHORIZED, "Authentication required.");
            };
            let current_username = db::string(user, "username");
            if !same_username(&username, &current_username) {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "You can only manage your own subscription.",
                );
            }
            let current_email = db::string(user, "email").trim().to_lowercase();
            if current_email.is_empty()
                || submitted_emails.len() != 1
                || !same_username(&submitted_emails[0], &current_email)
            {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "You can only manage your own subscription.",
                );
            }
            username = current_username;
            vec![current_email]
        } else {
            submitted_emails
        };
        let team = ctx.field("team");
        if username.trim().is_empty() || team.trim().is_empty() {
            return json_error(
                StatusCode::BAD_REQUEST,
                "Username, email, and team are required.",
            );
        }
        let mode = ctx.field("delivery_mode");
        let mode = if mode.is_empty() { "individual" } else { &mode };
        if !matches!(mode, "individual" | "grouped") {
            return json_error(StatusCode::BAD_REQUEST, "Invalid email delivery mode.");
        }
        let newsletter = match profile(state, "newsletter", &ctx.json["newsletter_profile"]).await {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
        };
        let report = match profile(state, "report", &ctx.json["report_profile"]).await {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
        };
        let users = db::collection(&state.web, "auth");
        let owner = users
            .find_one(doc! {"username_key":username.trim().to_lowercase()})
            .await
            .ok()
            .flatten();
        if self_only && owner.is_none() {
            return json_error(
                StatusCode::FORBIDDEN,
                "You can only manage your own subscription.",
            );
        }
        if ctx.is_organization_admin(state) {
            let Some(member) = owner.as_ref() else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "Account Hub user must be approved before creating a subscription.",
                );
            };
            if db::string(member, "auth_source") != "account_hub"
                || !ctx
                    .user
                    .as_ref()
                    .is_some_and(|manager| crate::auth::same_organization(manager, member))
            {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "You can only manage members of your organization.",
                );
            }
        }
        let existing=db::find_one(&state.web,"sub_account",doc!{"username":{"$regex":format!("^{}$",regex::escape(username.trim())),"$options":"i"}}).await.ok().flatten();
        if existing.is_some() {
            return json_error(
                StatusCode::CONFLICT,
                "A subscription already exists for this username.",
            );
        }
        let owner_id = if let Some(owner) = owner {
            if self_only && ctx.user_id() != owner.get_object_id("_id").ok() {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "You can only manage your own subscription.",
                );
            }
            let account_hub_member = ctx.is_organization_admin(state)
                && db::string(&owner, "auth_source") == "account_hub";
            if db::string(&owner, "role") != "user" && !account_hub_member {
                return json_error(
                    StatusCode::CONFLICT,
                    "Username is already used by the administrator.",
                );
            }
            owner.get_object_id("_id").unwrap()
        } else {
            if state.cfg.account_hub_enabled {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "Account Hub user must be approved before creating a subscription.",
                );
            }
            let password = ctx.field("password");
            if password.is_empty() || password.len() > 72 {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "Password is required and must be 72 bytes or fewer.",
                );
            }
            let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap();
            let now = bson::DateTime::now();
            match users.insert_one(doc!{"username":username.trim(),"username_key":username.trim().to_lowercase(),"email":&emails[0],"password":hash,"role":"user","auth_source":"local","must_change_password":false,"created_at":now,"updated_at":now}).await{Ok(v)=>v.inserted_id.as_object_id().unwrap(),Err(_)=>return json_error(StatusCode::SERVICE_UNAVAILABLE,"Unable to add subscription.")}
        };
        let now = bson::DateTime::now();
        let document = doc! {"owner_user_id":owner_id,"managed_by_user_id":ctx.user_id().unwrap(),"username":username.trim(),"emails":emails.clone(),"email":&emails[0],"team":team.trim(),"delivery_mode":mode,"newsletter_profile":db::json_doc(&newsletter).unwrap(),"report_profile":db::json_doc(&report).unwrap(),"created_at":now,"updated_at":now};
        return Some(
            match db::collection(&state.web, "sub_account")
                .insert_one(document)
                .await
            {
                Ok(v) => {
                    if notify(state, &emails, mode, "created", &username, &team)
                        .await
                        .is_err()
                    {
                        view::error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Subscription was saved, but the confirmation email could not be sent.",
                        )
                    } else {
                        view::json_response(
                            StatusCode::CREATED,
                            json!({"success":true,"id":v.inserted_id.as_object_id().map(|id|id.to_hex()).unwrap_or_default()}),
                        )
                    }
                }
                Err(_) => view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to add subscription.",
                ),
            },
        );
    }
    if let Some(tail) = ctx.path.strip_prefix("/api/subscriptions/") {
        let (identifier, action) = tail.split_once('/').unwrap_or((tail, ""));
        let Some(filter) = subscription_filter(state, ctx, Some(identifier)).await else {
            return json_error(StatusCode::FORBIDDEN, "Access denied.");
        };
        let coll = db::collection(&state.web, "sub_account");
        let Some(existing) = coll.find_one(filter).await.ok().flatten() else {
            return json_error(StatusCode::NOT_FOUND, "Subscription not found.");
        };
        let id = existing.get_object_id("_id").unwrap();
        if action == "run" && ctx.method == Method::POST {
            let old = db::bson_json(&existing);
            if old["report_profile"]["enabled"] != true {
                return json_error(StatusCode::BAD_REQUEST, "Report profile is disabled.");
            };
            let matches = match_profile(state, &old["report_profile"], 500).await;
            let selections: Vec<Value> = matches
                .iter()
                .map(|v| json!({"collection":v["collection"],"selection_id":v["selection_id"]}))
                .collect();
            return Some(view::json_response(
                StatusCode::OK,
                json!({"selections":selections,"count":selections.len()}),
            ));
        }
        if action == "send-statistic" && ctx.method == Method::POST {
            let sub = db::bson_json(&existing);
            if sub["newsletter_profile"]["enabled"] != true {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "Newsletter feed is disabled for this subscription.",
                );
            }
            let emails = recipients(&sub).unwrap_or_default();
            let mut total = 0u64;
            for email in &emails {
                total += db::collection(&state.web, "newsletter_deliveries")
                    .count_documents(doc! {"email":email})
                    .await
                    .unwrap_or(0)
            }
            let stats =
                json!({"email":emails.join(", "),"total":total,"by_collection":[],"databases":[]});
            let html = format!(
                "<html><body><h2>Newsletter delivery statistics</h2><p>Total delivered: {total}</p></body></html>"
            );
            let mode = sub["delivery_mode"].as_str().unwrap_or("individual");
            return Some(
                match mail::send(
                    state,
                    &emails,
                    mode,
                    "Newsletter delivery statistics",
                    &html,
                )
                .await
                {
                    Ok(_) => view::json_response(
                        StatusCode::OK,
                        json!({"success":true,"message":"Newsletter statistics email sent.","statistics":stats}),
                    ),
                    Err(e) => view::error(StatusCode::BAD_GATEWAY, &e),
                },
            );
        }
        if action.is_empty() && ctx.method == Method::DELETE {
            let old = db::bson_json(&existing);
            let emails = recipients(&old).unwrap_or_default();
            let mode = old["delivery_mode"].as_str().unwrap_or("individual");
            let username = old["username"].as_str().unwrap_or("");
            let team = old["team"].as_str().unwrap_or("");
            return Some(match coll.delete_one(doc! {"_id":id}).await {
                Ok(_) => {
                    if notify(state, &emails, mode, "cancelled", username, team)
                        .await
                        .is_err()
                    {
                        view::error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Subscription was cancelled, but the notification email could not be sent.",
                        )
                    } else {
                        view::json_response(StatusCode::OK, json!({"success":true}))
                    }
                }
                Err(_) => view::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to remove subscription.",
                ),
            });
        }
        if action.is_empty() && ctx.method == Method::PUT {
            if !can_manage_subscriptions(state, ctx)
                && ["username", "emails", "email", "password"]
                    .iter()
                    .any(|key| ctx.json.get(*key).is_some())
            {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "Only an administrator can edit subscription identity fields.",
                );
            }
            let mut data = db::bson_json(&existing);
            merge(&mut data, &ctx.json);
            let emails = match recipients(&data) {
                Ok(v) => v,
                Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
            };
            let newsletter = match profile(state, "newsletter", &data["newsletter_profile"]).await {
                Ok(v) => v,
                Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
            };
            let report = match profile(state, "report", &data["report_profile"]).await {
                Ok(v) => v,
                Err(e) => return json_error(StatusCode::BAD_REQUEST, &e),
            };
            let username = data["username"].as_str().unwrap_or("").trim();
            let team = data["team"].as_str().unwrap_or("").trim();
            if username.is_empty() || team.is_empty() {
                return json_error(StatusCode::BAD_REQUEST, "Username and team are required.");
            }
            let mode = data["delivery_mode"].as_str().unwrap_or("individual");
            if !matches!(mode, "individual" | "grouped") {
                return json_error(StatusCode::BAD_REQUEST, "Invalid email delivery mode.");
            }
            let mut update = doc! {"username":username,"email":&emails[0],"emails":emails.clone(),"team":team,"delivery_mode":mode,"newsletter_profile":db::json_doc(&newsletter).unwrap(),"report_profile":db::json_doc(&report).unwrap(),"updated_at":bson::DateTime::now()};
            if ctx.is_organization_admin(state) && ctx.json.get("username").is_some() {
                let Some(manager) = ctx.user.as_ref() else {
                    return json_error(StatusCode::UNAUTHORIZED, "Authentication required.");
                };
                let Some(member) = db::find_one(
                    &state.web,
                    "auth",
                    doc! {"username_key":username.to_lowercase()},
                )
                .await
                .ok()
                .flatten() else {
                    return json_error(
                        StatusCode::FORBIDDEN,
                        "You can only manage members of your organization.",
                    );
                };
                let Some(member_id) = member.get_object_id("_id").ok() else {
                    return json_error(StatusCode::FORBIDDEN, "Subscription owner is invalid.");
                };
                if db::string(&member, "auth_source") != "account_hub"
                    || !crate::auth::same_organization(manager, &member)
                {
                    return json_error(
                        StatusCode::FORBIDDEN,
                        "You can only manage members of your organization.",
                    );
                }
                let current_owner = existing.get_object_id("owner_user_id").ok();
                if current_owner != Some(member_id)
                    && coll
                        .find_one(doc! {"owner_user_id":member_id})
                        .await
                        .ok()
                        .flatten()
                        .is_some()
                {
                    return json_error(
                        StatusCode::CONFLICT,
                        "A subscription already exists for this username.",
                    );
                }
                update.insert("owner_user_id", member_id);
                update.insert("username", db::string(&member, "username"));
            }
            return Some(
                match coll.update_one(doc! {"_id":id}, doc! {"$set":update}).await {
                    Ok(_) => {
                        let changed = ctx.json.get("newsletter_profile").is_some()
                            || ctx.json.get("report_profile").is_some()
                            || ctx.json.get("emails").is_some()
                            || ctx.json.get("team").is_some();
                        if changed
                            && notify(state, &emails, mode, "updated", username, team)
                                .await
                                .is_err()
                        {
                            view::error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "Subscription was updated, but the notification email could not be sent.",
                            )
                        } else {
                            view::json_response(StatusCode::OK, json!({"success":true}))
                        }
                    }
                    Err(_) => view::error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Unable to update subscription.",
                    ),
                },
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::oid::ObjectId;

    #[test]
    fn organization_member_rows_include_account_status_and_subscription() {
        let owner_id = ObjectId::new();
        let user = doc! {
            "_id": owner_id,
            "username": "member",
            "email": "member@example.com",
            "role": "user",
            "auth_source": "account_hub",
            "account_hub_organization": "SW-ENG",
            "account_hub_organization_id": "1",
            "account_hub_is_organization_admin": false,
            "disabled": false,
        };
        let subscription = doc! {
            "_id": ObjectId::new(),
            "owner_user_id": owner_id,
            "username": "member",
            "email": "member@example.com",
            "emails": ["member@example.com"],
            "team": "SW-ENG",
            "newsletter_profile": {"enabled": true},
            "report_profile": {"enabled": false},
        };
        let row = public_organization_member(&user, Some(&subscription));
        assert_eq!(row["username"], "member");
        assert_eq!(row["account_status"], "active");
        assert_eq!(row["has_subscription"], true);
        assert!(row["subscription"]["id"].as_str().is_some());
    }

    #[test]
    fn organization_member_rows_keep_disabled_members_without_subscription() {
        let user = doc! {
            "_id": ObjectId::new(),
            "username": "disabled-member",
            "email": "disabled@example.com",
            "role": "user",
            "auth_source": "account_hub",
            "account_hub_organization": "SW-ENG",
            "account_hub_organization_id": "1",
            "disabled": true,
        };
        let row = public_organization_member(&user, None);
        assert_eq!(row["account_status"], "disabled");
        assert_eq!(row["has_subscription"], false);
        assert!(row["subscription"].is_null());
    }

    #[test]
    fn self_subscription_filter_includes_owner_and_legacy_identity() {
        let owner_id = ObjectId::new();
        let ctx = ReqCtx {
            method: Method::GET,
            path: "/api/subscriptions".into(),
            query: Vec::new(),
            headers: axum::http::HeaderMap::new(),
            body: Vec::new(),
            json: Value::Null,
            form: std::collections::HashMap::new(),
            user: Some(doc! {
                "_id": owner_id,
                "username": "member",
                "email": "member@example.com",
            }),
        };
        let filter = self_subscription_owner_filter(&ctx).unwrap();
        assert_eq!(filter.get_array("$or").unwrap().len(), 2);
    }
}
