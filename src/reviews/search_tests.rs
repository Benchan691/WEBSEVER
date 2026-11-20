use super::*;
use axum::{body::to_bytes, http::HeaderMap};
use mongodb::{Client, bson::oid::ObjectId};
use std::{path::PathBuf, sync::Arc};

fn request(path: &str, body: Value) -> ReqCtx {
    ReqCtx {
        method: Method::POST,
        path: path.into(),
        query: vec![],
        headers: HeaderMap::new(),
        body: vec![],
        json: body,
        form: HashMap::new(),
        user: None,
    }
}

async fn api(state: &AppState, ctx: ReqCtx) -> (StatusCode, Value) {
    let response = handle(state, &ctx).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn search(state: &AppState, body: Value) -> Value {
    let (status, value) = api(state, request("/api/reviews/search", body)).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    value
}

#[tokio::test]
#[ignore = "requires REVIEW_SEARCH_TEST_MONGO_URI for a disposable database"]
async fn review_source_picker_matches_exact_selected_providers() {
    let state = test_state().await;
    db::collection(&state.vuln, "news")
        .insert_many([
            doc! {"_id":"nvd:2026-12345", "code":"CVE-2026-12345", "source":{"provider":"nvd"}, "severity":"High"},
            doc! {"_id":"cnvd:2026-12346", "code":"CVE-2026-12346", "source":{"provider":"cnvd"}, "severity":"High"},
            doc! {"_id":"splunk:SVD-2026-1102", "code":"SVD-2026-1102", "source":{"provider":"splunk"}, "severity":"High"},
        ])
        .await
        .unwrap();
    let mut page = request("/reviews", Value::Null);
    page.method = Method::GET;
    let response = handle(&state, &page).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("id=\"review-collections-toggle\""));
    let (_, config) = html
        .split_once("<script id=\"page-config\" type=\"application/json\">")
        .unwrap();
    let config: Value = serde_json::from_str(config.split_once("</script>").unwrap().0).unwrap();
    assert_eq!(config["reviewSources"], json!(["cnvd", "nvd", "splunk"]));

    let matches = search(&state, json!({"source_provider":"nvd"})).await;
    assert_eq!(matches["total"], 1);
    assert_eq!(matches["data"][0]["source"], "nvd");
    let matches = search(&state, json!({"source_provider":["nvd", "splunk"]})).await;
    assert_eq!(matches["total"], 2);
    let sources = |rows: &Value| {
        rows.as_array()
            .unwrap()
            .iter()
            .map(|row| row["source"].as_str().unwrap().to_owned())
            .collect::<HashSet<_>>()
    };
    let expected = HashSet::from(["nvd".to_owned(), "splunk".to_owned()]);
    assert_eq!(sources(&matches["data"]), expected);
    let (status, selected) = api(
        &state,
        request(
            "/api/reviews/auto-select",
            json!({"count":10,"source_provider":["nvd", "splunk"]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(selected["selected"], 2);
    assert_eq!(sources(&selected["selections"]), expected);
    assert_eq!(
        search(&state, json!({"source_provider":[]})).await["total"],
        3
    );
    state.vuln.drop().await.unwrap();
}

async fn test_state() -> AppState {
    let uri = std::env::var("REVIEW_SEARCH_TEST_MONGO_URI").unwrap();
    let client = Client::with_uri_str(&uri).await.unwrap();
    let database = client.database(&format!("review_search_test_{}", ObjectId::new()));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    AppState {
        cfg: crate::config::Config {
            root: root.clone(),
            file: json!({}),
            mongo_uri: uri,
            web_database: database.name().into(),
            vulnerabilities_database: database.name().into(),
            vulnerabilities_collection: "news".into(),
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
    }
}

#[tokio::test]
#[ignore = "requires REVIEW_SEARCH_TEST_MONGO_URI for a disposable database"]
async fn keyword_search_optional_csv_pagination_and_auto_selection() {
    let state = test_state().await;
    let database = state.vuln.clone();
    let now = DateTime::parse_from_rfc3339("2026-11-13T09:30:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let date =
        |value: DateTime<Utc>| mongodb::bson::DateTime::from_millis(value.timestamp_millis());
    let news = db::collection(&database, "news");
    news.insert_many([
        doc! {"_id":"cve:2026-1001","code":"2026-1001","title":"OpenSSL Widget+ overflow","severity":"High","observed_at":date(now),"details":{"affected":[{"vendor":"Acme","product":"Widget"}]}},
        doc! {"_id":"cve:2026-1002","code":"2026-1002","title":"openssl widget regression","severity":"High","observed_at":date(now),"details":{"affected":[{"vendor":"Other","product":"Widget"}]}},
        doc! {"_id":"nvd:2026-1003","code":"2026-1003","title":"Remote issue","severity":"Critical","observed_at":date(now-chrono::Duration::days(1)),"details":{"cve_id":"CVE-2026-1003","containers":{"cna":{"descriptions":[{"value":"OPENSSL parser"}],"affected":[{"vendor":"Acme","product":"Widget"}]}}}},
        doc! {"_id":"cve:2026-1004","code":"2026-1004","title":"WidgetX anomaly","severity":"Low","observed_at":date(now-chrono::Duration::days(50))},
        doc! {"_id":"cve:2026-1005","code":"2026-1005","title":"OpenSSL unknown","observed_at":date(now)},
    ]).await.unwrap();
    let inventory = json!({"enabled":true,"schema_version":1,"rows":[{"vendor":"Acme","product":"Widget","vendor_aliases":[],"product_aliases":[]}]});

    assert_eq!(
        search(&state, json!({"search":"OPENSSL"})).await["total"],
        3
    );
    assert_eq!(search(&state, json!({"search":"  \t "})).await["total"], 4);
    assert_eq!(
        search(&state, json!({"search":"Widget+"})).await["total"],
        1
    );
    assert_eq!(
        search(&state, json!({"search":"regression anomaly"})).await["total"],
        2
    );
    assert_eq!(
        search(&state, json!({"search":"CVE-2026-1003"})).await["data"][0]["selection_id"],
        "nvd:2026-1003"
    );
    let first = search(&state, json!({"search":"openssl","page_size":1})).await;
    let second = search(&state, json!({"search":"openssl","page_size":1,"page":2})).await;
    assert_eq!(first["pages"], 3);
    assert_eq!(first["data"][0]["selection_id"], "cve:2026-1002");
    assert_eq!(second["data"][0]["selection_id"], "cve:2026-1001");
    assert_eq!(
        search(&state, json!({"page_size":1000})).await["page_size"],
        100
    );
    assert_eq!(
        search(&state, json!({"search":"openssl","page":99})).await["data"],
        json!([])
    );
    let narrowed = search(
        &state,
        json!({"search":"openssl","vendor_product_filter":inventory}),
    )
    .await;
    assert_eq!(narrowed["total"], 2);
    assert_eq!(
        search(
            &state,
            json!({"search":"regression","vendor_product_filter":inventory})
        )
        .await["total"],
        0
    );
    assert_eq!(
        search(
            &state,
            json!({"search":"regression","vendor_product_filter":{"enabled":false,"rows":[]}})
        )
        .await["total"],
        1
    );
    assert_eq!(
        search(
            &state,
            json!({"search":"openssl","vendor_product_filter":null})
        )
        .await["total"],
        3
    );
    let combined = json!({"search":"openssl","status":["High"],"time_window":"custom","start":"2026-11-13T00:00:00Z","end":"2026-11-14T00:00:00Z"});
    assert_eq!(search(&state, combined).await["total"], 2);
    assert_eq!(
        search(
            &state,
            json!({"search":"openssl","status":["High"],"include_unknown":true})
        )
        .await["total"],
        3
    );
    assert_eq!(
        search(&state, json!({"search":"openssl","include_unknown":false})).await["total"],
        3
    );

    let mut get = request("/api/reviews/search", Value::Null);
    get.method = Method::GET;
    get.query = vec![
        ("search".into(), "openssl".into()),
        ("include_unknown".into(), "true".into()),
    ];
    assert_eq!(api(&state, get).await.1["total"], 4);
    let mut collection = request("/api/reviews/news", Value::Null);
    collection.method = Method::GET;
    collection.query = vec![("search".into(), "Widget+".into())];
    assert_eq!(api(&state, collection).await.1["total"], 1);
    let mut get_csv = request("/api/reviews/search", Value::Null);
    get_csv.method = Method::GET;
    get_csv.query = vec![
        ("search".into(), "openssl".into()),
        ("vendor_product_filter".into(), inventory.to_string()),
    ];
    assert_eq!(api(&state, get_csv).await.1["total"], 2);
    let mut malformed = request("/api/reviews/search", Value::Null);
    malformed.method = Method::GET;
    malformed.query = vec![("vendor_product_filter".into(), "not-json".into())];
    assert_eq!(api(&state, malformed).await.0, StatusCode::BAD_REQUEST);
    for path in ["/api/reviews/search", "/api/reviews/auto-select"] {
        for value in [
            json!({"enabled":true,"rows":[]}),
            json!("invalid"),
            json!({"enabled":"no","rows":[]}),
        ] {
            assert_eq!(
                api(
                    &state,
                    request(path, json!({"count":1,"vendor_product_filter":value}))
                )
                .await
                .0,
                StatusCode::BAD_REQUEST
            );
        }
    }
    let (status, selected) = api(
        &state,
        request(
            "/api/reviews/auto-select",
            json!({"count":2,"search":"openssl"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(selected["matched"], 3);
    assert_eq!(selected["selected"], 2);
    let (status, selected) = api(
        &state,
        request(
            "/api/reviews/auto-select",
            json!({"count":2,"search":"openssl","vendor_product_filter":inventory}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(selected["matched"], 2);
    for count in [0, 501] {
        assert_eq!(
            api(
                &state,
                request("/api/reviews/auto-select", json!({"count":count}))
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let bulk = |number: i32| doc! {"_id":format!("cve:2026-{}",20000+number),"code":format!("2026-{}",20000+number),"title":"bulk-limit","severity":"High","observed_at":date(now),"details":{"affected":[{"vendor":"Acme","product":"Widget"}]}};
    news.insert_many((0..2000).map(bulk)).await.unwrap();
    let (status, selected) = api(
        &state,
        request(
            "/api/reviews/auto-select",
            json!({"count":1,"search":"bulk-limit"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(selected["matched"], 2000);
    news.insert_one(bulk(2000)).await.unwrap();
    for inventory in [Value::Null, inventory] {
        let (status, error) = api(
            &state,
            request(
                "/api/reviews/auto-select",
                json!({"count":1,"search":"bulk-limit","vendor_product_filter":inventory}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error["error"].as_str().unwrap().contains("too many"));
    }
    assert_eq!(
        filtered_rows(&state, &["news".into()], doc! {}, None, Some(2001))
            .await
            .unwrap()
            .len(),
        2001
    );
    assert_eq!(news.count_documents(doc! {}).await.unwrap(), 2006);
    database.drop().await.unwrap();
}

#[tokio::test]
#[ignore = "requires REVIEW_SEARCH_TEST_MONGO_URI for a disposable database"]
async fn wiz_catalog_search_previews_exports_and_newsletter_matching() {
    let state = test_state().await;
    db::collection(&state.vuln, "source_catalog")
        .insert_one(doc! {"_id":"active", "providers":["wiz","cve"]})
        .await
        .unwrap();

    async fn sources(state: &AppState) -> Value {
        let mut ctx = request("/api/subscriptions/collections", Value::Null);
        ctx.method = Method::GET;
        let response = crate::subscriptions::handle(state, &ctx).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
    }
    assert_eq!(
        sources(&state).await["data"][0],
        json!({"name":"wiz", "source":"wiz", "count":0})
    );

    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/wiz.json")).unwrap();
    let mut document = db::json_doc(&fixture).unwrap();
    for field in ["observed_at", "published_at", "updated_at"] {
        document.insert(
            field,
            mongodb::bson::DateTime::parse_rfc3339_str(fixture[field].as_str().unwrap()).unwrap(),
        );
    }
    let mut second = document.clone();
    second.insert("_id", "wiz:22222222-2222-4333-8444-555555555555");
    second.insert("code", "22222222-2222-4333-8444-555555555555");
    let third = doc! {
        "_id":"wiz:33333333-2222-4333-8444-555555555555",
        "code":"33333333-2222-4333-8444-555555555555",
        "title":"Historical cloud research",
        "observed_at": document.get_datetime("observed_at").unwrap(),
        "source":{"provider":"wiz"},
        "details":{"content":"Available historical metadata", "threat_type":"Research"},
    };
    let news = db::collection(&state.vuln, "news");
    news.insert_many([
        document,
        second,
        third,
        doc! {
            "_id":"cve:2026-12345", "code":"2026-12345", "severity":"High",
            "source":{"provider":"cve"}, "observed_at":mongodb::bson::DateTime::now(),
        },
        doc! {
            "_id":"cve:2026-10001", "code":"2026-10001", "severity":"Low",
            "source":{"provider":"cve"}, "observed_at":mongodb::bson::DateTime::now(),
        },
        doc! {
            "_id":"cve:2026-10002", "code":"2026-10002",
            "source":{"provider":"cve"}, "observed_at":mongodb::bson::DateTime::now(),
        },
    ])
    .await
    .unwrap();
    assert_eq!(sources(&state).await["data"][0]["count"], 3);
    assert_eq!(search(&state, json!({"source":"wiz"})).await["total"], 3);
    for include_unknown in [false, true] {
        assert_eq!(
            search(
                &state,
                json!({"source":"wiz", "status":["Critical"], "include_unknown":include_unknown})
            )
            .await["total"],
            3
        );
    }
    assert_eq!(
        search(&state, json!({"status":["Critical"]})).await["total"],
        3
    );
    assert_eq!(search(&state, json!({"status":["High"]})).await["total"], 4);
    assert_eq!(search(&state, json!({})).await["total"], 5);
    assert_eq!(
        search(&state, json!({"include_unknown":true})).await["total"],
        6
    );
    assert_eq!(
        search(&state, json!({"source":"cve", "status":["Critical"]})).await["total"],
        0
    );
    assert_eq!(
        search(
            &state,
            json!({"source":"wiz", "search":"unmatched-keyword"})
        )
        .await["total"],
        0
    );
    assert_eq!(search(&state, json!({"source":"wiz", "time_window":"custom", "start":"2026-11-19T00:00:00Z", "end":"2026-11-20T00:00:00Z"})).await["total"], 0);
    for keyword in [
        "credentials",
        "Example Actor",
        "public-facing",
        "exfiltration",
        "Credential Access",
        "Widget",
        "Finalized",
        "CVE-2026-54321",
    ] {
        assert_eq!(
            search(&state, json!({"source":"wiz", "search":keyword})).await["total"],
            2,
            "{keyword}"
        );
    }
    let results = search(&state, json!({"source":"wiz"})).await;
    assert_eq!(results["total"], 3);
    let row = results["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["selection_id"] == fixture["_id"])
        .unwrap();
    assert_eq!(row["document"]["code"], fixture["code"]);
    assert_eq!(row["document"]["cve"], "CVE-2026-12345");
    assert_eq!(row["document"]["published_at"], "2026-10-21T00:00:00Z");
    assert_eq!(row["document"]["details"], fixture["details"]);
    assert!(row["document"].get("severity").is_none());
    assert!(
        row["preview_url"]
            .as_str()
            .unwrap()
            .contains("wiz%3A11111111")
    );
    assert!(
        resolve(&state, "wiz", fixture["_id"].as_str().unwrap())
            .await
            .is_some()
    );

    let preview_ctx = request("/generated-newsletters/wiz/preview", Value::Null);
    let response = crate::newsletters::preview(
        &state,
        &preview_ctx,
        "wiz",
        fixture["_id"].as_str().unwrap(),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("Additional incident details appear here.</p>"));
    assert!(html.contains("Editorial status"));
    assert!(!html.contains("Severity:"));
    assert!(html.contains("2026-10-21T00:00:00Z"));
    assert!(html.contains("example-cloud-campaign"));

    let mut profile = json!({"enabled":true,"filters":{"collections_mode":"selected", "collections":["news"], "sources":["wiz"]}});
    let after = DateTime::parse_from_rfc3339("2026-11-17T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let batch = crate::subscriptions::match_profile_after(&state, &profile, after, 100)
        .await
        .unwrap();
    assert_eq!(batch.items.len(), 3);
    assert!(
        batch
            .items
            .iter()
            .all(|item| item["source_collection"] == "wiz")
    );
    assert_eq!(
        batch.items[0]["document"]["observed_at"],
        "2026-11-18T03:00:00Z"
    );
    for (sources, mode, expected) in [
        (vec!["wiz"], "selected", 3),
        (vec!["wiz", "cve"], "selected", 3),
        (vec!["cve"], "selected", 0),
        (vec![], "selected", 0),
        (vec![], "all", 3),
    ] {
        let mut filtered = profile.clone();
        filtered["filters"]["sources"] = json!(sources);
        filtered["filters"]["collections_mode"] = json!(mode);
        filtered["filters"]["status"] = json!(["Critical"]);
        filtered["filters"]["severity_threshold"] = json!("Critical");
        assert_eq!(
            crate::subscriptions::match_profile_after(&state, &filtered, after, 100)
                .await
                .unwrap()
                .items
                .len(),
            expected,
            "{sources:?}, {mode}"
        );
    }
    for (field, value) in [
        ("search", "public-facing"),
        ("search", "stole"),
        ("affected", "Cloud Widget"),
    ] {
        let mut filtered = profile.clone();
        filtered["filters"][field] = json!(value);
        assert_eq!(
            crate::subscriptions::match_profile_after(&state, &filtered, after, 100)
                .await
                .unwrap()
                .items
                .len(),
            2,
            "{field}: {value}"
        );
    }
    profile["filters"]["vendor_product_filter"] =
        json!({"enabled":true,"rows":[{"vendor":"Acme", "product":"Cloud Widget"}]});
    assert_eq!(
        crate::subscriptions::match_profile_after(&state, &profile, after, 100)
            .await
            .unwrap()
            .items
            .len(),
        2
    );
    profile["filters"]["include_unknown"] = json!(false);
    profile["filters"]["status"] = json!(["Critical"]);
    profile["filters"]["severity_threshold"] = json!("Critical");
    assert_eq!(
        crate::subscriptions::match_profile_after(&state, &profile, after, 100)
            .await
            .unwrap()
            .items
            .len(),
        2
    );

    let (status, selected) = api(
        &state,
        request(
            "/api/reviews/auto-select",
            json!({"count":5, "source":"wiz", "status":["Critical"]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(selected["matched"], 3);
    assert_eq!(selected["selected"], 3);
    let selections: Vec<Value> = selected["selections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| json!({"collection":"news", "selection_id":row["selection_id"]}))
        .collect();
    let (status, exported) = api(
        &state,
        request("/api/reviews/export-json", json!({"selections":selections})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(exported.as_array().unwrap().len(), 3);
    assert!(
        exported.as_array().unwrap().iter().any(
            |row| row["_id"] == fixture["_id"] && row["published_at"] == "2026-10-21T00:00:00Z"
        )
    );
    state.vuln.drop().await.unwrap();
}
