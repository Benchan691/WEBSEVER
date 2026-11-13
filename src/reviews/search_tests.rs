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
async fn keyword_search_optional_csv_pagination_and_auto_selection() {
    let uri = std::env::var("REVIEW_SEARCH_TEST_MONGO_URI").unwrap();
    let client = Client::with_uri_str(&uri).await.unwrap();
    let database = client.database(&format!("review_search_test_{}", ObjectId::new()));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let state = AppState {
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
    };
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
