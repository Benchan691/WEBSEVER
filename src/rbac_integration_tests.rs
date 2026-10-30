//! Opt-in HTTP/database regression. Uses only a disposable loopback SMTP receiver.
use crate::*;
use mongodb::bson::{doc, oid::ObjectId};
use tower::ServiceExt;

async fn call(
    app: &Router,
    cookie: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value, String) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "portal.example.test")
        .header("origin", "http://portal.example.test");
    if !cookie.is_empty() {
        request = request.header("cookie", cookie);
    }
    let body = if let Some(body) = body {
        request = request.header("content-type", "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .to_owned();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        cookie,
    )
}
async fn login(app: &Router, username: &str, password: &str) -> String {
    let (status, _, cookie) = call(
        app,
        "",
        Method::POST,
        "/login",
        Some(json!({"username":username,"password":password})),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(!cookie.is_empty());
    cookie
}
async fn first_login(app: &Router, username: &str, password: &str) -> String {
    let cookie = login(app, username, password).await;
    let (status, _, _) = call(app, &cookie, Method::GET, "/api/users", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let old_cookie = cookie.clone();
    let (status,body,cookie)=call(app,&cookie,Method::POST,"/api/auth/password",Some(json!({"current_password":password,"new_password":"replacement-local-password","new_password_confirmation":"replacement-local-password"}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["success"], true,
        "password-change API must return JSON"
    );
    assert!(!cookie.is_empty());
    assert_ne!(cookie, old_cookie);
    assert_eq!(
        call(app, &old_cookie, Method::GET, "/api/users", None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(app, &cookie, Method::GET, "/settings", None).await.0,
        StatusCode::OK
    );
    cookie
}

#[tokio::test]
#[ignore = "requires RBAC_TEST_MONGO_URI pointing to a disposable local MongoDB"]
async fn local_rbac_http_lifecycle_and_tenant_isolation() {
    let uri = std::env::var("RBAC_TEST_MONGO_URI").expect("set a disposable local MongoDB URI");
    assert!(
        uri.starts_with("mongodb://127.0.0.1:") || uri.starts_with("mongodb://localhost:"),
        "use an explicit local test server port"
    );
    let client = Client::with_uri_str(&uri).await.unwrap();
    let database = client.database(&format!("local_rbac_test_{}", ObjectId::new().to_hex()));
    let mut state = crate::rbac_tests::state().await;
    let mut smtp = crate::mail::tests::smtp_stub(&mut state).await;
    state.web = database.clone();
    state.vuln = database.clone();
    state.cfg.web_database = database.name().into();
    auth::ensure_bootstrap(&state).await.unwrap();
    db::collection(&database, "source_catalog")
        .insert_one(doc! {"_id":"active","providers":["cve"]})
        .await
        .unwrap();
    let app = Router::new()
        .fallback(any(dispatch))
        .with_state(state.clone());
    let root = login(&app, "admin", "bootstrap-test-password").await;
    let (status, a, _) = call(
        &app,
        &root,
        Method::POST,
        "/api/organizations",
        Some(json!({"name":"Organization A"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let a = a["data"]["id"].as_str().unwrap().to_owned();
    let (status, b, _) = call(
        &app,
        &root,
        Method::POST,
        "/api/organizations",
        Some(json!({"name":"Organization B"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let b = b["data"]["id"].as_str().unwrap().to_owned();
    for body in [
        json!({"username":"missing-email","organization_id":a}),
        json!({"username":"empty-email","email":"","organization_id":a}),
        json!({"username":"bad-email","email":"invalid","organization_id":a}),
        json!({"username":"missing-org","email":"new@example.test"}),
        json!({"username":"bad-org","email":"new@example.test","organization_id":""}),
    ] {
        let (status, body, _) = call(&app, &root, Method::POST, "/api/users", Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].is_string());
    }
    smtp.accept
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let (status, failed, _) = call(
        &app,
        &root,
        Method::POST,
        "/api/users",
        Some(
            json!({"username":"delivery-failed","email":"failed@example.test","organization_id":a}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(failed.get("temporary_password").is_none());
    assert_eq!(
        auth::accounts(&state)
            .count_documents(doc! {"username_key":"delivery-failed"})
            .await
            .unwrap(),
        0
    );
    smtp.accept.store(true, std::sync::atomic::Ordering::SeqCst);
    let (status, admin, _) = call(
        &app,
        &root,
        Method::POST,
        "/api/users",
        Some(json!({"username":"org-admin","email":"org-admin@example.test","organization_id":a})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(admin["temporary_password_sent"], true);
    assert!(admin.get("temporary_password").is_none());
    let admin_temporary = smtp.password_for("org-admin@example.test").await;
    let admin_id = admin["id"].as_str().unwrap();
    let (status, _, _) = call(
        &app,
        &root,
        Method::POST,
        &format!("/api/organizations/{a}/administrators"),
        Some(json!({"user_id":admin_id})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let administrator = first_login(&app, "org-admin", &admin_temporary).await;
    let grants = vec![
        "reviews.view",
        "roles.view",
        "roles.create",
        "roles.edit",
        "users.view",
        "users.create",
        "users.assign_roles",
        "subscriptions.view",
        "subscriptions.create",
        "subscriptions.edit",
        "subscriptions.delete",
        "reports.view",
        "reports.export",
    ];
    let (status, role, _) = call(
        &app,
        &administrator,
        Method::POST,
        "/api/roles",
        Some(json!({"name":"Delegating reviewer","permissions":grants})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let role_id = role["data"]["id"].as_str().unwrap().to_owned();
    let (status, member, _) = call(
        &app,
        &administrator,
        Method::POST,
        "/api/users",
        Some(json!({"username":"limited","email":"limited@example.test","organization_id":a,"role_id":role_id})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(member.get("temporary_password").is_none());
    let member_temporary = smtp.password_for("limited@example.test").await;
    let member_record = auth::accounts(&state)
        .find_one(doc! {"username_key":"limited"})
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        member_record.get_object_id("organization_id").unwrap(),
        db::object_id(&a).unwrap()
    );
    let member_id = member["id"].as_str().unwrap();
    let limited = first_login(&app, "limited", &member_temporary).await;
    let (status, _, _) = call(&app, &administrator, Method::POST, "/api/users",
        Some(json!({"username":"foreign-user","email":"foreign-create@example.test","organization_id":b}))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = call(
        &app,
        &limited,
        Method::PUT,
        "/api/auth/profile",
        Some(json!({"email":""})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = call(
        &app,
        &limited,
        Method::POST,
        "/api/roles",
        Some(json!({"name":"Permitted","permissions":["reviews.view"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for (body, expected) in [
        (
            json!({"name":"Escalation","permissions":["users.reset_password"]}),
            StatusCode::FORBIDDEN,
        ),
        (
            json!({"name":"Unknown","permissions":["arbitrary.permission"]}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"name":"Foreign","organization_id":b,"permissions":["reviews.view"]}),
            StatusCode::FORBIDDEN,
        ),
        (
            json!({"name":"superadmin","permissions":[]}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"name":"Global","permissions":["organizations.manage"]}),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let (status, _, _) = call(&app, &limited, Method::POST, "/api/roles", Some(body)).await;
        assert_eq!(status, expected);
    }
    for (path, body) in [
        (
            format!("/api/users/{member_id}/role"),
            json!({"role_id":role_id}),
        ),
        (
            format!("/api/users/{admin_id}/role"),
            json!({"role_id":role_id}),
        ),
        (
            format!("/api/roles/{role_id}"),
            json!({"name":"Self edited","permissions":grants}),
        ),
    ] {
        let (status, _, _) = call(&app, &limited, Method::PUT, &path, Some(body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status,subscription,_)=call(&app,&limited,Method::POST,"/api/subscriptions",Some(json!({"username":"limited","emails":["local@example.test"],"newsletter_profile":{"enabled":false},"report_profile":{"enabled":false}}))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(subscription["id"].is_string());
    let foreign_sub = ObjectId::new();
    db::collection(&database,"sub_account").insert_one(doc!{"_id":foreign_sub,"organization_id":db::object_id(&b).unwrap(),"username":"foreign-member","email":"foreign@example.test","newsletter_profile":{"enabled":false},"report_profile":{"enabled":false}}).await.unwrap();
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let (status, _, _) = call(
            &app,
            &limited,
            method,
            &format!("/api/subscriptions/{foreign_sub}"),
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let (status, list, _) = call(&app, &limited, Method::GET, "/api/subscriptions", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!list.to_string().contains("foreign@example.test"));
    for (organization, allowed) in [(&a, true), (&b, false)] {
        let id = ObjectId::new();
        db::collection(&database,"report_jobs").insert_one(doc!{"_id":id,"organization_id":db::object_id(organization).unwrap(),"status":"completed","generation_mode":"template","report_language":"en","report":{"title":"Test report","template_mode":true,"highlights":[],"trends":[],"recommendations":[],"executive_summary":"Test"}}).await.unwrap();
        for path in [
            format!("/api/reports/{id}"),
            format!("/reports/{id}/download"),
        ] {
            let (status, _, _) = call(&app, &limited, Method::GET, &path, None).await;
            assert_eq!(
                status,
                if allowed {
                    StatusCode::OK
                } else {
                    StatusCode::NOT_FOUND
                }
            );
        }
    }
    let (status, _, _) = call(&app, &limited, Method::GET, "/operations", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let reduced: Vec<_> = grants
        .iter()
        .copied()
        .filter(|p| *p != "reviews.view")
        .collect();
    let (status, _, _) = call(
        &app,
        &administrator,
        Method::PUT,
        &format!("/api/roles/{role_id}"),
        Some(json!({"name":"Reduced reviewer","permissions":reduced})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = call(&app, &limited, Method::GET, "/reviews", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let root_record = auth::accounts(&state)
        .find_one(doc! {"reserved_bootstrap":true})
        .await
        .unwrap()
        .unwrap();
    let root_id = root_record.get_object_id("_id").unwrap();
    for (method, tail, body) in [
        (Method::PUT, "", json!({"disabled":true})),
        (Method::DELETE, "", json!({})),
        (Method::POST, "/password-reset", json!({})),
        (Method::PUT, "/role", json!({"role_id":""})),
    ] {
        let (status, _, _) = call(
            &app,
            &root,
            method,
            &format!("/api/users/{root_id}{tail}"),
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    auth::ensure_bootstrap(&state).await.unwrap();
    let restarted = auth::accounts(&state)
        .find_one(doc! {"_id":root_id})
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        db::string(&restarted, "password"),
        db::string(&root_record, "password")
    );
    assert!(rbac::is_superadmin(&restarted));
    let before_reset = auth::accounts(&state)
        .find_one(doc! {"_id":db::object_id(member_id).unwrap()})
        .await
        .unwrap()
        .unwrap();
    smtp.accept
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let (status, body, _) = call(
        &app,
        &administrator,
        Method::POST,
        &format!("/api/users/{member_id}/password-reset"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.get("temporary_password").is_none());
    let after_failure = auth::accounts(&state)
        .find_one(doc! {"_id":db::object_id(member_id).unwrap()})
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        db::string(&before_reset, "password"),
        db::string(&after_failure, "password")
    );
    assert_eq!(
        db::string(&before_reset, "session_version"),
        db::string(&after_failure, "session_version")
    );
    assert_eq!(
        call(&app, &limited, Method::GET, "/settings", None).await.0,
        StatusCode::OK
    );
    smtp.accept.store(true, std::sync::atomic::Ordering::SeqCst);
    let (status, body, _) = call(
        &app,
        &administrator,
        Method::POST,
        &format!("/api/users/{member_id}/password-reset"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["temporary_password_sent"], true);
    assert!(body.get("temporary_password").is_none());
    let reset_password = smtp.password_for("limited@example.test").await;
    assert_eq!(
        call(&app, &limited, Method::GET, "/settings", None).await.0,
        StatusCode::FOUND
    );
    let limited = first_login(&app, "limited", &reset_password).await;
    let (status, _, _) = call(
        &app,
        &administrator,
        Method::PUT,
        &format!("/api/users/{member_id}"),
        Some(json!({"disabled":true})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = call(&app, &limited, Method::GET, "/api/subscriptions", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    database.drop().await.unwrap();
}
