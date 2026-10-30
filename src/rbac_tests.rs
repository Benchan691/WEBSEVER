//! Authorization regressions exercise the production resolver and HTTP guard;
//! no MongoDB server, live database, scheduler or SMTP transport is used.
use crate::*;
use axum::http::{Request, header};
use mongodb::bson::{Document, doc, oid::ObjectId};
use std::{collections::HashMap, future::ready};
use tower::ServiceExt;

fn org() -> ObjectId {
    ObjectId::parse_str("aaaaaaaaaaaaaaaaaaaaaaaa").unwrap()
}
fn other_org() -> ObjectId {
    ObjectId::parse_str("bbbbbbbbbbbbbbbbbbbbbbbb").unwrap()
}
fn user(permissions: &[&str]) -> Document {
    doc! {"_id":ObjectId::new(),"username":"manager","auth_source":"local","rbac_schema":1,"organization_id":org(),"effective_permissions":permissions.to_vec(),"disabled":false}
}
fn superadmin() -> Document {
    doc! {"_id":ObjectId::new(),"username":"admin","role":"superadmin","reserved_bootstrap":true,"auth_source":"local","rbac_schema":1,"disabled":false,"password":"saved-password-hash"}
}
fn context(method: Method, path: &str, user: Option<Document>) -> ReqCtx {
    ReqCtx {
        method,
        path: path.into(),
        query: vec![],
        headers: HeaderMap::new(),
        body: vec![],
        json: Value::Null,
        form: HashMap::new(),
        user,
    }
}
pub(crate) async fn state() -> AppState {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Client construction is lazy. The guard tests never execute DB operations.
    let client = Client::with_uri_str("mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=1")
        .await
        .unwrap();
    AppState {
        cfg: config::Config {
            root: root.clone(),
            file: json!({}),
            mongo_uri: String::new(),
            web_database: "unit_test_no_database".into(),
            vulnerabilities_database: "unit_test_no_database".into(),
            vulnerabilities_collection: "news".into(),
            secret: "unit-test-signing-secret-32-bytes-long".into(),
            bootstrap_username: "admin".into(),
            bootstrap_password: "bootstrap-test-password".into(),
            cookie_secure: false,
            account_collection: "accounts".into(),
            newsletter_root: root.join("newsletters"),
            port: 0,
        },
        web: client.database("unit_test_no_database"),
        vuln: client.database("unit_test_no_database"),
        templates: Arc::new(view::environment(&root)),
        http: reqwest::Client::new(),
    }
}

#[test]
fn fixed_catalog_rejects_unknown_duplicate_and_global_tenant_grants() {
    assert_eq!(rbac::CATALOG.len(), 27);
    let ids = rbac::CATALOG
        .iter()
        .map(|p| p.id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), rbac::CATALOG.len());
    assert!(rbac::valid_permissions(&[
        "reviews.view".into(),
        "users.create".into()
    ]));
    assert!(!rbac::valid_permissions(&[
        "reviews.view".into(),
        "reviews.view".into()
    ]));
    assert!(!rbac::has(&superadmin(), "arbitrary.permission"));
    let forged = user(&[
        "organizations.manage",
        "operations.configure",
        "operations.purge_cache",
    ]);
    for entry in rbac::CATALOG.iter().filter(|p| p.global) {
        assert!(!rbac::has(&forged, entry.id));
    }
}
#[test]
fn delegation_requires_current_permissions_and_exact_organization_id() {
    let manager = user(&["roles.create", "reviews.view", "subscriptions.view"]);
    assert!(rbac::may_delegate(
        &manager,
        org(),
        &["reviews.view".into()]
    ));
    assert!(!rbac::may_delegate(
        &manager,
        org(),
        &["users.create".into()]
    ));
    assert!(!rbac::may_delegate(&manager, org(), &["superadmin".into()]));
    assert!(!rbac::may_delegate(
        &manager,
        other_org(),
        &["reviews.view".into()]
    ));
    let mut unscoped = manager.clone();
    unscoped.remove("organization_id");
    unscoped.insert("organization", "same display name");
    assert!(!rbac::may_delegate(&unscoped, org(), &[]));
    assert!(!rbac::has(&unscoped, "reviews.view"));
}
#[test]
fn assignments_cannot_promote_self_root_or_foreign_users() {
    let actor = user(&["users.assign_roles", "reviews.view"]);
    let target = user(&["reviews.view"]);
    let role = doc! {"_id":ObjectId::new(),"organization_id":org(),"type":"custom","permissions":["reviews.view"]};
    assert!(rbac::may_assign(&actor, &target, &role));
    assert!(!rbac::may_assign(&actor, &actor, &role));
    assert!(!rbac::may_assign(&actor, &superadmin(), &role));
    let mut foreign = target.clone();
    foreign.insert("organization_id", other_org());
    assert!(!rbac::may_assign(&actor, &foreign, &role));
    for kind in ["superadmin", "organization_admin"] {
        let mut reserved = role.clone();
        reserved.insert("type", kind);
        assert!(!rbac::may_assign(&superadmin(), &target, &reserved));
    }
    let mut stronger = role.clone();
    stronger.insert("permissions", vec!["reviews.view", "users.create"]);
    assert!(!rbac::may_assign(&actor, &target, &stronger));
    let mut higher_target = target;
    higher_target.insert(
        "effective_permissions",
        vec!["reviews.view", "users.create"],
    );
    assert!(!rbac::may_assign(&actor, &higher_target, &role));
}
#[test]
fn own_role_and_delegation_ancestors_cannot_be_edited() {
    let id = ObjectId::new();
    let mut actor = user(&["roles.edit", "reviews.view"]);
    let role =
        doc! {"_id":id,"organization_id":org(),"type":"custom","permissions":["reviews.view"]};
    assert!(rbac::may_edit_role(&actor, &role));
    actor.insert("authorization_roles", vec![ObjectId::new(), id]);
    assert!(!rbac::may_edit_role(&actor, &role));
}
#[test]
fn bootstrap_startup_preserves_hash_and_normal_management_cannot_touch_it() {
    let mut root = superadmin();
    root.insert("session_version", "saved-session-version");
    let update = auth::bootstrap_update(&root, "admin").unwrap();
    let set = update.get_document("$set").unwrap();
    assert_eq!(set.get_str("role").unwrap(), "superadmin");
    assert!(set.get_bool("reserved_bootstrap").unwrap());
    assert!(!set.contains_key("password"));
    assert!(!set.contains_key("session_version"));
    assert!(!rbac::mutable_target(&superadmin(), &root));
    assert!(!rbac::mutable_target(
        &user(&rbac::CATALOG.iter().map(|p| p.id).collect::<Vec<_>>()),
        &root
    ));
    assert!(auth::bootstrap_update(&root, "renamed-admin").is_err());
    root.insert("auth_source", "external-provider");
    assert!(auth::bootstrap_update(&root, "admin").is_err());
    let mut legacy = superadmin();
    legacy.remove("reserved_bootstrap");
    legacy.insert("role", "admin");
    assert!(auth::bootstrap_update(&legacy, "admin").is_ok());
}
#[test]
fn scope_filters_are_never_empty_for_unscoped_or_tenant_users() {
    let actor = user(&[]);
    assert_eq!(rbac::scope(Some(&actor)), doc! {"organization_id":org()});
    assert!(!rbac::scope(None).is_empty());
    assert!(rbac::scope(Some(&superadmin())).is_empty());
    assert!(!rbac::scoped(&actor, &doc! {"organization_id":other_org()}));
    assert!(!rbac::scoped(&actor, &doc! {"organization":"same name"}));
    assert!(!rbac::scoped(
        &actor,
        &doc! {"organization_id":org().to_hex()}
    ));
    assert!(rbac::scoped(&actor, &doc! {"organization_id":org()}));
}
#[test]
fn known_routes_have_precise_action_grants_and_unknown_routes_deny() {
    let id = ObjectId::new().to_hex();
    let cases = [
        (Method::GET, "/reviews".into(), "reviews.view"),
        (
            Method::POST,
            "/api/reviews/export-json".into(),
            "reviews.export",
        ),
        (
            Method::GET,
            format!("/api/reports/{id}/logs"),
            "reports.view",
        ),
        (
            Method::GET,
            format!("/reports/{id}/download"),
            "reports.export",
        ),
        (
            Method::DELETE,
            format!("/api/subscriptions/{id}"),
            "subscriptions.delete",
        ),
        (
            Method::POST,
            format!("/api/users/{id}/password-reset"),
            "users.reset_password",
        ),
        (
            Method::PUT,
            format!("/api/users/{id}/role"),
            "users.assign_roles",
        ),
        (
            Method::POST,
            "/api/reports/evidence-cache/purge".into(),
            "operations.purge_cache",
        ),
    ];
    for (method, path, permission) in cases {
        assert_eq!(rbac::required(&method, &path), Some(permission));
    }
    for (method, path) in [
        (Method::POST, "/api/reviews/unknown/mutate"),
        (Method::DELETE, "/reviews"),
        (Method::PATCH, "/api/users/anything"),
        (Method::GET, "/login/local"),
        (Method::GET, "/login/2fa"),
        (Method::GET, "/api/admin/account-users"),
        (Method::GET, "/api/operations/unknown"),
    ] {
        assert_eq!(rbac::required(&method, path), None);
    }
}

struct Graph {
    user: Document,
    organization: Document,
    roles: HashMap<ObjectId, Document>,
    accounts: HashMap<ObjectId, Document>,
    parent: ObjectId,
    child: ObjectId,
    creator: ObjectId,
}
fn graph() -> Graph {
    let root = superadmin();
    let root_id = root.get_object_id("_id").unwrap();
    let creator = ObjectId::new();
    let parent = ObjectId::new();
    let child = ObjectId::new();
    let parent_role = doc! {"_id":parent,"type":"custom","organization_id":org(),"name":"Delegator","permissions":["reviews.view","roles.create"],"delegated_by_user_id":root_id};
    let child_role = doc! {"_id":child,"type":"custom","organization_id":org(),"name":"Reviewer","permissions":["reviews.view"],"delegated_by_user_id":creator};
    let mut creator_account = user(&[]);
    creator_account.insert("_id", creator);
    creator_account.insert("role_id", parent);
    let mut member = user(&[]);
    member.insert("role_id", child);
    Graph {
        user: member,
        organization: doc! {"_id":org(),"name":"Org A","administrator_role_id":ObjectId::new()},
        roles: HashMap::from([(parent, parent_role), (child, child_role)]),
        accounts: HashMap::from([(root_id, root), (creator, creator_account)]),
        parent,
        child,
        creator,
    }
}
async fn resolve(graph: &Graph) -> Document {
    auth::resolve_role_chain(
        graph.user.clone(),
        graph.organization.clone(),
        |id| ready(graph.roles.get(&id).cloned()),
        |id| ready(graph.accounts.get(&id).cloned()),
    )
    .await
}
#[tokio::test]
async fn production_resolver_intersects_with_current_creator_authority() {
    let mut graph = graph();
    let resolved = resolve(&graph).await;
    assert!(rbac::has(&resolved, "reviews.view"));
    assert!(!rbac::has(&resolved, "roles.create"));
    graph
        .roles
        .get_mut(&graph.parent)
        .unwrap()
        .insert("permissions", vec!["roles.create"]);
    assert!(!rbac::has(&resolve(&graph).await, "reviews.view"));
    graph
        .roles
        .get_mut(&graph.parent)
        .unwrap()
        .insert("permissions", vec!["reviews.view", "roles.create"]);
    graph
        .accounts
        .get_mut(&graph.creator)
        .unwrap()
        .insert("disabled", true);
    assert!(rbac::strings(&resolve(&graph).await, "effective_permissions").is_empty());
}
#[tokio::test]
async fn production_resolver_rejects_foreign_missing_retired_cyclic_and_unknown_roles() {
    for kind in [
        "foreign-role",
        "foreign-creator",
        "missing-parent",
        "retired-parent",
        "cycle",
        "unknown-permission",
        "global-permission",
        "non-string-permission",
        "forged-org-admin",
    ] {
        let mut graph = graph();
        match kind {
            "foreign-role" => {
                graph
                    .roles
                    .get_mut(&graph.child)
                    .unwrap()
                    .insert("organization_id", other_org());
            }
            "foreign-creator" => {
                graph
                    .accounts
                    .get_mut(&graph.creator)
                    .unwrap()
                    .insert("organization_id", other_org());
            }
            "missing-parent" => {
                graph.roles.remove(&graph.parent);
            }
            "retired-parent" => {
                graph
                    .roles
                    .get_mut(&graph.parent)
                    .unwrap()
                    .insert("disabled", true);
            }
            "cycle" => {
                graph
                    .roles
                    .get_mut(&graph.parent)
                    .unwrap()
                    .insert("delegated_by_user_id", graph.creator);
            }
            "unknown-permission" => {
                graph
                    .roles
                    .get_mut(&graph.child)
                    .unwrap()
                    .insert("permissions", vec!["arbitrary.permission"]);
            }
            "global-permission" => {
                graph
                    .roles
                    .get_mut(&graph.child)
                    .unwrap()
                    .insert("permissions", vec!["operations.configure"]);
            }
            "non-string-permission" => {
                graph
                    .roles
                    .get_mut(&graph.child)
                    .unwrap()
                    .insert("permissions", vec![1i32]);
            }
            "forged-org-admin" => {
                graph
                    .roles
                    .get_mut(&graph.child)
                    .unwrap()
                    .insert("type", "organization_admin");
            }
            _ => unreachable!(),
        }
        assert!(
            rbac::strings(&resolve(&graph).await, "effective_permissions").is_empty(),
            "{kind}"
        );
        assert!(
            !db::bool_field(&resolve(&graph).await, "authorization_valid"),
            "{kind}"
        );
    }
}
#[tokio::test]
async fn reserved_org_administrator_gets_tenant_permissions_only() {
    let mut graph = graph();
    let child = graph.roles.get_mut(&graph.child).unwrap();
    child.insert("type", "organization_admin");
    child.insert("reserved", true);
    graph
        .organization
        .insert("administrator_role_id", graph.child);
    let resolved = resolve(&graph).await;
    for permission in rbac::CATALOG {
        assert_eq!(
            rbac::has(&resolved, permission.id),
            !permission.global,
            "{}",
            permission.id
        );
    }
}
#[tokio::test]
async fn guard_enforces_api_page_password_and_origin_requirements() {
    let state = state().await;
    for (method, path) in [
        (Method::GET, "/api/users"),
        (Method::GET, "/api/roles"),
        (Method::GET, "/api/subscriptions"),
        (Method::POST, "/api/reports"),
    ] {
        let ctx = context(method, path, None);
        assert_eq!(
            guard(&state, &ctx).unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    for path in [
        "/management",
        "/reviews",
        "/reports",
        "/operations",
        "/subscriptions",
    ] {
        assert_eq!(
            guard(&state, &context(Method::GET, path, Some(user(&[]))))
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    for (method, path) in [
        (Method::GET, "/api/reviews/vendor-product-template.csv"),
        (Method::POST, "/api/reviews/vendor-product-import"),
    ] {
        assert!(
            guard(
                &state,
                &context(method, path, Some(user(&["reviews.view"])))
            )
            .is_none()
        );
    }
    let mut ctx = context(Method::GET, "/reviews", Some(user(&["reviews.view"])));
    assert!(guard(&state, &ctx).is_none());
    ctx.path = "/reports".into();
    assert_eq!(guard(&state, &ctx).unwrap().status(), StatusCode::FORBIDDEN);
    ctx.user
        .as_mut()
        .unwrap()
        .insert("must_change_password", true);
    ctx.path = "/api/users".into();
    assert_eq!(guard(&state, &ctx).unwrap().status(), StatusCode::FORBIDDEN);
    ctx.path = "/api/auth/password".into();
    ctx.method = Method::POST;
    assert!(guard(&state, &ctx).is_none());
    ctx.headers
        .insert("origin", "https://evil.example".parse().unwrap());
    ctx.headers
        .insert("host", "portal.example".parse().unwrap());
    assert_eq!(guard(&state, &ctx).unwrap().status(), StatusCode::FORBIDDEN);
    assert!(
        guard(
            &state,
            &context(
                Method::POST,
                "/api/operations/not-a-route",
                Some(superadmin())
            )
        )
        .is_some()
    );
}
#[tokio::test]
async fn actual_http_dispatch_denies_unauthenticated_access_without_db_io() {
    let app = Router::new()
        .fallback(any(dispatch))
        .with_state(state().await);
    for (method, path, status) in [
        ("GET", "/api/users", StatusCode::UNAUTHORIZED),
        ("POST", "/api/subscriptions", StatusCode::UNAUTHORIZED),
        ("GET", "/reports", StatusCode::FOUND),
        ("GET", "/login", StatusCode::OK),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{method} {path}");
        if path == "/login" {
            let body = to_bytes(response.into_body(), 100000).await.unwrap();
            let html = String::from_utf8(body.to_vec()).unwrap();
            assert!(html.contains("Local password"));
            assert!(!html.contains("Zimbra"));
        }
    }
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::ORIGIN, "https://foreign.example")
                .header(header::HOST, "portal.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn malformed_custom_roles_never_pass_assignment_or_edit_validation() {
    let actor = superadmin();
    let target = user(&[]);
    for permissions in [
        mongodb::bson::Bson::Array(vec![1.into()]),
        mongodb::bson::Bson::Array(vec!["reviews.view".into(), "reviews.view".into()]),
        "reviews.view".into(),
    ] {
        let role = doc! {"_id":ObjectId::new(),"type":"custom","organization_id":org(),"permissions":permissions};
        assert!(!rbac::may_assign(&actor, &target, &role));
        assert!(!rbac::may_edit_role(&actor, &role));
    }
}
