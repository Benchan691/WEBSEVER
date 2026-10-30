//! Closed permission catalog and fail-closed tenant authorization.
use crate::{ReqCtx, db};
use axum::http::Method;
use mongodb::bson::{Bson, Document, doc, oid::ObjectId};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Serialize)]
pub struct Permission {
    pub id: &'static str,
    pub group: &'static str,
    pub label: &'static str,
    pub global: bool,
}
macro_rules! permission {
    ($id:literal, $group:literal, $label:literal) => {
        Permission {
            id: $id,
            group: $group,
            label: $label,
            global: false,
        }
    };
    ($id:literal, $group:literal, $label:literal, global) => {
        Permission {
            id: $id,
            group: $group,
            label: $label,
            global: true,
        }
    };
}
pub const CATALOG: &[Permission] = &[
    permission!("users.view", "Users", "View organization accounts"),
    permission!("users.create", "Users", "Provision local accounts"),
    permission!("users.edit", "Users", "Edit or disable accounts"),
    permission!(
        "users.delete",
        "Users",
        "Retire accounts (preserve records)"
    ),
    permission!("users.reset_password", "Users", "Issue temporary passwords"),
    permission!("users.assign_roles", "Users", "Assign custom roles"),
    permission!("roles.view", "Roles", "View roles and permission catalog"),
    permission!("roles.create", "Roles", "Create custom roles"),
    permission!("roles.edit", "Roles", "Edit custom roles"),
    permission!("roles.delete", "Roles", "Retire custom roles"),
    permission!(
        "organizations.view",
        "Organizations",
        "View own organization"
    ),
    permission!(
        "organizations.manage",
        "Organizations",
        "Manage organizations and appoint administrators",
        global
    ),
    permission!(
        "subscriptions.view",
        "Subscriptions",
        "View organization subscriptions and inventories"
    ),
    permission!(
        "subscriptions.create",
        "Subscriptions",
        "Create subscriptions"
    ),
    permission!(
        "subscriptions.edit",
        "Subscriptions",
        "Edit subscriptions and schedules"
    ),
    permission!(
        "subscriptions.delete",
        "Subscriptions",
        "Delete subscriptions"
    ),
    permission!(
        "subscriptions.send",
        "Subscriptions",
        "Send statistics and enable scheduled delivery"
    ),
    permission!(
        "reviews.view",
        "Reviews and newsletters",
        "Browse and search shared advisory sources"
    ),
    permission!(
        "reviews.export",
        "Reviews and newsletters",
        "Export advisory records"
    ),
    permission!(
        "newsletters.view",
        "Reviews and newsletters",
        "Preview shared advisory newsletters"
    ),
    permission!(
        "reports.view",
        "Reports",
        "View organization jobs, logs and previews"
    ),
    permission!(
        "reports.create",
        "Reports",
        "Generate and translate reports"
    ),
    permission!(
        "reports.manage",
        "Reports",
        "Cancel and delete organization reports"
    ),
    permission!("reports.export", "Reports", "Download organization reports"),
    permission!(
        "operations.view",
        "Operations",
        "View organization delivery health"
    ),
    permission!(
        "operations.configure",
        "Operations",
        "Edit global newsletter templates and source settings",
        global
    ),
    permission!(
        "operations.purge_cache",
        "Operations",
        "Purge shared report caches",
        global
    ),
];

pub fn is_superadmin(user: &Document) -> bool {
    db::bool_field(user, "reserved_bootstrap")
        && db::string(user, "role") == "superadmin"
        && db::string(user, "auth_source") == "local"
        && !db::bool_field(user, "disabled")
        && !user.contains_key("deleted_at")
}
pub fn organization(user: &Document) -> Option<ObjectId> {
    user.get_object_id("organization_id").ok()
}
pub fn strings(user: &Document, field: &str) -> BTreeSet<String> {
    user.get_array(field)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Bson::as_str)
        .map(str::to_owned)
        .collect()
}
pub fn valid_permissions(values: &[String]) -> bool {
    values.iter().all(|id| CATALOG.iter().any(|p| p.id == id))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}
pub fn custom_permissions(role: &Document) -> Option<BTreeSet<String>> {
    if db::string(role, "type") != "custom"
        || db::bool_field(role, "disabled")
        || organization(role).is_none()
    {
        return None;
    }
    let values = role
        .get_array("permissions")
        .ok()?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    if !valid_permissions(&values)
        || values.iter().any(|id| {
            CATALOG
                .iter()
                .any(|permission| permission.id == id && permission.global)
        })
    {
        return None;
    }
    Some(values.into_iter().collect())
}
pub fn has(user: &Document, permission: &str) -> bool {
    let Some(entry) = CATALOG.iter().find(|p| p.id == permission) else {
        return false;
    };
    if db::bool_field(user, "disabled") || user.contains_key("deleted_at") {
        return false;
    }
    if is_superadmin(user) {
        return true;
    }
    !entry.global
        && organization(user).is_some()
        && user.get_i32("rbac_schema").ok() == Some(1)
        && strings(user, "effective_permissions").contains(permission)
}
pub fn tenant_permissions() -> Vec<String> {
    CATALOG
        .iter()
        .filter(|p| !p.global)
        .map(|p| p.id.to_owned())
        .collect()
}
pub fn scoped(user: &Document, resource: &Document) -> bool {
    is_superadmin(user)
        || organization(user)
            .is_some_and(|id| resource.get_object_id("organization_id").ok() == Some(id))
}
pub fn scope(user: Option<&Document>) -> Document {
    match user {
        Some(user) if is_superadmin(user) => doc! {},
        Some(user) if organization(user).is_some() => {
            doc! {"organization_id": organization(user).unwrap()}
        }
        _ => doc! {"_id": {"$exists": false}},
    }
}
pub fn within_scope(user: &Document, org: ObjectId) -> bool {
    is_superadmin(user) || organization(user) == Some(org)
}
pub fn may_delegate(actor: &Document, org: ObjectId, permissions: &[String]) -> bool {
    within_scope(actor, org)
        && valid_permissions(permissions)
        && permissions.iter().all(|permission| has(actor, permission))
}
pub fn mutable_target(actor: &Document, target: &Document) -> bool {
    !db::bool_field(target, "reserved_bootstrap")
        && db::string(target, "role") != "superadmin"
        && db::id_string(actor) != db::id_string(target)
        && scoped(actor, target)
        && (is_superadmin(actor)
            || strings(target, "effective_permissions")
                .iter()
                .all(|p| has(actor, p)))
}
pub fn may_assign(actor: &Document, target: &Document, role: &Document) -> bool {
    let Some(grants) = custom_permissions(role) else {
        return false;
    };
    mutable_target(actor, target)
        && organization(role) == organization(target)
        && organization(target)
            .is_some_and(|org| may_delegate(actor, org, &grants.into_iter().collect::<Vec<_>>()))
}
pub fn may_edit_role(actor: &Document, role: &Document) -> bool {
    let Ok(id) = role.get_object_id("_id") else {
        return false;
    };
    let Some(grants) = custom_permissions(role) else {
        return false;
    };
    scoped(actor, role)
        && actor.get_object_id("role_id").ok() != Some(id)
        && actor
            .get_array("authorization_roles")
            .ok()
            .is_none_or(|chain| !chain.contains(&Bson::ObjectId(id)))
        && organization(role)
            .is_some_and(|org| may_delegate(actor, org, &grants.into_iter().collect::<Vec<_>>()))
}

/// Exact verbs and known route shapes only. Unknown routes/verbs have no grant.
pub fn required(method: &Method, path: &str) -> Option<&'static str> {
    match (method.as_str(), path) {
        ("GET", "/api/permissions") => Some("roles.view"),
        ("GET", "/api/users") => Some("users.view"),
        ("POST", "/api/users") => Some("users.create"),
        ("GET", "/api/roles") => Some("roles.view"),
        ("POST", "/api/roles") => Some("roles.create"),
        ("GET", "/api/organizations") => Some("organizations.view"),
        ("POST", "/api/organizations") => Some("organizations.manage"),
        (
            "GET",
            "/subscriptions"
            | "/api/subscriptions"
            | "/api/subscriptions/schema"
            | "/api/subscriptions/collections"
            | "/api/subscriptions/vendor-product-template.csv",
        ) => Some("subscriptions.view"),
        ("POST", "/api/subscriptions") => Some("subscriptions.create"),
        (
            "POST",
            "/api/subscriptions/vendor-product-import"
            | "/api/subscriptions/preview"
            | "/api/subscriptions/report-preview",
        ) => Some("subscriptions.view"),
        ("GET", "/reviews" | "/api/reviews" | "/api/reviews/search")
        | ("POST", "/api/reviews/search" | "/api/reviews/auto-select") => Some("reviews.view"),
        ("POST", "/api/reviews/vendor-product-import")
        | ("GET", "/api/reviews/vendor-product-template.csv") => Some("reviews.view"),
        ("POST", "/api/reviews/export-json") => Some("reviews.export"),
        ("GET", "/reports" | "/api/reports") => Some("reports.view"),
        ("POST", "/api/reports") => Some("reports.create"),
        ("POST", "/api/reports/evidence-cache/purge" | "/api/reports/search-cache/purge") => {
            Some("operations.purge_cache")
        }
        ("GET", "/operations" | "/api/operations/health") => Some("operations.view"),
        (
            "GET",
            "/api/operations/newsletter-templates"
            | "/api/operations/source-list"
            | "/api/operations/newsletter-editor",
        )
        | ("PUT", "/api/operations/newsletter-editor")
        | ("POST", "/api/operations/newsletter-editor/preview" | "/set-news") => {
            Some("operations.configure")
        }
        ("GET", "/en" | "/zh" | "/cn") => Some("newsletters.view"),
        _ => {
            let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
            match (method.as_str(), parts.as_slice()) {
                ("PUT", ["api", "organizations", id]) if ObjectId::parse_str(id).is_ok() => {
                    Some("organizations.manage")
                }
                ("POST", ["api", "organizations", id, "administrators"])
                    if ObjectId::parse_str(id).is_ok() =>
                {
                    Some("organizations.manage")
                }
                ("PUT", ["api", "users", id]) if ObjectId::parse_str(id).is_ok() => {
                    Some("users.edit")
                }
                ("DELETE", ["api", "users", id]) if ObjectId::parse_str(id).is_ok() => {
                    Some("users.delete")
                }
                ("POST", ["api", "users", id, "password-reset"])
                    if ObjectId::parse_str(id).is_ok() =>
                {
                    Some("users.reset_password")
                }
                ("PUT", ["api", "users", id, "role"]) if ObjectId::parse_str(id).is_ok() => {
                    Some("users.assign_roles")
                }
                ("PUT", ["api", "roles", id]) if ObjectId::parse_str(id).is_ok() => {
                    Some("roles.edit")
                }
                ("DELETE", ["api", "roles", id]) if ObjectId::parse_str(id).is_ok() => {
                    Some("roles.delete")
                }
                ("GET", ["reviews", name] | ["api", "reviews", name]) if !name.is_empty() => {
                    Some("reviews.view")
                }
                ("GET", ["generated-newsletters", source, id, "preview"])
                    if !source.is_empty() && !id.is_empty() =>
                {
                    Some("newsletters.view")
                }
                ("GET", ["api", "subscriptions", id]) if ObjectId::parse_str(id).is_ok() => {
                    Some("subscriptions.view")
                }
                ("PUT", ["api", "subscriptions", id]) if ObjectId::parse_str(id).is_ok() => {
                    Some("subscriptions.edit")
                }
                ("DELETE", ["api", "subscriptions", id]) if ObjectId::parse_str(id).is_ok() => {
                    Some("subscriptions.delete")
                }
                (
                    "GET",
                    [
                        "api",
                        "subscriptions",
                        id,
                        "vendor-products.csv" | "statistic-preview",
                    ],
                ) if ObjectId::parse_str(id).is_ok() => Some("subscriptions.view"),
                ("POST", ["api", "subscriptions", id, "send-statistic"])
                    if ObjectId::parse_str(id).is_ok() =>
                {
                    Some("subscriptions.send")
                }
                ("POST", ["api", "subscriptions", id, "run"])
                    if ObjectId::parse_str(id).is_ok() =>
                {
                    Some("reports.create")
                }
                ("GET", ["api", "reports", id] | ["api", "reports", id, "logs"])
                    if ObjectId::parse_str(id).is_ok() =>
                {
                    Some("reports.view")
                }
                ("POST", ["api", "reports", id, "translations"])
                    if ObjectId::parse_str(id).is_ok() =>
                {
                    Some("reports.create")
                }
                ("POST", ["api", "reports", id, "cancel"]) | ("DELETE", ["api", "reports", id])
                    if ObjectId::parse_str(id).is_ok() =>
                {
                    Some("reports.manage")
                }
                ("GET", ["reports", id, "preview"]) if ObjectId::parse_str(id).is_ok() => {
                    Some("reports.view")
                }
                ("GET", ["reports", id, "download"]) if ObjectId::parse_str(id).is_ok() => {
                    Some("reports.export")
                }
                _ => None,
            }
        }
    }
}
pub fn allowed(ctx: &ReqCtx, permission: &str) -> bool {
    ctx.user.as_ref().is_some_and(|user| has(user, permission))
}
