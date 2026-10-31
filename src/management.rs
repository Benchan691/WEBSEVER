//! Application-managed organizations, scoped local users and delegated roles.
use crate::{AppState, ReqCtx, auth, db, mail, rbac, render, view};
use axum::{
    http::{Method, StatusCode, header},
    response::Response,
};
use mongodb::bson::{self, Document, doc, oid::ObjectId};
use serde_json::{Value, json};

fn response(value: Value) -> Response {
    view::json_response(StatusCode::OK, value)
}
fn bad(message: &str) -> Response {
    view::error(StatusCode::BAD_REQUEST, message)
}
fn denied() -> Response {
    view::error(
        StatusCode::FORBIDDEN,
        "Permission, delegation ceiling, or organization scope denied.",
    )
}
fn unavailable() -> Response {
    view::error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Unable to save management data.",
    )
}
fn exact(ctx: &ReqCtx, fields: &[&str]) -> bool {
    ctx.json
        .as_object()
        .is_some_and(|o| o.keys().all(|key| fields.contains(&key.as_str())))
}
fn name(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= 100 && !value.chars().any(char::is_control))
        .then_some(value)
}
fn role_name(value: &str) -> Option<&str> {
    name(value).filter(|value| {
        !matches!(
            auth::key(value).as_str(),
            "superadmin" | "organization_admin" | "organization administrator"
        )
    })
}
fn permission_input(ctx: &ReqCtx) -> Option<Vec<String>> {
    let values = ctx.json.get("permissions")?.as_array()?;
    let values = values
        .iter()
        .map(|v| v.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    rbac::valid_permissions(&values).then_some(values)
}
fn requested_org(ctx: &ReqCtx) -> Option<ObjectId> {
    let actor = ctx.user.as_ref()?;
    let requested = if rbac::is_superadmin(actor) {
        db::object_id(&ctx.field("organization_id"))
    } else {
        rbac::organization(actor)
    }?;
    if ctx.json.get("organization_id").is_some()
        && db::object_id(&ctx.field("organization_id")) != Some(requested)
    {
        return None;
    }
    rbac::within_scope(actor, requested).then_some(requested)
}
async fn active_org(state: &AppState, id: ObjectId) -> Option<Document> {
    db::find_one(
        &state.web,
        "organizations",
        doc! {"_id":id,"disabled":{"$ne":true}},
    )
    .await
    .ok()
    .flatten()
}
fn scoped_id(ctx: &ReqCtx, id: ObjectId) -> Document {
    doc! {"$and":[rbac::scope(ctx.user.as_ref()),{"_id":id}]}
}
fn role_public(role: &Document) -> Value {
    json!({"id":db::id_string(role),"name":db::string(role,"name"),"organization_id":rbac::organization(role).map(|id|id.to_hex()),"type":db::string(role,"type"),"permissions":rbac::strings(role,"permissions"),"disabled":db::bool_field(role,"disabled")})
}
fn org_public(org: &Document) -> Value {
    json!({"id":db::id_string(org),"name":db::string(org,"name"),"disabled":db::bool_field(org,"disabled")})
}
async fn temporary_credentials() -> Result<(String, Document), String> {
    let temporary = auth::new_secret();
    let hash = auth::password_hash(temporary.clone()).await?;
    Ok((
        temporary,
        doc! {"password":hash,"must_change_password":true,"temporary_password_expires_at":bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis()+24*3600*1000),"session_version":auth::new_secret(),"updated_at":bson::DateTime::now()},
    ))
}
fn credential_response(id: ObjectId, email: &str) -> Response {
    let mut response = response(
        json!({"success":true,"id":id.to_hex(),"email":email,"temporary_password_sent":true,"expires_in_hours":24}),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}
fn email_unavailable(message: &str) -> Response {
    view::json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({"error":message,"code":"credential_email_failed"}),
    )
}
async fn target_user(state: &AppState, ctx: &ReqCtx, id: ObjectId) -> Option<Document> {
    let target = auth::accounts(state)
        .find_one(scoped_id(ctx, id))
        .await
        .ok()??;
    // Legacy identities can be audited, but require the explicit offline recovery.
    let disabled = db::bool_field(&target, "disabled");
    let mut checked = target;
    checked.insert("disabled", false);
    let mut resolved = auth::principal(state, checked).await?;
    resolved.insert("disabled", disabled);
    Some(resolved)
}
async fn load_role(state: &AppState, id: ObjectId, org: ObjectId) -> Option<Document> {
    db::find_one(
        &state.web,
        "roles",
        doc! {"_id":id,"organization_id":org,"disabled":{"$ne":true}},
    )
    .await
    .ok()
    .flatten()
}

pub async fn handle(state: &AppState, ctx: &ReqCtx) -> Option<Response> {
    if ctx.path == "/management" && ctx.method == Method::GET {
        return Some(render(
            state,
            ctx,
            "auth/management.html",
            json!({"permission_catalog":rbac::CATALOG}),
        ));
    }
    if ctx.path == "/api/permissions" && ctx.method == Method::GET {
        return Some(response(json!({"data":rbac::CATALOG})));
    }
    let actor = ctx.user.as_ref()?;
    if ctx.path == "/api/organizations" {
        if ctx.method == Method::GET {
            let filter = if rbac::is_superadmin(actor) {
                doc! {}
            } else {
                doc! {"_id":rbac::organization(actor)?}
            };
            return Some(
                match db::find_sorted(
                    &state.web,
                    "organizations",
                    filter,
                    doc! {"name_key":1},
                    5000,
                )
                .await
                {
                    Ok(rows) => {
                        response(json!({"data":rows.iter().map(org_public).collect::<Vec<_>>()}))
                    }
                    Err(_) => unavailable(),
                },
            );
        }
        if ctx.method == Method::POST {
            if !rbac::is_superadmin(actor) {
                return Some(denied());
            }
            if !exact(ctx, &["name"]) {
                return Some(bad("Only an organization name is accepted."));
            }
            let value = ctx.field("name");
            let Some(value) = name(&value) else {
                return Some(bad("Organization name is required (up to 100 bytes)."));
            };
            let id = ObjectId::new();
            let role_id = ObjectId::new();
            let organization = doc! {"_id":id,"name":value,"name_key":auth::key(value),"administrator_role_id":role_id,"disabled":false,"created_at":bson::DateTime::now()};
            return Some(
                match db::collection(&state.web, "organizations")
                    .insert_one(organization.clone())
                    .await
                {
                    Ok(_) => response(json!({"data":org_public(&organization)})),
                    Err(_) => view::error(
                        StatusCode::CONFLICT,
                        "Organization could not be created; check for a duplicate name.",
                    ),
                },
            );
        }
    }
    if ctx.path == "/api/roles" {
        if ctx.method == Method::GET {
            // Retired roles (disabled) are kept for delegation history and
            // only list again when explicitly requested.
            let mut scope = rbac::scope(Some(actor));
            if ctx.arg("include_deleted").is_empty() {
                scope.insert("disabled", doc! {"$ne": true});
            }
            return Some(
                match db::find_sorted(
                    &state.web,
                    "roles",
                    scope,
                    doc! {"name_key":1},
                    5000,
                )
                .await
                {
                    Ok(rows) => {
                        response(json!({"data":rows.iter().map(role_public).collect::<Vec<_>>()}))
                    }
                    Err(_) => unavailable(),
                },
            );
        }
        if ctx.method == Method::POST {
            if !exact(ctx, &["name", "organization_id", "permissions"]) {
                return Some(bad("Unknown role field."));
            }
            let value = ctx.field("name");
            let Some(value) = role_name(&value) else {
                return Some(bad("Choose a non-reserved role name (up to 100 bytes)."));
            };
            let Some(org) = requested_org(ctx) else {
                return Some(denied());
            };
            let Some(grants) = permission_input(ctx) else {
                return Some(bad(
                    "Select permissions from the fixed catalog; duplicates are invalid.",
                ));
            };
            if !rbac::may_delegate(actor, org, &grants)
                || grants.iter().any(|p| {
                    rbac::CATALOG
                        .iter()
                        .any(|entry| entry.id == p && entry.global)
                })
                || active_org(state, org).await.is_none()
            {
                return Some(denied());
            }
            let id = ObjectId::new();
            let role = doc! {"_id":id,"organization_id":org,"type":"custom","name":value,"name_key":auth::key(value),"permissions":grants,"delegated_by_user_id":ctx.user_id().unwrap(),"disabled":false,"created_at":bson::DateTime::now()};
            return Some(
                match db::collection(&state.web, "roles")
                    .insert_one(role.clone())
                    .await
                {
                    Ok(_) => response(json!({"data":role_public(&role)})),
                    Err(_) => view::error(
                        StatusCode::CONFLICT,
                        "Role name already exists or role could not be saved.",
                    ),
                },
            );
        }
    }
    if ctx.path == "/api/users" {
        if ctx.method == Method::GET {
            // Retired accounts (deleted_at set) keep their records for
            // subscriptions and audit trails, but no longer list in the panel
            // unless the caller asks for them.
            let mut scope = rbac::scope(Some(actor));
            if ctx.arg("include_deleted").is_empty() {
                scope.insert("deleted_at", doc! {"$exists": false});
            }
            return Some(
                match db::find_sorted(
                    &state.web,
                    &state.cfg.account_collection,
                    scope,
                    doc! {"username_key":1},
                    5000,
                )
                .await
                {
                    Ok(rows) => response(
                        json!({"data":rows.iter().map(auth::public_user).collect::<Vec<_>>()}),
                    ),
                    Err(_) => unavailable(),
                },
            );
        }
        if ctx.method == Method::POST {
            if !exact(ctx, &["username", "email", "organization_id", "role_id"]) {
                return Some(bad(
                    "Only username, email, organization_id and role_id are accepted. Passwords are generated locally.",
                ));
            }
            let username = ctx.field("username");
            let Some(username) = name(&username) else {
                return Some(bad("Username is required (up to 100 bytes)."));
            };
            if auth::key(username) == auth::key(&state.cfg.bootstrap_username)
                || auth::key(username) == "superadmin"
            {
                return Some(denied());
            }
            if ["email", "role_id"]
                .iter()
                .any(|key| ctx.json.get(*key).is_some_and(|value| !value.is_string()))
            {
                return Some(bad("Email and role_id must be text."));
            }
            let email = auth::key(&ctx.field("email"));
            if !auth::valid_email(&email) {
                return Some(bad(
                    "A valid email address is required to receive the temporary password.",
                ));
            }
            if ctx
                .json
                .get("organization_id")
                .and_then(Value::as_str)
                .and_then(db::object_id)
                .is_none()
            {
                return Some(bad("Select an organization for the new account."));
            }
            let Some(org) = requested_org(ctx) else {
                return Some(denied());
            };
            let Some(organization) = active_org(state, org).await else {
                return Some(denied());
            };
            let id = ObjectId::new();
            let mut account = doc! {"_id":id,"username":username,"username_key":auth::key(username),"email":&email,"organization_id":org,"organization":db::string(&organization,"name"),"auth_source":"local","rbac_schema":1,"role":"user","disabled":false,"created_at":bson::DateTime::now()};
            let role_id = ctx.field("role_id");
            if !role_id.is_empty() {
                if !ctx.can("users.assign_roles") {
                    return Some(denied());
                }
                let Some(role_id) = db::object_id(&role_id) else {
                    return Some(bad("Invalid role id."));
                };
                let Some(role) = load_role(state, role_id, org).await else {
                    return Some(denied());
                };
                if !rbac::may_assign(actor, &account, &role) {
                    return Some(denied());
                }
                account.insert("role_id", role_id);
                let Some(resolved) = auth::principal(state, account.clone()).await else {
                    return Some(denied());
                };
                if !db::bool_field(&resolved, "authorization_valid")
                    || !rbac::strings(&role, "permissions")
                        .is_subset(&rbac::strings(&resolved, "effective_permissions"))
                {
                    return Some(denied());
                }
                account.insert("role", db::string(&role, "name"));
            }
            account.insert("email_key", &email);
            let (temporary, credentials) = match temporary_credentials().await {
                Ok(values) => values,
                Err(_) => return Some(unavailable()),
            };
            account.extend(credentials);
            let delivery = match mail::TemporaryPasswordEmail::prepare(
                state,
                &email,
                username,
                &db::string(&organization, "name"),
                &temporary,
            ) {
                Ok(delivery) => delivery,
                Err(_) => {
                    return Some(email_unavailable(
                        "Unable to prepare the temporary-password email. Check SMTP_HOST, SMTP_FROM, transport settings and WEB_PUBLIC_URL. No account was created.",
                    ));
                }
            };
            let version = db::string(&account, "session_version");
            if auth::accounts(state).insert_one(account).await.is_err() {
                return Some(view::error(
                    StatusCode::CONFLICT,
                    "Account could not be created; username or email may already exist.",
                ));
            }
            if delivery.send().await.is_err() {
                // Remove only this untouched provisioning attempt, never an
                // account modified by a concurrent administrator.
                let removed = auth::accounts(state)
                    .delete_one(
                        doc! {"_id":id,"session_version":version,"must_change_password":true},
                    )
                    .await;
                return Some(if removed.is_ok_and(|result| result.deleted_count == 1) {
                    email_unavailable(
                        "Temporary-password email could not be sent. No account was created. Check SMTP delivery and retry.",
                    )
                } else {
                    email_unavailable(
                        "Temporary-password email could not be confirmed. The account remains saved; check SMTP delivery and use Reset password to retry.",
                    )
                });
            }
            return Some(credential_response(id, &email));
        }
    }
    let parts = ctx
        .path
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    if let ["api", "organizations", raw, tail @ ..] = parts.as_slice() {
        if !rbac::is_superadmin(actor) {
            return Some(denied());
        }
        let Some(id) = db::object_id(raw) else {
            return Some(bad("Invalid organization id."));
        };
        let org = db::find_one(&state.web, "organizations", doc! {"_id":id})
            .await
            .ok()
            .flatten();
        let Some(org) = org else {
            return Some(view::error(
                StatusCode::NOT_FOUND,
                "Organization not found.",
            ));
        };
        if tail.is_empty() && ctx.method == Method::PUT {
            if !exact(ctx, &["name", "disabled"])
                || ctx.json.get("disabled").is_some_and(|v| !v.is_boolean())
            {
                return Some(bad("Only name and a boolean disabled flag are accepted."));
            }
            let mut set = doc! {"updated_at":bson::DateTime::now()};
            if ctx.json.get("name").is_some() {
                let value = ctx.field("name");
                let Some(value) = name(&value) else {
                    return Some(bad("Invalid organization name."));
                };
                set.insert("name", value);
                set.insert("name_key", auth::key(value));
            }
            if let Some(disabled) = ctx.json.get("disabled").and_then(Value::as_bool) {
                set.insert("disabled", disabled);
            }
            return Some(
                match db::collection(&state.web, "organizations")
                    .update_one(doc! {"_id":id}, doc! {"$set":set})
                    .await
                {
                    Ok(_) => response(json!({"success":true})),
                    Err(_) => view::error(
                        StatusCode::CONFLICT,
                        "Organization name already exists or update failed.",
                    ),
                },
            );
        }
        if *tail == ["administrators"] && ctx.method == Method::POST {
            if !exact(ctx, &["user_id"]) || db::bool_field(&org, "disabled") {
                return Some(bad("Select an active organization and user_id."));
            }
            let Some(user_id) = db::object_id(&ctx.field("user_id")) else {
                return Some(bad("Invalid user id."));
            };
            let Some(target)=auth::accounts(state).find_one(doc!{"_id":user_id,"organization_id":id,"auth_source":"local","rbac_schema":1,"disabled":false,"deleted_at":{"$exists":false},"reserved_bootstrap":{"$ne":true}}).await.ok().flatten() else {return Some(denied());};
            if !rbac::mutable_target(actor, &target) {
                return Some(denied());
            }
            let Ok(role_id) = org.get_object_id("administrator_role_id") else {
                return Some(unavailable());
            };
            let role = doc! {"name":"Organization administrator","name_key":"organization_admin","type":"organization_admin","reserved":true,"organization_id":id,"permissions":rbac::tenant_permissions(),"disabled":false};
            if db::collection(&state.web, "roles")
                .update_one(doc! {"_id":role_id}, doc! {"$setOnInsert":role})
                .upsert(true)
                .await
                .is_err()
            {
                return Some(unavailable());
            }
            return Some(match auth::accounts(state).update_one(doc!{"_id":user_id,"organization_id":id,"reserved_bootstrap":{"$ne":true}},doc!{"$set":{"role_id":role_id,"role":"Organization administrator","session_version":auth::new_secret(),"updated_at":bson::DateTime::now()}}).await {Ok(_)=>response(json!({"success":true})),Err(_)=>unavailable()});
        }
    }
    if let ["api", "roles", raw, "restore"] = parts.as_slice() {
        if ctx.method == Method::POST {
            let Some(id) = db::object_id(raw) else {
                return Some(bad("Invalid role id."));
            };
            let Some(role) = db::find_one(&state.web, "roles", scoped_id(ctx, id))
                .await
                .ok()
                .flatten()
            else {
                return Some(view::error(StatusCode::NOT_FOUND, "Role not found."));
            };
            // custom_permissions() refuses disabled roles, so authorization
            // runs against the role as it will exist after the restore.
            let mut check = role.clone();
            check.insert("disabled", false);
            if !rbac::may_edit_role(actor, &check) {
                return Some(denied());
            }
            if !db::bool_field(&role, "disabled") {
                return Some(bad("Role is not retired."));
            }
            return Some(
                match db::collection(&state.web, "roles")
                    .update_one(
                        scoped_id(ctx, id),
                        doc! {"$set":{"disabled":false,"updated_at":bson::DateTime::now()}},
                    )
                    .await
                {
                    Ok(_) => response(json!({"success":true})),
                    Err(_) => unavailable(),
                },
            );
        }
    }
    if let ["api", "roles", raw, "purge"] = parts.as_slice() {
        if ctx.method == Method::DELETE {
            let Some(id) = db::object_id(raw) else {
                return Some(bad("Invalid role id."));
            };
            let Some(role) = db::find_one(&state.web, "roles", scoped_id(ctx, id))
                .await
                .ok()
                .flatten()
            else {
                return Some(view::error(StatusCode::NOT_FOUND, "Role not found."));
            };
            // Same authorization as restore: the actor must hold every grant
            // the role would confer, checked as if the role were active.
            let mut check = role.clone();
            check.insert("disabled", false);
            if !rbac::may_edit_role(actor, &check) {
                return Some(denied());
            }
            if !db::bool_field(&role, "disabled") {
                return Some(bad("Role is not retired."));
            }
            return Some(
                match db::collection(&state.web, "roles")
                    .delete_one(scoped_id(ctx, id))
                    .await
                {
                    Ok(result) if result.deleted_count == 1 => {
                        // Accounts still assigned the purged role revert to the
                        // default no-access state; best effort after the delete.
                        if let Some(org) = rbac::organization(&role) {
                            let _ = auth::accounts(state)
                                .update_many(
                                    doc! {"organization_id":org,"role_id":id},
                                    doc! {"$set":{"role":"user"},"$unset":{"role_id":""}},
                                )
                                .await;
                        }
                        response(json!({"success":true}))
                    }
                    _ => unavailable(),
                },
            );
        }
    }
    if let ["api", "roles", raw] = parts.as_slice() {
        let Some(id) = db::object_id(raw) else {
            return Some(bad("Invalid role id."));
        };
        let Some(role) = db::find_one(&state.web, "roles", scoped_id(ctx, id))
            .await
            .ok()
            .flatten()
        else {
            return Some(view::error(StatusCode::NOT_FOUND, "Role not found."));
        };
        if !rbac::may_edit_role(actor, &role) {
            return Some(denied());
        }
        if ctx.method == Method::DELETE {
            return Some(
                match db::collection(&state.web, "roles")
                    .update_one(
                        scoped_id(ctx, id),
                        doc! {"$set":{"disabled":true,"updated_at":bson::DateTime::now()}},
                    )
                    .await
                {
                    Ok(_) => response(json!({"success":true})),
                    Err(_) => unavailable(),
                },
            );
        }
        if ctx.method == Method::PUT {
            if !exact(ctx, &["name", "permissions"]) {
                return Some(bad("Unknown or immutable role field."));
            }
            let value = ctx.field("name");
            let Some(value) = role_name(&value) else {
                return Some(bad("Choose a non-reserved role name."));
            };
            let Some(grants) = permission_input(ctx) else {
                return Some(bad("Select permissions from the fixed catalog."));
            };
            if !rbac::may_delegate(actor, rbac::organization(&role).unwrap(), &grants)
                || grants.iter().any(|p| {
                    rbac::CATALOG
                        .iter()
                        .any(|entry| entry.id == p && entry.global)
                })
            {
                return Some(denied());
            }
            // Keep the original delegation parent: a later editor cannot remove its ceiling.
            return Some(match db::collection(&state.web,"roles").update_one(scoped_id(ctx,id),doc!{"$set":{"name":value,"name_key":auth::key(value),"permissions":grants,"updated_at":bson::DateTime::now()}}).await {Ok(_)=>response(json!({"success":true})),Err(_)=>view::error(StatusCode::CONFLICT,"Role name already exists or update failed.")});
        }
    }
    if let ["api", "users", raw, tail @ ..] = parts.as_slice() {
        let Some(id) = db::object_id(raw) else {
            return Some(bad("Invalid user id."));
        };
        if *tail == ["restore"] && ctx.method == Method::POST {
            // Retired accounts are rejected by principal(), so the raw record
            // is loaded here instead of going through target_user().
            let Some(target) = auth::accounts(state)
                .find_one(scoped_id(ctx, id))
                .await
                .ok()
                .flatten()
            else {
                return Some(view::error(
                    StatusCode::NOT_FOUND,
                    "Local account not found. Legacy accounts require explicit migration.",
                ));
            };
            if db::bool_field(&target, "reserved_bootstrap") {
                return Some(denied());
            }
            if !target.contains_key("deleted_at") {
                return Some(bad("Account is not retired."));
            }
            // Restoring also clears the disabled flag set by the retire action
            // and rotates the session version so stale sessions stay invalid.
            return Some(
                match auth::accounts(state)
                    .update_one(
                        doc! {"$and":[scoped_id(ctx,id),{"reserved_bootstrap":{"$ne":true}}]},
                        doc! {"$set":{"disabled":false,"updated_at":bson::DateTime::now(),"session_version":auth::new_secret()},"$unset":{"deleted_at":""}},
                    )
                    .await
                {
                    Ok(result) if result.matched_count == 1 => response(json!({"success":true})),
                    _ => unavailable(),
                },
            );
        }
        if *tail == ["purge"] && ctx.method == Method::DELETE {
            // Retired accounts are rejected by principal(), so the raw record
            // is loaded here instead of going through target_user().
            let Some(target) = auth::accounts(state)
                .find_one(scoped_id(ctx, id))
                .await
                .ok()
                .flatten()
            else {
                return Some(view::error(
                    StatusCode::NOT_FOUND,
                    "Local account not found. Legacy accounts require explicit migration.",
                ));
            };
            if db::bool_field(&target, "reserved_bootstrap") {
                return Some(denied());
            }
            if !target.contains_key("deleted_at") {
                return Some(bad("Account is not retired."));
            }
            // The deleted_at guard in the filter prevents a purge racing a
            // concurrent restore.
            return Some(
                match auth::accounts(state)
                    .delete_one(doc! {"$and":[scoped_id(ctx,id),{"deleted_at":{"$exists":true}}]})
                    .await
                {
                    Ok(result) if result.deleted_count == 1 => response(json!({"success":true})),
                    _ => unavailable(),
                },
            );
        }
        let Some(target) = target_user(state, ctx, id).await else {
            return Some(view::error(
                StatusCode::NOT_FOUND,
                "Local account not found. Legacy accounts require explicit migration.",
            ));
        };
        if !rbac::mutable_target(actor, &target) {
            return Some(denied());
        }
        let mut set =
            doc! {"updated_at":bson::DateTime::now(),"session_version":auth::new_secret()};
        if tail.is_empty() && ctx.method == Method::DELETE {
            set.insert("disabled", true);
            set.insert("deleted_at", bson::DateTime::now());
        } else if tail.is_empty() && ctx.method == Method::PUT {
            if !exact(ctx, &["disabled", "email"])
                || ctx.json.as_object().is_none_or(|object| object.is_empty())
                || ctx
                    .json
                    .get("disabled")
                    .is_some_and(|value| !value.is_boolean())
            {
                return Some(bad(
                    "Only an email address and a boolean disabled flag are accepted. Use the separate role assignment action.",
                ));
            }
            if let Some(disabled) = ctx.json.get("disabled").and_then(Value::as_bool) {
                set.insert("disabled", disabled);
            }
            if let Some(value) = ctx.json.get("email") {
                let Some(email) = value
                    .as_str()
                    .map(auth::key)
                    .filter(|email| auth::valid_email(email))
                else {
                    return Some(bad("A valid email address is required."));
                };
                set.insert("email", &email);
                set.insert("email_key", email);
            }
        } else if *tail == ["password-reset"] && ctx.method == Method::POST {
            if !exact(ctx, &[]) {
                return Some(bad(
                    "Password reset generates a new local temporary password; no password input is accepted.",
                ));
            }
            let (temporary, credentials) = match temporary_credentials().await {
                Ok(values) => values,
                Err(_) => return Some(unavailable()),
            };
            let email = db::string(&target, "email");
            if !auth::valid_email(&email) {
                return Some(bad(
                    "Set a valid account email address before resetting the password.",
                ));
            }
            let delivery = match mail::TemporaryPasswordEmail::prepare(
                state,
                &email,
                &db::string(&target, "username"),
                &db::string(&target, "organization"),
                &temporary,
            ) {
                Ok(delivery) => delivery,
                Err(_) => {
                    return Some(email_unavailable(
                        "Unable to prepare the temporary-password email. Check SMTP_HOST, SMTP_FROM, transport settings and WEB_PUBLIC_URL. The password was not changed.",
                    ));
                }
            };
            // Failed delivery must not invalidate the user's working password.
            if delivery.send().await.is_err() {
                return Some(email_unavailable(
                    "Temporary-password email could not be sent. The password was not changed. Check SMTP delivery and retry.",
                ));
            }
            return Some(
                match auth::accounts(state)
                    .update_one(
                        doc! {"$and":[scoped_id(ctx,id),{"reserved_bootstrap":{"$ne":true},"email":&email,"session_version":db::string(&target,"session_version")}]},
                        doc! {"$set":credentials},
                    )
                    .await
                {
                    Ok(result) if result.matched_count == 1 => credential_response(id, &email),
                    _ => view::error(StatusCode::CONFLICT, "The account changed while the email was being sent. Request a new password reset."),
                },
            );
        } else if *tail == ["role"] && ctx.method == Method::PUT {
            if !exact(ctx, &["role_id"]) {
                return Some(bad("Only role_id is accepted."));
            }
            let Some(raw) = ctx.json.get("role_id").and_then(Value::as_str) else {
                return Some(bad(
                    "role_id must be text; use an explicit empty string to remove access.",
                ));
            };
            if raw.is_empty() {
                set.insert("role", "user");
                return Some(
                    match auth::accounts(state)
                        .update_one(
                            doc! {"$and":[scoped_id(ctx,id),{"reserved_bootstrap":{"$ne":true}}]},
                            doc! {"$set":set,"$unset":{"role_id":""}},
                        )
                        .await
                    {
                        Ok(_) => response(json!({"success":true})),
                        Err(_) => unavailable(),
                    },
                );
            }
            let Some(role_id) = db::object_id(raw) else {
                return Some(bad("Invalid role id."));
            };
            let Some(role) = load_role(state, role_id, rbac::organization(&target).unwrap()).await
            else {
                return Some(denied());
            };
            if !rbac::may_assign(actor, &target, &role) {
                return Some(denied());
            }
            // A custom role cannot be assigned to any of its own delegation ancestors.
            let mut hypothetical = target.clone();
            hypothetical.insert("role_id", role_id);
            let Some(resolved) = auth::principal(state, hypothetical).await else {
                return Some(denied());
            };
            if !db::bool_field(&resolved, "authorization_valid")
                || !rbac::strings(&role, "permissions")
                    .is_subset(&rbac::strings(&resolved, "effective_permissions"))
            {
                return Some(denied());
            }
            set.insert("role_id", role_id);
            set.insert("role", db::string(&role, "name"));
        } else {
            return None;
        }
        return Some(
            match auth::accounts(state)
                .update_one(
                    doc! {"$and":[scoped_id(ctx,id),{"reserved_bootstrap":{"$ne":true}}]},
                    doc! {"$set":set},
                )
                .await
            {
                Ok(result) if result.matched_count == 1 => response(json!({"success":true})),
                _ => unavailable(),
            },
        );
    }
    None
}
