# Local authentication and organization RBAC API

All endpoints are served by the Rust portal. Authentication uses the signed `rust_session` HttpOnly, SameSite=Strict cookie; production cookies are Secure. No external authentication or synchronization endpoints are used.

API mutations accept JSON, except supported multipart report and CSV uploads. Browser mutations must have the same Origin as the portal. Clients must preserve the public Host through their reverse proxy. Authentication failures return 401 for APIs and redirect browser pages to `/login`; missing authority returns 403. Tenant-scoped ID lookups return 404 for foreign resources. Unknown routes and verbs are denied.

## Self service

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET / POST | `/login` | Local login form; form fields `username`, `password`, optional local `next` path |
| POST | `/logout` | Clear the local session cookie |
| GET | `/settings` | Profile and password page; available during first-login password change |
| POST | `/api/auth/password` | `current_password`, `new_password`, `new_password_confirmation`; invalidates previous sessions and issues a replacement cookie |
| PUT | `/api/auth/profile` | Own `email` only; requires completion of first-login password change |
| GET | `/management` | Management page; needs at least one of users/roles/organizations view permissions |

## Organization management

| Method | Endpoint | Permission / body |
| --- | --- | --- |
| GET | `/api/organizations` | `organizations.view`; own organization, or all for superadmin |
| POST | `/api/organizations` | `organizations.manage`, superadmin only; `{"name":"Example"}` |
| PUT | `/api/organizations/{id}` | Superadmin only; `name` and/or boolean `disabled` |
| POST | `/api/organizations/{id}/administrators` | Superadmin only; `{"user_id":"local-account-id"}`; target must belong to that organization |

Disabling an organization prevents its members from signing in or using existing sessions, and pauses its scheduled processing. Organizations are retained for recovery and are not physically deleted.

## Accounts and roles

| Method | Endpoint | Permission / body |
| --- | --- | --- |
| GET | `/api/permissions` | `roles.view`; fixed grouped catalog including global-only flags |
| GET | `/api/users` | `users.view`; organization-scoped account metadata; no password hashes or tokens. Retired accounts are hidden unless `?include_deleted=1` |
| POST | `/api/users` | `users.create`; `username`, required `email` and `organization_id`, optional custom `role_id`; assigning a role additionally requires `users.assign_roles` |
| PUT | `/api/users/{id}` | `users.edit`; valid `email` and/or boolean `disabled` |
| DELETE | `/api/users/{id}` | `users.delete`; retires account without removing its records |
| POST | `/api/users/{id}/restore` | `users.delete`; empty object `{}`; reactivates a retired account with its previous role and invalidates its stale sessions; rejects the reserved superadmin and accounts that are not retired |
| DELETE | `/api/users/{id}/purge` | `users.delete`; permanently removes a retired account record; only accounts with `deleted_at` can be purged |
| POST | `/api/users/{id}/password-reset` | `users.reset_password`; empty object `{}`; emails a random temporary password to the account; rotates credentials/sessions only after SMTP acceptance |
| PUT | `/api/users/{id}/role` | `users.assign_roles`; `role_id` for a custom role, or empty string to remove access |
| GET | `/api/roles` | `roles.view`; roles within current organization. Retired roles are hidden unless `?include_deleted=1` |
| POST | `/api/roles` | `roles.create`; `name`, `permissions` array from catalog, `organization_id` |
| PUT | `/api/roles/{id}` | `roles.edit`; `name` and `permissions`; immutable organization and delegation parent |
| DELETE | `/api/roles/{id}` | `roles.delete`; retires a custom role and revokes dependent authority |
| POST | `/api/roles/{id}/restore` | `roles.delete`; empty object `{}`; reactivates a retired role, restoring its permissions and delegations; rejects roles that are not retired |
| DELETE | `/api/roles/{id}/purge` | `roles.delete`; permanently removes a retired custom role; assigned accounts revert to the no-access default; only retired roles can be purged |

Account creation requires an explicit active `organization_id`; tenant administrators can only submit their own BSON ObjectId. Provisioning/reset always require a valid account email and SMTP delivery. Successful responses return `success`, `id`, `email`, `temporary_password_sent: true` and `expires_in_hours: 24`, never plaintext passwords. Responses use `Cache-Control: no-store`. SMTP failures return JSON 503 with `code: credential_email_failed`. A failed reset leaves the previous password/session version unchanged. If the account changes during reset delivery, JSON 409 instructs the administrator to retry. First-login sessions can only change their password, view Settings, or sign out.

Ordinary role assignment never grants the reserved superadmin or organization-administrator role. Only the explicit superadmin organization-appointment action grants the organization-administrator role. Self role changes, account-management changes to oneself, break-glass mutations, stronger target/role assignments and foreign-organization operations are rejected.

## Existing application areas

| Area | Endpoints | Required permissions |
| --- | --- | --- |
| Subscriptions | `/subscriptions`, `/api/subscriptions`, schema/collections, CSV template/import, preview, report-preview, `{id}`, `{id}/vendor-products.csv`, `{id}/statistic-preview` | `.view` for reads and non-persisting previews/import validation; `.create`, `.edit`, `.delete` for CRUD |
| Subscription send | `/api/subscriptions/{id}/send-statistic` | `subscriptions.send` |
| Subscription report selection | `/api/subscriptions/{id}/run` | `reports.create`; same organization subscription |
| Reviews | `/reviews`, `/reviews/{collection}`, `/api/reviews`, `/api/reviews/{collection}`, search, auto-select | `reviews.view` |
| Review inventory validation | `/api/reviews/vendor-product-import`, `/api/reviews/vendor-product-template.csv` | `reviews.view`; reviewers do not need subscription permissions |
| Advisory export | `/api/reviews/export-json` | `reviews.export` |
| Newsletter previews | `/generated-newsletters/{source}/{id}/preview`, `/en`, `/zh`, `/cn` | `newsletters.view` |
| Reports | `/reports`, `/api/reports`, `{id}`, `{id}/logs`, `/reports/{id}/preview` | `reports.view` |
| Generate / translate | POST `/api/reports`, `/api/reports/{id}/translations` | `reports.create` |
| Cancel / delete | `/api/reports/{id}/cancel`, DELETE `/api/reports/{id}` | `reports.manage` |
| Download | `/reports/{id}/download` | `reports.export` |
| Health | `/operations`, `/api/operations/health` | `operations.view`; subscription information scoped to organization |
| Shared templates | `/api/operations/newsletter-templates`, source-list, newsletter-editor, newsletter-editor/preview; `/set-news` | `operations.configure`; superadmin only |
| Shared caches | POST `/api/reports/evidence-cache/purge`, search-cache/purge | `operations.purge_cache`; superadmin only |

Subscription ownership and tenant IDs cannot be changed by editing display metadata. Supply `organization_id` when superadmin creates a subscription or report. Creating a subscription requires an existing local owner username in that organization. Subscriptions accept `emails`, optional `cc`/`bcc`, newsletter/report profiles and individual delivery; they do not provision authentication credentials.

The machine-readable permission catalog and the route/verb allowlist in `src/rbac.rs` are authoritative.
