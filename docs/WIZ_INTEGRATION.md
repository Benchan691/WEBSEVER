# Wiz Cloud Threat Landscape integration

The portal consumes Cyberclawer's schema-v2 Wiz documents from the configured
shared news collection (`VULNERABILITIES_COLLECTION`, default `news`). Provider
identity is `source.provider = "wiz"`. Ingestion stays in Cyberclawer; the portal
does not need a Wiz API key or fetch Wiz pages itself.

## Source selection and filters

Publish Cyberclawer's source catalog with Wiz enabled, then select `wiz` in the
portal's subscription source picker. The existing catalog-backed picker exposes
the source even before its first news document is stored. No `wiz_review` view
or extra physical news collection is required.

Wiz supplies no severity rating and bypasses severity selections, severity
thresholds, and the **Include unknown severity** setting in reviews and
subscriptions. Other filters, including selected sources, keywords, dates, and
inventory, still apply. Other providers retain their existing severity rules.
Wiz previews and newsletters omit the severity section. Editorial status such as
`Finalized` and impact labels such as `Data exfiltration` are displayed separately
and never treated as severity.

Review keyword search and subscription search include article content, threat
type, actors, initial access, impact, observed techniques, targeted technologies,
editorial status, author, title, and CVE IDs. Affected-system filters also search
targeted technologies. Inventory matching uses article text and technology labels
as text evidence; these source labels do not establish a structured vendor/product
classification. Product-only matching still requires the existing opt-in.

## Identity, rendering, and dates

- `_id = "wiz:<guid>"` remains the stable selection/export/delivery key. `code`
  remains the unprefixed GUID. Only `cve_ids` supplies Wiz's actual CVE identifiers.
- Auto-selection keeps distinct Wiz incidents, including records without CVEs
  and multiple incidents mentioning the same CVE. Other providers retain their
  existing CVE-based deduplication.
- Previews, newsletters, and fixed-template reports use `details.content` as
  escaped plain text with newline-separated blocks. Missing content falls back
  to `details.summary`. They use the existing generated newsletter template and
  its configurable field order.
- The metadata table displays available threat type, actors, initial access,
  observed techniques, editorial status, author, and source dates. Impact and
  targeted technologies have their own labeled sections. No remediation advice
  is inferred from these properties.
- References prefer `details.article_url`, followed by the permanent
  `source.detail_url` and deduplicated HTTP/HTTPS reference links. Missing
  canonical URLs fall back to the permanent URL.
- News responses and exports serialize BSON `observed_at`, `published_at`, and
  `updated_at` as ISO 8601 UTC strings, retaining millisecond precision. Dates
  stay BSON dates in MongoDB for querying. Subscription/account/job date formats
  are unaffected.
- `observed_at` describes the stored observation, not the last poll.
  `updated_at` may equal publication time without proving an edit occurred.
- Missing optional lists default to empty presentation lists. Additional detail
  fields and future threat types remain accepted and are preserved in exports.

Monthly delivery statistics label this provider **Wiz Cloud Threat Landscape**.
Scheduled newsletters use the existing subscription cursor and delivery history.
Search-assisted enriched reports retain their existing CVE scope.

## API examples

Review search (authenticated administrator request):

```http
POST /api/reviews/search
Content-Type: application/json

{"source":"wiz","search":"Credential Access"}
```

Generated preview, with the stored `_id` URL-encoded:

```text
/generated-newsletters/wiz/wiz%3A11111111-2222-4333-8444-555555555555/preview
```

Subscription newsletter filter scope:

```json
{
  "collections_mode": "selected",
  "collections": ["news"],
  "sources": ["wiz"]
}
```

Use the configured physical collection name in place of `news` where needed.
Public subscription responses also accept/expose logical provider names through
`collections`, as with the other sources.

## Verification

The synthetic fixture is `tests/fixtures/wiz.json`. Unit tests cover normalization,
optional fields, future types, UUID/CVE separation, UTC dates, HTML escaping,
canonical/permanent references, inventory evidence, statistics, and report output.

```sh
cargo fmt -- --check
cargo test
```

Against an isolated, disposable MongoDB instance, run both the existing review
regression test and the Wiz integration test:

```sh
REVIEW_SEARCH_TEST_MONGO_URI=mongodb://127.0.0.1:27017 cargo test reviews::search_tests -- --ignored
```

Each test creates and drops its own uniquely named database. The Wiz test verifies
catalog discovery before ingestion, provider counts, database search, date
serialization, preview rendering, subscription/inventory matching,
severity bypass, other-provider severity filtering, incident-based auto-selection,
and JSON export. It does not send SMTP mail or require the live Wiz feed.
