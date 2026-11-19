use super::*;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../tests/fixtures/wiz.json")).unwrap()
}

#[test]
fn wiz_preserves_article_properties_without_inventing_severity_or_remediation() {
    let record = fixture();
    let newsletter = normalize(&record, "wiz", &json!({}));
    assert_eq!(newsletter["template_key"], "wiz");
    assert_eq!(newsletter["title"], record["title"]);
    assert_eq!(newsletter["overview"], record["details"]["content"]);
    assert_eq!(newsletter["overview_blocks"].as_array().unwrap().len(), 2);
    assert_eq!(newsletter["severity"], json!([]));
    assert_eq!(newsletter["show_severity"], false);
    assert_eq!(newsletter["cvss"], "");
    assert_eq!(newsletter["impacts"], json!(["Data exfiltration"]));
    assert_eq!(newsletter["show_impacts"], true);
    assert_eq!(newsletter["affected"], json!(["Acme Cloud Widget"]));
    assert_eq!(newsletter["labels"]["affected"], "Targeted technologies:");
    assert_eq!(newsletter["cves"], record["cve_ids"]);
    assert_eq!(newsletter["recommendations"], json!([]));
    assert_eq!(newsletter["show_recommendations"], false);
    assert_eq!(
        newsletter["references"][0],
        record["details"]["article_url"]
    );
    assert_eq!(newsletter["references"][1], record["source"]["detail_url"]);
    assert_eq!(newsletter["references"].as_array().unwrap().len(), 3);
    for (label, value) in [
        ("Threat type", "Campaign"),
        ("Actors", "Example Actor"),
        (
            "Initial access",
            "Exploitation of public-facing application",
        ),
        ("Observed techniques", "Credential Access"),
        ("Editorial status", "Finalized"),
        ("Author", "threat.hunters@wiz.io (Wiz Threat Research)"),
        ("Published (UTC)", "2026-10-21T00:00:00Z"),
        ("Updated (UTC)", "2026-10-29T09:31:00Z"),
        ("Observed (UTC)", "2026-11-18T03:00:00Z"),
    ] {
        assert!(
            newsletter["table"]["rows"]
                .as_array()
                .unwrap()
                .contains(&json!([label, value]))
        );
    }
}

#[test]
fn wiz_missing_optional_fields_and_future_types_are_supported() {
    let record = json!({
        "code":"11111111-2222-4333-8444-555555555555",
        "title":"Historical incident",
        "source":{"provider":"wiz", "detail_url":"https://threats.wiz.io/permanent"},
        "details":{"content":"Available historical metadata", "threat_type":"Future source type", "extra_field":"Additional metadata"}
    });
    let newsletter = normalize(&record, "wiz", &json!({}));
    for field in ["severity", "impacts", "affected", "cves", "recommendations"] {
        assert_eq!(newsletter[field], json!([]), "{field}");
    }
    assert_eq!(newsletter["overview"], "Available historical metadata");
    assert_eq!(newsletter["show_affected"], false);
    assert_eq!(newsletter["show_impacts"], false);
    assert_eq!(
        newsletter["table"]["rows"],
        json!([["Threat type", "Future source type"]])
    );
    assert_eq!(newsletter["references"][0], record["source"]["detail_url"]);
}

#[test]
fn wiz_plain_text_is_escaped_and_newline_blocks_survive_rendering() {
    let mut record = fixture();
    record["details"]["content"] =
        json!("<script>alert('article')</script>\n**Plain text** & symbols");
    record["details"]["actors"] = json!(["<img src=x onerror=alert(1)>"]);
    record["details"]["reference_links"] =
        json!(["javascript:alert(1)", "http://example.com/reference"]);
    let newsletter = normalize(&record, "wiz", &json!({}));
    assert!(
        newsletter["references"]
            .as_array()
            .unwrap()
            .contains(&json!("http://example.com/reference"))
    );
    let env = crate::view::environment(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    let html = env
        .get_template(template_name("wiz"))
        .unwrap()
        .render(json!({"newsletter":newsletter}))
        .unwrap();
    assert!(html.contains("&lt;script&gt;"));
    assert!(!html.contains("<script>"));
    assert!(!html.contains("<img"));
    assert!(html.contains("**Plain text** &amp; symbols</p>"));
    assert!(html.contains("Editorial status"));
    assert!(!html.contains("Severity:"));
    assert!(html.contains("Targeted technologies:"));
    assert!(!html.contains("Refer to the vendor guidance"));
    assert!(!html.contains("javascript:"));
    assert!(html.contains("example.com"));
}

#[test]
fn wiz_uses_summary_and_permanent_url_when_article_fields_are_unavailable() {
    let mut record = fixture();
    record["details"].as_object_mut().unwrap().remove("content");
    record["details"]["article_url"] = json!("javascript:alert(1)");
    record["details"]
        .as_object_mut()
        .unwrap()
        .remove("reference_links");
    let newsletter = normalize(&record, "wiz", &json!({}));
    assert_eq!(newsletter["overview"], record["details"]["summary"]);
    assert_eq!(
        newsletter["references"],
        json!([record["source"]["detail_url"]])
    );
}
