use super::{text, values};
use serde_json::{Value, json};

fn key(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn heading(value: &str) -> String {
    if key(value) == "vulnerabilityclasshighestlevelcwe" {
        return "Vulnerability Class (Highest-Level CWE)".into();
    }
    value
        .split('_')
        .map(|word| match word.to_ascii_lowercase().as_str() {
            "cve" | "cwe" | "cvss" | "id" | "url" | "api" => word.to_ascii_uppercase(),
            _ => {
                let mut chars = word.chars();
                chars
                    .next()
                    .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                    .unwrap_or_default()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn source_table(table: &Value) -> Option<Value> {
    let headers = table["headers"].as_array()?;
    let rows = table["rows"].as_array()?;
    if headers.is_empty() || rows.is_empty() || headers.iter().any(|header| !header.is_string()) {
        return None;
    }
    let headers: Vec<&str> = headers.iter().filter_map(Value::as_str).collect();
    if headers.iter().any(|header| key(header).is_empty()) {
        return None;
    }
    let mut body = Vec::with_capacity(rows.len());
    for row in rows {
        let cells: Vec<String> = if let Some(row) = row.as_object() {
            headers
                .iter()
                .map(|header| {
                    row.get(*header)
                        .or_else(|| {
                            row.iter()
                                .find(|(name, _)| key(name) == key(header))
                                .map(|(_, value)| value)
                        })
                        .map(|value| values(value).join("\n"))
                        .unwrap_or_default()
                })
                .collect()
        } else if let Some(row) = row.as_array() {
            if row.len() != headers.len() {
                return None;
            }
            row.iter().map(|value| values(value).join("\n")).collect()
        } else {
            return None;
        };
        if cells.iter().all(String::is_empty) {
            return None;
        }
        body.push(cells);
    }
    Some(
        json!({"headers": headers.iter().map(|header| heading(header)).collect::<Vec<_>>(), "rows": body}),
    )
}

pub(super) fn product_status(details: &Value) -> Value {
    let Some(rows) = details["product_status"].as_array() else {
        return Value::Null;
    };
    let headers: Vec<&str> = [
        "product",
        "base_version",
        "component",
        "affected_version",
        "fix_version",
    ]
    .into_iter()
    .filter(|header| rows.iter().any(|row| !values(&row[*header]).is_empty()))
    .collect();
    source_table(&json!({"headers": headers, "rows": rows})).unwrap_or(Value::Null)
}

fn consume(lines: &[&str], mut position: usize, expected: &str) -> Option<usize> {
    let expected = key(expected);
    if expected.is_empty() {
        return Some(position);
    }
    let mut actual = String::new();
    while let Some(line) = lines.get(position) {
        actual.push_str(&key(line));
        position += 1;
        if actual == expected {
            return Some(position);
        }
        if !expected.starts_with(&actual) {
            return None;
        }
    }
    None
}

fn table_span(lines: &[&str], table: &Value) -> Option<(usize, usize)> {
    let cells: Vec<&str> = table["headers"]
        .as_array()?
        .iter()
        .chain(
            table["rows"]
                .as_array()?
                .iter()
                .filter_map(Value::as_array)
                .flatten(),
        )
        .filter_map(Value::as_str)
        .collect();
    for start in 0..lines.len() {
        let mut position = Some(start);
        for cell in &cells {
            position = position.and_then(|cursor| consume(lines, cursor, cell));
            if position.is_none() {
                break;
            }
        }
        if let Some(end) = position {
            return Some((start, end));
        }
    }
    None
}

fn text_blocks(content: &str, blocks: &mut Vec<Value>) {
    let mut paragraph = Vec::new();
    for line in content.lines().map(str::trim).chain(std::iter::once("")) {
        // The crawler puts superscript footnote numbers on their own lines.
        // Keep each note as a paragraph while rejoining wrapped inline text.
        if (line.is_empty() || line.chars().all(|c| c.is_ascii_digit())) && !paragraph.is_empty() {
            blocks.push(json!({"kind": "paragraph", "text": paragraph.join(" ")}));
            paragraph.clear();
        }
        if !line.is_empty() {
            paragraph.push(line);
        }
    }
}

fn section_blocks(content: &str, pending: &mut Vec<Value>, blocks: &mut Vec<Value>) {
    let lines: Vec<&str> = content.lines().collect();
    let mut spans: Vec<_> = pending
        .iter()
        .enumerate()
        .filter_map(|(index, table)| {
            let (start, end) = table_span(&lines, table)?;
            Some((start, end, index))
        })
        .collect();
    spans.sort_by_key(|span| span.0);
    let mut cursor = 0;
    let mut rendered = Vec::new();
    for (start, end, index) in spans {
        if start < cursor {
            continue;
        }
        text_blocks(&lines[cursor..start].join("\n"), blocks);
        blocks.push(json!({"kind": "table", "table": pending[index]}));
        rendered.push(index);
        cursor = end;
    }
    text_blocks(&lines[cursor..].join("\n"), blocks);
    rendered.sort_unstable();
    for index in rendered.into_iter().rev() {
        pending.remove(index);
    }
}

pub(super) fn overview(details: &Value, description: &str) -> Vec<Value> {
    let mut pending: Vec<Value> = Vec::new();
    for field in ["description_tables", "tables"] {
        for table in details[field]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(source_table)
        {
            if !pending.contains(&table) {
                pending.push(table);
            }
        }
    }
    // Older crawler records may retain the package rows without the original
    // description_tables wrapper. This is still structured source data.
    if let Some(table) = source_table(
        &json!({"headers": ["package", "remediation", "cve", "severity"], "rows": details["packages"]}),
    ) {
        if !pending.contains(&table) {
            pending.insert(0, table);
        }
    }
    if pending.is_empty() {
        return Vec::new();
    }
    let mut blocks = Vec::new();
    section_blocks(description, &mut pending, &mut blocks);
    let additional = text(&details["details"]);
    if !additional.is_empty() && additional != description {
        blocks.push(json!({"kind": "heading", "text": "Details"}));
        section_blocks(&additional, &mut pending, &mut blocks);
    }
    // Some source tables, such as the CVE summary, are outside Description.
    // Keep those tables even when there is no matching flattened text block.
    blocks.extend(
        pending
            .into_iter()
            .map(|table| json!({"kind": "table", "table": table})),
    );
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{newsletter_normalizer::normalize, view};
    use std::path::Path;

    fn render(newsletter: Value) -> String {
        view::environment(Path::new(env!("CARGO_MANIFEST_DIR")))
            .get_template("newsletters/generated.html")
            .unwrap()
            .render(json!({"newsletter": newsletter}))
            .unwrap()
    }

    #[test]
    fn description_table_replaces_flattened_cells_and_keeps_footnotes() {
        let rows = json!([{
            "severity": "High", "cve": "CVE-2026-12345",
            "remediation": "Upgrade to 2.0", "package": "example\n1"
        }]);
        let newsletter = normalize(
            &json!({"details": {
                "description": "Package fixes.\nPackage\nRemediation\nCVE\nSeverity\nexample\n1\nUpgrade to 2.0\nCVE-2026-12345\nHigh\n1\nAdditional remediation guidance.",
                "description_tables": [{"headers": ["package", "remediation", "cve", "severity"], "rows": rows}],
                "packages": rows,
                "product_status": [{"product": "Splunk Enterprise", "base_version": "10.0", "affected_version": "Below 10.0.2", "fix_version": "10.0.2"}]
            }}),
            "splunk",
            &json!({}),
        );
        let blocks = newsletter["overview_blocks"].as_array().unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0]["text"], "Package fixes.");
        assert_eq!(
            blocks[1]["table"]["headers"],
            json!(["Package", "Remediation", "CVE", "Severity"])
        );
        assert_eq!(
            blocks[1]["table"]["rows"],
            json!([["example\n1", "Upgrade to 2.0", "CVE-2026-12345", "High"]])
        );
        assert_eq!(blocks[2]["text"], "1 Additional remediation guidance.");
        assert_eq!(
            newsletter["affected_table"]["headers"],
            json!(["Product", "Base Version", "Affected Version", "Fix Version"])
        );
        let html = render(newsletter);
        let overview_html = html.split("<p><b>Severity:</b>").next().unwrap();
        assert_eq!(overview_html.matches("Upgrade to 2.0").count(), 1);
        assert!(html.contains("example<br>\n1"));
        assert!(html.contains("1 Additional remediation guidance."));
        assert_eq!(html.matches("class=\"source-overview-table\"").count(), 2);
    }

    #[test]
    fn details_and_separate_cve_tables_are_preserved_in_source_order() {
        let newsletter = normalize(
            &json!({"details": {
                "description": "Security hardening.",
                "details": "Each CVE groups findings.\nCVE ID\nHighest CVSS Score\nVulnerability Class (Highest-Level CWE)\nDescription\nCVE-2026-12345\n9.3\nCWE-284\nAccess Control\nAdditional details.",
                "tables": [
                    {"headers": ["cve_id", "highest_cvss_score", "vulnerability_class_highest_level_cwe", "description"], "rows": [{"description": "Access Control", "cve_id": "CVE-2026-12345", "highest_cvss_score": "9.3", "vulnerability_class_highest_level_cwe": "CWE-284"}]},
                    {"headers": ["cve", "summary", "cwe", "severity", "score"], "rows": [["CVE-2026-12346", "Another fix", "CWE-79", "Medium", "5.7"]]}
                ]
            }}),
            "splunk",
            &json!({}),
        );
        let blocks = newsletter["overview_blocks"].as_array().unwrap();
        assert_eq!(blocks[0]["text"], "Security hardening.");
        assert_eq!(blocks[1]["text"], "Details");
        assert_eq!(blocks[2]["text"], "Each CVE groups findings.");
        assert_eq!(
            blocks[3]["table"]["headers"][2],
            "Vulnerability Class (Highest-Level CWE)"
        );
        assert_eq!(blocks[4]["text"], "Additional details.");
        assert_eq!(
            blocks[5]["table"]["headers"],
            json!(["CVE", "Summary", "CWE", "Severity", "Score"])
        );
        let html = render(newsletter);
        assert_eq!(html.matches("Access Control").count(), 1);
        assert!(html.contains("Another fix"));
    }

    #[test]
    fn legacy_packages_and_optional_component_use_structured_columns() {
        let newsletter = normalize(
            &json!({"details": {
                "description": "Update the package.",
                "packages": [{"package": "example", "remediation": "Upgrade", "cve": "Multiple", "severity": "High"}],
                "product_status": [{"product": "Splunk Enterprise", "base_version": "10.0", "component": "MCP Server", "affected_version": "1.0", "fix_version": "1.1"}]
            }}),
            "splunk",
            &json!({}),
        );
        assert_eq!(
            newsletter["overview_blocks"][1]["table"]["rows"][0][0],
            "example"
        );
        assert_eq!(
            newsletter["affected_table"]["headers"],
            json!([
                "Product",
                "Base Version",
                "Component",
                "Affected Version",
                "Fix Version"
            ])
        );
        assert_eq!(newsletter["affected_table"]["rows"][0][2], "MCP Server");
    }

    #[test]
    fn missing_or_invalid_tables_keep_plain_overviews() {
        for details in [
            json!({"description": "An advance notice."}),
            json!({"description": "An advance notice.", "tables": [{"headers": ["cve"], "rows": [["one", "two"]]}]}),
            json!({"description": "An advance notice.", "description_tables": [{"headers": ["cve"], "rows": [{"unrelated": "value"}]}]}),
            json!({"description": "An advance notice.", "tables": [{"headers": [""], "rows": [["value"]]}]}),
        ] {
            let newsletter = normalize(&json!({"details": details}), "splunk", &json!({}));
            assert!(newsletter["overview_blocks"].is_null());
            let html = render(newsletter);
            assert_eq!(html.matches("An advance notice.").count(), 1);
            assert!(!html.contains("class=\"source-overview-table\""));
        }
    }

    #[test]
    fn overview_and_table_cells_are_escaped() {
        let newsletter = normalize(
            &json!({"details": {
                "description": "<script>alert(1)</script>",
                "tables": [{"headers": ["cve", "summary"], "rows": [["CVE-2026-12345", "<img src=x onerror=alert(1)>\nNext line & text"]]}]
            }}),
            "splunk",
            &json!({}),
        );
        let html = render(newsletter);
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;<br>\nNext line &amp; text"));
    }
}
