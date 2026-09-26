use regex::Regex;
use serde_json::{Map, Value, json};
use std::collections::HashSet;

const ORDER: [&str; 12] = [
    "title",
    "collection",
    "overview",
    "table",
    "severity",
    "cvss",
    "impacts",
    "affected",
    "cves",
    "recommendations",
    "references",
    "related_links",
];

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.trim().to_owned(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn values(value: &Value) -> Vec<String> {
    match value {
        Value::String(_) | Value::Number(_) | Value::Bool(_) => {
            let s = text(value);
            if s.is_empty() { vec![] } else { vec![s] }
        }
        Value::Array(items) => items.iter().flat_map(values).collect(),
        Value::Object(items) => items.values().flat_map(values).collect(),
        _ => vec![],
    }
}

fn path<'a>(value: &'a Value, keys: &[&str]) -> &'a Value {
    keys.iter().fold(value, |item, key| &item[*key])
}

fn first(details: &Value, document: &Value, fields: &[&str]) -> String {
    for source in [details, document] {
        for field in fields {
            if let Some(value) = values(&source[*field]).into_iter().next() {
                return value;
            }
        }
    }
    String::new()
}

fn all(details: &Value, document: &Value, fields: &[&str]) -> Vec<String> {
    let mut result = vec![];
    let mut seen = HashSet::new();
    for source in [details, document] {
        for field in fields {
            for value in values(&source[*field]) {
                if seen.insert(value.to_lowercase()) {
                    result.push(value);
                }
            }
        }
    }
    result
}

fn nested_values(value: &Value, fields: &[&str]) -> Vec<String> {
    fn walk(value: &Value, fields: &[&str], out: &mut Vec<String>, seen: &mut HashSet<String>) {
        match value {
            Value::Object(items) => {
                for (key, child) in items {
                    if fields.contains(&key.as_str()) {
                        for item in values(child) {
                            if seen.insert(item.clone()) {
                                out.push(item);
                            }
                        }
                    }
                    walk(child, fields, out, seen);
                }
            }
            Value::Array(items) => {
                for child in items {
                    walk(child, fields, out, seen);
                }
            }
            _ => (),
        }
    }
    let mut out = vec![];
    walk(value, fields, &mut out, &mut HashSet::new());
    out
}

fn fallback(
    primary: Vec<String>,
    details: &Value,
    document: &Value,
    fields: &[&str],
) -> Vec<String> {
    if !primary.is_empty() {
        return primary;
    }
    let found = nested_values(details, fields);
    if found.is_empty() {
        nested_values(document, fields)
    } else {
        found
    }
}

fn list_field(value: &Value, field: &str) -> Vec<String> {
    value
        .as_array()
        .map(|a| a.iter().flat_map(|v| values(&v[field])).collect())
        .unwrap_or_default()
}

fn urls(input: &[String], https_only: bool) -> Vec<String> {
    let mut out = vec![];
    let mut seen = HashSet::new();
    for item in input {
        for part in item.split_whitespace() {
            let candidate = part.trim_matches(|c: char| " ,;()[]<>\r\n\t".contains(c));
            let valid = candidate.starts_with("https://")
                || (!https_only && candidate.starts_with("http://"));
            if valid
                && candidate
                    .split("//")
                    .nth(1)
                    .is_some_and(|host| !host.is_empty())
                && seen.insert(candidate.to_owned())
            {
                out.push(candidate.to_owned());
            }
        }
    }
    out
}

fn cves(input: &[String]) -> Vec<String> {
    let re = Regex::new(r"(?i)\b(?:CVE-)?(\d{4}-\d{4,})\b").unwrap();
    let mut out = vec![];
    let mut seen = HashSet::new();
    for item in input {
        for cap in re.captures_iter(item) {
            let cve = format!("CVE-{}", cap[1].to_uppercase());
            if seen.insert(cve.clone()) {
                out.push(cve);
            }
        }
    }
    out
}

fn cvss(value: &Value, in_cvss: bool, key: &str, out: &mut Vec<String>) {
    let current = in_cvss || key.to_lowercase().contains("cvss");
    match value {
        Value::Object(m) => {
            if current {
                let lookup = |names: &[&str]| {
                    names
                        .iter()
                        .find_map(|n| {
                            m.iter()
                                .find(|(k, _)| k.replace('-', "_").eq_ignore_ascii_case(n))
                                .map(|(_, v)| text(v))
                        })
                        .unwrap_or_default()
                };
                let vector = lookup(&["vector_string", "vectorstring", "vector"]);
                let score = lookup(&["base_score", "basescore", "score"]);
                let severity = lookup(&["base_severity", "baseseverity", "severity"]);
                if !vector.is_empty() {
                    out.push(if score.is_empty() {
                        vector
                    } else if severity.is_empty() {
                        format!("{vector} ({score})")
                    } else {
                        format!("{vector} ({score} {severity})")
                    });
                    return;
                }
                if !score.is_empty() {
                    out.push(if severity.is_empty() {
                        score
                    } else {
                        format!("{score} ({severity})")
                    });
                    return;
                }
            }
            for (k, v) in m {
                cvss(v, current, k, out);
            }
        }
        Value::Array(a) => {
            for v in a {
                cvss(v, current, key, out);
            }
        }
        _ if current => {
            let s = text(value);
            if !s.is_empty() {
                out.push(s);
            }
        }
        _ => (),
    }
}

fn cvss_string(document: &Value, details: &Value) -> String {
    let mut out = vec![];
    cvss(document, false, "", &mut out);
    cvss(details, false, "", &mut out);
    let mut seen = HashSet::new();
    out.retain(|s| seen.insert(s.clone()));
    out.join("; ")
}

fn joined(value: &Value, fields: &[&str]) -> Vec<String> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|item| {
                    let line = fields
                        .iter()
                        .map(|f| text(&item[*f]))
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(" ");
                    if line.is_empty() { None } else { Some(line) }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn table_from_objects(value: &Value) -> Value {
    let Some(rows) = value.as_array() else {
        return Value::Null;
    };
    if rows.is_empty() || rows.iter().any(|r| !r.is_object()) {
        return Value::Null;
    }
    let mut headers = vec![];
    for row in rows {
        if let Some(m) = row.as_object() {
            for key in m.keys() {
                if !headers.contains(key) {
                    headers.push(key.clone());
                }
            }
        }
    }
    if headers.is_empty() {
        return Value::Null;
    }
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|r| headers.iter().map(|h| text(&r[h])).collect())
        .collect();
    json!({"headers": headers, "rows": body})
}

fn table_from_grid(value: &Value) -> Value {
    let Some(grids) = value.as_array() else {
        return Value::Null;
    };
    for grid in grids {
        let Some(rows) = grid.as_array() else {
            continue;
        };
        if rows.len() < 2 {
            continue;
        }
        let body: Vec<Vec<String>> = rows
            .iter()
            .filter_map(|r| r.as_array().map(|a| a.iter().map(text).collect()))
            .collect();
        if body.len() < 2 {
            continue;
        }
        let width = body.iter().map(Vec::len).max().unwrap_or(0);
        let headers: Vec<String> = (0..width)
            .map(|i| {
                body[0]
                    .get(i)
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .unwrap_or_else(|| format!("Column {}", i + 1))
            })
            .collect();
        let rows: Vec<Vec<String>> = body
            .into_iter()
            .skip(1)
            .map(|mut r| {
                r.resize(width, String::new());
                r
            })
            .collect();
        return json!({"headers":headers,"rows":rows});
    }
    Value::Null
}

fn severity_label(value: &str) -> String {
    match value.trim() {
        "1" | "超危" | "严重" => "Critical".into(),
        "2" | "高危" | "高" => "High".into(),
        "3" | "中危" | "中" => "Medium".into(),
        "4" | "低危" | "低" => "Low".into(),
        other => other.to_owned(),
    }
}

fn labels(chinese: bool) -> Value {
    if chinese {
        json!({"greeting":"尊敬的客户：","overview":"概述：","severity":"严重程度：","cvss":"CVSS：","impacts":"影响：","affected":"受影响系统：","cves":"CVE：","recommendations":"建议：","references":"参考资料：","related_links":"相关链接：","collection":"来源集合：","not_specified":"未说明","default_recommendation":"请参考供应商指南并应用可用修复。","footer":"如有任何疑问，请联系安全运营中心。谢谢。"})
    } else {
        json!({"greeting":"Dear Valued Customer,","overview":"Overview:","severity":"Severity:","cvss":"CVSS:","impacts":"Impacts:","affected":"Affected system:","cves":"CVEs:","recommendations":"Recommendations:","references":"References:","related_links":"Related Links:","collection":"Source collection:","not_specified":"Not specified","default_recommendation":"Refer to the vendor guidance and apply available fixes.","footer":"Should you have any queries, please contact the Security Operation Centre. Thank you."})
    }
}

fn hpe_lines(value: &Value) -> Vec<String> {
    let mut out = vec![];
    for item in values(value) {
        for line in item.lines().map(str::trim) {
            let lower = line.to_lowercase();
            if !line.is_empty()
                && !lower.starts_with("supported software versions")
                && !lower.starts_with("only impacted versions")
                && !out.iter().any(|v| v == line)
            {
                out.push(line.to_owned());
            }
        }
    }
    out
}

fn hpe_section(value: &Value, heading: &str) -> String {
    let mut lines: Vec<String> = values(value)
        .join("\n")
        .lines()
        .map(|l| l.trim().to_owned())
        .collect();
    if lines
        .first()
        .is_some_and(|s| s.eq_ignore_ascii_case(heading))
    {
        lines.remove(0);
    }
    lines.join("\n").trim().to_owned()
}

fn paragraphs(s: &str) -> Vec<String> {
    s.split("\n\n")
        .map(|block| block.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| !s.is_empty())
        .collect()
}

fn markdown_text(value: &str) -> String {
    value.replace("**", "").replace("__", "").replace('`', "")
}

fn markdown_blocks(value: &str) -> Vec<Value> {
    let mut blocks = Vec::new();
    let mut paragraph = Vec::new();
    let mut list = Vec::new();
    let mut code = Vec::new();
    let mut in_code = false;

    let flush_paragraph = |blocks: &mut Vec<Value>, paragraph: &mut Vec<String>| {
        if !paragraph.is_empty() {
            blocks.push(json!({
                "kind": "paragraph",
                "text": markdown_text(&paragraph.join(" "))
            }));
            paragraph.clear();
        }
    };
    let flush_list = |blocks: &mut Vec<Value>, list: &mut Vec<String>| {
        if !list.is_empty() {
            blocks.push(json!({"kind":"list","items":list.iter().map(|item| markdown_text(item)).collect::<Vec<_>>() }));
            list.clear();
        }
    };

    for line in value.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if in_code {
                blocks.push(json!({"kind":"code","text":code.join("\n")}));
                code.clear();
            } else {
                flush_paragraph(&mut blocks, &mut paragraph);
                flush_list(&mut blocks, &mut list);
            }
            in_code = !in_code;
            continue;
        }
        if in_code {
            code.push(line.trim_end().to_owned());
            continue;
        }
        if trimmed.is_empty() {
            flush_paragraph(&mut blocks, &mut paragraph);
            flush_list(&mut blocks, &mut list);
            continue;
        }
        if let Some(heading) = trimmed.strip_prefix("### ") {
            flush_paragraph(&mut blocks, &mut paragraph);
            flush_list(&mut blocks, &mut list);
            blocks.push(json!({"kind":"heading","text":markdown_text(heading)}));
            continue;
        }
        if let Some(heading) = trimmed.strip_prefix("## ") {
            flush_paragraph(&mut blocks, &mut paragraph);
            flush_list(&mut blocks, &mut list);
            blocks.push(json!({"kind":"heading","text":markdown_text(heading)}));
            continue;
        }
        if let Some(heading) = trimmed.strip_prefix("# ") {
            flush_paragraph(&mut blocks, &mut paragraph);
            flush_list(&mut blocks, &mut list);
            blocks.push(json!({"kind":"heading","text":markdown_text(heading)}));
            continue;
        }
        let item = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
            .or_else(|| trimmed.strip_prefix("+ "))
            .or_else(|| {
                let dot = trimmed.find(". ")?;
                trimmed[..dot]
                    .chars()
                    .all(|c| c.is_ascii_digit())
                    .then(|| &trimmed[dot + 2..])
            });
        if let Some(item) = item {
            flush_paragraph(&mut blocks, &mut paragraph);
            list.push(item.to_owned());
            continue;
        }
        if trimmed == "---" || trimmed == "***" {
            flush_paragraph(&mut blocks, &mut paragraph);
            flush_list(&mut blocks, &mut list);
            blocks.push(json!({"kind":"rule"}));
            continue;
        }
        paragraph.push(trimmed.to_owned());
    }
    if in_code {
        blocks.push(json!({"kind":"code","text":code.join("\n")}));
    }
    flush_paragraph(&mut blocks, &mut paragraph);
    flush_list(&mut blocks, &mut list);
    blocks
}

fn hpe_summary_paragraphs(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut current = Vec::new();
    for block in s.split("\n\n") {
        for line in block.lines().map(str::trim).filter(|s| !s.is_empty()) {
            let lower = line.to_lowercase();
            let boundary = (lower.starts_with("on ") && lower.contains("pacific time)"))
                || lower.starts_with("these advisories will")
                || lower.starts_with("hpe networking product lines");
            if boundary && !current.is_empty() {
                out.push(current.join(" "));
                current.clear();
            }
            current.push(line);
        }
        if !current.is_empty() {
            out.push(current.join(" "));
            current.clear();
        }
    }
    out
}

fn date(value: &Value) -> String {
    text(value).split('T').next().unwrap_or("").to_owned()
}

pub fn template_name(source: &str) -> &'static str {
    match source {
        "github_advisory" => "newsletters/github_advisory.html",
        "hpe" => "newsletters/hpe.html",
        "nvd" => "newsletters/nvd.html",
        "zimbra" => "newsletters/zimbra.html",
        _ => "newsletters/generated.html",
    }
}

pub fn normalize(document: &Value, source: &str, config: &Value) -> Value {
    let null = Value::Null;
    let details = document
        .get("details")
        .filter(|v| v.is_object())
        .unwrap_or(&null);
    let mut title = text(&document["title"]);
    if title.is_empty() {
        title = first(details, &null, &["title", "advisory_title", "vulName"]);
    }
    let mut overview = first(
        details,
        document,
        &["intro", "summary", "description", "vulDesc", "productDesc"],
    );
    if overview.is_empty() {
        overview = nested_values(
            details,
            &[
                "intro",
                "summary",
                "description",
                "overview",
                "vulDesc",
                "productDesc",
            ],
        )
        .into_iter()
        .next()
        .unwrap_or_default();
    }
    let mut severity = fallback(
        all(details, document, &["impact", "impacts", "severity"]),
        details,
        document,
        &["impact", "impacts", "severity"],
    );
    let mut affected = fallback(
        all(
            details,
            document,
            &[
                "systems_affected",
                "affected_systems",
                "affected",
                "affected_products",
                "affectedSystem",
                "affectedProduct",
                "product_names",
            ],
        ),
        details,
        document,
        &[
            "systems_affected",
            "affected_systems",
            "affected",
            "affected_products",
            "affectedSystem",
            "affectedProduct",
            "product_names",
        ],
    );
    let mut recommendations = fallback(
        all(
            details,
            document,
            &[
                "solutions",
                "solution",
                "recommendation",
                "recommendations",
                "patch",
                "mitigation",
                "remediation",
            ],
        ),
        details,
        document,
        &[
            "solutions",
            "solution",
            "recommendation",
            "recommendations",
            "patch",
            "mitigation",
            "remediation",
        ],
    );
    let mut reference_values = fallback(
        all(
            details,
            document,
            &[
                "references",
                "reference_links",
                "referUrl",
                "publication_url",
                "solution_links",
                "more_information_links",
            ],
        ),
        details,
        document,
        &[
            "references",
            "reference_links",
            "referUrl",
            "publication_url",
            "solution_links",
            "more_information_links",
        ],
    );
    let mut related_values = fallback(
        all(details, document, &["related_links", "related_link"]),
        details,
        document,
        &["related_links", "related_link"],
    );
    let mut show_severity = true;
    let mut show_affected = true;
    let mut show_recommendations = true;
    let mut table = Value::Null;
    let mut affected_table = Value::Null;
    let mut extras = Map::new();

    if matches!(
        source,
        "avd"
            | "cisco"
            | "cnnvd"
            | "cnvd"
            | "cve"
            | "fortiguard"
            | "github_advisory"
            | "hikvision"
            | "huawei_sa"
            | "juniper"
            | "nvd"
            | "paloalto"
            | "qianxin"
            | "splunk"
    ) {
        let document_severity = values(&document["severity"]);
        if !document_severity.is_empty() {
            severity = document_severity;
        }
    }
    match source {
        "avd" => {
            affected = joined(
                &details["affected_software"],
                &["vendor", "product", "version", "impact"],
            )
        }
        "cisco" => {
            if !text(&details["summary"]).is_empty() {
                overview = text(&details["summary"]);
            }
            affected = values(&details["product_names"]);
            reference_values = values(&json!([
                details["publication_url"],
                details["cvrf_url"],
                details["csaf_url"]
            ]));
        }
        "cnvd" => {
            let mut candidate = text(path(details, &["raw_fields", "厂商补丁"]));
            if candidate == "(无补丁信息)" || candidate == "（无补丁信息）" {
                candidate.clear();
            }
            if let Some(stripped) = candidate.strip_suffix("的补丁") {
                candidate = stripped.trim().to_owned();
            }
            for name in [candidate, text(&document["title"]), text(&details["title"])] {
                if !name.is_empty() && name != "相关漏洞" {
                    title = name;
                    break;
                }
            }
            affected = values(&details["affected_products"]);
            reference_values = values(path(details, &["raw_fields", "参考链接"]));
        }
        "cnnvd" => {
            overview = first(details, &null, &["vulDesc", "productDesc"]);
            let label = severity_label(&first(&null, document, &["severity"]));
            let label = if label.is_empty() {
                severity_label(&text(&details["hazardLevel"]))
            } else {
                label
            };
            severity = if label.is_empty() {
                vec![]
            } else {
                vec![label]
            };
            affected = values(&json!([
                details["affectedProduct"],
                details["affectedSystem"],
                details["affectedVendor"]
            ]));
            recommendations = values(&details["patch"]);
            reference_values = values(&details["referUrl"]);
        }
        "nvd" => {
            if !text(&details["description"]).is_empty() {
                overview = text(&details["description"]);
            }
            affected = values(&details["affected_products"]);
            reference_values = values(&details["reference_links"]);
            for (key, value) in [
                ("published", json!(date(&document["published_at"]))),
                ("updated", json!(date(&document["updated_at"]))),
                ("vuln_status", json!(text(&details["vuln_status"]))),
            ] {
                extras.insert(key.into(), value);
            }
        }
        "cve" => {
            let generic = Regex::new(r"(?i)^\s*(?:CVE-)?\d{4}-\d{4,}(?:\s+Record)?\s*$").unwrap();
            if title.is_empty() || generic.is_match(&title) {
                title = cves(&all(details, document, &["cve", "cve_ids", "code", "id"]))
                    .into_iter()
                    .next()
                    .unwrap_or(title);
            }
            overview = list_field(&details["descriptions"], "value")
                .into_iter()
                .next()
                .unwrap_or_default();
            affected = vec![];
            if let Some(items) = details["affected"].as_array() {
                for item in items {
                    let versions = item["versions"]
                        .as_array()
                        .cloned()
                        .unwrap_or_else(|| vec![json!({})]);
                    for version in versions {
                        let version_text = if !text(&version["lessThanOrEqual"]).is_empty() {
                            format!("<= {}", text(&version["lessThanOrEqual"]))
                        } else if !text(&version["lessThan"]).is_empty() {
                            format!("< {}", text(&version["lessThan"]))
                        } else {
                            text(&version["version"])
                        };
                        let line = [
                            text(&item["vendor"]),
                            text(&item["product"]),
                            if version_text == "0" {
                                String::new()
                            } else {
                                version_text
                            },
                        ]
                        .into_iter()
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(" ");
                        if !line.is_empty() && !affected.contains(&line) {
                            affected.push(line);
                        }
                    }
                }
            }
            reference_values = list_field(&details["references"], "url");
        }
        "github_advisory" => {
            overview = first(details, &null, &["description", "summary"]);
            affected = vec![];
            if let Some(items) = details["vulnerabilities"].as_array() {
                for item in items {
                    let package = &item["package"];
                    let name = text(&package["name"]);
                    let prefix = if text(&package["ecosystem"]).is_empty() {
                        name
                    } else {
                        format!("{}:{name}", text(&package["ecosystem"]))
                    };
                    let line = [prefix, text(&item["vulnerable_version_range"])]
                        .into_iter()
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(" ");
                    if !line.is_empty() {
                        affected.push(line);
                    }
                }
            }
            recommendations = list_field(&details["vulnerabilities"], "first_patched_version");
            reference_values = values(&details["references"]);
            let mut vulnerability_details = Vec::new();
            if let Some(items) = details["vulnerabilities"].as_array() {
                for item in items {
                    let package = &item["package"];
                    let ecosystem = text(&package["ecosystem"]);
                    let name = text(&package["name"]);
                    let range = text(&item["vulnerable_version_range"]);
                    let patched = text(&item["first_patched_version"]);
                    if !name.is_empty() || !range.is_empty() || !patched.is_empty() {
                        vulnerability_details.push(json!({
                            "ecosystem": ecosystem,
                            "package": name,
                            "range": range,
                            "patched": patched,
                        }));
                    }
                }
            }
            let cwes = details["cwes"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|item| {
                            let id = text(&item["cwe_id"]);
                            let name = text(&item["name"]);
                            [id, name]
                                .into_iter()
                                .filter(|value| !value.is_empty())
                                .collect::<Vec<_>>()
                                .join(" — ")
                        })
                        .filter(|value| !value.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            for (key, value) in [
                ("ghsa_id", json!(text(&details["ghsa_id"]))),
                ("advisory_type", json!(text(&details["advisory_type"]))),
                ("advisory_url", json!(text(&details["html_url"]))),
                (
                    "repository_url",
                    json!(text(&details["source_code_location"])),
                ),
                (
                    "github_reviewed_at",
                    json!(date(&details["github_reviewed_at"])),
                ),
                (
                    "nvd_published_at",
                    json!(date(&details["nvd_published_at"])),
                ),
                ("cwes", json!(cwes)),
                ("vulnerability_details", json!(vulnerability_details)),
                ("description_blocks", json!(markdown_blocks(&overview))),
            ] {
                extras.insert(key.into(), value);
            }
        }
        "hkcert" => {
            table = table_from_objects(&details["table"]);
            affected = values(&details["systems_affected"]);
            recommendations = values(&details["solutions"]);
            reference_values = values(&details["solution_links"]);
            related_values = values(&details["related_links"]);
        }
        "huawei_sa" => {
            show_affected = false;
            affected.clear();
        }
        "govcert" | "infosec" => {
            overview = first(details, &null, &["description", "summary"]);
            severity = values(&details["impact"]);
            affected = values(&details["affected_systems"]);
            recommendations = values(&details["recommendation"]);
            reference_values = values(&details["more_information_links"]);
        }
        "juniper" => {
            affected.clear();
            affected_table = table_from_grid(&details["raw_tables"]);
        }
        "paloalto" => {
            affected = values(&details["products"]);
            recommendations = values(&json!([details["solution"], details["workarounds"]]));
        }
        "fortiguard" => {
            if !text(&details["summary"]).is_empty() {
                overview = text(&details["summary"]);
            }
            affected.clear();
            recommendations.clear();
            show_recommendations = false;
            if let Some(rows) = details["affected_products"].as_array() {
                let body: Vec<Vec<String>> = rows
                    .iter()
                    .map(|r| {
                        vec![
                            text(&r["version"]),
                            text(&r["affected"]),
                            text(&r["solution"]),
                        ]
                    })
                    .filter(|r| r.iter().any(|s| !s.is_empty()))
                    .collect();
                if !body.is_empty() {
                    affected_table =
                        json!({"headers":["Version","Affected","Solution"],"rows":body});
                }
            }
            reference_values = values(&json!([details["cvrf_url"], details["csaf_url"]]));
        }
        "qianxin" => {
            let vulnerability = path(details, &["description", "vulnerability_information"]);
            overview = [
                text(path(details, &["description", "security_advisory"])),
                text(&vulnerability["summary"]),
                overview,
            ]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or_default();
            affected = vec![];
            let product = [
                text(&vulnerability["vendor"]),
                text(&vulnerability["product"]),
            ]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
            if !product.is_empty() {
                affected.push(product);
            }
            affected.extend(values(&vulnerability["affected_versions"]));
            let other = text(&vulnerability["other_affected_components"]);
            if !other.is_empty() && other != "无" {
                affected.push(other);
            }
            recommendations = values(path(details, &["description", "recommendations"]));
            reference_values = values(&json!([
                details["reference_links"],
                path(details, &["description", "references"])
            ]));
        }
        "hikvision" => reference_values.clear(),
        "ransomwarelive" => {
            overview = first(details, document, &["press", "title"]);
            show_severity = false;
            show_affected = false;
        }
        "zeroday" => {
            show_severity = false;
            show_affected = false;
            severity.clear();
            affected.clear();
        }
        "hpe" => {
            title = [text(&document["title"]), text(&details["summary"]), title]
                .into_iter()
                .find(|s| !s.is_empty())
                .unwrap_or_default();
            let versions = hpe_lines(if details["supported_software_versions"].is_null() {
                &details["supported_versions"]
            } else {
                &details["supported_software_versions"]
            });
            let reference_ids: Vec<String> = hpe_lines(&details["references"])
                .into_iter()
                .filter(|s| !s.eq_ignore_ascii_case("references:"))
                .collect();
            let raw_cvss = text(&details["cvss_text"]);
            let vulnerability_summary = Regex::new(r"(?is)(?:^|\n)VULNERABILITY SUMMARY\s*\n(.*?)(?:\n(?:References:|SUPPORTED SOFTWARE VERSIONS)|\z)").unwrap()
                .captures(&raw_cvss).map(|c| c[1].trim().to_owned()).unwrap_or_else(|| {
                    let summary = text(&details["summary"]);
                    if summary == text(&details["title"]) { String::new() } else { summary }
                });
            let background = hpe_section(&details["background"], "BACKGROUND");
            let resolution = hpe_section(&details["resolution"], "RESOLUTION");
            let history = hpe_section(&details["history"], "HISTORY");
            overview = [vulnerability_summary.clone(), background.clone(), overview]
                .into_iter()
                .find(|s| !s.is_empty())
                .unwrap_or_default();
            affected = versions.clone();
            recommendations = if resolution.is_empty() {
                vec![]
            } else {
                vec![resolution.clone()]
            };
            reference_values = values(&json!([
                details["doc_display_url"],
                details["reference_links"]
            ]));
            for (key, value) in [
                (
                    "vulnerability_summary",
                    json!(vulnerability_summary.clone()),
                ),
                (
                    "vulnerability_summary_paragraphs",
                    json!(hpe_summary_paragraphs(&vulnerability_summary)),
                ),
                ("bulletin_id", json!(text(&details["bulletin_id"]))),
                (
                    "document_subtype",
                    json!(text(&details["document_subtype"])),
                ),
                (
                    "document_version",
                    json!(text(&details["document_version"])),
                ),
                (
                    "potential_security_impact",
                    json!(text(&details["potential_security_impact"])),
                ),
                ("source_name", json!(text(&details["source"]))),
                ("supported_versions", json!(versions)),
                ("background", json!(background.clone())),
                ("background_paragraphs", json!(paragraphs(&background))),
                ("resolution", json!(resolution.clone())),
                ("resolution_paragraphs", json!(paragraphs(&resolution))),
                ("history", json!(history.clone())),
                ("history_paragraphs", json!(paragraphs(&history))),
                ("reference_ids", json!(reference_ids)),
                ("published_at", json!(date(&document["published_at"]))),
                ("updated_at", json!(date(&document["updated_at"]))),
            ] {
                extras.insert(key.into(), value);
            }
        }
        "zimbra" => {
            title = [text(&document["title"]), text(&details["title"]), title]
                .into_iter()
                .find(|s| !s.is_empty())
                .unwrap_or_default();
            let security_fixes = values(&details["security_fixes"]);
            let mut fixed_issues = vec![];
            if let Some(m) = details["fixed_issues"].as_object() {
                for (category, items) in m {
                    fixed_issues.push(json!({"category":category,"items":values(items)}));
                }
            }
            let mut packages = vec![];
            if let Some(m) = details["packages"].as_object() {
                for (name, version) in m {
                    packages.push(json!({"name":name,"version":text(version)}));
                }
            }
            if !security_fixes.is_empty() || !fixed_issues.is_empty() {
                let issue_count: usize = fixed_issues
                    .iter()
                    .map(|g| g["items"].as_array().map(Vec::len).unwrap_or(0))
                    .sum();
                overview = format!(
                    "{} security fix(es) and {issue_count} other fix(es) are included in this patch release.",
                    security_fixes.len()
                );
            }
            recommendations = security_fixes.clone();
            for group in &fixed_issues {
                for item in values(&group["items"]) {
                    recommendations.push(format!("{}: {item}", text(&group["category"])));
                }
            }
            affected = packages
                .iter()
                .map(|p| format!("{}: {}", text(&p["name"]), text(&p["version"])))
                .collect();
            reference_values = values(&json!([
                details["reference_links"],
                details["patch_installation_url"],
                details["open_source_repo_url"]
            ]));
            let patch = urls(&values(&details["patch_installation_url"]), true)
                .into_iter()
                .next()
                .unwrap_or_default();
            let repo = urls(&values(&details["open_source_repo_url"]), true)
                .into_iter()
                .next()
                .unwrap_or_default();
            let refs: Vec<String> = urls(&reference_values, true)
                .into_iter()
                .filter(|v| v != &patch && v != &repo)
                .collect();
            for (key, value) in [
                ("subtitle", json!(text(&details["title"]))),
                ("security_fixes", json!(security_fixes)),
                ("fixed_issues", json!(fixed_issues)),
                ("packages", json!(packages)),
                ("patch_installation_url", json!(patch)),
                ("open_source_repo_url", json!(repo)),
                ("reference_links", json!(refs)),
                ("product_release", json!(text(&details["product_release"]))),
                ("codename", json!(text(&details["codename"]))),
                (
                    "third_party_patch_level",
                    json!(text(&details["third_party_patch_level"])),
                ),
                (
                    "general_availability",
                    json!(text(&details["general_availability"])),
                ),
            ] {
                extras.insert(key.into(), value);
            }
        }
        _ => (),
    }

    let source_urls = &document["source"];
    let detail_url = text(&source_urls["detail_url"]);
    if !detail_url.is_empty() {
        reference_values.insert(0, detail_url);
    }
    let source_url = text(&source_urls["url"]);
    if !source_url.is_empty() {
        related_values.insert(0, source_url);
    }
    let https_only = matches!(source, "hpe" | "zimbra");
    let references = urls(&reference_values, https_only);
    let related_links: Vec<String> = urls(&related_values, https_only)
        .into_iter()
        .filter(|v| !references.contains(v))
        .collect();
    let cves = cves(&all(
        details,
        document,
        &[
            "cve",
            "cve_ids",
            "cveCode",
            "cve_id",
            "vulnerability_identifiers",
        ],
    ));
    let mut score = cvss_string(document, details);
    let mut impacts = vec![];
    let mut show_impacts = false;
    if source == "hkcert" {
        impacts = values(&details["impact"]);
        severity = values(&details["risk_level"]);
        if severity.is_empty() {
            severity = values(&document["severity"]);
        }
        show_impacts = true;
    }
    if source == "hpe" {
        score.clear();
    }
    let chinese = matches!(source, "cnvd" | "cnnvd" | "huawei_sa" | "qianxin");
    let labels = labels(chinese);
    if title.is_empty() {
        title = "Security Advisory".into();
    }
    if overview.is_empty() {
        overview = "No overview was provided in the source record.".into();
    }
    let order: Vec<String> = config
        .pointer(&format!("/sources/{source}/fields"))
        .and_then(Value::as_array)
        .map(|a| {
            let mut seen = HashSet::new();
            a.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| ORDER.contains(s) && seen.insert(*s))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_else(|| ORDER.iter().map(|s| s.to_string()).collect());
    let subject = config
        .pointer("/common/subject")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("Security newsletter: {{title}}")
        .replace("{{title}}", &title)
        .replace("{{collection}}", source)
        .replace("{{source_collection}}", source);
    let footer = config
        .pointer("/common/footer")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| labels["footer"].as_str().unwrap_or(""));
    let template_key = if matches!(
        source,
        "avd"
            | "cisco"
            | "cnnvd"
            | "cnvd"
            | "cve"
            | "fortiguard"
            | "github_advisory"
            | "govcert"
            | "hikvision"
            | "hkcert"
            | "hpe"
            | "huawei_sa"
            | "infosec"
            | "juniper"
            | "nvd"
            | "paloalto"
            | "qianxin"
            | "ransomwarelive"
            | "splunk"
            | "zeroday"
            | "zimbra"
    ) {
        source
    } else {
        "generic"
    };
    let mut result = json!({"template_key":template_key,"language":if chinese {"zh-Hans"} else {"en"},"labels":labels,"title":title,"subject":subject,"collection":source,"overview":overview,"severity":severity,"cvss":score,"impacts":impacts,"affected":affected,"recommendations":recommendations,"references":references,"related_links":related_links,"cves":cves,"table":table,"affected_table":affected_table,"show_severity":show_severity,"show_impacts":show_impacts,"show_affected":show_affected,"show_recommendations":show_recommendations,"field_order":order,"extra":config.pointer("/common/extra").and_then(Value::as_str).unwrap_or(""),"footer":footer});
    for (key, value) in extras {
        result[&key] = value;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_specific_fields_are_preserved() {
        let config = json!({});
        let zimbra = normalize(
            &json!({"title":"Patch release","details":{"security_fixes":["Fixed injection"],"fixed_issues":{"Mail":["Fixed redirect"]},"packages":{"zimbra-patch":"10.1"},"reference_links":["https://example.com/patch"]}}),
            "zimbra",
            &config,
        );
        assert_eq!(
            zimbra["recommendations"],
            json!(["Fixed injection", "Mail: Fixed redirect"])
        );
        assert_eq!(zimbra["affected"], json!(["zimbra-patch: 10.1"]));
        assert_eq!(template_name("zimbra"), "newsletters/zimbra.html");

        let hkcert = normalize(
            &json!({"details":{"risk_level":"High Risk","impact":["Remote execution"],"table":[{"Product":"A","Risk":"High"}]}}),
            "hkcert",
            &config,
        );
        assert_eq!(hkcert["severity"], json!(["High Risk"]));
        assert_eq!(hkcert["impacts"], json!(["Remote execution"]));
        assert_eq!(hkcert["table"]["rows"], json!([["A", "High"]]));

        let hpe = normalize(
            &json!({"title":"HPE Bulletin","severity":"Critical","details":{"bulletin_id":"HPESB1","cvss_text":"VULNERABILITY SUMMARY\nFirst line\nOn September 1st, 2026 (Pacific Time) second line\nThese advisories will be reviewed.\nReferences:\nPSRT1\nSUPPORTED SOFTWARE VERSIONS\nProduct A","supported_versions":"Product A","resolution":"RESOLUTION\nUpgrade now."}}),
            "hpe",
            &config,
        );
        assert_eq!(hpe["bulletin_id"], "HPESB1");
        assert_eq!(
            hpe["vulnerability_summary_paragraphs"],
            json!([
                "First line",
                "On September 1st, 2026 (Pacific Time) second line",
                "These advisories will be reviewed."
            ])
        );
        assert_eq!(hpe["resolution"], "Upgrade now.");
        assert_eq!(template_name("hpe"), "newsletters/hpe.html");
    }

    #[test]
    fn cve_and_cvss_values_use_source_structure() {
        let document = json!({"title":"CVE-2026-1000","severity":"High","details":{"descriptions":[{"value":"Useful description"}],"affected":[{"vendor":"Acme","product":"Widget","versions":[{"lessThan":"2.0"}]}],"references":[{"url":"https://example.com/cve"}],"metrics":{"cvss_v31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N","baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}});
        let normalized = normalize(&document, "cve", &json!({}));
        assert_eq!(normalized["overview"], "Useful description");
        assert_eq!(normalized["affected"], json!(["Acme Widget < 2.0"]));
        assert_eq!(normalized["references"], json!(["https://example.com/cve"]));
        assert_eq!(normalized["cvss"], "CVSS:3.1/AV:N (9.8 CRITICAL)");
    }

    #[test]
    fn github_advisories_get_structured_email_fields() {
        let normalized = normalize(
            &json!({
                "title": "Advisory",
                "details": {
                    "ghsa_id": "GHSA-1234",
                    "description": "## Summary\n\nA description.\n\n- One item\n\n```sh\necho test\n```",
                    "vulnerabilities": [{
                        "package": {"ecosystem": "npm", "name": "demo"},
                        "vulnerable_version_range": "< 1.0.0",
                        "first_patched_version": "1.0.0"
                    }],
                    "html_url": "https://github.com/advisories/GHSA-1234"
                }
            }),
            "github_advisory",
            &json!({}),
        );
        assert_eq!(
            template_name("github_advisory"),
            "newsletters/github_advisory.html"
        );
        assert_eq!(normalized["ghsa_id"], "GHSA-1234");
        assert_eq!(normalized["vulnerability_details"][0]["package"], "demo");
        assert_eq!(normalized["vulnerability_details"][0]["patched"], "1.0.0");
        assert!(
            normalized["description_blocks"]
                .as_array()
                .is_some_and(|blocks| blocks.iter().any(|block| block["kind"] == "code"))
        );
    }
}
