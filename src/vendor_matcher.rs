use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

fn key(s: &str) -> String {
    s.to_lowercase()
        .replace('&', " ")
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn vendor_key(s: &str) -> String {
    let k = key(s);
    let mut tokens: Vec<&str> = k.split_whitespace().collect();
    while tokens.len() > 1
        && matches!(
            tokens.last().copied(),
            Some(
                "co" | "company"
                    | "corp"
                    | "corporation"
                    | "gmbh"
                    | "inc"
                    | "incorporated"
                    | "limited"
                    | "llc"
                    | "ltd"
                    | "plc"
            )
        )
    {
        tokens.pop();
    }
    tokens.join(" ")
}

fn identity(row: &Value, field: &str, aliases: &str, vendor: bool) -> Vec<String> {
    std::iter::once(&row[field])
        .chain(row[aliases].as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .map(|s| if vendor { vendor_key(s) } else { key(s) })
        .filter(|s| !s.is_empty())
        .collect()
}

fn path<'a>(value: &'a Value, keys: &[&str]) -> &'a Value {
    keys.iter().fold(value, |v, k| &v[*k])
}
fn str_value(v: &Value) -> &str {
    v.as_str().unwrap_or("").trim()
}

fn structured_pairs(document: &Value) -> Vec<(String, String, String)> {
    let mut out = vec![];
    let pairs: [(&[&str], &[&str], &str); 4] = [
        (&["vendor"], &["product"], "vendor/product"),
        (
            &["details", "vendor"],
            &["details", "product"],
            "details.vendor/product",
        ),
        (
            &["details", "affectedVendor"],
            &["details", "affectedProduct"],
            "details.affectedVendor/affectedProduct",
        ),
        (
            &[
                "details",
                "description",
                "vulnerability_information",
                "vendor",
            ],
            &[
                "details",
                "description",
                "vulnerability_information",
                "product",
            ],
            "details.description.vulnerability_information.vendor/product",
        ),
    ];
    for (vendor, product, source) in pairs {
        let v = str_value(path(document, vendor));
        let p = str_value(path(document, product));
        if !v.is_empty() || !p.is_empty() {
            out.push((source.into(), v.into(), p.into()));
        }
    }
    let arrays: [&[&str]; 8] = [
        &["details", "affected"],
        &["details", "containers", "cna", "affected"],
        &["details", "affected_software"],
        &["details", "affected_products"],
        &["details", "vulnerabilities"],
        &["affected"],
        &["affected_products"],
        &["affected_software"],
    ];
    for names in arrays {
        let value = path(document, names);
        let entries: Vec<&Value> = value
            .as_array()
            .map(|a| a.iter().collect())
            .unwrap_or_else(|| vec![value]);
        for (i, entry) in entries.into_iter().enumerate() {
            if !entry.is_object() {
                continue;
            }
            let vendor = ["vendor", "vendor_name", "manufacturer", "affectedVendor"]
                .iter()
                .find_map(|k| entry[*k].as_str().filter(|s| !s.trim().is_empty()))
                .unwrap_or_else(|| {
                    ["ecosystem", "vendor", "vendor_name", "manufacturer"]
                        .iter()
                        .find_map(|k| {
                            entry["package"][*k]
                                .as_str()
                                .filter(|s| !s.trim().is_empty())
                        })
                        .unwrap_or("")
                });
            let product = [
                "product",
                "product_name",
                "packageName",
                "affectedProduct",
                "affected",
            ]
            .iter()
            .find_map(|k| entry[*k].as_str().filter(|s| !s.trim().is_empty()))
            .unwrap_or_else(|| {
                ["name", "product", "product_name", "packageName"]
                    .iter()
                    .find_map(|k| {
                        entry["package"][*k]
                            .as_str()
                            .filter(|s| !s.trim().is_empty())
                    })
                    .unwrap_or("")
            });
            if !vendor.is_empty() || !product.is_empty() {
                out.push((
                    format!("{}[{i}]", names.join(".")),
                    vendor.into(),
                    product.into(),
                ));
            }
        }
    }
    out
}

fn segments(document: &Value) -> Vec<(String, String)> {
    const PATHS: &[&[&str]] = &[
        &["affected"],
        &["affected_products"],
        &["affected_software"],
        &["systems_affected"],
        &["affected_systems"],
        &["products"],
        &["product_names"],
        &["title"],
        &["description"],
        &["descriptions"],
        &["summary"],
        &["impacts"],
        &["details", "affected"],
        &["details", "affected_products"],
        &["details", "affected_software"],
        &["details", "systems_affected"],
        &["details", "affected_systems"],
        &["details", "products"],
        &["details", "product_names"],
        &["details", "affectedProduct"],
        &["details", "affectedSystem"],
        &["details", "affectedVendor"],
        &["details", "description"],
        &["details", "descriptions"],
        &["details", "summary"],
        &["details", "containers", "cna", "descriptions"],
    ];
    fn push(value: &Value, source: &str, out: &mut Vec<(String, String)>) {
        match value {
            Value::String(s) if !s.trim().is_empty() => out.push((source.into(), s.trim().into())),
            Value::Array(a) => {
                for v in a {
                    push(v, source, out);
                }
            }
            Value::Object(m) => {
                if let Some(v) = m.get("value") {
                    push(v, source, out);
                }
            }
            _ => (),
        }
    }
    let mut out = vec![];
    for names in PATHS {
        push(path(document, names), &names.join("."), &mut out);
    }
    out
}

fn contains(segment: &str, phrase: &str) -> bool {
    if phrase.is_empty() {
        return false;
    }
    let cjk = phrase
        .chars()
        .any(|c| ('\u{3040}'..='\u{9fff}').contains(&c) || ('\u{ac00}'..='\u{d7af}').contains(&c));
    if cjk {
        segment.replace(' ', "").contains(&phrase.replace(' ', ""))
    } else {
        format!(" {segment} ").contains(&format!(" {phrase} "))
    }
}

fn known(s: &str) -> bool {
    !matches!(
        s,
        "" | "*" | "n a" | "na" | "none" | "not specified" | "unknown" | "unspecified"
    )
}
fn distinctive(s: &str) -> bool {
    let generic = [
        "app",
        "application",
        "client",
        "device",
        "enterprise",
        "library",
        "package",
        "platform",
        "plugin",
        "product",
        "server",
        "service",
        "software",
        "system",
        "tool",
        "web",
    ];
    !generic.contains(&s) && s.chars().filter(|c| !c.is_whitespace()).count() >= 4
}

pub fn validate(filter: &Value) -> Result<(), String> {
    if filter.is_null() {
        return Ok(());
    }
    let Some(m) = filter.as_object() else {
        return Err("Vendor/product filter must be an object.".into());
    };
    for field in m.keys() {
        if ![
            "enabled",
            "schema_version",
            "include_possible_matches",
            "rows",
        ]
        .contains(&field.as_str())
        {
            return Err(format!(
                "Vendor/product filter contains unknown field: {field}"
            ));
        }
    }
    if !filter["enabled"].is_boolean() && !filter["enabled"].is_null() {
        return Err("Vendor/product filter enabled must be true or false.".into());
    }
    if !filter["include_possible_matches"].is_boolean()
        && !filter["include_possible_matches"].is_null()
    {
        return Err("Include possible matches must be true or false.".into());
    }
    if !filter["schema_version"].is_null() && filter["schema_version"] != 1 {
        return Err("Invalid vendor/product schema version.".into());
    }
    let rows = filter["rows"]
        .as_array()
        .ok_or("Vendor/product rows must be a list.")?;
    if rows.len() > 500 {
        return Err("Vendor/product filter must contain at most 500 rows.".into());
    }
    if filter["enabled"] == true && rows.is_empty() {
        return Err("Enabled vendor/product filter requires at least one row.".into());
    }
    let mut total = 0;
    for (i, row) in rows.iter().enumerate() {
        if !row.is_object() {
            return Err(format!("Row {} must be an object.", i + 2));
        }
        if let Some(number) = row.get("row_number")
            && !number
                .as_u64()
                .is_some_and(|n| (2..=1_048_577).contains(&n))
        {
            return Err(format!("Row {} row_number is invalid.", i + 2));
        }
        for field in ["vendor", "product"] {
            let s = row[field]
                .as_str()
                .ok_or_else(|| format!("Row {} {field} is required.", i + 2))?
                .trim();
            if s.chars().count() > 200 || !known(&key(s)) {
                return Err(format!(
                    "Row {} {field} must contain a usable identity.",
                    i + 2
                ));
            }
            total += s.chars().count();
        }
        for field in ["vendor_aliases", "product_aliases"] {
            let aliases: &[Value] = if let Some(items) = row[field].as_array() {
                items
            } else if row[field].is_null() {
                &[]
            } else {
                return Err(format!("Row {} {field} must be a list.", i + 2));
            };
            if aliases.len() > 10 {
                return Err(format!(
                    "Row {} {field} must contain at most 10 aliases.",
                    i + 2
                ));
            }
            for alias in aliases {
                let s = alias
                    .as_str()
                    .ok_or_else(|| format!("Row {} {field} contains a non-text alias.", i + 2))?;
                if s.chars().count() > 200 || !known(&key(s)) {
                    return Err(format!("Row {} {field} contains an invalid alias.", i + 2));
                }
                total += s.chars().count();
            }
        }
    }
    if total > 100_000 {
        return Err("Vendor/product filter text is too large.".into());
    }
    Ok(())
}

pub fn classify(document: &Value, filter: &Value) -> Option<Value> {
    if filter["enabled"] != true {
        return None;
    }
    let rows = filter["rows"].as_array()?;
    let pairs = structured_pairs(document);
    let segments = segments(document);
    let complete = pairs
        .iter()
        .any(|(_, v, p)| known(&vendor_key(v)) && known(&key(p)));
    for (i, row) in rows.iter().enumerate() {
        let vk = identity(row, "vendor", "vendor_aliases", true);
        let pk = identity(row, "product", "product_aliases", false);
        for (source, v, p) in &pairs {
            if vk.contains(&vendor_key(v)) && pk.contains(&key(p)) {
                return Some(
                    json!({"confidence":"confirmed","matched_vendor":row["vendor"],"matched_product":row["product"],"row_number":row["row_number"].as_u64().unwrap_or((i+2) as u64),"evidence":{"type":"structured_pair","source":source,"vendor":v,"product":p}}),
                );
            }
        }
        if !complete {
            for (source, segment) in &segments {
                let sk = key(segment);
                if vk.iter().any(|v| contains(&sk, v)) && pk.iter().any(|p| contains(&sk, p)) {
                    return Some(
                        json!({"confidence":"probable","matched_vendor":row["vendor"],"matched_product":row["product"],"row_number":row["row_number"].as_u64().unwrap_or((i+2) as u64),"evidence":{"type":"fallback_segment","source":source,"text":segment}}),
                    );
                }
            }
        }
    }
    if filter["include_possible_matches"] != true
        || pairs.iter().any(|(_, v, _)| known(&vendor_key(v)))
    {
        return None;
    }
    let mut owners: HashMap<String, HashSet<String>> = HashMap::new();
    let all_vendor_keys: Vec<String> = rows
        .iter()
        .flat_map(|row| identity(row, "vendor", "vendor_aliases", true))
        .collect();
    for row in rows {
        for product in identity(row, "product", "product_aliases", false) {
            owners
                .entry(product)
                .or_default()
                .insert(vendor_key(str_value(&row["vendor"])));
        }
    }
    for (i, row) in rows.iter().enumerate() {
        let products: Vec<String> = identity(row, "product", "product_aliases", false)
            .into_iter()
            .filter(|p| distinctive(p) && owners.get(p).is_some_and(|v| v.len() == 1))
            .collect();
        let own_vendor_keys = identity(row, "vendor", "vendor_aliases", true);
        for (source, _, product) in &pairs {
            if products.contains(&key(product)) {
                return Some(
                    json!({"confidence":"possible","matched_vendor":row["vendor"],"matched_product":row["product"],"row_number":row["row_number"].as_u64().unwrap_or((i+2) as u64),"evidence":{"type":"structured_product_without_vendor","source":source,"product":product}}),
                );
            }
        }
        for (source, segment) in &segments {
            let sk = key(segment);
            if products.iter().any(|p| contains(&sk, p))
                && !all_vendor_keys
                    .iter()
                    .filter(|v| !own_vendor_keys.contains(v))
                    .any(|v| contains(&sk, v))
            {
                return Some(
                    json!({"confidence":"possible","matched_vendor":row["vendor"],"matched_product":row["product"],"row_number":row["row_number"].as_u64().unwrap_or((i+2) as u64),"evidence":{"type":"product_without_structured_vendor","source":source,"text":segment}}),
                );
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_structured_entry_is_required() {
        let filter = json!({"enabled":true,"rows":[{"vendor":"Acme","product":"Widget","vendor_aliases":[],"product_aliases":[]}]});
        let crossed = json!({"details":{"affected":[{"vendor":"Acme","product":"Different"},{"vendor":"Other","product":"Widget"}]}});
        assert!(classify(&crossed, &filter).is_none());
        let matched = json!({"details":{"affected":[{"vendor":"Acme, Inc.","product":"Widget"}]}});
        assert_eq!(
            classify(&matched, &filter).unwrap()["confidence"],
            "confirmed"
        );
    }
}
