use futures::TryStreamExt;
use mongodb::{
    Collection, Database,
    bson::{self, Document, oid::ObjectId},
};
use serde_json::{Value, json};

pub fn object_id(value: &str) -> Option<ObjectId> {
    ObjectId::parse_str(value).ok()
}
pub fn bson_json(document: &Document) -> Value {
    serde_json::to_value(document).unwrap_or(json!({}))
}
pub fn json_doc(value: &Value) -> Result<Document, String> {
    bson::to_document(value).map_err(|e| e.to_string())
}
pub fn collection(db: &Database, name: &str) -> Collection<Document> {
    db.collection::<Document>(name)
}
pub async fn find_one(
    db: &Database,
    name: &str,
    filter: Document,
) -> Result<Option<Document>, mongodb::error::Error> {
    collection(db, name).find_one(filter).await
}
pub async fn find_many(
    db: &Database,
    name: &str,
    filter: Document,
    limit: i64,
) -> Result<Vec<Document>, mongodb::error::Error> {
    let mut cursor = collection(db, name).find(filter).limit(limit).await?;
    let mut rows = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        rows.push(doc);
    }
    Ok(rows)
}
pub async fn find_sorted(
    db: &Database,
    name: &str,
    filter: Document,
    sort: Document,
    limit: i64,
) -> Result<Vec<Document>, mongodb::error::Error> {
    let mut cursor = collection(db, name)
        .find(filter)
        .sort(sort)
        .limit(limit)
        .await?;
    let mut rows = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        rows.push(doc);
    }
    Ok(rows)
}
pub fn string(doc: &Document, key: &str) -> String {
    doc.get_str(key).unwrap_or("").to_owned()
}
pub fn bool_field(doc: &Document, key: &str) -> bool {
    doc.get_bool(key).unwrap_or(false)
}
pub fn id_string(doc: &Document) -> String {
    doc.get_object_id("_id")
        .map(|id| id.to_hex())
        .unwrap_or_else(|_| doc.get_str("_id").unwrap_or("").to_owned())
}
pub fn public_id(mut value: Value) -> Value {
    if let Some(id) = value
        .get("_id")
        .and_then(|v| v.get("$oid"))
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        value["id"] = Value::String(id);
        value.as_object_mut().unwrap().remove("_id");
    }
    value
}
