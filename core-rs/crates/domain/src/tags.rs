//! Contact tags (`bm_tags`).

use serde::Serialize;

/// A tag as returned by `/api/tags/list` and `/api/tags/all`. Field names match
/// Go's `entity.Tag` JSON. `group_name` is `"Unknown"` when the group is gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct Tag {
    pub id: i32,
    pub group_id: i32,
    pub group_name: String,
    pub name: String,
    pub create_time: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialises_with_go_field_names() {
        let tag = Tag {
            id: 1,
            group_id: 2,
            group_name: "VIP".into(),
            name: "hot".into(),
            create_time: 1_700_000_000,
        };
        let json = serde_json::to_value(&tag).expect("serialise");
        assert_eq!(
            json,
            serde_json::json!({
                "id": 1, "group_id": 2, "group_name": "VIP",
                "name": "hot", "create_time": 1_700_000_000
            })
        );
    }
}
