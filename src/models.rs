use diesel::prelude::*;
use serde_json;
use time::PrimitiveDateTime;
use uuid::Uuid;

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::clients)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Clients {
    client_id: Uuid,
    client_identity: Vec<u8>,
    registration_timestamp: PrimitiveDateTime,
    metadata: Option<serde_json::Value>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::group_members)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct GroupMembers {
    group_id: Vec<u8>,
    client_id: Uuid,
    join_timestamp: PrimitiveDateTime,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::groups)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Groups {
    group_id: Vec<u8>,
    creator_client_id: Option<Uuid>,
    creation_timestamp: PrimitiveDateTime,
    group_name: Option<String>,
    metadata: Option<serde_json::Value>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::key_packages)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct KeyPackages {
    key_package_hash: Vec<u8>,
    client_id: Uuid,
    key_package_data: Vec<u8>,
    publication_timestamp: PrimitiveDateTime,
    protocol_version: Option<String>,
    cipher_suites: Option<serde_json::Value>,
    is_active: bool,
}
