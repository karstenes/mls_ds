 use diesel::prelude::*;
use serde_json;
use time::PrimitiveDateTime;
use uuid::Uuid;

#[derive(Queryable, Selectable, Identifiable)]
#[diesel(primary_key(client_id))]
#[diesel(table_name = crate::schema::clients)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Client {
    pub client_id: Uuid,
    pub client_identity: Vec<u8>,
    pub registration_timestamp: PrimitiveDateTime,
    pub public_key: serde_json::Value,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::clients)]
pub struct NewClient {
    pub client_id: Uuid,
    pub client_identity: Vec<u8>,
    pub registration_timestamp: Option<PrimitiveDateTime>,
    pub public_key: serde_json::Value,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::group_members)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct GroupMembers {
    group_id: Vec<u8>,
    client_id: Uuid,
    join_timestamp: PrimitiveDateTime,
}

#[derive(Queryable, Selectable, Identifiable)]
#[diesel(primary_key(group_id))]
#[diesel(table_name = crate::schema::groups)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Group {
    group_id: Vec<u8>,
    creator_client_id: Option<Uuid>,
    creation_timestamp: PrimitiveDateTime,
    group_name: Option<String>,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::groups)]
pub struct NewGroup {
    pub group_id: Vec<u8>,
    pub creator_client_id: Option<Uuid>,
    pub creation_timestamp: Option<PrimitiveDateTime>,
    pub group_name: Option<String>,
}

#[derive(Queryable, Selectable, Associations, Identifiable)]
#[diesel(primary_key(key_package_id))]
#[diesel(belongs_to(Client))]
#[diesel(table_name = crate::schema::key_packages)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct KeyPackage {
    pub key_package_id: Uuid,
    pub client_id: Uuid,
    pub key_package_data: Vec<u8>,
    pub publication_timestamp: PrimitiveDateTime,
    pub is_active: bool,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::key_packages)]
pub struct NewKeyPackage {
    pub key_package_id: Uuid,
    pub client_id: Uuid,
    pub key_package_data: Vec<u8>,
    pub publication_timestamp: Option<PrimitiveDateTime>,
    pub is_active: bool,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::messages)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Message {
    message_id: i64,
    group_id: Vec<u8>,
    sender_client_id: Option<Uuid>,
    message_data: Vec<u8>,
    sent_timestamp: PrimitiveDateTime,
    epoch: i64,
}
