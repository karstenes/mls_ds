// @generated automatically by Diesel CLI.

diesel::table! {
    clients (client_id) {
        client_id -> Uuid,
        client_identity -> Bytea,
        registration_timestamp -> Timestamptz,
        metadata -> Nullable<Jsonb>,
    }
}

diesel::table! {
    group_members (group_id, client_id) {
        group_id -> Bytea,
        client_id -> Uuid,
        join_timestamp -> Timestamptz,
    }
}

diesel::table! {
    groups (group_id) {
        group_id -> Bytea,
        creator_client_id -> Nullable<Uuid>,
        creation_timestamp -> Timestamptz,
        group_name -> Nullable<Text>,
        metadata -> Nullable<Jsonb>,
    }
}

diesel::table! {
    key_packages (key_package_hash) {
        key_package_hash -> Bytea,
        client_id -> Uuid,
        key_package_data -> Bytea,
        publication_timestamp -> Timestamptz,
        protocol_version -> Nullable<Text>,
        cipher_suites -> Nullable<Jsonb>,
        is_active -> Bool,
    }
}

diesel::joinable!(group_members -> clients (client_id));
diesel::joinable!(group_members -> groups (group_id));
diesel::joinable!(groups -> clients (creator_client_id));
diesel::joinable!(key_packages -> clients (client_id));

diesel::allow_tables_to_appear_in_same_query!(
    clients,
    group_members,
    groups,
    key_packages,
);
