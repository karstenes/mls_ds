// @generated automatically by Diesel CLI.

diesel::table! {
    clients (client_id) {
        client_id -> Uuid,
        client_identity -> Bytea,
        registration_timestamp -> Timestamptz,
        public_key -> Jsonb,
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
    }
}

diesel::table! {
    key_packages (key_package_id) {
        key_package_id -> Uuid,
        client_id -> Uuid,
        key_package_data -> Bytea,
        publication_timestamp -> Timestamptz,
        is_active -> Bool,
    }
}

diesel::table! {
    messages (message_id) {
        message_id -> Int8,
        group_id -> Bytea,
        sender_client_id -> Nullable<Uuid>,
        message_data -> Bytea,
        sent_timestamp -> Timestamptz,
        epoch -> Int8,
    }
}

diesel::joinable!(key_packages -> clients (client_id));

diesel::allow_tables_to_appear_in_same_query!(
    clients,
    group_members,
    groups,
    key_packages,
    messages,
);
