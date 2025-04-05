DROP INDEX idx_clients_identity;

DROP INDEX idx_groups_creator_client_id;

DROP INDEX idx_key_packages_client_id;

DROP INDEX idx_key_packages_publication_timestamp;

DROP INDEX idx_key_packages_is_active;

DROP INDEX idx_group_members_group_id;

DROP INDEX idx_group_members_client_id;

DROP INDEX idx_messages_group_id;

DROP INDEX idx_messages_sender_client_id;

DROP INDEX idx_messages_sent_timestamp;

DROP INDEX idx_messages_group_epoch;

DROP INDEX idx_messages_group_timestamp;

DROP TABLE message;

DROP TABLE group_members;

DROP TABLE key_packages;

DROP TABLE groups;

DROP TABLE clients;