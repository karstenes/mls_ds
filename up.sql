CREATE TABLE clients (
    client_id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    client_identity BYTEA UNIQUE NOT NULL,
    registration_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW (),
    metadata JSONB NULL
);

CREATE INDEX idx_clients_identity ON clients (client_identity);

CREATE TABLE groups (
    group_id BYTEA PRIMARY KEY,
    creator_client_id UUID NULL,
    creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW (),
    group_name TEXT NULL,
    metadata JSONB NULL,
    CONSTRAINT fk_groups_creator_client FOREIGN KEY (creator_client_id) REFERENCES clients (client_id) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE INDEX idx_groups_creator_client_id ON groups (creator_client_id);

CREATE TABLE key_packages (
    key_package_hash BYTEA PRIMARY KEY,
    client_id UUID NOT NULL,
    key_package_data BYTEA NOT NULL,
    publication_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW (),
    protocol_version TEXT NULL,
    cipher_suites JSONB NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT fk_key_packages_client FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
);

CREATE INDEX idx_key_packages_client_id ON key_packages (client_id);

CREATE INDEX idx_key_packages_publication_timestamp ON key_packages (publication_timestamp DESC);

CREATE INDEX idx_key_packages_is_active ON key_packages (is_active)
WHERE
    is_active = TRUE;

CREATE TABLE group_members (
    group_id BYTEA NOT NULL,
    client_id UUID NOT NULL,
    join_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW (),
    PRIMARY KEY (group_id, client_id),
    CONSTRAINT fk_group_members_group FOREIGN KEY (group_id) REFERENCES groups (group_id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_group_members_client FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX idx_group_members_group_id ON group_members (group_id);

CREATE INDEX idx_group_members_client_id ON group_members (client_id);
