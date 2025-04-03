CREATE TABLE clients (
    client_id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    client_identity BYTEA UNIQUE NOT NULL,
    registration_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW (),
    metadata JSONB NULL -- Optional application-specific data
);

CREATE INDEX idx_clients_identity ON clients (client_identity);

COMMENT ON TABLE clients IS 'Stores information about each registered client or identity.';

COMMENT ON COLUMN clients.client_identity IS 'Application-specific unique identifier (e.g., public key hash, username bytes). Must be unique.';

COMMENT ON COLUMN clients.metadata IS 'Optional application-specific data in JSON format.';

CREATE TABLE groups (
    group_id BYTEA PRIMARY KEY,
    creator_client_id UUID NULL,
    creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW (),
    group_name TEXT NULL,
    metadata JSONB NULL,
    CONSTRAINT fk_groups_creator_client FOREIGN KEY (creator_client_id) REFERENCES clients (client_id) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE INDEX idx_groups_creator_client_id ON groups (creator_client_id);

COMMENT ON TABLE groups IS 'Stores basic information about MLS groups.';

COMMENT ON COLUMN groups.group_id IS 'MLS Group ID, often arbitrary bytes. Primary Key.';

COMMENT ON COLUMN groups.creator_client_id IS 'Client who created the group. Foreign key to clients table.';

COMMENT ON COLUMN groups.group_name IS 'Optional application-level friendly name for the group.';

COMMENT ON COLUMN groups.metadata IS 'Optional application-specific group data in JSON format.';

CREATE TABLE key_packages (
    key_package_hash BYTEA PRIMARY KEY,
    client_id UUID NOT NULL,
    key_package_data BYTEA NOT NULL,
    publication_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW (),
    protocol_version TEXT NULL,
    cipher_suites JSONB NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT fk_key_packages_client FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX idx_key_packages_client_id ON key_packages (client_id);

CREATE INDEX idx_key_packages_publication_timestamp ON key_packages (publication_timestamp DESC);

CREATE INDEX idx_key_packages_is_active ON key_packages (is_active)
WHERE
    is_active = TRUE;

COMMENT ON TABLE key_packages IS 'Stores the MLS Key Packages published by clients.';

COMMENT ON COLUMN key_packages.key_package_hash IS 'Primary Key. A hash of the key_package_data can be used to ensure uniqueness.';

COMMENT ON COLUMN key_packages.client_id IS 'The client who published this key package. Foreign key to clients table.';

COMMENT ON COLUMN key_packages.key_package_data IS 'The raw MLS KeyPackage bytes.';

COMMENT ON COLUMN key_packages.publication_timestamp IS 'Timestamp when the key package was published/uploaded.';

COMMENT ON COLUMN key_packages.cipher_suites IS 'Optional: Supported cipher suites (storing as JSONB for flexibility).';

COMMENT ON COLUMN key_packages.is_active IS 'Flag to indicate if the key package is currently considered valid/active.';

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

COMMENT ON TABLE group_members IS 'Models the many-to-many relationship between clients and groups (membership).';

COMMENT ON COLUMN group_members.group_id IS 'References the group. Part of the composite primary key.';

COMMENT ON COLUMN group_members.client_id IS 'References the client member. Part of the composite primary key.';

COMMENT ON COLUMN group_members.join_timestamp IS 'Timestamp when the client joined the group.';
