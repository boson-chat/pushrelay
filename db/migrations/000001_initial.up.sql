-- One row per (device, install): where a push for /v1/push/<id> goes.
CREATE TABLE mailboxes (
    id             text PRIMARY KEY,
    platform       text NOT NULL CHECK (platform IN ('apns', 'apns-sandbox', 'fcm')),
    token          text NOT NULL,
    vapid_key      text NOT NULL,
    install        text NOT NULL,
    secret_hash    bytea NOT NULL,
    paused         boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    last_used_at   timestamptz NOT NULL,
    push_day       text NOT NULL DEFAULT '',
    push_day_count integer NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX mailboxes_device_install ON mailboxes (platform, token, install);
CREATE INDEX mailboxes_install ON mailboxes (install);
CREATE INDEX mailboxes_last_used_at ON mailboxes (last_used_at);

-- Install domains the operator blocked: pushes 403, mailboxes paused.
CREATE TABLE blocked_installs (
    install    text PRIMARY KEY,
    reason     text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL
);

-- Single-use attestation challenges (GET /v1/challenge), stored hashed.
CREATE TABLE challenges (
    hash       bytea PRIMARY KEY,
    expires_at timestamptz NOT NULL
);
CREATE INDEX challenges_expires_at ON challenges (expires_at);

-- App Attest keys registered with an attestation object; assertions are
-- checked against the public key and a strictly increasing counter.
CREATE TABLE app_attest_keys (
    key_id       text PRIMARY KEY,
    public_key   bytea NOT NULL,
    counter      bigint NOT NULL,
    environment  text NOT NULL,
    created_at   timestamptz NOT NULL,
    last_used_at timestamptz NOT NULL
);
