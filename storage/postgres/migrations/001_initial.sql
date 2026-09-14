CREATE TABLE authlier_users (
    id text PRIMARY KEY,
    email text NOT NULL UNIQUE,
    email_verified boolean NOT NULL DEFAULT false,
    webauthn_handle bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL
);
-- authlier:split
CREATE TABLE authlier_password_credentials (
    user_id text PRIMARY KEY REFERENCES authlier_users(id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    updated_at timestamptz NOT NULL
);
-- authlier:split
CREATE TABLE authlier_google_identities (
    provider_subject text PRIMARY KEY,
    user_id text NOT NULL REFERENCES authlier_users(id) ON DELETE CASCADE,
    email text NOT NULL,
    linked_at timestamptz NOT NULL
);
-- authlier:split
CREATE INDEX authlier_google_identities_user_idx ON authlier_google_identities(user_id);
-- authlier:split
CREATE TABLE authlier_email_verifications (
    user_id text PRIMARY KEY REFERENCES authlier_users(id) ON DELETE CASCADE,
    email text NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
-- authlier:split
CREATE TABLE authlier_password_resets (
    user_id text PRIMARY KEY REFERENCES authlier_users(id) ON DELETE CASCADE,
    email text NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
-- authlier:split
CREATE TABLE authlier_sessions (
    token_hash bytea PRIMARY KEY,
    subject_id text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    extended_at timestamptz,
    revoked_at timestamptz
);
-- authlier:split
CREATE INDEX authlier_sessions_subject_idx ON authlier_sessions(subject_id, created_at DESC);
-- authlier:split
CREATE TABLE authlier_access_sessions (
    id text PRIMARY KEY,
    subject_id text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
-- authlier:split
CREATE TABLE authlier_refresh_tokens (
    token_hash bytea PRIMARY KEY,
    session_id text NOT NULL REFERENCES authlier_access_sessions(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    rotated_at timestamptz,
    revoked_at timestamptz
);
-- authlier:split
CREATE INDEX authlier_refresh_tokens_session_idx ON authlier_refresh_tokens(session_id);
-- authlier:split
CREATE TABLE authlier_google_challenges (
    state_hash bytea PRIMARY KEY,
    nonce text NOT NULL,
    code_verifier text NOT NULL,
    subject_id text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
-- authlier:split
CREATE TABLE authlier_oidc_challenges (
    state_hash bytea PRIMARY KEY,
    connection_id text NOT NULL,
    issuer text NOT NULL,
    client_id text NOT NULL,
    redirect_url text NOT NULL,
    scopes text[] NOT NULL,
    require_verified_email boolean NOT NULL,
    nonce text NOT NULL,
    code_verifier text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
-- authlier:split
CREATE TABLE authlier_saml_requests (
    state_hash bytea PRIMARY KEY,
    connection_id text NOT NULL,
    connection_hash bytea NOT NULL,
    request_id text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
-- authlier:split
CREATE TABLE authlier_totp_enrollments (
    subject_id text PRIMARY KEY,
    encrypted_secret bytea NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
-- authlier:split
CREATE TABLE authlier_totp_credentials (
    subject_id text PRIMARY KEY,
    encrypted_secret bytea NOT NULL,
    enabled_at timestamptz NOT NULL,
    last_used_counter bigint,
    disabled_at timestamptz
);
-- authlier:split
CREATE TABLE authlier_totp_recovery_codes (
    subject_id text NOT NULL REFERENCES authlier_totp_credentials(subject_id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    used_at timestamptz,
    PRIMARY KEY (subject_id, code_hash)
);
-- authlier:split
CREATE TABLE authlier_totp_challenges (
    token_hash bytea PRIMARY KEY,
    subject_id text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
-- authlier:split
CREATE TABLE authlier_passkey_credentials (
    credential_id bytea PRIMARY KEY,
    subject_id text NOT NULL REFERENCES authlier_users(id) ON DELETE CASCADE,
    credential jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
-- authlier:split
CREATE INDEX authlier_passkey_credentials_subject_idx ON authlier_passkey_credentials(subject_id);
-- authlier:split
CREATE TABLE authlier_passkey_ceremonies (
    token_hash bytea PRIMARY KEY,
    ceremony_type text NOT NULL,
    subject_id text NOT NULL DEFAULT '',
    session_data jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
