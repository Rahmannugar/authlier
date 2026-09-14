CREATE TABLE IF NOT EXISTS authlier_users (
    id varchar(36) PRIMARY KEY,
    email varchar(320) NOT NULL UNIQUE,
    email_verified boolean NOT NULL DEFAULT false,
    webauthn_handle varbinary(64) NOT NULL UNIQUE,
    created_at datetime(6) NOT NULL
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_password_credentials (
    user_id varchar(36) PRIMARY KEY,
    password_hash text NOT NULL,
    updated_at datetime(6) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES authlier_users(id) ON DELETE CASCADE
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_google_identities (
    provider_subject varchar(255) PRIMARY KEY,
    user_id varchar(36) NOT NULL,
    email varchar(320) NOT NULL,
    linked_at datetime(6) NOT NULL,
    INDEX authlier_google_identities_user_idx (user_id),
    FOREIGN KEY (user_id) REFERENCES authlier_users(id) ON DELETE CASCADE
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_email_verifications (
    user_id varchar(36) PRIMARY KEY,
    email varchar(320) NOT NULL,
    token_hash binary(32) NOT NULL UNIQUE,
    created_at datetime(6) NOT NULL,
    expires_at datetime(6) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES authlier_users(id) ON DELETE CASCADE
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_password_resets (
    user_id varchar(36) PRIMARY KEY,
    email varchar(320) NOT NULL,
    token_hash binary(32) NOT NULL UNIQUE,
    created_at datetime(6) NOT NULL,
    expires_at datetime(6) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES authlier_users(id) ON DELETE CASCADE
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_sessions (
    token_hash binary(32) PRIMARY KEY,
    subject_id varchar(255) NOT NULL,
    created_at datetime(6) NOT NULL,
    expires_at datetime(6) NOT NULL,
    extended_at datetime(6),
    revoked_at datetime(6),
    INDEX authlier_sessions_subject_idx (subject_id, created_at DESC)
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_access_sessions (
    id varchar(255) PRIMARY KEY,
    subject_id varchar(255) NOT NULL,
    created_at datetime(6) NOT NULL,
    expires_at datetime(6) NOT NULL,
    revoked_at datetime(6)
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_refresh_tokens (
    token_hash binary(32) PRIMARY KEY,
    session_id varchar(255) NOT NULL,
    created_at datetime(6) NOT NULL,
    expires_at datetime(6) NOT NULL,
    rotated_at datetime(6),
    revoked_at datetime(6),
    INDEX authlier_refresh_tokens_session_idx (session_id),
    FOREIGN KEY (session_id) REFERENCES authlier_access_sessions(id) ON DELETE CASCADE
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_google_challenges (
    state_hash binary(32) PRIMARY KEY,
    nonce text NOT NULL,
    code_verifier text NOT NULL,
    subject_id varchar(255) NOT NULL DEFAULT '',
    created_at datetime(6) NOT NULL,
    expires_at datetime(6) NOT NULL
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_oidc_challenges (
    state_hash binary(32) PRIMARY KEY,
    connection_id varchar(255) NOT NULL,
    issuer text NOT NULL,
    client_id text NOT NULL,
    redirect_url text NOT NULL,
    scopes json NOT NULL,
    require_verified_email boolean NOT NULL,
    nonce text NOT NULL,
    code_verifier text NOT NULL,
    created_at datetime(6) NOT NULL,
    expires_at datetime(6) NOT NULL
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_saml_requests (
    state_hash binary(32) PRIMARY KEY,
    connection_id varchar(255) NOT NULL,
    connection_hash binary(32) NOT NULL,
    request_id varchar(255) NOT NULL,
    created_at datetime(6) NOT NULL,
    expires_at datetime(6) NOT NULL
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_totp_enrollments (
    subject_id varchar(255) PRIMARY KEY,
    encrypted_secret blob NOT NULL,
    created_at datetime(6) NOT NULL,
    expires_at datetime(6) NOT NULL
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_totp_credentials (
    subject_id varchar(255) PRIMARY KEY,
    encrypted_secret blob NOT NULL,
    enabled_at datetime(6) NOT NULL,
    last_used_counter bigint unsigned,
    disabled_at datetime(6)
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_totp_recovery_codes (
    subject_id varchar(255) NOT NULL,
    code_hash binary(32) NOT NULL,
    used_at datetime(6),
    PRIMARY KEY (subject_id, code_hash),
    FOREIGN KEY (subject_id) REFERENCES authlier_totp_credentials(subject_id) ON DELETE CASCADE
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_totp_challenges (
    token_hash binary(32) PRIMARY KEY,
    subject_id varchar(255) NOT NULL,
    created_at datetime(6) NOT NULL,
    expires_at datetime(6) NOT NULL,
    consumed_at datetime(6)
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_passkey_credentials (
    credential_id varbinary(1024) PRIMARY KEY,
    subject_id varchar(36) NOT NULL,
    credential json NOT NULL,
    created_at datetime(6) NOT NULL,
    updated_at datetime(6) NOT NULL,
    INDEX authlier_passkey_credentials_subject_idx (subject_id),
    FOREIGN KEY (subject_id) REFERENCES authlier_users(id) ON DELETE CASCADE
);
-- authlier:split
CREATE TABLE IF NOT EXISTS authlier_passkey_ceremonies (
    token_hash binary(32) PRIMARY KEY,
    ceremony_type varchar(32) NOT NULL,
    subject_id varchar(255) NOT NULL DEFAULT '',
    session_data json NOT NULL,
    created_at datetime(6) NOT NULL,
    expires_at datetime(6) NOT NULL,
    consumed_at datetime(6)
);
