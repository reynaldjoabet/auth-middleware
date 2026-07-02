BEGIN;

CREATE SCHEMA IF NOT EXISTS auth;
CREATE EXTENSION IF NOT EXISTS citext;

-- ---------------------------------------------------------------------------
-- updated_at maintenance trigger
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION auth.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE auth.users (
    id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    username               citext      NOT NULL,
    email                  citext,
    email_confirmed        boolean     NOT NULL DEFAULT false,
    phone_number           text,
    phone_number_confirmed boolean     NOT NULL DEFAULT false,
    -- Hashed credentials only -- never store plaintext.
    password_hash          text,
    -- Bumped to invalidate existing sessions/tokens on credential change.
    security_stamp         uuid        NOT NULL DEFAULT gen_random_uuid(),
    -- Optimistic concurrency token.
    concurrency_stamp      uuid        NOT NULL DEFAULT gen_random_uuid(),
    two_factor_enabled     boolean     NOT NULL DEFAULT false,
    lockout_enabled        boolean     NOT NULL DEFAULT true,
    lockout_end            timestamptz,
    access_failed_count    integer     NOT NULL DEFAULT 0,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT users_access_failed_count_nonneg CHECK (access_failed_count >= 0)
);

CREATE UNIQUE INDEX users_username_key ON auth.users (username);
CREATE UNIQUE INDEX users_email_key    ON auth.users (email) WHERE email IS NOT NULL;

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON auth.users
    FOR EACH ROW EXECUTE FUNCTION auth.set_updated_at();

COMMENT ON TABLE auth.users IS 'Application user accounts.';
COMMENT ON COLUMN auth.users.security_stamp IS 'Rotated to invalidate issued security tokens/sessions.';

-- ---------------------------------------------------------------------------
-- roles
-- ---------------------------------------------------------------------------
CREATE TABLE auth.roles (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name              citext      NOT NULL,
    concurrency_stamp uuid        NOT NULL DEFAULT gen_random_uuid(),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX roles_name_key ON auth.roles (name);

CREATE TRIGGER roles_set_updated_at
    BEFORE UPDATE ON auth.roles
    FOR EACH ROW EXECUTE FUNCTION auth.set_updated_at();

-- ---------------------------------------------------------------------------
-- user_roles  (many-to-many)
-- ---------------------------------------------------------------------------
CREATE TABLE auth.user_roles (
    user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES auth.roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX user_roles_role_id_idx ON auth.user_roles (role_id);

-- ---------------------------------------------------------------------------
-- user_claims / role_claims
-- ---------------------------------------------------------------------------
CREATE TABLE auth.user_claims (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     uuid        NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    claim_type  text        NOT NULL,
    claim_value text
);

CREATE INDEX user_claims_user_id_idx ON auth.user_claims (user_id);

CREATE TABLE auth.role_claims (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_id     uuid        NOT NULL REFERENCES auth.roles (id) ON DELETE CASCADE,
    claim_type  text        NOT NULL,
    claim_value text
);

CREATE INDEX role_claims_role_id_idx ON auth.role_claims (role_id);

-- ---------------------------------------------------------------------------
-- external_logins  (OAuth / OIDC provider links)
-- ---------------------------------------------------------------------------
CREATE TABLE auth.external_logins (
    provider              text NOT NULL,
    provider_key          text NOT NULL,
    provider_display_name text,
    user_id               uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    PRIMARY KEY (provider, provider_key)
);

CREATE INDEX external_logins_user_id_idx ON auth.external_logins (user_id);

-- ---------------------------------------------------------------------------
-- user_tokens  (provider-issued tokens: refresh, recovery, etc.)
-- ---------------------------------------------------------------------------
CREATE TABLE auth.user_tokens (
    user_id  uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    provider text NOT NULL,
    name     text NOT NULL,
    value    text,
    PRIMARY KEY (user_id, provider, name)
);

-- ---------------------------------------------------------------------------
-- passkeys  (WebAuthn credential records)
--   One row per registered authenticator credential.
--   See: https://www.w3.org/TR/webauthn-3/#credential-record
-- ---------------------------------------------------------------------------
CREATE TABLE auth.passkeys (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            uuid        NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,

    -- Raw WebAuthn credential id; globally unique, spec-capped at 1023 bytes.
    credential_id      bytea       NOT NULL,

    -- COSE-encoded public key used to verify assertion signatures.
    public_key         bytea       NOT NULL,

    -- Authenticator signature counter (uint32). Strictly increasing per use;
    -- a non-increasing value on assertion signals possible credential cloning.
    sign_count         bigint      NOT NULL DEFAULT 0,

    -- AuthenticatorTransport values: usb | nfc | ble | internal | hybrid | smart-card.
    transports         text[]      NOT NULL DEFAULT '{}',

    -- Authenticator flag state captured at registration / refreshed on use.
    is_user_verified   boolean     NOT NULL DEFAULT false,
    is_backup_eligible boolean     NOT NULL DEFAULT false,
    is_backed_up       boolean     NOT NULL DEFAULT false,

    -- Raw artifacts retained from the registration ceremony (audit / re-verify).
    attestation_object bytea       NOT NULL,
    client_data_json   bytea       NOT NULL,

    -- User-facing friendly name (e.g. "iPhone", "YubiKey 5").
    name               text,

    created_at         timestamptz NOT NULL DEFAULT now(),
    last_used_at       timestamptz,

    CONSTRAINT passkeys_credential_id_unique     UNIQUE (credential_id),
    CONSTRAINT passkeys_credential_id_length     CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    CONSTRAINT passkeys_sign_count_uint32        CHECK (sign_count BETWEEN 0 AND 4294967295),
    -- BS may only be set if BE is set (WebAuthn backup state invariant).
    CONSTRAINT passkeys_backup_state_valid       CHECK (is_backup_eligible OR NOT is_backed_up),
    CONSTRAINT passkeys_transports_valid CHECK (
        transports <@ ARRAY['usb','nfc','ble','internal','hybrid','smart-card']::text[]
    )
);

CREATE INDEX passkeys_user_id_idx ON auth.passkeys (user_id);

COMMENT ON TABLE auth.passkeys IS 'WebAuthn/FIDO2 credential records (passkeys).';
COMMENT ON COLUMN auth.passkeys.credential_id IS 'Raw WebAuthn credential id; unique across all users.';
COMMENT ON COLUMN auth.passkeys.sign_count   IS 'Authenticator signature counter; non-increase on use implies possible cloning.';

COMMIT;
