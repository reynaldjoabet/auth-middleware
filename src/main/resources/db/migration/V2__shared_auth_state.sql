-- Shared auth state for `app.store.backend = postgres`: the Postgres
-- counterparts of the Redis keys revoked:jti:*, dpop:jti:* and dpop:nonce:*.
-- See app.infra.postgres.PostgresStores.
--
-- Every row carries its own expiry. Reads treat an expired row as absent, so
-- correctness never depends on the sweeper; the sweeper only reclaims space.
--
-- The tables are ordinary (logged) tables, so their rows are replicated and
-- survive a crash or failover. That is the durability Redis without
-- persistence does not give: a restarted Redis forgets every revocation.

-- ---------------------------------------------------------------------------
-- revoked_tokens: access tokens rejected before they expire
-- ---------------------------------------------------------------------------
CREATE TABLE auth.revoked_tokens (
    jti        text        PRIMARY KEY,
    -- The token's own expiry: past it the token is rejected anyway.
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX revoked_tokens_expires_at_idx ON auth.revoked_tokens (expires_at);

COMMENT ON TABLE auth.revoked_tokens IS 'Revocation denylist, keyed by the access token jti.';

-- ---------------------------------------------------------------------------
-- dpop_spent_jtis: DPoP proofs already accepted (RFC 9449 §11.1)
-- ---------------------------------------------------------------------------
CREATE TABLE auth.dpop_spent_jtis (
    jti        text        PRIMARY KEY,
    expires_at timestamptz NOT NULL
);

-- BRIN, not btree: only the sweeper reads it, and a btree here would be one
-- more index to update on every insert. expires_at rises with insertion
-- order, which is what BRIN summarises well, and it stays a few pages in size.
CREATE INDEX dpop_spent_jtis_expires_at_idx ON auth.dpop_spent_jtis USING brin (expires_at);

COMMENT ON TABLE auth.dpop_spent_jtis IS 'Single-use set of DPoP proof jtis; one insert per DPoP request.';

-- ---------------------------------------------------------------------------
-- dpop_nonces: single-use server nonces (RFC 9449 §8), nonce mode `redis`
-- ---------------------------------------------------------------------------
CREATE TABLE auth.dpop_nonces (
    nonce      text        PRIMARY KEY,
    expires_at timestamptz NOT NULL
);

CREATE INDEX dpop_nonces_expires_at_idx ON auth.dpop_nonces USING brin (expires_at);

COMMENT ON TABLE auth.dpop_nonces IS 'Outstanding single-use DPoP nonces; deleted when used.';

-- The two DPoP tables take an insert (and, for nonces, a delete) per request.
-- The global autovacuum thresholds are a fraction of the table size, which
-- lets dead tuples from that churn pile up; vacuum these after a fixed count.
ALTER TABLE auth.dpop_spent_jtis SET (
    autovacuum_vacuum_scale_factor        = 0,
    autovacuum_vacuum_threshold           = 10000,
    autovacuum_vacuum_insert_scale_factor = 0,
    autovacuum_vacuum_insert_threshold    = 10000
);

ALTER TABLE auth.dpop_nonces SET (
    autovacuum_vacuum_scale_factor        = 0,
    autovacuum_vacuum_threshold           = 10000,
    autovacuum_vacuum_insert_scale_factor = 0,
    autovacuum_vacuum_insert_threshold    = 10000
);
