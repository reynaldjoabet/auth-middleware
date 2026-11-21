-- Time-ordered primary keys for new rows: uuidv7() instead of gen_random_uuid().
--
-- A v4 key is random, so each insert lands on a random leaf of the primary-key
-- btree. After every checkpoint, the first change to that leaf writes a
-- full-page image to WAL, and leaves split half-full. A v7 key starts with its
-- creation time, so inserts append to the rightmost leaf. Measured on
-- PostgreSQL 19 (50,000 single-row inserts into auth.users after a checkpoint,
-- 500,000 rows already present): full-page images 2,439 -> 78, WAL
-- 34 MB -> 20 MB, and the primary-key index 21 MB -> 17 MB at 90% leaf density
-- instead of 72%.
--
-- Only the defaults change. Existing ids keep their values, and new v7 ids sort
-- together, so inserts stay sequential.
--
-- A v7 id carries its row's creation time to the millisecond. Anywhere an id
-- is exposed (a token's `sub`, a URL), it reveals when the row was created.
--
-- security_stamp and concurrency_stamp stay gen_random_uuid(): they are
-- unguessable tokens, not keys, and no index orders them.

ALTER TABLE auth.users    ALTER COLUMN id SET DEFAULT uuidv7();
ALTER TABLE auth.roles    ALTER COLUMN id SET DEFAULT uuidv7();
ALTER TABLE auth.passkeys ALTER COLUMN id SET DEFAULT uuidv7();
