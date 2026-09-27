-- @microtoll/blind-store — the schema: the account tables, the objects and
-- their members, the share links, the mailbox drops, the live triggers and
-- the service role, as DESIGN.md §2 describes and DECISIONS.md D-33 and
-- D-35 decided.
--
-- Runs first on an empty database (the init files run in name order); an
-- app's own tables and columns go in its own later file, and may extend
-- `users` with ALTER TABLE. Postgres 13 or later
-- (gen_random_uuid() is built in).
--
-- Two structural rules apply throughout, and test/schema.test.mjs enforces
-- them against the live database:
--   - Primary keys are random UUIDs, never sequential: sequential ids leak
--     creation order exactly as timestamps do.
--   - No timestamp unless something functionally needs one. The two that
--     exist (share_links.expires_at, mailbox_drops.expires_at) exist only so
--     the sweep can delete what has expired.
-- The server never reads what these tables hold beyond the plaintext
-- columns named here; THREATMODEL.md §6 lists what they reveal.

-- #############################################################################
-- users
-- The routing public key (plaintext) is the primary key directly: it is a
-- random, unguessable 32-byte value with no identity meaning of its own, so
-- a surrogate UUID would only add an unused index. Everything a person needs
-- restored after unlock lives inside sealed_identity_blob, sealed under
-- K_master_symm, which is derived on the device from the root key and never
-- stored anywhere.
-- #############################################################################
CREATE TABLE users (
    routing_public_key      BYTEA PRIMARY KEY
        CONSTRAINT users_routing_public_key_32 CHECK (octet_length(routing_public_key) = 32),
    sealed_identity_blob    BYTEA NOT NULL,
    -- Bumped by the server when an unlock method is removed, the recovery
    -- code is rotated, or the person signs out everywhere. A trusted-device
    -- session saved under an older generation is discarded on restore and
    -- the device asks for a fresh unlock. Cooperative, not cryptographic.
    -- One low-cardinality integer, no time, no join: it says how many
    -- times, never when. Never add a *_at beside it.
    session_generation      INT NOT NULL DEFAULT 1
        CONSTRAINT users_session_generation_positive CHECK (session_generation >= 1),
    -- Compare-and-swap token for the blob, minted fresh by the client on
    -- every write. The blob is read-modify-written whole, so without this
    -- the second of two concurrent writers silently destroys the first
    -- one's changes. Random rather than a counter on purpose: a counter
    -- would be a running total of how often an account changes its settings.
    -- This says only "changed" or "not changed". Never add a *_at beside it.
    identity_blob_token     BYTEA NOT NULL DEFAULT '\x00000000000000000000000000000000'::bytea
        CONSTRAINT users_identity_blob_token_16 CHECK (octet_length(identity_blob_token) = 16)
);

-- #############################################################################
-- unlock_methods
-- One row per way a person can unwrap their root key. Deleting any one row
-- must never lock the account out: the server refuses to remove the last
-- one (account.js), and the client keeps the same rule.
--
-- Two lookup paths, by method type:
--   passkey-prf   -> WebAuthn returns credential_id directly; looked up by it.
--   recovery-code -> no discoverable id exists, so the client derives
--                    recovery_lookup_hash from the entered code under a
--                    different label from the one that derives the unwrap
--                    key. Knowing the lookup hash never helps derive the
--                    unwrap key, or the other way round.
-- #############################################################################
CREATE TABLE unlock_methods (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_routing_public_key BYTEA NOT NULL REFERENCES users(routing_public_key) ON DELETE CASCADE,
    method_type              TEXT NOT NULL CHECK (method_type IN ('passkey-prf', 'recovery-code')),
    credential_id            BYTEA UNIQUE,   -- passkey-prf only
    prf_salt                 BYTEA,          -- passkey-prf only
    pbkdf2_salt              BYTEA,          -- recovery-code only
    recovery_lookup_hash     BYTEA UNIQUE    -- recovery-code only; 32 bytes
        CONSTRAINT unlock_methods_recovery_lookup_hash_32 CHECK (recovery_lookup_hash IS NULL OR octet_length(recovery_lookup_hash) = 32),
    wrapped_root_key         BYTEA NOT NULL, -- a versioned AEAD blob: [version][iv][ciphertext+tag]
    sealed_label             BYTEA,          -- optional device/method nickname, sealed under K_master_symm
    CONSTRAINT unlock_method_fields_match_type CHECK (
        (method_type = 'passkey-prf'
            AND credential_id IS NOT NULL AND prf_salt IS NOT NULL
            AND pbkdf2_salt IS NULL AND recovery_lookup_hash IS NULL)
        OR
        (method_type = 'recovery-code'
            AND credential_id IS NULL AND prf_salt IS NULL
            AND pbkdf2_salt IS NOT NULL AND recovery_lookup_hash IS NOT NULL)
    )
);
CREATE INDEX idx_unlock_methods_owner ON unlock_methods(owner_routing_public_key);

-- #############################################################################
-- pointers
-- The account's own sealed record of something it holds a key to: the
-- object id, K_object, the epoch, its capability secrets, the app's own
-- fields. No object id column, deliberately: it is what stops the server
-- building a per-account list of objects. The consequence: deleting an
-- object cannot cascade to the pointers that name it; stale pointers are
-- discarded by the client on next use.
-- #############################################################################
CREATE TABLE pointers (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_routing_public_key BYTEA NOT NULL REFERENCES users(routing_public_key) ON DELETE CASCADE,
    sealed_pointer           BYTEA NOT NULL
);
CREATE INDEX idx_pointers_owner ON pointers(owner_routing_public_key);

-- #############################################################################
-- objects (DESIGN.md §2.1)
-- No creator identity anywhere. The plaintext columns are the coarse public
-- selector (which the app chooses at a precision it fixes), the optional
-- date window, the epoch, the two capability hashes and two flags. The
-- server indexes by (collection, selector, window) and answers a query with
-- everything matching, filtered by nothing else: the client decrypts what
-- it holds keys for, and the rest is the cover traffic the model relies on.
-- #############################################################################
CREATE TABLE objects (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection             TEXT NOT NULL CHECK (length(collection) BETWEEN 1 AND 32),
    selector               TEXT NOT NULL CHECK (length(selector) BETWEEN 1 AND 64),
    window_start           DATE,
    window_end             DATE,
    sealed_content         BYTEA NOT NULL,   -- sealed under K_object
    -- The second tier, nullable: sealed under a key that is NOT K_object and
    -- never derived from it, so a share-link holder cannot read it.
    sealed_detail          BYTEA,
    key_epoch              INT NOT NULL DEFAULT 1 CHECK (key_epoch >= 1),
    -- SHA-256 of a per-object random secret, replaced on every rotation.
    admin_capability_hash  BYTEA NOT NULL
        CONSTRAINT objects_admin_capability_hash_32 CHECK (octet_length(admin_capability_hash) = 32),
    -- SHA-256 of a secret DERIVED from K_object, so every legitimate holder
    -- of the key can recompute it and nothing has to be distributed. Gates
    -- reading the member list. Rotation necessarily changes it, which is
    -- what locks a removed member -- who still holds the old K_object -- out.
    read_capability_hash   BYTEA NOT NULL
        CONSTRAINT objects_read_capability_hash_32 CHECK (octet_length(read_capability_hash) = 32),
    -- The engine only ever writes 'active'. A host that needs to hide an
    -- object sets any other value from its own code: every engine read path
    -- then serves it as not found, and every admin action refuses it.
    status                 TEXT NOT NULL DEFAULT 'active' CHECK (length(status) BETWEEN 1 AND 32),
    -- When true, the member list needs a ROW capability -- proof of having
    -- a row -- rather than the read capability every key holder can derive.
    -- One accepted low-cardinality bit.
    roster_members_only    BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT objects_window_both_or_neither CHECK ((window_start IS NULL) = (window_end IS NULL)),
    CONSTRAINT objects_window_valid CHECK (window_end IS NULL OR window_end >= window_start)
);
CREATE INDEX idx_objects_selector ON objects(collection, selector, window_start, window_end);

-- #############################################################################
-- object_members
-- One row per member: their sealed row (signed by them, sealed under
-- K_object) and their copy of K_object sealed to their own key. No identity
-- column and no reference to users, by design: the server cannot say who
-- is a member of what. A row is addressed by its capability hash.
-- #############################################################################
CREATE TABLE object_members (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    object_id             UUID NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    sealed_row            BYTEA NOT NULL,   -- sealed under K_object
    sealed_object_key     BYTEA NOT NULL,   -- K_object sealed to this member's key (ECIES v3, or v2 hybrid)
    row_capability_hash   BYTEA NOT NULL
        CONSTRAINT object_members_row_capability_hash_32 CHECK (octet_length(row_capability_hash) = 32),
    key_epoch             INT NOT NULL CHECK (key_epoch >= 1),
    status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed_by_admin', 'left'))
);
CREATE INDEX idx_object_members_object ON object_members(object_id);

-- #############################################################################
-- share_links
-- A sealed payload filed under the SHA-256 hex of a token that only ever
-- appears in a URL fragment. No owner and no object id: the server cannot
-- say whose link it is or what it opens.
-- #############################################################################
CREATE TABLE share_links (
    hashed_token           TEXT PRIMARY KEY CHECK (hashed_token ~ '^[0-9a-f]{64}$'),
    sealed_payload         BYTEA NOT NULL,
    max_uses               INT NOT NULL DEFAULT 1 CHECK (max_uses >= 1)
        CONSTRAINT share_links_max_uses_bounded CHECK (max_uses <= 200),
    use_count              INT NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    -- Required, and at most 400 days out (limits.js INVITE_MAX_DAYS). A link
    -- used up or past this has its payload emptied, and is deleted a week
    -- after it, by blind_store_sweep() below.
    expires_at             TIMESTAMPTZ NOT NULL,
    -- SHA-256 of a random secret kept only in the creator's own pointer.
    -- Gates revoking a link and reading its use count. It cannot be the
    -- hashed token itself: everyone who RECEIVED the link knows the token,
    -- and gating on that would let any recipient revoke a link for everyone.
    manage_capability_hash BYTEA NOT NULL
        CONSTRAINT share_links_manage_capability_hash_32 CHECK (octet_length(manage_capability_hash) = 32),
    CONSTRAINT share_links_use_count_within_limit CHECK (use_count <= max_uses)
);
CREATE INDEX idx_share_links_expires ON share_links (expires_at);

-- #############################################################################
-- mailbox_drops
-- Pairwise dead-drop mailboxes: opaque rows under opaque labels. The label
-- is derived from a shared secret only the two parties can compute, so the
-- server can neither attribute a row nor guess a label, and the bundle is
-- sealed to the recipient on top. No created_at: it would be a correlation
-- key, and `consumed` already carries the only state anyone needs.
-- #############################################################################
CREATE TABLE mailbox_drops (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mailbox_id     BYTEA NOT NULL CHECK (octet_length(mailbox_id) = 32),
    sealed_bundle  BYTEA NOT NULL,
    consumed       BOOLEAN NOT NULL DEFAULT FALSE,
    -- Required: deleted once past by blind_store_sweep(); until then a
    -- consumed row -- its bundle already emptied -- is the sender's record
    -- that it was collected.
    expires_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_mailbox_drops_mailbox ON mailbox_drops(mailbox_id);
CREATE INDEX idx_mailbox_drops_expires ON mailbox_drops (expires_at);

-- #############################################################################
-- rate_limit_counters
-- The one table that writes a routing key beside an action a person took.
-- It records that the key did the action today, never its object: nothing
-- here links to any other row. A documented trade (THREATMODEL.md §6).
-- Rows older than two days are deleted by blind_store_sweep().
-- #############################################################################
CREATE TABLE rate_limit_counters (
    routing_key BYTEA NOT NULL,
    action      TEXT  NOT NULL,
    day         DATE  NOT NULL,
    count       INT   NOT NULL DEFAULT 0,
    PRIMARY KEY (routing_key, action, day)
);
CREATE INDEX idx_rate_limit_day ON rate_limit_counters (day);

-- #############################################################################
-- blind_store_sweep() (D-35). Empties the
-- payload of every share link used up or past its expiry, deletes a link a
-- week after its expiry, a mailbox drop once past its expiry, and rate
-- counters older than two days. Objects are never swept: what to keep is
-- the app's decision. Returns how many rows it changed. The library runs it
-- at start and every hour.
-- #############################################################################
CREATE OR REPLACE FUNCTION blind_store_sweep() RETURNS INT LANGUAGE plpgsql AS $$
DECLARE
    v_total INT := 0;
    v_n INT;
BEGIN
    UPDATE share_links SET sealed_payload = ''::bytea
     WHERE (use_count >= max_uses OR expires_at < now()) AND octet_length(sealed_payload) > 0;
    GET DIAGNOSTICS v_n = ROW_COUNT; v_total := v_total + v_n;
    DELETE FROM share_links WHERE expires_at < now() - interval '7 days';
    GET DIAGNOSTICS v_n = ROW_COUNT; v_total := v_total + v_n;
    DELETE FROM mailbox_drops WHERE expires_at < now();
    GET DIAGNOSTICS v_n = ROW_COUNT; v_total := v_total + v_n;
    DELETE FROM rate_limit_counters WHERE day < current_date - 2;
    GET DIAGNOSTICS v_n = ROW_COUNT; v_total := v_total + v_n;
    RETURN v_total;
END;
$$;
REVOKE ALL ON FUNCTION blind_store_sweep() FROM PUBLIC;

-- #############################################################################
-- Live updates (DESIGN.md §2.3). Fires pg_notify('blind_store_object_live',
-- <json>) on every change another viewer needs to see: an object created,
-- edited, deleted, hidden or re-sealed by a rotation, and any change to a
-- member row.
--
-- The payload carries the routing selector -- collection, selector and
-- window -- rather than only the id, because the server routes live updates
-- to connections by exactly the selector they already sent with their query.
-- That is the whole point: the server decides who to notify WITHOUT ever
-- learning which objects belong to which account. prev* carries the
-- pre-update selector so an object that moves still reaches the viewers
-- watching where it used to be. Content never rides in the payload: the
-- server re-reads the row (pg_notify's payload is capped at 8,000 bytes,
-- and a re-read is the only way to send the current state).
--
-- Row-level and undebounced: one rotation updates object_members once per
-- remaining member, and collapsing that is the live hub's job (live.js).
-- #############################################################################
CREATE FUNCTION notify_object_live() RETURNS TRIGGER AS $$
DECLARE
    v_kind       TEXT;
    v_id         UUID;
    v_collection TEXT;
    v_selector   TEXT;
    v_start      DATE;
    v_end        DATE;
    v_prev_sel   TEXT := NULL;
    v_prev_start DATE := NULL;
    v_prev_end   DATE := NULL;
BEGIN
    IF TG_TABLE_NAME = 'objects' THEN
        IF TG_OP = 'DELETE' THEN
            v_kind       := 'deleted';
            v_id         := OLD.id;
            v_collection := OLD.collection;
            v_selector   := OLD.selector;
            v_start      := OLD.window_start;
            v_end        := OLD.window_end;
        ELSE
            -- An object that is already hidden has nothing to say to a live
            -- viewer: nobody can fetch it, so an update to it must not be
            -- broadcast as though it were still there.
            IF NEW.status <> 'active' AND (TG_OP = 'INSERT' OR OLD.status <> 'active') THEN
                RETURN NULL;
            END IF;
            v_kind := CASE WHEN TG_OP = 'INSERT' THEN 'created' ELSE 'updated' END;
            -- active -> hidden is reported as 'deleted': from every viewer's
            -- side that is exactly what happened, and 'deleted' is the kind a
            -- client already handles by dropping the item.
            IF TG_OP = 'UPDATE' AND OLD.status = 'active' AND NEW.status <> 'active' THEN
                v_kind := 'deleted';
            END IF;
            v_id         := NEW.id;
            v_collection := NEW.collection;
            v_selector   := NEW.selector;
            v_start      := NEW.window_start;
            v_end        := NEW.window_end;
            IF TG_OP = 'UPDATE' THEN
                v_prev_sel   := OLD.selector;
                v_prev_start := OLD.window_start;
                v_prev_end   := OLD.window_end;
            END IF;
        END IF;
    ELSE
        -- object_members has no selector of its own; the object carries one.
        v_kind := 'participation';
        v_id   := NEW.object_id;
        -- Hidden objects are filtered here as well: a member row can still
        -- change underneath one, and routing that would tell watchers there
        -- is activity on an object none of them can open.
        SELECT o.collection, o.selector, o.window_start, o.window_end
          INTO v_collection, v_selector, v_start, v_end
          FROM objects o WHERE o.id = v_id AND o.status = 'active';
        IF v_selector IS NULL THEN
            RETURN NULL;
        END IF;
    END IF;

    PERFORM pg_notify('blind_store_object_live', json_build_object(
        'id',              v_id,
        'kind',            v_kind,
        'collection',      v_collection,
        'selector',        v_selector,
        'windowStart',     to_char(v_start, 'YYYY-MM-DD'),
        'windowEnd',       to_char(v_end,   'YYYY-MM-DD'),
        'prevSelector',    v_prev_sel,
        'prevWindowStart', to_char(v_prev_start, 'YYYY-MM-DD'),
        'prevWindowEnd',   to_char(v_prev_end,   'YYYY-MM-DD')
    )::text);

    RETURN NULL; -- AFTER trigger: the return value is ignored either way
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_objects_live
    AFTER INSERT OR UPDATE OR DELETE ON objects
    FOR EACH ROW EXECUTE FUNCTION notify_object_live();

CREATE TRIGGER trg_object_members_live
    AFTER INSERT OR UPDATE ON object_members
    FOR EACH ROW EXECUTE FUNCTION notify_object_live();

-- #############################################################################
-- Mailbox wake-up. Fires pg_notify('blind_store_mailbox_live', <mailbox_id
-- hex>) whenever a drop lands, so a recipient's open session collects it at
-- once instead of on its next unlock. The payload is the label and nothing
-- else: the label is already the only thing the server sees about a drop,
-- so routing on it adds nothing. INSERT only: `consumed` flipping is the
-- recipient's own acknowledgement and needs no push.
-- #############################################################################
CREATE FUNCTION notify_mailbox_live() RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('blind_store_mailbox_live', encode(NEW.mailbox_id, 'hex'));
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_mailbox_drops_live
    AFTER INSERT ON mailbox_drops
    FOR EACH ROW EXECUTE FUNCTION notify_mailbox_live();

-- #############################################################################
-- The service role (D-35). The server connects as this
-- role, never as the owner of the schema: it can read and write the eight
-- tables above and run the sweep, and nothing else -- no DDL, no other
-- roles, no other schema. NOLOGIN here: the deployment gives it a login and
-- a password from a secret file (packages/blind-store/schema/900_app_login.sh), never this
-- file, and the tests do the same on their throwaway database.
-- #############################################################################
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'blind_store_app') THEN
    CREATE ROLE blind_store_app NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION;
  END IF;
END $$;
COMMENT ON ROLE blind_store_app IS
  'The blind-store server. Reads and writes its own eight tables and runs the sweep; no DDL, no other roles, no other schema.';

GRANT USAGE ON SCHEMA public TO blind_store_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, unlock_methods, pointers, objects, object_members,
  share_links, mailbox_drops, rate_limit_counters TO blind_store_app;
GRANT EXECUTE ON FUNCTION blind_store_sweep() TO blind_store_app;
