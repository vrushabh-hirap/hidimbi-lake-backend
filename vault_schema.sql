-- ---------------------------------------------------------------------------
-- Hidimbi's Town — Vault schema (external datastore).
--
-- PostgreSQL 15+. The flag value exists ONLY as a row in this table, in this
-- container. It is never present in config.json, in the app image, in the
-- backend image, in the flag-service image, or in the challenge repository.
--
-- The row is selected by a 32-byte "vault selector" that only a complete
-- exploitation chain (stages 1-22) can derive. The flagger never inserts,
-- updates or chooses the selector — it only *recomputes* it for validation
-- and then uses the player's own derived bytes as the bound parameter of the
-- SELECT that reads the row.
-- ---------------------------------------------------------------------------


-- ---------------------------------------------------------------------------
-- Roles. Created first so the grants in init_vault.py can reference them.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('vault_owner',   'own'),
        ('vault_flagger', 'r'),
        ('vault_rotator', 'rw')
    ) AS t(role_name, mode)
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r.role_name) THEN
            EXECUTE format('CREATE ROLE %I', r.role_name);
        END IF;
    END LOOP;
END
$$;

CREATE SCHEMA IF NOT EXISTS vault;

-- pgcrypto lives INSIDE the vault schema, because every function below runs
-- with a restricted search_path and needs gen_random_bytes().
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA vault;

-- Flag instances. One row per (instance, team, epoch). Rotation inserts a new
-- epoch row and expires the old one; the selector is recomputed from the new
-- epoch id so old links stop authorising reads.
CREATE TABLE IF NOT EXISTS vault.flag_instances (
    instance_id    text        NOT NULL,
    team_id        text        NOT NULL,
    epoch_id       integer     NOT NULL DEFAULT 1,
    selector_sha   bytea       NOT NULL,
    flag_value     text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz,
    consumed       boolean     NOT NULL DEFAULT false,
    consumed_at    timestamptz,

    CONSTRAINT flag_instances_pkey PRIMARY KEY (instance_id, team_id, epoch_id),
    CONSTRAINT selector_is_32_bytes  CHECK (octet_length(selector_sha) = 32),
    CONSTRAINT flag_value_kctf        CHECK (flag_value LIKE 'KCTF{%}')
);

-- Exactly one live (unconsumed, unexpired) row per team.
CREATE UNIQUE INDEX IF NOT EXISTS flag_instances_live_unique
    ON vault.flag_instances (instance_id, team_id)
    WHERE consumed = false AND expires_at IS NULL;

CREATE INDEX IF NOT EXISTS flag_instances_selector_idx
    ON vault.flag_instances (selector_sha);

-- One-time redemption ledger. A selector may only be used once.
CREATE TABLE IF NOT EXISTS vault.flag_redemptions (
    instance_id    text        NOT NULL,
    team_id        text        NOT NULL,
    epoch_id       integer     NOT NULL,
    selector_sha   bytea       NOT NULL,
    redeemed_at    timestamptz NOT NULL DEFAULT now(),
    client_ip      inet,
    PRIMARY KEY (instance_id, team_id, epoch_id)
);

-- Audit of rejected attempts (auth failures, wrong selector, bad proof).
CREATE TABLE IF NOT EXISTS vault.flag_rejections (
    id             bigserial   PRIMARY KEY,
    instance_id    text,
    team_id        text,
    reason         text        NOT NULL,
    detail         text,
    selector_sha   bytea,
    client_ip      inet,
    attempted_at   timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Provisioning. Runs as the owner, once per instance/team.
-- ---------------------------------------------------------------------------

-- salt is the 32-byte per-instance secret from config.json; the selector is a
-- real keyed derivation over the full chain material so it cannot be
-- guessed, replayed or inferred from any single stage output.
CREATE OR REPLACE FUNCTION vault.provision(
    p_instance_id  text,
    p_team_id      text,
    p_salt         bytea,
    p_epoch_id     integer DEFAULT 1,
    p_ttl_hours    integer DEFAULT 24
) RETURNS bytea
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
AS $$
DECLARE
    v_flag   text;
    v_sel    bytea;
    v_alphabet text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    v_i integer;
BEGIN
    -- 12 uppercase alphanumeric characters, drawn from pgcrypto's CSPRNG.
    v_flag := 'KCTF{HIDIMBI_TOWN_';
    FOR v_i IN 1..12 LOOP
        v_flag := v_flag || substr(
            v_alphabet, (get_byte(gen_random_bytes(4), 0) %
                         length(v_alphabet)) + 1, 1);
    END LOOP;
    v_flag := v_flag || '}';

    v_sel := digest(
        p_instance_id || ':' || p_team_id || ':' || p_epoch_id::text || ':' ||
        encode(p_salt, 'hex'), 'sha256');

    INSERT INTO vault.flag_instances
        (instance_id, team_id, epoch_id, selector_sha, flag_value, expires_at)
    VALUES
        (p_instance_id, p_team_id, p_epoch_id, v_sel, v_flag,
         CASE WHEN p_ttl_hours > 0
              THEN now() + make_interval(hours => p_ttl_hours)
              ELSE NULL END)
    ON CONFLICT (instance_id, team_id, epoch_id) DO NOTHING;

    RETURN v_sel;
END;
$$;

-- ---------------------------------------------------------------------------
-- Rotation. Called by the rotator; old epochs are retired so a leaked
-- selector from a previous epoch stops authorising reads.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION vault.rotate(
    p_instance_id text,
    p_team_id     text,
    p_ttl_hours   integer DEFAULT 24
) RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
AS $$
DECLARE
    v_epoch integer;
BEGIN
    UPDATE vault.flag_instances
       SET expires_at = now(), consumed = CASE WHEN consumed THEN true ELSE false END
     WHERE instance_id = p_instance_id AND team_id = p_team_id
       AND expires_at IS NULL;

    SELECT COALESCE(MAX(epoch_id), 0) INTO v_epoch
      FROM vault.flag_instances
     WHERE instance_id = p_instance_id AND team_id = p_team_id;

    INSERT INTO vault.flag_instances (instance_id, team_id, epoch_id, selector_sha,
                                      flag_value, expires_at)
    SELECT instance_id, team_id, v_epoch + 1, selector_sha, flag_value,
           CASE WHEN p_ttl_hours > 0
                THEN now() + make_interval(hours => p_ttl_hours) ELSE NULL END
      FROM vault.flag_instances
     WHERE instance_id = p_instance_id AND team_id = p_team_id
       AND epoch_id = v_epoch;

    RETURN v_epoch + 1;
END;
$$;

-- ---------------------------------------------------------------------------
-- vault.provision_with_selector — provisioning with an externally supplied
-- selector (used by the deployment tooling, which derives the selector with
-- the exact same keyed SHA-256 the solver and the flagger use).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION vault.provision_with_selector(
    p_instance_id  text,
    p_team_id      text,
    p_epoch_id     integer DEFAULT 1,
    p_selector     bytea  DEFAULT NULL,
    p_ttl_hours    integer DEFAULT 24
) RETURNS bytea
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
AS $$
DECLARE
    v_flag  text;
    v_sel   bytea;
    v_salt  bytea;
BEGIN
    IF p_selector IS NOT NULL THEN
        v_sel := p_selector;
    ELSE
        SELECT vault.provision(p_instance_id, p_team_id, v_salt, p_epoch_id, p_ttl_hours)
          INTO v_sel;
        RETURN v_sel;
    END IF;

    v_flag := 'KCTF{HIDIMBI_TOWN_';
    FOR v_i IN 1..12 LOOP
        v_flag := v_flag || substr(
            'ABCDEFGHJKLMNPQRSTUVWXYZ23456789',
            (get_byte(gen_random_bytes(4), 0) % 32) + 1, 1);
    END LOOP;
    v_flag := v_flag || '}';

    INSERT INTO vault.flag_instances
        (instance_id, team_id, epoch_id, selector_sha, flag_value, expires_at)
    VALUES
        (p_instance_id, p_team_id, p_epoch_id, v_sel, v_flag,
         CASE WHEN p_ttl_hours > 0
              THEN now() + make_interval(hours => p_ttl_hours)
              ELSE NULL END)
    ON CONFLICT (instance_id, team_id, epoch_id) DO NOTHING;

    RETURN v_sel;
END;
$$;

-- ---------------------------------------------------------------------------
-- vault.stub_for_team — Stage 12's non-flag descriptor.
--
-- Returns only the instance/team/epoch metadata a solver needs to aim at.
-- It NEVER touches the flag_value column, so the flagger role does not need
-- (and does not have) SELECT on the table.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION vault.stub_for_team(
    p_instance_id text,
    p_team_id     text
) RETURNS TABLE (epoch_id integer, consumed boolean, expires_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
    SELECT f.epoch_id, f.consumed, f.expires_at
      FROM vault.flag_instances f
     WHERE f.instance_id = p_instance_id AND f.team_id = p_team_id
     ORDER BY f.epoch_id DESC
     LIMIT 1;
$$;

-- ---------------------------------------------------------------------------
-- v.log_rejection — records a rejected attempt.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vault.flag_rejections (
    id             bigserial   PRIMARY KEY,
    instance_id    text,
    team_id        text,
    reason         text        NOT NULL,
    detail         text,
    selector_sha   bytea,
    revoked        boolean     NOT NULL DEFAULT false,
    attempted_at   timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION vault.log_rejection(
    p_instance_id  text,
    p_team_id      text,
    p_reason       text,
    p_detail       text,
    p_selector     bytea DEFAULT NULL,
    p_client_ip    inet  DEFAULT NULL
) RETURNS void
LANGUAGE sql
VOLATILE
SECURITY DEFINER
AS $$
    INSERT INTO vault.flag_rejections
        (instance_id, team_id, reason, detail, selector_sha, client_ip)
    VALUES
        (p_instance_id, p_team_id, p_reason, p_detail, p_selector, p_client_ip);
$$;

-- ---------------------------------------------------------------------------
-- The single query the flag service executes.
--
-- The player's derived selector is the *bound parameter* of this read, so
-- retrieving the real flag genuinely requires a live database query whose
-- authorisation came out of the exploit chain. There is no API key, no
-- config value and no file anywhere that lets you skip it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION vault.claim_by_selector(
    p_instance_id  text,
    p_team_id      text,
    p_selector     bytea,
    p_client_ip    inet DEFAULT NULL
) RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
AS $$
DECLARE
    v_flag  text;
    v_epoch integer;
BEGIN
    IF octet_length(p_selector) <> 32 THEN
        RAISE EXCEPTION 'SELECTOR_MALFORMED' USING ERRCODE = '22023';
    END IF;

    SELECT flag_value, epoch_id INTO v_flag, v_epoch
      FROM vault.flag_instances
     WHERE instance_id = p_instance_id
       AND team_id = p_team_id
       AND selector_sha = p_selector
       AND consumed = false
       AND (expires_at IS NULL OR expires_at > now())
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'SELECTOR_MISMATCH' USING ERRCODE = 'P0001';
    END IF;

    UPDATE vault.flag_instances
       SET consumed = true, consumed_at = now()
     WHERE instance_id = p_instance_id AND team_id = p_team_id
       AND epoch_id = v_epoch;

    INSERT INTO vault.flag_redemptions
        (instance_id, team_id, epoch_id, selector_sha, client_ip)
    VALUES
        (p_instance_id, p_team_id, v_epoch, p_selector, p_client_ip);

    RETURN v_flag;
END;
$$;

-- ---------------------------------------------------------------------------
-- vault.ensure_team_flag — lazy per-team provisioning.
--
-- A player's team_id is derived from their device fingerprint, so it cannot be
-- known in advance. The flagger calls this the first time it sees a team
-- (at the Stage-12 ticket gate), passing the selector it has itself derived
-- from the chain material in its own config. That way every player gets a
-- unique flag row with no organizer intervention, while the selector still
-- only becomes usable once the whole chain has been walked.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION vault.ensure_team_flag(
    p_instance_id  text,
    p_team_id      text,
    p_selector     bytea,
    p_ttl_hours    integer DEFAULT 24
) RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = vault, pg_temp
AS $$
DECLARE
    v_epoch integer;
    v_flag  text;
BEGIN
    IF octet_length(p_selector) <> 32 THEN
        RAISE EXCEPTION 'SELECTOR_LENGTH' USING ERRCODE = '22023';
    END IF;

    -- already live for this team?
    SELECT epoch_id INTO v_epoch
      FROM vault.flag_instances
     WHERE instance_id = p_instance_id AND team_id = p_team_id
       AND consumed = false AND (expires_at IS NULL OR expires_at > now())
     ORDER BY epoch_id DESC
     LIMIT 1;

    IF v_epoch IS NOT NULL THEN
        RETURN v_epoch;
    END IF;

    -- otherwise start a fresh epoch on top of whatever exists
    SELECT epoch_id INTO v_epoch
      FROM vault.flag_instances
     WHERE instance_id = p_instance_id AND team_id = p_team_id
     ORDER BY epoch_id DESC
     LIMIT 1;

    v_flag := 'KCTF{HIDIMBI_TOWN_';
    FOR i IN 1..12 LOOP
        v_flag := v_flag || substr(
            'ABCDEFGHJKLMNPQRSTUVWXYZ23456789',
            (get_byte(gen_random_bytes(4), 0) % 32) + 1, 1);
    END LOOP;
    v_flag := v_flag || '}';

    INSERT INTO vault.flag_instances
        (instance_id, team_id, epoch_id, selector_sha, flag_value, expires_at)
    VALUES
        (p_instance_id, p_team_id, COALESCE(v_epoch, 0) + 1, p_selector, v_flag,
         CASE WHEN p_ttl_hours > 0
              THEN now() + make_interval(hours => p_ttl_hours) ELSE NULL END)
    ON CONFLICT (instance_id, team_id, epoch_id) DO UPDATE
        SET selector_sha = EXCLUDED.selector_sha,
            flag_value   = EXCLUDED.flag_value,
            expires_at   = EXCLUDED.expires_at,
            consumed     = false,
            consumed_at  = NULL;

    RETURN COALESCE(v_epoch, 0) + 1;
END;
$$;
