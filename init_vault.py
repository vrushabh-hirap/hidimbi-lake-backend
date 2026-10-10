#!/usr/bin/env python3
"""
backend_lake/init_vault.py

Applies the Vault schema, roles and grants to a PostgreSQL database that has
NOT been initialised.

Render's Managed PostgreSQL does not run /docker-entrypoint-initdb.d, so the
compose-style init never happens. The Lake container carries this script and
its entrypoint runs it before starting uvicorn, which means the database
initialises itself the first time the service boots.

It is fully idempotent: safe to run on every deploy, and re-running never
consumes a flag row or changes an existing team's epoch.
"""

import os
import sys

import psycopg2

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = os.path.join(HERE, "vault_schema.sql")

# Everything the runtime roles may do. Ordered deliberately: every REVOKE
# runs before every GRANT, otherwise the blanket "REVOKE ALL ON ALL FUNCTIONS"
# wipes the specific grants that follow it.
GRANTS = """
-- CRITICAL: PostgreSQL grants EXECUTE to PUBLIC on every new function by
-- default. Without this revoke, EVERY role (including vault_rotator) can call
-- claim_by_selector and read a flag.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA vault FROM PUBLIC;

GRANT USAGE ON SCHEMA vault TO vault_flagger, vault_rotator;

GRANT EXECUTE ON FUNCTION vault.claim_by_selector(text, text, bytea, inet)
    TO vault_flagger;
GRANT EXECUTE ON FUNCTION vault.stub_for_team(text, text)
    TO vault_flagger;
GRANT EXECUTE ON FUNCTION vault.ensure_team_flag(text, text, bytea, integer)
    TO vault_flagger;
GRANT EXECUTE ON FUNCTION vault.log_rejection(text, text, text, text, bytea, inet)
    TO vault_flagger;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA vault TO vault_flagger;
GRANT SELECT, INSERT ON vault.flag_rejections TO vault_flagger;

GRANT EXECUTE ON FUNCTION vault.rotate(text, text, integer) TO vault_rotator;

ALTER TABLE vault.flag_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault.flag_redemptions ENABLE ROW LEVEL SECURITY;
"""

# --- the shared / non-consuming claim path ---------------------------------
# Used when HIDIMBI_TEAM_SCOPE=shared: one flag row serves every player, so
# redemptions are audited here instead of in flag_redemptions (which has a
# unique key that only permits one claim per instance/team/epoch).
SHARED_CLAIMS_DDL = """
CREATE TABLE IF NOT EXISTS vault.flag_shared_claims (
    id           bigserial PRIMARY KEY,
    instance_id  text NOT NULL,
    team_id      text NOT NULL,
    epoch_id     integer NOT NULL,
    selector_sha bytea NOT NULL,
    claimed_at   timestamptz NOT NULL DEFAULT now(),
    client_ip    inet
);
ALTER TABLE vault.flag_shared_claims ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON vault.flag_shared_claims FROM vault_flagger, vault_rotator, PUBLIC;
GRANT INSERT ON vault.flag_shared_claims TO vault_flagger;

CREATE OR REPLACE FUNCTION vault.claim_by_selector_shared(
    p_instance_id text, p_team_id text, p_selector bytea, p_client_ip inet DEFAULT NULL
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = vault, pg_temp
AS $$
DECLARE v_flag text; v_epoch integer;
BEGIN
    SELECT flag_value, epoch_id INTO v_flag, v_epoch
      FROM vault.flag_instances
     WHERE instance_id = p_instance_id AND team_id = p_team_id
       AND selector_sha = p_selector AND consumed = false
       AND (expires_at IS NULL OR expires_at > now())
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'SELECTOR_MISMATCH' USING ERRCODE = 'P0001';
    END IF;
    INSERT INTO vault.flag_shared_claims
        (instance_id, team_id, epoch_id, selector_sha, client_ip)
    VALUES (p_instance_id, p_team_id, v_epoch, p_selector, p_client_ip);
    RETURN v_flag;
END;
$$;
REVOKE ALL ON FUNCTION vault.claim_by_selector_shared(text,text,bytea,inet) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vault.claim_by_selector_shared(text,text,bytea,inet) TO vault_flagger;
"""

REVOKES = """
REVOKE ALL ON SCHEMA vault FROM vault_flagger, vault_rotator;
REVOKE ALL ON ALL TABLES    IN SCHEMA vault FROM vault_flagger, vault_rotator;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA vault FROM vault_flagger, vault_rotator;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA vault FROM vault_flagger, vault_rotator;
"""


def dsn() -> str:
    """Connection string for the INITIALISER.

    The initialiser must connect as the DATABASE OWNER, because it creates the
    `vault_flagger` and `vault_rotator` roles. On Render that is the user in
    your External Database URL (e.g. `hidimbi_vault_user`), which is NOT the
    same user the runtime services use. Set INIT_DB_USER / INIT_DB_PASSWORD to
    it; they fall back to the runtime DB_* values for a docker-compose-style
    deployment where the owner and the runtime user coincide.
    """
    if os.environ.get("INIT_DATABASE_URL"):
        return os.environ["INIT_DATABASE_URL"]
    return (
        f"host={os.environ.get('DB_HOST', 'vault')} "
        f"port={os.environ.get('DB_PORT', '5432')} "
        f"dbname={os.environ.get('DB_NAME', 'hidimbi_vault')} "
        f"user={os.environ.get('INIT_DB_USER', os.environ.get('DB_USER', 'vault_flagger'))} "
        f"password={os.environ.get('INIT_DB_PASSWORD', os.environ.get('DB_PASSWORD', ''))} "
        "connect_timeout=10"
    )


def already_initialised(cur) -> bool:
    cur.execute(
        "SELECT 1 FROM pg_namespace WHERE nspname = 'vault'")
    if not cur.fetchone():
        return False
    cur.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = 'vault' AND table_name = 'flag_instances'")
    return bool(cur.fetchone())


def main() -> int:
    runtime_pw = os.environ.get("DB_PASSWORD")
    rotator_pw = os.environ.get("ROTATOR_PASSWORD") or runtime_pw
    if not runtime_pw:
        print("[init-vault] DB_PASSWORD not set; skipping initialisation")
        return 0

    conn = None
    try:
        conn = psycopg2.connect(dsn())
    except psycopg2.Error as exc:
        # Do NOT block boot on this. The service will come up and report a
        # clean 503 per request, which is the intended fail-closed behaviour.
        print(f"[init-vault] cannot reach the database ({exc}); skipping")
        return 0

    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            if already_initialised(cur) and os.environ.get("FORCE_INIT", "0") != "1":
                print("[init-vault] already initialised; nothing to do")
                return 0

            print("[init-vault] applying schema")
            cur.execute(open(SCHEMA).read())

            print("[init-vault] setting runtime role passwords")
            cur.execute(
                "DO $$ BEGIN "
                "  IF NOT EXISTS (SELECT 1 FROM pg_roles "
                "                WHERE rolname='vault_flagger') THEN "
                "    CREATE ROLE vault_flagger LOGIN PASSWORD %s; "
                "  ELSE "
                "    ALTER ROLE vault_flagger WITH LOGIN PASSWORD %s; "
                "  END IF; "
                "  IF NOT EXISTS (SELECT 1 FROM pg_roles "
                "                WHERE rolname='vault_rotator') THEN "
                "    CREATE ROLE vault_rotator LOGIN PASSWORD %s; "
                "  ELSE "
                "    ALTER ROLE vault_rotator WITH LOGIN PASSWORD %s; "
                "  END IF; END $$;",
                (runtime_pw, runtime_pw, rotator_pw, rotator_pw))

            print("[init-vault] applying least-privilege grants")
            cur.execute(REVOKES)
            cur.execute(GRANTS)
            cur.execute(SHARED_CLAIMS_DDL)
            print("[init-vault] shared-claim path ready")

        print("[init-vault] done")
        return 0
    except psycopg2.Error as exc:
        conn.rollback()
        print(f"[init-vault] FAILED: {exc}")
        return 0            # still must not block boot
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
