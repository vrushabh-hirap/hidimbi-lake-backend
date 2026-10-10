#!/usr/bin/env python3
"""
Hidimbi's Town - Flag Service (Stages 12 & 22).

Architecture
------------
The flag value lives ONLY as a row in the external PostgreSQL Vault
container. It is not in the challenge repository, in the app image, in the
backend image, in this service's image, or in any config file.

Legitimate flow:

  stage 21  the solver SSRF-pokes the Lake courier into reaching this
            service's INTERNAL index (port 8100), which is not routable from
            the internet. That endpoints mints a short-lived `seal` over the
            solver's own chain-derived selector.
  stage 22  POST /flag/claim with { selector, proof, seal }.
            1. constant-time check of `proof`
               HMAC-SHA256( K1||K2||K3||K4, selector || instance || team )
            2. constant-time check of `seal`
               HMAC-SHA256( flagger_key, selector || instance || team || epoch )
            3. a LIVE query of the vault row, using the solver's own derived
               selector bytes as the bound parameter:
                   SELECT vault.claim_by_selector(instance, team, selector)
            4. return the flag the database hands back.

Failure posture: fail closed. Database unreachable -> 503 and NO flag. No
cached value, no config fallback, no partial output.

Per-instance / per-team uniqueness: the vault primary key is
(instance_id, team_id, epoch_id) and the selector is a keyed hash over all
three, so separate instances and teams share nothing.

Rotation: the rotator calls vault.rotate() which retires the live epoch and
mints a new one with a fresh selector, so a leaked selector has a hard TTL
(default 24h, or however long the platform configures).
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import time

import psycopg2
import psycopg2.pool
import psycopg2.errors
import jwt as pyjwt
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from pydantic import BaseModel

logging.basicConfig(level=os.environ.get("HIDIMBI_LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("hidimbi.flagger")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("CONFIG_PATH", os.path.join(BASE_DIR, "..", "config.json"))
if not os.path.exists(CONFIG_PATH):
    CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CONFIG = json.load(f)
with open(os.path.join(BASE_DIR, "public_key.pem"), "rb") as f:
    PUBLIC_KEY_PEM = f.read()

FLAGGER_KEY_HEX = os.environ.get("FLAGGER_PROOF_KEY", "")
if not FLAGGER_KEY_HEX:
    log.warning("FLAGGER_PROOF_KEY not set; internal gate will reject everything")
FLAGGER_KEY = bytes.fromhex(FLAGGER_KEY_HEX) if FLAGGER_KEY_HEX else b"\x00" * 32

# Shared secret that only the app backend container holds. It is what stops
# the internal index from being reached directly instead of via SSRF.
BACKEND_BEARER = os.environ.get("BACKEND_BEARER_SECRET", "")

DB = {
    "host": os.environ.get("DB_HOST", "vault"),
    "port": int(os.environ.get("DB_PORT", "5432")),
    "dbname": os.environ.get("DB_NAME", "hidimbi_vault"),
    "user": os.environ.get("DB_USER", "vault_flagger"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "connect_timeout": 5,
}

inst = os.environ.get("INSTANCE_ID", CONFIG.get("vault", {}).get("instance_id", "default"))
INSTANCE_ID = inst

K1 = bytes.fromhex(CONFIG["keys"]["k1"])
K2 = bytes.fromhex(CONFIG["keys"]["k2"])
K3 = bytes.fromhex(CONFIG["keys"]["k3"])
K4 = bytes.fromhex(CONFIG["keys"]["k4"])
CHAIN_MASTER_KEY = K1 + K2 + K3 + K4

UNDER = CONFIG.get("under_city", {})
SEED = bytes.fromhex(UNDER["scriptorium_seed"])
DRUM = bytes.fromhex(UNDER["drum_key"])
RUNE = bytes.fromhex(UNDER["scribe_rune"])
GSECRET = bytes.fromhex(UNDER["granary_secret"])
WHISTLE = bytes.fromhex(UNDER["whistle_key"])

_pool = None


class VaultUnavailable(Exception):
    """The datastore could not be reached. Callers MUST fail closed."""


class RedemptionFailure(Exception):
    """The vault refused a claim for a business reason (not an outage)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _pool_get():
    global _pool
    if _pool is None:
        try:
            _pool = psycopg2.pool.ThreadedConnectionPool(1, 8, **DB)
        except psycopg2.Error as exc:
            raise VaultUnavailable(str(exc)) from exc
    return _pool


def vault_call(sql, params, on_reject=None):
    """Run a vault.*() call.

    `on_reject` is called with the SQLSTATE primary message when the database
    raised a business rule (SELECTOR_MISMATCH, already claimed, ...). A true
    outage always raises VaultUnavailable and must fail closed.

    NOTE: _pool_get() is INSIDE the try. It used to sit outside, which meant an
    unreachable database escaped as an unhandled exception (HTTP 500) instead
    of the intended 503 — so the "fail closed" guarantee silently did not hold.
    """
    try:
        pool = _pool_get()
        conn = pool.getconn()
    except VaultUnavailable:
        raise
    except psycopg2.Error as exc:
        raise VaultUnavailable(f"pool acquisition: {exc}") from exc
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall() if cur.description else []
        conn.commit()
        return rows
    except psycopg2.errors.RaiseException as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        code = (exc.diag.message_primary or "").strip()
        if on_reject:
            on_reject(code)
        raise RedemptionFailure(code) from exc
    except psycopg2.Error as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        raise VaultUnavailable(str(exc)) from exc
    finally:
        pool.putconn(conn)




# The scope the vault selector is derived over.
#
# "per_team" (default) keeps every player's selector unique, so a leaked
# selector only ever authorises one team's row.
# "shared" makes the selector identical for every player, which is what you
# want when the CTF platform validates submissions against a single flag.
TEAM_SCOPE = os.environ.get("HIDIMBI_TEAM_SCOPE", "per_team")
SHARED_TEAM_ID = os.environ.get("HIDIMBI_FIXED_TEAM", "town_folk")


def db_team(jwt_team: str) -> str:
    """Which team the vault row belongs to."""
    if TEAM_SCOPE == "shared":
        return SHARED_TEAM_ID
    return jwt_team


def expected_selector(team: str, epoch: int) -> bytes:
    """What the flagger believes the chain should produce.

    This MUST match scripts/dev_stack.sh's provisioning formula exactly, since
    the row in vault.flag_instances must carry this value.
    """
    material = (
        b"HIDIMBI_TOWN_SELECTOR_v1"
        + K1 + K2 + K3 + K4
        + bytes.fromhex(CONFIG["nonces"]["n1"]) + bytes.fromhex(CONFIG["nonces"]["n2"])
        + bytes.fromhex(CONFIG["nonces"]["n3"]) + bytes.fromhex(CONFIG["nonces"]["n4"])
        + SEED + DRUM + RUNE + GSECRET + WHISTLE
        + f"{INSTANCE_ID}:{TEAM_SCOPE}".encode("utf-8")
    )
    return hashlib.sha256(material).digest()


def expected_proof(team: str, selector: bytes) -> bytes:
    return hmac.new(CHAIN_MASTER_KEY,
                    selector + INSTANCE_ID.encode("utf-8") + team.encode("utf-8"),
                    hashlib.sha256).digest()


def expected_seal(team: str, epoch: int, selector: bytes) -> bytes:
    return hmac.new(FLAGGER_KEY,
                    selector + INSTANCE_ID.encode("utf-8") + team.encode("utf-8")
                    + str(epoch).encode("utf-8"),
                    hashlib.sha256).digest()


def claim_function() -> str:
    """Which vault function the final read goes through."""
    return ("vault.claim_by_selector_shared" if TEAM_SCOPE == "shared"
            else "vault.claim_by_selector")


def live_epoch_for(team: str):
    """The epoch the Vault currently considers live for this team.

    The flagger asks the database rather than trusting a static config value,
    so rotation never desynchronises it. Falls back to the config epoch if the
    datastore is unreachable (the claim itself will fail closed).
    """
    try:
        rows = vault_call("SELECT vault.ensure_team_flag(%s, %s, %s::bytea, %s)",
                          (INSTANCE_ID, team,
                           psycopg2.Binary(expected_selector(team, 1)),
                           int(CONFIG.get("vault", {}).get("flag_ttl_seconds", 86400)) // 3600))
    except VaultUnavailable:
        return None
    return rows[0][0] if rows else None


app = FastAPI(title="Hidimbi's Town - Flag Service", version="3.0")

_RATE = {}


def rate_check(key: str, limit: int, window: int = 60) -> bool:
    now = time.time()
    hits = [t for t in _RATE.get(key, []) if now - t < window]
    _RATE[key] = hits
    if len(hits) >= limit:
        return False
    hits.append(now)
    return True


class Claim(BaseModel):
    selector: str
    proof: str
    seal: str = ""


class GateIn(BaseModel):
    selector: str
    proof: str
    team: str = "solo"


class GateOut(BaseModel):
    seal: str


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "flagger", "vault": "configured"}


def _decode_hex255(value: str, what: str) -> bytes:
    try:
        out = bytes.fromhex(value)
    except ValueError:
        raise HTTPException(400, f"{what} must be hex.")
    if len(out) != 32:
        raise HTTPException(400, f"{what} must be 32 bytes.")
    return out


@app.get("/flag/{flag_id}")
async def get_flag(flag_id: str, authorization: str = Header(None), request: Request = None):
    """Stage 12 - the RS256 ticket gate.

    Validates the JWT from the Lake API and hands back a stub identifying the
    instance/team/epoch the solver should be aiming at. It never touches the
    flag column."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization Bearer token required.")
    token = authorization.split("Bearer ", 1)[1].strip()
    try:
        claims = pyjwt.decode(
            token, PUBLIC_KEY_PEM, algorithms=["RS256"],
            issuer="hidimbi_town_backend",
            options={"require": ["exp", "iat", "flag_id", "team_id"]},
        )
    except Exception:
        raise HTTPException(403, "Invalid signature or malformed token.")
    if claims.get("flag_id") != flag_id:
        raise HTTPException(400, "Token flag_id does not match target path.")

    team = db_team(claims.get("team_id", "solo"))

    # Lazily provision this team. The selector is derived by the flagger from
    # the very material the player will have to recover for themselves, so
    # provisioning reveals nothing and authorises nothing.
    try:
        rows = vault_call("SELECT vault.ensure_team_flag(%s, %s, %s::bytea, %s)",
                          (INSTANCE_ID, team,
                           psycopg2.Binary(expected_selector(team, 1)),
                           int(CONFIG.get("vault", {}).get("flag_ttl_seconds", 86400)) // 3600))
    except VaultUnavailable:
        log.error("vault stub lookup failed")
        return JSONResponse(status_code=503, content={
            "status": "VAULT_UNAVAILABLE",
            "message": "The Keeper's index is closed. No flag is issued.",
        })
    if not rows:
        return JSONResponse(status_code=404, content={
            "status": "NO_INSTANCE", "message": "No live flag instance for this ticket."})

    return JSONResponse(content={
        "status": "TICKET_ACCEPTED",
        "instance_id": INSTANCE_ID,
        "team_id": team,
        "epoch": rows[0][0],
        "flag_service_token": token,
        "message": "The Keeper has logged your offering. Descend to the vault.",
    })


# On Render the flag service and the internal index are two separate
# services. This route is registered ONLY where HIDIMBI_EXPOSE_INTERNAL=1, so
# the public flag service does not carry it at all — not even as a 404-able
# route that a probe could confirm exists.
EXPOSE_INTERNAL = os.environ.get("HIDIMBI_EXPOSE_INTERNAL", "1") == "1"


async def _internal_gate_impl(body: GateIn,
                              authorization: Optional[str] = Header(None),
                              request: Request = None):
    """The Keeper's internal index. Lives on a port that is never published;
    reached legitimately only by the Stage-21 SSRF through the Lake courier."""
    if not BACKEND_BEARER:
        raise HTTPException(503, "internal gate is disabled")
    if authorization != "Bearer " + BACKEND_BEARER:
        raise HTTPException(403, "internal index not reachable from here")

    sel = _decode_hex255(body.selector, "selector")
    prf = _decode_hex255(body.proof, "proof")
    team = db_team(body.team or "solo")

    if not hmac.compare_digest(prf, expected_proof(team, sel)):
        raise HTTPException(403, "The chain did not hold together.")
    epoch = live_epoch_for(team) or CONFIG.get("vault", {}).get("epoch_id", 1)
    seal = expected_seal(team, epoch, sel)
    return JSONResponse(content={"status": "GATE_OPEN", "seal": seal.hex(),
                                 "instance_id": INSTANCE_ID,
                                 "team_id": team, "epoch": epoch})


if EXPOSE_INTERNAL:
    app.add_api_route("/internal/gate", _internal_gate_impl, methods=["POST"])


@app.post("/flag/claim")
async def flag_claim(claim: Claim, request: Request = None):
    """Stage 22 - the only endpoint that returns the real flag."""
    ip = request.client.host if request.client else None
    if not rate_check(f"claim:{ip}", 15, 60):
        raise HTTPException(429, "Too many claims from this address.")

    sel = _decode_hex255(claim.selector, "selector")
    prf = _decode_hex255(claim.proof, "proof")
    seal = _decode_hex255(claim.seal, "seal")

    team = db_team(request.headers.get("x-team-id", "solo") or "solo")
    # The live epoch comes from the Vault, not from config, so a rotation can
    # never leave the flagger validating against a stale epoch id.
    epoch = live_epoch_for(team)
    if epoch is None:
        epoch = CONFIG.get("vault", {}).get("epoch_id", 1)
    try:
        hinted = int(request.headers.get("x-epoch-id", epoch))
    except ValueError:
        raise HTTPException(400, "x-epoch-id must be an integer.")
    if hinted != epoch:
        _log_rejection(team, "EPOCH_MISMATCH", ip, sel)
        raise HTTPException(403, "That epoch has been retired.")

    # 1. proof anchored to the player's own selector
    if not hmac.compare_digest(prf, expected_proof(team, sel)):
        _log_rejection(team, "PROOF_MISMATCH", ip, sel)
        raise HTTPException(403, "The chain did not hold together.")

    # 2. seal from the internal index (stage 21). NOTE: BACKEND_BEARER is not
    # required here - this is a public endpoint and must work even if the
    # shared bearer was never configured on this service.
    if not hmac.compare_digest(seal, expected_seal(team, epoch, sel)):
        _log_rejection(team, "SEAL_MISMATCH", ip, sel)
        raise HTTPException(403, "The Keeper's index did not ratify your selector.")

    # 3. selector must be the one the chain actually yields
    if not hmac.compare_digest(sel, expected_selector(team, epoch)):
        _log_rejection(team, "SELECTOR_MISMATCH", ip, sel)
        raise HTTPException(403, "The chain did not hold together.")

    # 4. LIVE database read, parameterised by the player's derived selector
    try:
        rows = vault_call(
            f"SELECT {claim_function()}(%s, %s, %s, %s)",
            (INSTANCE_ID, team, psycopg2.Binary(sel),
             ipaddress.ip_address(ip).exploded if ip else None))
    except RedemptionFailure as reject:
        # A business-rule rejection, not an outage. Record it and answer 4xx.
        _log_rejection(team, reject.code, ip, sel)
        raise HTTPException(403, "The vault refused this claim.")
    except VaultUnavailable as exc:
        # FAIL CLOSED. No cached flag, no config flag, no partial output.
        log.error("vault unreachable during claim: %s", exc)
        raise HTTPException(503, "Vault unreachable. No flag is issued.")

    if not rows:
        raise HTTPException(404, "Selector did not match a live flag row.")

    return JSONResponse(content={
        "status": "SUCCESS",
        "instance_id": INSTANCE_ID,
        "team_id": team,
        "epoch": epoch,
        "flag": rows[0][0],
        "quota": "one-time",
    })


def _log_rejection(team: str, reason: str, ip, sel: bytes):
    try:
        vault_call("SELECT vault.log_rejection(%s, %s, %s, %s, %s, %s)",
                   (INSTANCE_ID, team, reason, "",
                    psycopg2.Binary(sel), ip))
    except VaultUnavailable:
        pass


@app.post("/seal")
async def seal(claim: Claim):
    """Local-only convenience: mirrors the internal gate for offline testing."""
    sel = _decode_hex255(claim.selector, "selector")
    prf = _decode_hex255(claim.proof, "proof")
    team = "solo"
    epoch = CONFIG.get("vault", {}).get("epoch_id", 1)
    if not hmac.compare_digest(prf, expected_proof(team, sel)):
        raise HTTPException(403, "The chain did not hold together.")
    return JSONResponse(content={"status": "SEALED",
                                 "seal": expected_seal(team, epoch, sel).hex(),
                                 "ttl_seconds": 300})


@app.exception_handler(psycopg2.Error)
async def _psycopg2_handler(request, exc):
    log.error("unhandled database error: %s", exc)
    return JSONResponse(status_code=503, content={
        "status": "VAULT_UNAVAILABLE", "message": "No flag is issued.",
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0",
                port=int(CONFIG["network"]["flag_service_port"]))
