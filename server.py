#!/usr/bin/env python3
"""
Hidimbi's Town — Lake API (Stages 9, 10, 18-21).

Extends the original WAF-hardened Lake API with the Observatory
(JWT/HS256 signature confusion + ECC small-subgroup attack), the Keeper's
Whistle (differential timing side channel) and the Courier's Errand
(SSRF against the flag service).

Stage 12's flag lookup is proxied by the external flag service, which reads
the real flag from the external PostgreSQL Vault container.
"""

import os
import json
import time
import hmac
import hashlib
import secrets
import asyncio
import ipaddress
import socket
import urllib.request
import urllib.parse
import urllib.error
import logging
from collections import defaultdict
from typing import Optional

from fastapi import FastAPI, Request, Header, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import jwt as pyjwt
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

logging.basicConfig(level=os.environ.get("HIDIMBI_LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("hidimbi.lake")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("CONFIG_PATH", os.path.join(BASE_DIR, "..", "config.json"))
if not os.path.exists(CONFIG_PATH):
    CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CONFIG = json.load(f)

PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "private_key.pem")
with open(PRIVATE_KEY_PATH, "rb") as f:
    PRIVATE_KEY_PEM = f.read()

PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "public_key.pem")
with open(PUBLIC_KEY_PATH, "rb") as f:
    PUBLIC_KEY_PEM = f.read()

UNDER = CONFIG.get("under_city", {})
VAULT_CFG = CONFIG.get("vault", {})
NET = CONFIG.get("network", {})

# --- chain material -------------------------------------------------------
K1 = bytes.fromhex(CONFIG["keys"]["k1"])
K2 = bytes.fromhex(CONFIG["keys"]["k2"])
K3 = bytes.fromhex(CONFIG["keys"]["k3"])
K4 = bytes.fromhex(CONFIG["keys"]["k4"])
N1 = bytes.fromhex(CONFIG["nonces"]["n1"])
N2 = bytes.fromhex(CONFIG["nonces"]["n2"])
N3 = bytes.fromhex(CONFIG["nonces"]["n3"])
N4 = bytes.fromhex(CONFIG["nonces"]["n4"])
MASTER_HMAC_KEY = K1 + K2 + K3 + K4

SCRIPTORIUM_SEED = bytes.fromhex(UNDER["scriptorium_seed"])
OBSERVATORY_SALT = bytes.fromhex(UNDER["curve_nonce_seed"])
WHISTLE_KEY = bytes.fromhex(UNDER["whistle_key"])

app = FastAPI(title="Hidimbi's Town - Lake API", version="3.0.0")

RATE_LIMIT_STORE = defaultdict(list)
MAX_REQ_PER_MIN = NET.get("rate_limit_per_minute", 5)
REPLAY_WINDOW_SEC = NET.get("replay_window_seconds", 60)

# The flag service is a *separate container*. The backend reaches it over the
# internal docker network; the player cannot reach the internal port directly.
FLAGGER_HOST = os.environ.get("FLAGGER_HOST", "flagger")
FLAGGER_PORT = int(os.environ.get("FLAGGER_PORT", "8001"))
FLAGGER_INTERNAL_PORT = int(os.environ.get("FLAGGER_INTERNAL_PORT", "8100"))

BACKEND_BEARER = os.environ.get("BACKEND_BEARER_SECRET", "")


# --------------------------------------------------------------------------
class TradeRequest(BaseModel):
    node_id: int
    device_id: str
    timestamp: int
    proof: str


def derive_artifact_keys():
    salt = K1 + K2
    ikm = K3 + K4
    info = N1 + N2 + N3 + N4
    derived = HKDF(ikm, 44, salt, SHA256, 1, context=info)
    return derived[:32], derived[32:44]


def team_from_device(device_id: str) -> str:
    return device_id[:12]


# ==========================================================================
# Stage 9 / 10 — unchanged Lake trade endpoint (kept verbatim in behaviour)
# ==========================================================================
# Operations note: the rolling-window helper under ops/ is a standalone
# dashboard prototype; this route still uses RATE_LIMIT_STORE for compatibility.
@app.post("/api/v1/lake/trade")
async def lake_trade(req: TradeRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()

    timestamps = [t for t in RATE_LIMIT_STORE[client_ip] if now - t < 60]
    RATE_LIMIT_STORE[client_ip] = timestamps
    if len(timestamps) >= MAX_REQ_PER_MIN:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "Rate limit exceeded. Too many trade offerings to the Lake.")
    RATE_LIMIT_STORE[client_ip].append(now)

    ua = request.headers.get("user-agent", "")
    if ua != f"TownClient/2.0 (Device:{req.device_id})":
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "WAF: Invalid client identity or rejected user agent profile.")

    if req.node_id != 31:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "WAF: Trade rejected. Coordinates do not point to the sacred Lake.")

    if abs(now - req.timestamp) > REPLAY_WINDOW_SEC:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "WAF: Expired or future timestamp. Replay protection triggered.")

    if len(req.device_id) != 64 or not all(c in "0123456789abcdefABCDEF" for c in req.device_id):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "WAF: Malformed device fingerprint.")

    msg = f"31:{req.device_id}:{req.timestamp}:{N1.hex()}:{N2.hex()}:{N3.hex()}:{N4.hex()}"
    expected = hmac.new(MASTER_HMAC_KEY, msg.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(req.proof.lower(), expected.lower()):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid cryptographic proof.")

    flag_id = secrets.token_hex(16)
    team_id = team_from_device(req.device_id)
    now_i = int(now)

    claims = {
        "flag_id": flag_id,
        "team_id": team_id,
        "iss": "hidimbi_town_backend",
        "iat": now_i,
        "exp": now_i + 3600,
        "instance_id": VAULT_CFG.get("instance_id", "default"),
        "epoch": VAULT_CFG.get("epoch_id", 1),
    }
    ticket = pyjwt.encode(claims, PRIVATE_KEY_PEM, algorithm="RS256")

    payload = json.dumps({"flag_id": flag_id, "flag_service_token": ticket}).encode()
    aes_key, aes_iv = derive_artifact_keys()
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_iv)
    ct, tag = cipher.encrypt_and_digest(payload)
    artifact_b64 = __import__("base64").b64encode(aes_iv + tag + ct).decode()

    return JSONResponse(content={
        "status": "SACRED_OFFERING_ACCEPTED",
        "artifact": artifact_b64,
        "flag_id": flag_id,
        "team_id": team_id,
    })


# ==========================================================================
# Stage 18 — Observatory: JWKS confusion (RS256 -> HS256)
# ==========================================================================
# The Observatory publishes its key as a JWK. Historically the verification
# helper read `alg` from the token header and selected the *matching* key,
# which for HS256 is the raw PEM bytes. A solver who fetches the published
# JWK therefore forges an HS256 JWT using the PEM as the HMAC secret.
OBSERVATORY_JWK = None


def observatory_jwk():
    global OBSERVATORY_JWK
    if OBSERVATORY_JWK is None:
        from Crypto.PublicKey import RSA
        key = RSA.import_key(open(PRIVATE_KEY_PATH, "rb").read())
        n = key.n
        e = key.e
        int_to_b64 = lambda i: __import__("base64").urlsafe_b64encode(
            i.to_bytes((i.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
        OBSERVATORY_JWK = {
            "keys": [{
                "kty": "RSA", "use": "sig", "alg": "RS256",
                "kid": "hidimbi-observatory-1",
                "n": int_to_b64(n), "e": int_to_b64(e),
            }]
        }
    return OBSERVATORY_JWK


@app.get("/api/v1/observatory/jwks.json")
async def observatory_jwks():
    """Publishes the Observatory's public key.

    The Observatory's verifier trusts the `alg` in the incoming header, so an
    attacker that obtains this JWK can sign an HS256 token with the PEM as
    the secret."""
    return JSONResponse(content=observatory_jwk())


class ObservatoryLogin(BaseModel):
    token: str


@app.post("/api/v1/observatory/login")
async def observatory_login(req: ObservatoryLogin, request: Request):
    """Stage 18 — signature confusion.

    The Observatory believes it is verifying RS256. It actually accepts
    whatever `alg` the token claims, and for HS256 it uses the raw PEM bytes
    as the HMAC key. Hand it back what you gave it."""
    ip = request.client.host if request.client else "127.0.0.1"
    if len([t for t in RATE_LIMIT_STORE[f"obs:{ip}"] if time.time() - t < 60]) >= 20:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "The telescope is busy.")
    RATE_LIMIT_STORE[f"obs:{ip}"].append(time.time())

    try:
        header = pyjwt.get_unverified_header(req.token)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Malformed token.")

    alg = header.get("alg")
    claims = None
    if alg == "HS256":
        # THE BUG. The Observatory resolves the signing key from its JWKS by
        # `kid`, gets {kty: "RSA", n, e}, and then — instead of requiring an
        # RSA public key — feeds the JWK's own `n` (a base64url string) to the
        # HMAC verifier. Anyone who has fetched the published JWKS can
        # therefore sign an HS256 token with a string that is world-readable.
        jwk = observatory_jwk()["keys"][0]
        secret = jwk["n"].encode("ascii")
        try:
            claims = pyjwt.decode(req.token, secret, algorithms=["HS256"])
        except pyjwt.InvalidSignatureError:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid signature.")
    elif alg == "RS256":
        try:
            claims = pyjwt.decode(req.token, PRIVATE_KEY_PEM, algorithms=["RS256"])
        except Exception:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid signature.")
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Unsupported alg (the Observatory only speaks RS256 and HS256).")

    if claims is None or claims.get("sub") != "observatory_admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not an Observatory administrator.")

    # Issue the astronomer's session token (RS256, correctly signed).
    now_i = int(time.time())
    session = pyjwt.encode({
        "sub": "astronomer",
        "iat": now_i, "exp": now_i + 900,
        "curve_nonce": OBSERVATORY_SALT.hex(),
    }, PRIVATE_KEY_PEM, algorithm="RS256")

    return JSONResponse(content={
        "status": "ADMITTED",
        "astronomer_token": session,
        "curve_hint": "the orrery has x25519 for you",
    })


# ==========================================================================
# Stage 19 — ECC small-subgroup confinement
# ==========================================================================
CURVE_P = 2**255 - 19
CURVE_A24 = 121665
# A published point of order 4 on the twist of Curve25519. Because the
# orrery's ladder is unclamped and performs no validation, submitting this
# point collapses the shared secret to one of only two values.
TWIST_ORDER_4 = 325606250916557431795983626356110631294008115727848805560023387167927233504
ASTRONOMER_D = int.from_bytes(
    hmac.new(PRIVATE_KEY_PEM, b"hidimbi-orrery-scalar", hashlib.sha256).digest(), "big") % (2**255)


def x25519_ladder(scalar: int, u: int) -> int:
    """RFC 7748 Montgomery ladder. Left deliberately unclamped and
    unvalidated — this is the vulnerability."""
    x1 = u % CURVE_P
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in reversed(range(255)):
        k_t = (scalar >> t) & 1
        if swap ^ k_t:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t
        A = (x2 + z2) % CURVE_P
        AA = A * A % CURVE_P
        B = (x2 - z2) % CURVE_P
        BB = B * B % CURVE_P
        E = (AA - BB) % CURVE_P
        C = (x3 + z3) % CURVE_P
        D = (x3 - z3) % CURVE_P
        DA = D * A % CURVE_P
        CB = C * B % CURVE_P
        x3 = (DA + CB) ** 2 % CURVE_P
        z3 = x1 * (DA - CB) ** 2 % CURVE_P
        x2 = AA * BB % CURVE_P
        z2 = E * ((AA + CURVE_A24 * E) % CURVE_P) % CURVE_P
    return 0 if z2 == 0 else x2 * pow(z2, CURVE_P - 2, CURVE_P) % CURVE_P


class Ecdh(BaseModel):
    u: str = Field(..., description="hex point coordinate")


def astronomer_session_or_403(authorization: Optional[str]) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Astronomer token required.")
    try:
        # RS256 tokens are verified with the PUBLIC key; the private key is
        # only ever used to sign (and, via the bug below, is never readable
        # by a solver anyway).
        return pyjwt.decode(authorization.split("Bearer ", 1)[1].strip(),
                            PUBLIC_KEY_PEM, algorithms=["RS256"], audience=None)
    except Exception:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid astronomer token.")


@app.post("/api/v1/observatory/ecdh")
async def observatory_ecdh(req: Ecdh, request: Request,
                           authorization: str = Header(None)):
    """Stage 19 — small-subgroup confinement.

    Submit the order-4 twist point. The shared secret collapses into a tiny,
    enumerable set, and the resulting handshake id is the credential for
    Stage 20's whistle."""
    astronomer_session_or_403(authorization)
    ip = request.client.host if request.client else "127.0.0.1"
    if len([t for t in RATE_LIMIT_STORE[f"ec:{ip}"] if time.time() - t < 60]) >= 60:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "The orrery is spinning.")
    RATE_LIMIT_STORE[f"ec:{ip}"].append(time.time())

    try:
        u = int(req.u, 16)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "u must be hex.")

    shared = x25519_ladder(ASTRONOMER_D, u)
    handshake = hmac.new(OBSERVATORY_SALT, b"%x" % shared, hashlib.sha256).hexdigest()
    return JSONResponse(content={
        "status": "HANDSHAKE",
        "handshake": handshake,
        "hint": "the telescope sees only a few u-coordinates now",
    })


# ==========================================================================
# Stage 20 — the Keeper's Whistle (differential timing side channel)
# ==========================================================================
# Metrics schema experiments are catalogued under ops/metrics_exporter.py;
# the timing response below remains the relay's own direct measurement.
@app.post("/api/v1/observatory/whistle")
async def observatory_whistle(request: Request):
    """Differential-timing oracle on the whistle key.

    The whistle is the astronomer's slave relay: it copies the submitted key
    into a fixed buffer and reports how far the relay goes, so the delay
    reveals the number of matching leading bytes."""
    ip = request.client.host if request.client else "127.0.0.1"
    # The whistle is a timing oracle, so it MUST accept a few thousand
    # measurements or the stage is unsolvable. The bound below is still a real
    # guard: it caps the oracle at the rate a byte-wise attack needs
    # (256 * key_length * samples) plus headroom, and blocks blind spraying.
    per_min = int(os.environ.get("WHISTLE_RATE_PER_MIN", "100000"))
    if len([t for t in RATE_LIMIT_STORE[f"wh:{ip}"] if time.time() - t < 60]) >= per_min:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "The relay is hot.")
    RATE_LIMIT_STORE[f"wh:{ip}"].append(time.time())

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "JSON required.")
    # The oracle accepts a hex string; it is compared byte-wise against the
    # relay's internal key.
    raw = body.get("whistle", "")
    guess = bytes.fromhex(raw) if isinstance(raw, str) else b""
    t0 = time.perf_counter()
    matched = 0
    for i in range(len(WHISTLE_KEY)):
        if i < len(guess) and guess[i] == WHISTLE_KEY[i]:
            matched += 1
        else:
            break
    time.sleep(matched * UNDER.get("whistle_delay_us", 300) / 1_000_000.0)
    elapsed = int((time.perf_counter() - t0) * 1_000_000)

    if matched == len(WHISTLE_KEY):
        return JSONResponse(content={
            "status": "THE_WHISTLE_ANSWERS",
            "whistle_key": WHISTLE_KEY.hex(),
            "curve_secret": hmac.new(SCRIPTORIUM_SEED, WHISTLE_KEY,
                                     hashlib.sha256).hexdigest(),
            "elapsed_us": elapsed,
        })
    return JSONResponse(content={"status": "LISTENED", "matched_bytes": matched,
                                 "elapsed_us": elapsed})


# ==========================================================================
# Stage 21 — Courier's Errand (SSRF against the flag service itself)
# ==========================================================================
ALLOWED_SCHEMES = ("http",)
INTERNAL_ONLY_HOSTS = ("flagger", "vault")


def _is_internal(host: str) -> bool:
    return host in INTERNAL_ONLY_HOSTS


@app.post("/api/v1/lake/courier")
async def lake_courier(request: Request):
    """Stage 21 — SSRF.

    The Lake's courier will fetch a URL on the pilgrim's behalf, including
    internal hostnames that are not exposed to the internet."""
    ip = request.client.host if request.client else "127.0.0.1"
    if len([t for t in RATE_LIMIT_STORE[f"cour:{ip}"] if time.time() - t < 60]) >= 20:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "The courier is resting.")
    RATE_LIMIT_STORE[f"cour:{ip}"].append(time.time())

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "JSON required.")

    url = body.get("url", "")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Only http is supported.")
    if not parsed.hostname:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing host.")
    if not _is_internal(parsed.hostname):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "The courier only serves internal recipients.")

    target = f"http://{parsed.hostname}:{FLAGGER_INTERNAL_PORT}{parsed.path or '/'}"
    if parsed.query:
        target += "?" + parsed.query

    # In a Docker deployment `flagger` resolves on the internal network. For
    # local development the platform may remap the courier's recipient.
    override = os.environ.get("COURIER_INTERNAL_TARGET")
    if override:
        target = f"http://{override}{parsed.path or '/'}"
        if parsed.query:
            target += "?" + parsed.query

    payload = body.get("body")
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json",
               "X-Forwarded-By": "lake-courier"}
    if BACKEND_BEARER:
        headers["Authorization"] = "Bearer " + BACKEND_BEARER

    try:
        req = urllib.request.Request(target, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
    except Exception as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            "The courier could not reach {}: {}".format(parsed.hostname, exc))

    try:
        return JSONResponse(content=json.loads(raw.decode("utf-8")))
    except Exception:
        return JSONResponse(content={"status": "RELAYED", "body": raw.decode("utf-8", "replace")})


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "lake"}
