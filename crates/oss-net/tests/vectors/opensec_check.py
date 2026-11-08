#!/usr/bin/env python3
"""Independent check of the OpenSec v1 test vectors.

Written from docs/protocol/opensec.md alone, with no code shared with the Rust
implementation: X25519 (RFC 7748), ChaCha20-Poly1305 (RFC 8439) and HKDF-SHA256
(RFC 5869) are implemented below from their RFCs, and each primitive is first
checked against the RFC's own test vectors. The script then rebuilds every
handshake and record in opensec.txt, and applies the spec's rules to every
rejected hello and every replay-window sequence.

Usage: python3 opensec_check.py [path/to/opensec.txt]
Needs only the Python 3 standard library. Slow, constant-time it is not:
this is a reference for checking, never for real traffic.

Licence: MIT (part of oss-core).
"""

import hashlib
import hmac
import struct
import sys
from pathlib import Path

# --- X25519 (RFC 7748, section 5) ----------------------------------------------

P = 2**255 - 19
A24 = 121665


def clamp(k: bytes) -> int:
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def x25519(k: bytes, u: bytes) -> bytes:
    scalar = clamp(k)
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def public_key(secret: bytes) -> bytes:
    return x25519(secret, (9).to_bytes(32, "little"))


# --- ChaCha20-Poly1305 (RFC 8439) -------------------------------------------------


def _rotl(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = (
        [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
        + list(struct.unpack("<8I", key))
        + [counter]
        + list(struct.unpack("<3I", nonce))
    )
    s = state[:]
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12)
        _quarter(s, 1, 5, 9, 13)
        _quarter(s, 2, 6, 10, 14)
        _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15)
        _quarter(s, 1, 6, 11, 12)
        _quarter(s, 2, 7, 8, 13)
        _quarter(s, 3, 4, 9, 14)
    return struct.pack("<16I", *((x + y) & 0xFFFFFFFF for x, y in zip(s, state)))


def chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i : i + 64], block))
    return bytes(out)


def poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc, p = 0, (1 << 130) - 5
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i : i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def _pad16(b: bytes) -> bytes:
    return b"\x00" * (-len(b) % 16)


def _mac_data(aad: bytes, ct: bytes) -> bytes:
    return aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))


def aead_seal(key, nonce, aad, plaintext):
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20(key, 1, nonce, plaintext)
    return ct, poly1305(otk, _mac_data(aad, ct))


def aead_open(key, nonce, aad, ct, tag):
    otk = chacha20_block(key, 0, nonce)[:32]
    if not hmac.compare_digest(poly1305(otk, _mac_data(aad, ct)), tag):
        return None
    return chacha20(key, 1, nonce, ct)


# --- HKDF-SHA256 (RFC 5869) ------------------------------------------------------


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def self_test():
    h = bytes.fromhex
    # RFC 7748 5.2 (first vector) and 6.1.
    assert x25519(
        h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ) == h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    assert public_key(a) == h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    assert x25519(a, public_key(b)) == h(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )
    # RFC 8439 2.8.2.
    key = bytes(range(0x80, 0xA0))
    msg = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
        b"for the future, sunscreen would be it."
    )
    ct, tag = aead_seal(key, h("070000004041424344454647"), h("50515253c0c1c2c3c4c5c6c7"), msg)
    assert ct[:16] == h("d31a8d34648e60db7b86afbc53ef7ec2")
    assert tag == h("1ae10b594f09e26a7e902ecbd0600691")
    # RFC 5869 test case 1.
    assert hkdf(h("000102030405060708090a0b0c"), b"\x0b" * 22, h("f0f1f2f3f4f5f6f7f8f9"), 42) == h(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


# --- OpenSec v1, from docs/protocol/opensec.md --------------------------------------

MAGIC = b"OSEC"
VERSION = 1
SERVER_AUTH = 0x0001
CLIENT_HELLO_LEN = 90
SALT = b"OpenSec v1 handshake"
C2S, S2C = 1, 2
ZERO32 = bytes(32)


class Reject(Exception):
    pass


def nonce(direction: int, counter: int) -> bytes:
    return struct.pack("<IQ", direction, counter)


def client_hello(ec_public: bytes, caps: int) -> bytes:
    return (b"\x00\x01" + MAGIC + bytes([VERSION, 0]) + struct.pack("<H", caps) + ec_public).ljust(
        CLIENT_HELLO_LEN, b"\x00"
    )


def derive(ch: bytes, sh_body: bytes, ee: bytes, es: bytes):
    transcript = hashlib.sha256(ch + sh_body).digest()
    okm = hkdf(SALT, ee + es, transcript, 64)
    _, tag = aead_seal(okm[32:], nonce(S2C, 0), transcript, b"")
    return transcript, okm, tag


def server_respond(ch: bytes, es_secret: bytes, static_secret, server_caps: int) -> bytes:
    """The server's checks and reply; raises Reject if it must ignore the hello."""
    if len(ch) != CLIENT_HELLO_LEN or ch[:2] != b"\x00\x01" or ch[2:6] != MAGIC:
        raise Reject("not a v1 client hello")
    if ch[6] != VERSION:
        raise Reject("version")
    client_caps = struct.unpack("<H", ch[8:10])[0]
    ec = ch[10:42]
    caps = client_caps & server_caps
    caps = caps | SERVER_AUTH if static_secret else caps & ~SERVER_AUTH
    ee = x25519(es_secret, ec)
    if ee == ZERO32:
        raise Reject("low-order client key")
    body = b"\x00\x02" + MAGIC + bytes([VERSION, 0]) + struct.pack("<H", caps) + public_key(es_secret)
    es = b""
    if static_secret:
        body += public_key(static_secret)
        es = x25519(static_secret, ec)
    _, _, tag = derive(ch, body, ee, es)
    return body + tag


def client_finish(ch: bytes, ec_secret: bytes, sh: bytes, pinned):
    """The client's checks; returns (key_c2s, key_s2c, server key) or raises Reject."""
    if len(sh) < 58 or sh[:2] != b"\x00\x02" or sh[2:6] != MAGIC:
        raise Reject("not a server hello")
    if sh[6] != VERSION:
        raise Reject("version")
    caps = struct.unpack("<H", sh[8:10])[0]
    offered = struct.unpack("<H", ch[8:10])[0]
    if caps & ~offered:
        raise Reject("capability not offered")
    auth = bool(caps & SERVER_AUTH)
    if len(sh) != (90 if auth else 58):
        raise Reject("length")
    ee = x25519(ec_secret, sh[10:42])
    if ee == ZERO32:
        raise Reject("low-order server ephemeral key")
    es, server_key = b"", None
    if auth:
        server_key = sh[42:74]
        if pinned is not None and pinned != server_key:
            raise Reject("pinned key mismatch")
        es = x25519(ec_secret, server_key)
        if es == ZERO32:
            raise Reject("low-order server static key")
    elif pinned is not None:
        raise Reject("pinned but anonymous")
    _, okm, tag = derive(ch, sh[:-16], ee, es)
    if not hmac.compare_digest(tag, sh[-16:]):
        raise Reject("confirmation tag")
    return okm[:32], okm[32:], server_key


def seal_record(key: bytes, direction: int, counter: int, plaintext: bytes) -> bytes:
    header = b"\xf5" + struct.pack("<I", counter & 0xFFFFFFFF)
    ct, tag = aead_seal(key, nonce(direction, counter), header, plaintext)
    return header + ct + tag


class Receiver:
    """Counter reconstruction and the 64-record replay window, as specified."""

    def __init__(self, key: bytes, direction: int):
        self.key, self.direction = key, direction
        self.highest, self.seen = 0, set()

    def expand(self, low: int) -> int:
        c = (self.highest & ~0xFFFFFFFF) | low
        if c + 2**31 < self.highest:
            c += 2**32
        elif c > self.highest + 2**31 and c >= 2**32:
            c -= 2**32
        return c

    def receive(self, datagram: bytes):
        if len(datagram) < 21 or datagram[0] != 0xF5:
            return None
        c = self.expand(struct.unpack("<I", datagram[1:5])[0])
        if c == 0 or c in self.seen or c + 63 < self.highest:
            return None
        pt = aead_open(self.key, nonce(self.direction, c), datagram[:5], datagram[5:-16], datagram[-16:])
        if pt is None:
            return None
        self.seen.add(c)
        self.highest = max(self.highest, c)
        return c


def check(path: Path):
    self_test()
    h = bytes.fromhex
    counts = {}

    def count(k):
        counts[k] = counts.get(k, 0) + 1

    case = {}

    def finish_case():
        if not case:
            return
        ce, se = h(case["client_ephemeral_secret"]), h(case["server_ephemeral_secret"])
        ss = h(case["server_static_secret"]) if "server_static_secret" in case else None
        assert public_key(ce).hex() == case["client_ephemeral_public"]
        assert public_key(se).hex() == case["server_ephemeral_public"]
        if ss:
            assert public_key(ss).hex() == case["server_static_public"]
        ch = client_hello(public_key(ce), SERVER_AUTH)
        assert ch.hex() == case["client_hello"], "client hello"
        sh = server_respond(ch, se, ss, SERVER_AUTH)
        assert sh.hex() == case["server_hello"], "server hello"
        ee = x25519(ce, public_key(se))
        assert ee.hex() == case["ee"]
        es = x25519(ce, public_key(ss)) if ss else b""
        assert es.hex() == case.get("es", "")
        transcript, okm, tag = derive(ch, sh[:-16], ee, es)
        assert transcript.hex() == case["transcript"]
        assert okm.hex() == case["okm"]
        assert (okm[:32].hex(), okm[32:].hex()) == (case["key_c2s"], case["key_s2c"])
        assert tag.hex() == case["confirm_tag"]
        pin = public_key(ss) if ss else None
        assert client_finish(ch, ce, sh, pin)[:2] == (okm[:32], okm[32:])
        for direction, counter, plain, wire in case["records"]:
            key, d = (okm[:32], C2S) if direction == "c2s" else (okm[32:], S2C)
            assert seal_record(key, d, counter, plain) == wire, f"record {direction} {counter}"
            rx = Receiver(key, d)
            rx.highest = counter - 1  # a receiver that has seen everything before it
            assert rx.receive(wire) == counter
            assert rx.receive(wire) is None, "replay"
            rx = Receiver(key, d)
            rx.highest = counter - 1
            assert rx.receive(wire[:-1] + bytes([wire[-1] ^ 1])) is None, "tampered tag"
            count("record")
        for direction, counter, n in case["nonces"]:
            assert nonce(C2S if direction == "c2s" else S2C, counter) == n
        count("handshake")
        case.clear()

    for raw in path.read_text().splitlines():
        if not raw or raw.startswith("#"):
            continue
        f = raw.split(" ")
        kind = f[0]
        if kind == "case":
            finish_case()
            case.update(name=f[1], records=[], nonces=[])
        elif kind == "record":
            case["records"].append((f[1], int(f[2]), h(f[3]), h(f[4])))
        elif kind == "nonce":
            case["nonces"].append((f[1], int(f[2]), h(f[3])))
        elif kind == "reject-client-hello":
            finish_case()
            try:
                server_respond(h(f[2]), h("40" * 32), None, SERVER_AUTH)
            except Reject:
                count("rejected client hello")
            else:
                raise AssertionError(f"client hello {f[1]} was accepted")
        elif kind == "reject-server-hello":
            _, name, ce, ch, pin, sh = f
            try:
                client_finish(h(ch), h(ce), h(sh), None if pin == "-" else h(pin))
            except Reject:
                count("rejected server hello")
            else:
                raise AssertionError(f"server hello {name} was accepted")
        elif kind == "window":
            finish_case()
            # Any key will do: only the counter logic is under test.
            key = bytes(32)
            rx = Receiver(key, C2S)
            for step in f[2:]:
                left, want = step.split("=")
                forged = left.endswith("!")
                low = int(left.rstrip("!"))
                full = rx.expand(low)
                wire = seal_record(key, C2S, full, b"\x01")
                if forged:
                    wire = wire[:-1] + bytes([wire[-1] ^ 1])
                got = rx.receive(wire)
                assert (str(got) if got is not None else "x") == want, f"window {f[1]} step {step}"
            count("window sequence")
        else:
            case[kind] = f[1]
    finish_case()
    return counts


if __name__ == "__main__":
    here = Path(__file__).with_name("opensec.txt")
    counts = check(Path(sys.argv[1]) if len(sys.argv) > 1 else here)
    print("OpenSec vectors agree with the spec:", ", ".join(f"{v} {k}s" for k, v in counts.items()))
