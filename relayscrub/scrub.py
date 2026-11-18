# ==============================================================================
# Program: scrub.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Pure Standard Library Deterministic Privacy Scrubber & Restorer.
#          Scrubs sensitive credentials, cloud API keys, private IPv4/IPv6 addresses,
#          MAC hardware addresses, user filesystem paths, emails, and hostnames
#          prior to outbound transmission to external LLMs.
#          Key Technical Features:
#            1. Unicode NFKD normalization & homoglyph / confusable folding
#            2. Multi-token credential regex engines (AWS, OpenAI, GitHub, Slack, JWT, SSH)
#            3. Network identifier detection (RFC 1918, Cisco/ARP MACs, base64 MACs)
#            4. Reversible placeholder mapping (<HOST-n>, <PATH-n>) via RelayMap
#            5. Fail-closed double-verification barrier (withholds output on leakage)
# ==============================================================================

from __future__ import annotations

import base64
import binascii
import codecs
import html
import json
import os
import re
import sys
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union

SELF = Path(__file__).resolve()
DEFAULT_DATA_DIR = SELF.parent / "data"
if not DEFAULT_DATA_DIR.exists() and (SELF.parent.parent / "data").exists():
    DEFAULT_DATA_DIR = SELF.parent.parent / "data"
DATA_DIR = Path(os.environ.get("RELAYSCRUB_DATA_DIR", DEFAULT_DATA_DIR))

MAX_INPUT = 2_000_000
RESTORABLE = ("HOST", "PATH")
CATS = ("SECRET", "EMAIL", "PATH", "MAC", "IP", "HOST", "ID")  # merge priority, high -> low
PH_RX = re.compile(r"<(?:MAC|HOST|IP|SECRET|EMAIL|PATH|ID)-\d+>")
PH_ESC_RX = re.compile(r"<(?=(?:MAC|HOST|IP|SECRET|EMAIL|PATH|ID)-\d+>)", re.I)
PH_FULL = re.compile(r"<(?:MAC|HOST|IP|SECRET|EMAIL|PATH|ID)-\d+>", re.I)

DISTRO_WORDS = {
    "fedora", "ubuntu", "debian", "arch", "centos", "rhel", "alpine", "mint", "kali", "nixos",
    "suse", "opensuse", "gentoo", "manjaro", "popos", "rocky", "almalinux"
}
HOST_CONTEXT = re.compile(
    r"(?i)(ssh|scp|sftp|rsync|ping|host|hostname|machine|\bbox\b|node|server|\bvm\b|laptop|"
    r"@|\.local|\bnamed\b|\bcalled\b|fleet|peer|\bon the\b)"
)


class ScrubError(Exception):
    """Raised when scrubbing data files are corrupted, missing, or an invariant is violated."""
    pass


# --------------------------------------------------------------------------- normalisation
_CONF_SRC = (
    "аеорсху" "іјѕӏһԁԛԝɡɑ" "οανρικτυχϲ" "ոօս"
    "АВЕКМНОРСТХ" "ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ" "ʼ’‘ˈ"
)
_CONF_DST = (
    "aeopcxy" "ijsl" "hdqwga" "oavpiktuxc" "nou"
    "ABEKMHOPCTX" "ABEZHIKMNOPTYX" "''''"
)
CONF = dict(zip(_CONF_SRC, _CONF_DST))
CONF.update({c: "-" for c in "‐‑‒–—―−⁃﹘﹣－֊־"})
CONF.update({c: ":" for c in "꞉ː∶։：ⴀ".replace("ⴀ", "")})
CONF.update({c: "." for c in "․‧。．﹒܁܂"})
CONF.update({c: "/" for c in "∕⁄／⧸"})
CONF.update({c: "@" for c in "＠﹫"})


def normalise(text: str) -> Tuple[str, List[int]]:
    """Build a normalized detection view of the input text with coordinate index mapping.

    Educational Note on Unicode Normalization (NFKD):
        Attackers and accidental formatting frequently inject characters that deceive simple string matchers:
          - Unicode Confusables: Cyrillic 'а' (U+0430) looks identical to ASCII 'a' (U+0061).
          - Zero-Width Characters: Non-printing characters (U+200B zero-width space, U+200C non-joiner)
            interleaved between secret characters (e.g. s<U+200B>k<U+200B>-...).
          - Unicode Category Cf (Format), Mn (Non-spacing mark), Me (Enclosing mark).
        Normalization Form KD (NFKD) decomposes composite characters into base letters and compatibility forms.
        We drop formatting marks and map confusables to standard ASCII, while recording `idx[i]`,
        which maps each normalized character position back to its exact offset in the raw source string.

    Parameters:
        text (str): Raw input prompt string.

    Returns:
        Tuple[str, List[int]]:
            view: Cleaned detection view where confusables are folded to ASCII.
            idx: List of source string character indices corresponding to each character in view.
    """
    out: List[str] = []
    idx: List[int] = []
    n_text = len(text)

    # Step 1: Iterate over raw characters
    for i, ch in enumerate(text):
        # Step 1a: Handle JSON-escaped forward slashes: "\/Users\/x" -> "/Users/x"
        if ch == "\\" and i + 1 < n_text and text[i + 1] == "/":
            continue

        cat = unicodedata.category(ch)
        # Step 1b: Skip zero-width formatting and non-spacing combining marks
        if cat in ("Cf", "Mn", "Me"):
            continue

        # Step 1c: Normalize newline-like separators to standard newline or space
        if ch in "\u2028\u2029\x0b\x0c\x85":
            out.append("\n" if ch in "\u2028\u2029\x85" else " ")
            idx.append(i)
            continue

        # Step 1d: Skip other control characters (except newline, tab, carriage return)
        if cat == "Cc" and ch not in "\n\t\r":
            continue

        # Step 1e: Decompose character via NFKD and map known confusables to ASCII
        for c in unicodedata.normalize("NFKD", ch):
            if unicodedata.category(c) in ("Mn", "Me", "Cf"):
                continue
            out.append(CONF.get(c, c))
            idx.append(i)

    return "".join(out), idx


# --------------------------------------------------------------------------- data files
def _norm_name(v: str) -> str:
    return re.sub(r"[-_\s']+", "-", v.strip().lower())


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ScrubError("cannot read %s (%s)" % (path.name, type(exc).__name__))


def load_names(data_dir: Path) -> Tuple[List[str], List[str]]:
    """(host names, literals). Any of the three files missing/corrupt, or zero hosts -> ScrubError (fail closed)."""
    hosts: set = set()
    literals: set = set()

    def add(v):
        if isinstance(v, str) and len(v.strip()) >= 3:
            hosts.add(_norm_name(v))

    red = _read_json(data_dir / "public_release_redactions.json")
    if not isinstance(red, dict):
        raise ScrubError("redactions file has wrong shape")
    for x in red.get("hosts", []) if isinstance(red.get("hosts"), list) else []:
        add(x)
    for x in red.get("literals", []) if isinstance(red.get("literals"), list) else []:
        if isinstance(x, str) and x.strip():
            literals.add(x.strip())
    fr = _read_json(data_dir / "fleet_roles.json")
    if not isinstance(fr, dict) or not isinstance(fr.get("hosts"), dict):
        raise ScrubError("fleet_roles file has wrong shape")
    for k, v in fr["hosts"].items():
        add(k)
        if isinstance(v, dict):
            for a in v.get("aliases", []) if isinstance(v.get("aliases"), list) else []:
                add(a)
            add(v.get("callsign"))
    rh = _read_json(data_dir / "retired_hosts.json")
    if not isinstance(rh, dict) or not isinstance(rh.get("hosts"), list):
        raise ScrubError("retired_hosts file has wrong shape")
    for v in rh["hosts"]:
        if isinstance(v, dict):
            add(v.get("host"))
            for a in v.get("aliases", []) if isinstance(v.get("aliases"), list) else []:
                add(a)
            add(v.get("callsign"))
        else:
            add(v)
    if not hosts:
        raise ScrubError("no host names loaded")
    return sorted(hosts, key=lambda s: (-len(s), s)), sorted(literals, key=lambda s: (-len(s), s))


def _name_rx(name: str) -> "re.Pattern[str]":
    toks = [t for t in re.split(r"[-_\s']+", name) if t]
    parts = []
    for t in toks:
        if len(t) > 3 and t.endswith("s") and t.isalpha():
            parts.append(re.escape(t[:-1]) + "'?s")
        else:
            parts.append(re.escape(t))
    return re.compile(r"(?<![a-z0-9])" + r"[-_\s]*".join(parts) + r"(?![a-z0-9])", re.I)


# ==============================================================================
# SECTION: Detection Regular Expressions & Token Patterns
# Educational Explanation of Regular Expression Tokens:
#   - (?<!...) and (?!...): Negative lookbehind and lookahead assertions.
#     These ensure our regex matches only standalone tokens rather than substrings
#     inside legitimate identifier words or long hashes.
#   - MAC_RX: Matches standard IEEE 802 MAC addresses (e.g. 00:00:00:00:00:00 or 00-1A-2B-...)
#     using hexadecimal pairs separated by colons, hyphens, or tabs.
#   - MAC_CISCO: Matches Cisco-style dotted tri-groups (e.g. 0123.4567.89ab).
#   - HOME_RX: Detects personal home directory paths on Unix (/Users/..., /home/...),
#     system server mounts (/srv/..., /Volumes/..., /mnt/...), and Windows (C:\Users\...).
#   - IPV4_RX: Matches dotted-decimal IPv4 addresses while validating against RFC 1918
#     private address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 169.254/16).
#   - SECRET_RES: Dedicated high-precision signatures for API keys and tokens:
#       * sk-[...]: OpenAI secret API keys
#       * gh[pousr]_[...], github_pat_[...]: GitHub personal and organization tokens
#       * AKIA[...]: AWS access key IDs
#       * AIza[...]: Google cloud platform API keys
#       * xox[abprs]-[...]: Slack bot and user OAuth tokens
#       * eyJ[...]: JSON Web Tokens (JWT base64-encoded header)
#       * -----BEGIN ... KEY-----: OpenSSH and RSA/ECDSA private key blocks
# ==============================================================================

HEX = "[0-9a-f]"
MAC_SEP = r"(?:\s*[:\-]\s*|[ \t]+|\r?\n)"
MAC_RX = re.compile(r"(?<!%s)%s{2}(?:%s%s{2}){5,7}(?!%s)" % (HEX, HEX, MAC_SEP, HEX, HEX), re.I)
MAC_CISCO = re.compile(r"(?<!%s)%s{4}(?:\s*\.\s*%s{4}){2}(?!%s)" % (HEX, HEX, HEX, HEX), re.I)
MAC_RUN = re.compile(r"(?<!%s)%s{12}(?!%s)" % (HEX, HEX, HEX), re.I)
LOCAL_RX = re.compile(r"(?i)(?<![a-z0-9-])[a-z0-9][a-z0-9-]{1,40}\.local(?![a-z0-9-])")
_PTAIL = r"(?:/[^\s\\'\"<>;,)\]}|]*)*"
HOME_RX = re.compile(
    r"(?i)(?:/Users|/home|/srv|/Volumes|/mnt|/media|/root)/[ \t]{0,3}[^\s/\\'\"<>:;,)\]}|]+" + _PTAIL
    + r"|(?<![A-Za-z0-9])[A-Z]:\\Users\\[^\s/\\'\"<>:;,)\]}|]+(?:\\[^\s\\'\"<>;,)\]}|]*)*"
    + r"|(?<![\w~])~[A-Za-z_][\w.\-]*(?=/)" + _PTAIL
    + r"|\busers[ \t]+(?:then|slash|and then|->)[ \t]+[\w.\-]+"
)
EMAIL_RX = re.compile(r"[A-Za-z0-9._%+\-]{1,128}@[A-Za-z0-9][A-Za-z0-9.\-]{0,255}")
DOT = r"(?:\.|[\[\(]\.[\]\)])"
IPV4_RX = re.compile(r"(?<![\d.])(\d{1,3})%s(\d{1,3})%s(\d{1,3})%s(\d{1,3})(?!\d)" % (DOT, DOT, DOT))
IPV6_RX = re.compile(r"(?i)(?<![0-9a-f:])(?:fe[89ab][0-9a-f]|f[cd][0-9a-f]{2})(?::[0-9a-f]{0,4}){2,7}(?![0-9a-f:])")
KV_RX = re.compile(
    r"(?i)(?<![a-z0-9])(?:password|passwd|passphrase|pwd|pw|pass|secret|token|api[_\- ]?key|apikey|"
    r"access[_\- ]?key|private[_\- ]?key|auth|credential|credentials)[\"']?"
    r"(?:[ \t]*[:=][ \t]*|[ \t]+(?:is|was)[ \t]+)"
    r"(?P<v>\"[^\"\n]*\"|'[^'\n]*'|[^\s\"']\S*)"
)
SECRET_RES = [
    re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?(?:-----END [A-Z0-9 ]+-----|$)", re.S),
    re.compile(r"(?i)\bBearer[ \t]+\S{8,}"),
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*"),
    re.compile(r"(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-ssh-\S+)[ \t]+AAAA[A-Za-z0-9+/=]+"),
    re.compile(r"(?i)(?<![a-z0-9+.\-])[a-z][a-z0-9+.\-]{0,30}://[^\s/:@]{1,128}:[^\s/@]{1,256}@"),
    re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z])"),
    # leading part of a known key shape followed by an ellipsis
    re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]_|github_pat_|sk-|AKIA|AIza|xox[abprs]-|eyJ)[A-Za-z0-9_\-]{4,64}(?:\.{2,}|\u2026)"),
]
LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")
B64_RX = re.compile(r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{8,}={0,6}")
B64_MULTI = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/=]{16,}[ \t]*\r?\n[ \t]*)+[A-Za-z0-9+/=]{4,}")
HEXBLOB = re.compile(r"(?<![0-9a-f])(?:[0-9a-f]{2}){4,}(?![0-9a-f])", re.I)


def _long_token_ok(tok: str) -> bool:
    if not any(c.isdigit() for c in tok):
        return False
    if len(tok) >= 40 and "/" not in tok:
        return True
    return (any(c.isupper() for c in tok) and any(c.islower() for c in tok)) or any(c in "+=" for c in tok)


def _private_ipv4(a: int, b: int) -> bool:
    return (
        a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
        or (a == 169 and b == 254) or (a == 100 and 64 <= b <= 127)
    )


def _printable_ratio(s: str) -> float:
    return sum(1 for c in s if c.isprintable() or c in "\n\t\r") / len(s) if s else 0.0


def _decode_candidates(tok: str):
    t = re.sub(r"\s+", "", tok)
    yield_list = []
    for alt in (t, t.replace("-", "+").replace("_", "/")):
        pad = alt + "=" * (-len(alt) % 4)
        try:
            yield_list.append(base64.b64decode(pad, validate=False))
        except (binascii.Error, ValueError):
            pass
    t32 = t.rstrip("=").upper()
    if re.fullmatch(r"[A-Z2-7]{8,}", t32):
        try:
            yield_list.append(base64.b32decode(t32 + "=" * (-len(t32) % 8)))
        except (binascii.Error, ValueError):
            pass
    if re.fullmatch(r"(?i)(?:[0-9a-f]{2})+", t):
        try:
            yield_list.append(bytes.fromhex(t))
        except ValueError:
            pass
    return yield_list


Span = Tuple[int, int, str, str]  # (start, end) in view coordinates, category, key

UUID_RX = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])")
UUID_J = re.compile(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
PREFIX_RES = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,36}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,60}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{10,48}"),
    re.compile(r"(?i)akia[0-9a-z]{16}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{30,40}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,60}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*"),
]
JOIN_DROP = dict.fromkeys(map(ord, " \t\r\n\"'`+|*>,\\"), None)
JOIN_DROP2 = dict(JOIN_DROP)
JOIN_DROP2.update(dict.fromkeys(map(ord, ":{}[]=-;()"), None))
ROT13 = {}
for _i, _c in enumerate("abcdefghijklmnopqrstuvwxyz"):
    ROT13[ord(_c)] = "abcdefghijklmnopqrstuvwxyz"[(_i + 13) % 26]
    ROT13[ord(_c.upper())] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[(_i + 13) % 26]

LEET_I = str.maketrans("4301578", "aeoistb")
LEET_L = str.maketrans("4301578", "aeolstb")
ROT47 = {c: chr(33 + ((c - 33 + 47) % 94)) for c in range(33, 127)}
_OCT = r"(?:0x[0-9a-f]{1,2}|\d{1,3})"
_SEPI = r"(?:[ \t\r\n]{0,3}\.[ \t\r\n]{0,3}|,|-|[ \t]+dot[ \t]+|[\[\(]\.[\]\)])"
IPX_RX = re.compile(r"(?i)(?<![\w.])(%s)(?:%s(%s)){3}(?![\w])" % (_OCT, _SEPI, _OCT))
IPX_PARTS = re.compile(r"(?i)0x[0-9a-f]{1,2}|\d{1,3}")
IP_HEXINT = re.compile(r"(?i)(?<![\w.])0x([0-9a-f]{8})(?![\w])")
IP_DECINT = re.compile(r"(?<![\w.\-])(\d{8,10})(?![\w])")
IP_MAPPED = re.compile(r"(?i)(?<![0-9a-f:])::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})(?![0-9a-f:])")
EMAIL_AT = re.compile(
    r"(?i)(?<![\w.+\-])[\w.+\-]{1,64}[ \t]{0,3}(?:[\[\(\{<]at[\]\)\}>]|[ \t]at[ \t])[ \t]{0,3}[\w\-]{1,63}"
    r"(?:[ \t]{0,3}(?:\.|[\[\(\{<]dot[\]\)\}>]|[ \t]dot[ \t])[ \t]{0,3}[\w\-]{1,63})+"
)
EMAIL_AT_BR = re.compile(r"(?i)[\[\(\{<]at[\]\)\}>]|[\[\(\{<]dot[\]\)\}>]|\sdot\s")
ASSIGN_RX = re.compile(
    r"(?<![A-Za-z0-9_])(?P<n>[A-Za-z_][A-Za-z0-9_.\-]{0,60})[\"']?\s{0,40}[:=]\s{0,40}"
    r"(?P<v>\"[^\"\n]*\"|'[^'\n]*'|[^\s\"']\S*)"
)
ASSIGN_TAIL = re.compile(r"[ \t]+(\S+)")
ENT_RX = re.compile(r"[^\s\"'<>`|]{8,}")
B64_MAC_RX = re.compile(r"(?i)\b(?:mac|hwaddr|hw|ether|bssid|address)\b[^\n]{0,12}?(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{8})(?![A-Za-z0-9+/=])")
CHUNK_RX = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/=]{4,}[ \t]{1,2}){7,}[A-Za-z0-9+/=]{4,}")
ARP_RX = re.compile(r"(?i)(?<![0-9a-z:\-])[0-9a-f]{1,2}(?:[:\-][0-9a-f]{1,2}){5}(?![0-9a-z])")
MAC_INT_RX = re.compile(r"(?i)\b(?:mac|hwaddr|ether|bssid|address)\b[^\n]{0,24}?(?<![\w.])(\d{9,15})(?![\w.])")
TOK_RX = re.compile(r"[0-9A-Za-z]+")
_KW_LONG = ("password", "passwd", "passphrase", "secret", "token", "apikey", "credential", "privatekey")
_KW_PARTS = {"auth", "pass", "pw", "pwd", "key", "cred", "creds", "login", "pin", "passcode", "bearer"}
_SYM = set("!@#$%^&*?~")
_HEXC = set("0123456789abcdefABCDEF")


def _bl(v: str, s: int) -> bool:
    return s <= 0 or not v[s - 1].isalnum()


def _br(v: str, e: int) -> bool:
    return e >= len(v) or not v[e].isalnum()


def _kw_name(n: str) -> bool:
    ln = n.lower()
    flat = re.sub(r"[_.\-]", "", ln)
    if any(k in flat for k in _KW_LONG):
        return True
    if flat.endswith("key") and len(flat) > 3:
        return True
    return any(p in _KW_PARTS for p in re.split(r"[_.\-]", ln))


def _env_value_entropy(val: str) -> bool:
    return (len(val) >= 8 and "/" not in val and any(c.isdigit() for c in val) and any(c.isalpha() for c in val))


def _entropy_token(tok: str) -> bool:
    if len(tok) < 8 or "/" in tok:
        return False
    return (any(c.isupper() for c in tok) and any(c.islower() for c in tok) and any(c.isdigit() for c in tok)
            and any(c in _SYM for c in tok))


def _ip_from_ints(o: List[int]) -> Optional[str]:
    if len(o) == 4 and all(0 <= x <= 255 for x in o) and _private_ipv4(o[0], o[1]):
        return ".".join(map(str, o))
    return None


def _decode_ip_parts(parts: List[str]) -> Optional[str]:
    o = [int(p, 16) if p.lower().startswith("0x") else int(p) for p in parts]
    r = _ip_from_ints(o)
    if r:
        return r
    if all(not p.lower().startswith("0x") for p in parts):
        return _ip_from_ints([int(p[::-1]) for p in reversed(parts)])
    return None


def _int_private(n: int) -> bool:
    return _private_ipv4((n >> 24) & 255, (n >> 16) & 255) and n < (1 << 32)


def _variant(text: str, drop=None, rev=False, rot=False) -> Tuple[str, List[int]]:
    out: List[str] = []
    idx: List[int] = []
    for i, ch in enumerate(text):
        if drop is not None and (ord(ch) in drop or (ord(ch) > 127 and not ch.isalnum())):
            continue
        out.append(ch)
        idx.append(i)
    s = "".join(out)
    if rot:
        s = s.translate(ROT13)
    if rev:
        s = s[::-1]
        idx = idx[::-1]
    return s, idx


def _cover_index(spans: List[Span]):
    iv = sorted((s, e) for s, e, _, _ in spans)
    merged: List[List[int]] = []
    for s, e in iv:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    return [m[0] for m in merged], [m[1] for m in merged]


def _covered(cov, pos: int) -> bool:
    import bisect
    starts, ends = cov
    i = bisect.bisect_right(starts, pos) - 1
    return i >= 0 and pos < ends[i]


class Detector:
    def __init__(self, hosts: Optional[Sequence[str]] = None, literals: Optional[Sequence[str]] = None):
        self.hosts = [(h, _name_rx(h), h in DISTRO_WORDS) for h in (hosts or [])]
        self.literals = [(l, _name_rx(l)) for l in (literals or [])]

    def find(self, v: str, depth: int = 0) -> List[Span]:
        sp: List[Span] = []
        for rx in (MAC_RX, MAC_CISCO, MAC_RUN):
            for m in rx.finditer(v):
                sp.append((m.start(), m.end(), "MAC", "mac:" + re.sub(r"[^0-9a-f]", "", m.group(0).lower())))
        for m in LOCAL_RX.finditer(v):
            if m.group(0).lower() != "localhost.local":
                sp.append((m.start(), m.end(), "HOST", _norm_name(m.group(0))))
        for name, rx, distro in self.hosts:
            for m in rx.finditer(v):
                if distro and not self._distro_is_host(v, m):
                    continue
                sp.append((m.start(), m.end(), "HOST", _norm_name(m.group(0))))
        for lit, rx in self.literals:
            for m in rx.finditer(v):
                sp.append((m.start(), m.end(), "ID", "id:" + _norm_name(m.group(0))))
        for m in HOME_RX.finditer(v):
            sp.append((m.start(), m.end(), "PATH", "path:" + m.group(0).lower()))
        for m in EMAIL_RX.finditer(v):
            sp.append((m.start(), m.end(), "EMAIL", "email:" + m.group(0).lower()))
        for m in IPV4_RX.finditer(v):
            o = [int(g) for g in m.groups()]
            if all(x <= 255 for x in o) and _private_ipv4(o[0], o[1]):
                sp.append((m.start(), m.end(), "IP", "ip:" + ".".join(map(str, o))))
        for m in IPV6_RX.finditer(v):
            sp.append((m.start(), m.end(), "IP", "ip:" + m.group(0).lower()))
        for m in UUID_RX.finditer(v):
            sp.append((m.start(), m.end(), "ID", "uuid:" + re.sub(r"[^0-9a-f]", "", m.group(0).lower())))
        for m in KV_RX.finditer(v):
            val = m.group("v").strip("\"'")
            if PH_FULL.fullmatch(val):
                continue
            sp.append((m.start(), m.end(), "SECRET", "sec:" + m.group(0)))
        for rx in SECRET_RES:
            for m in rx.finditer(v):
                sp.append((m.start(), m.end(), "SECRET", "sec:" + m.group(0)))
        for m in LONG_TOKEN.finditer(v):
            if _long_token_ok(m.group(0)):
                sp.append((m.start(), m.end(), "SECRET", "sec:" + m.group(0)))
        if depth == 0:
            sp.extend(self._extra(v, sp))
        if depth < 3:
            for rx in (B64_RX, B64_MULTI, HEXBLOB):
                for m in rx.finditer(v):
                    if self._blob_hits(m.group(0), depth):
                        sp.append((m.start(), m.end(), "SECRET", "sec:" + m.group(0)))
        return sp

    def _extra(self, v: str, plain: List[Span]) -> List[Span]:
        out: List[Span] = []
        cov = _cover_index(plain) if plain else ([], [])
        n = len(v)

        def add(lo, hi, cat, key):
            out.append((lo, hi, cat, key))

        def sec_extend(hi):
            k = 0
            while hi < n and k < 40 and (v[hi].isalnum() or v[hi] in "-_"):
                hi += 1
                k += 1
            return hi

        variants = [
            (_variant(v, JOIN_DROP), "f"), (_variant(v, None, rev=True), "r"),
            (_variant(v, None, rot=True), "f"), (_variant(v, JOIN_DROP, rev=True), "r"),
            (_variant(v, JOIN_DROP, rot=True), "f"), (_variant(v, None, rev=True, rot=True), "r"),
            (_variant(v, JOIN_DROP2), "f")
        ]
        for vi, ((x, xi), direction) in enumerate(variants):
            if not x:
                continue
            rules = list(PREFIX_RES) + [EMAIL_RX]
            if vi == 0:
                rules.append(UUID_J)
            if vi == 6:
                rules = [r for r in PREFIX_RES if r is not PREFIX_RES[2]]
            for rx in rules:
                for m in rx.finditer(x):
                    seg = xi[m.start():m.end()]
                    lo, hi = min(seg), max(seg) + 1
                    if rx is PREFIX_RES[3] and not any(c.isdigit() for c in m.group(0)):
                        continue
                    if direction == "f" and not _bl(v, lo):
                        continue
                    if direction == "r" and not _br(v, hi):
                        continue
                    if rx is EMAIL_RX:
                        if m.group(0).count("@") != 1 or not re.search(r"[A-Za-z0-9]", m.group(0).split("@")[0]):
                            continue
                        cat, key = "EMAIL", "email:" + re.sub(r"[^a-z0-9@.]", "", m.group(0).lower())
                    elif rx is UUID_J:
                        cat, key = "ID", "uuid:" + re.sub(r"[^0-9a-f]", "", m.group(0).lower())
                    else:
                        cat, key = "SECRET", None
                        hi = sec_extend(hi) if direction == "f" else hi
                    if _covered(cov, lo) and cat != "ID":
                        continue
                    add(lo, hi, cat, key or ("sec:" + v[lo:hi]))

        targets = []
        for h, _rx, distro in self.hosts:
            b = re.sub(r"[^0-9a-z]", "", h)
            if not b:
                continue
            targets.append((b, "HOST", _norm_name(h), distro, True))
            if len(b) >= 5:
                targets.append((b[::-1], "HOST", _norm_name(h), distro, False))
                targets.append((b.translate(ROT13), "HOST", _norm_name(h), distro, False))
        for lit, _rx in self.literals:
            b = re.sub(r"[^0-9a-z]", "", lit.lower())
            if len(b) >= 4:
                targets.append((b, "ID", "id:" + _norm_name(lit), False, False))

        def scan_names(txt: str, leet_tables, only_fwd=False):
            cmap = [m.start() for m in re.finditer(r"[0-9A-Za-z]", txt)]
            if not cmap:
                return
            base = "".join(txt[i] for i in cmap).lower()
            for table in leet_tables:
                cl = base.translate(table) if table is not None else base
                if table is not None and cl == base:
                    continue
                for w, cat, key, distro, fwd in targets:
                    if only_fwd and not fwd:
                        continue
                    if table is not None and not fwd:
                        continue
                    pos = cl.find(w)
                    while pos != -1:
                        s, e = cmap[pos], cmap[pos + len(w) - 1] + 1
                        if _bl(v, s) and _br(v, e):
                            if not (distro and not self._distro_ok(v, s, e)):
                                add(s, e, cat, key)
                        pos = cl.find(w, pos + 1)

        scan_names(v, [None, LEET_I, LEET_L])
        if any(33 <= ord(c) <= 126 and not c.isalnum() for c in v):
            scan_names(v.translate(ROT47), [None], only_fwd=True)

        for m in IPX_RX.finditer(v):
            ip = _decode_ip_parts(IPX_PARTS.findall(m.group(0)))
            if ip:
                add(m.start(), m.end(), "IP", "ip:" + ip)
        for m in IP_HEXINT.finditer(v):
            if _int_private(int(m.group(1), 16)):
                add(m.start(), m.end(), "IP", "ip:hex" + m.group(1).lower())
        for m in IP_DECINT.finditer(v):
            if 8 <= len(m.group(1)) and _int_private(int(m.group(1))):
                add(m.start(), m.end(), "IP", "ip:int" + m.group(1))
        for m in IP_MAPPED.finditer(v):
            a, b = int(m.group(1), 16), int(m.group(2), 16)
            if _ip_from_ints([a >> 8, a & 255, b >> 8, b & 255]):
                add(m.start(), m.end(), "IP", "ip:map" + m.group(0).lower())

        run: List[Tuple[int, int, str]] = []

        def flush_hex():
            if len(run) >= 2 and sum(len(t[2]) for t in run) >= 12 and any(c in "abcdefABCDEF" for t in run for c in t[2]):
                add(run[0][0], run[-1][1], "MAC", "mac:" + "".join(t[2] for t in run).lower())
            run.clear()

        for m in TOK_RX.finditer(v):
            t = m.group(0)
            ok = len(t) in (1, 2, 4) and all(c in _HEXC for c in t)
            if ok and run and (len(run[0][2]) != len(t) or m.start() - run[-1][1] > 6):
                flush_hex()
            if ok:
                run.append((m.start(), m.end(), t))
            else:
                flush_hex()
        flush_hex()

        dec: List[Tuple[int, int, str]] = []

        def flush_dec():
            if len(dec) >= 6 and sum(1 for t in dec if int(t[2]) >= 100) >= 2:
                add(dec[0][0], dec[-1][1], "MAC", "mac:dec" + ",".join(t[2] for t in dec))
            dec.clear()

        for m in TOK_RX.finditer(v):
            t = m.group(0)
            if t.isdigit() and len(t) <= 3 and int(t) <= 255:
                if dec and not re.fullmatch(r"[:,.\-] ?", v[dec[-1][1]:m.start()]):
                    flush_dec()
                dec.append((m.start(), m.end(), t))
            else:
                flush_dec()
        flush_dec()

        for m in ARP_RX.finditer(v):
            if any(c in "abcdefABCDEF" for c in m.group(0)):
                add(m.start(), m.end(), "MAC", "mac:" + "".join(x.zfill(2) for x in re.split(r"[:\-]", m.group(0).lower())))
        for m in MAC_INT_RX.finditer(v):
            if int(m.group(1)) < (1 << 48):
                add(m.start(1), m.end(1), "MAC", "mac:int" + m.group(1))
        for m in B64_MAC_RX.finditer(v):
            t = m.group(1)
            if any(c.isdigit() for c in t) or any(c.isupper() for c in t[1:]):
                try:
                    if len(base64.b64decode(t)) == 6:
                        add(m.start(1), m.end(1), "MAC", "mac:b64" + t)
                except (binascii.Error, ValueError):
                    pass

        for m in ASSIGN_RX.finditer(v):
            name, val = m.group("n"), m.group("v")
            raw = val.strip("\"'")
            if PH_FULL.fullmatch(raw) or not raw:
                continue
            envstyle = bool(re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", name)) and _env_value_entropy(raw)
            if not (_kw_name(name) or envstyle):
                continue
            end = m.end()
            for _ in range(3):
                t = ASSIGN_TAIL.match(v, end)
                if not t:
                    break
                tok = t.group(1)
                if PH_FULL.fullmatch(tok) or not (any(c.isdigit() or c in _SYM or c in "-_" for c in tok)):
                    break
                end = t.end()
            add(m.start("v"), end, "SECRET", "sec:" + v[m.start("v"):end])
        for m in ENT_RX.finditer(v):
            tok = m.group(0)
            if _entropy_token(tok):
                add(m.start(), m.end(), "SECRET", "sec:" + tok)
        for m in CHUNK_RX.finditer(v):
            toks = m.group(0).split()
            if sum(len(t) for t in toks) < 48:
                continue
            mixed = sum(1 for t in toks if any(c.isupper() for c in t[1:]) and any(c.islower() for c in t))
            if mixed * 10 >= len(toks) * 6 and any(c.isdigit() for c in m.group(0)):
                add(m.start(), m.end(), "SECRET", "sec:" + m.group(0))

        for m in EMAIL_AT.finditer(v):
            g = m.group(0)
            if EMAIL_AT_BR.search(g):
                add(m.start(), m.end(), "EMAIL", "email:" + re.sub(r"[^a-z0-9]", "", g.lower()))
        return out

    @staticmethod
    def _distro_ok(v: str, s: int, e: int) -> bool:
        raw = v[s:e]
        if raw == raw.lower():
            return True
        ctx = v[max(0, s - 24):s] + " " + v[e:e + 24]
        return bool(HOST_CONTEXT.search(ctx))

    @staticmethod
    def _distro_is_host(v: str, m) -> bool:
        raw = m.group(0)
        if raw == raw.lower():
            return True
        ctx = v[max(0, m.start() - 24):m.start()] + " " + v[m.end():m.end() + 24]
        return bool(HOST_CONTEXT.search(ctx))

    def _blob_hits(self, tok: str, depth: int) -> bool:
        for raw in _decode_candidates(tok):
            if not raw:
                continue
            if len(raw) < 4:
                continue
            if len(tok) < 24 and not all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
                continue
            s = raw.decode("utf-8", "replace")
            if _printable_ratio(s) < 0.9:
                continue
            if "BEGIN" in s and "KEY" in s:
                return True
            nv, _ = normalise(s)
            if self.find(nv, depth + 1):
                return True
        return False


# ==============================================================================
# SECTION: RelayMap (Localized Reversible Placeholder Map)
# Educational Note:
# RelayMap stores the bidirectional mapping between temporary placeholders
# (e.g. <HOST-1>, <PATH-1>) and real local values on the developer's machine.
# Security Invariant:
#   - RelayMap is strictly LOCAL to the client machine and NEVER transmitted.
#   - Only benign identifiers (HOST and PATH) are restorable via `restorable()`.
#   - Sensitive credentials, MACs, private IPs, and emails are categorized as
#     NON-RESTORABLE: they are scrubbed outbound and permanently withheld.
# ==============================================================================

class RelayMap:
    """LOCAL ONLY. placeholder <-> real value. Never printed, never in a report."""

    def __init__(self):
        self.by_key: Dict[Tuple[str, str], str] = {}
        self.values: Dict[str, Tuple[str, str]] = {}
        self.counters: Dict[str, int] = {}

    def __repr__(self):
        return "<RelayMap entries=%d (values hidden)>" % len(self.values)

    __str__ = __repr__

    def placeholder(self, cat: str, key: str, value: str) -> str:
        ph = self.by_key.get((cat, key))
        if ph is None:
            n = self.counters.get(cat, 0) + 1
            self.counters[cat] = n
            ph = "<%s-%d>" % (cat, n)
            self.by_key[(cat, key)] = ph
            self.values[ph] = (cat, value)
        return ph

    def restorable(self) -> Dict[str, str]:
        return {p: v for p, (c, v) in self.values.items() if c in RESTORABLE}

    def dump_restorable(self) -> str:
        return json.dumps(self.restorable(), sort_keys=True)

    @classmethod
    def load_restorable(cls, s: str) -> "RelayMap":
        m = cls()
        d = json.loads(s)
        if not isinstance(d, dict):
            raise ScrubError("bad map file")
        for p, v in d.items():
            mm = re.fullmatch(r"<(HOST|PATH)-(\d+)>", str(p))
            if mm and isinstance(v, str):
                m.values[p] = (mm.group(1), v)
                m.counters[mm.group(1)] = max(m.counters.get(mm.group(1), 0), int(mm.group(2)))
        return m


_DET_CACHE: Dict[str, Detector] = {}


def _detector(data_dir: Path) -> Detector:
    k = str(data_dir)
    if k not in _DET_CACHE:
        hosts, lits = load_names(data_dir)
        _DET_CACHE[k] = Detector(hosts, lits)
    return _DET_CACHE[k]


def _merge(spans: List[Span]) -> List[Tuple[int, int, str, Optional[str]]]:
    spans = sorted(spans, key=lambda s: (s[0], -s[1]))
    out: List[list] = []
    for s, e, c, k in spans:
        if out and s < out[-1][1]:
            last = out[-1]
            if e > last[1]:
                last[1] = e
                last[4] = True
            if CATS.index(c) < CATS.index(last[2]):
                last[2] = c
            last[3].add(k)
        else:
            out.append([s, e, c, {k}, False])
    return [(a, b, c, (next(iter(ks)) if len(ks) == 1 and not wd else None)) for a, b, c, ks, wd in out]


def _view_hits(det: Detector, text: str) -> List[Span]:
    v, _ = normalise(text)
    return det.find(v)


# ==============================================================================
# SECTION: Core Scrubbing Engine with Fail-Closed Verification
# Educational Note on Fail-Closed Sanitization:
# In high-assurance security engineering, a single bug in regex replacement could
# leak sensitive credentials (e.g. an overlapping match or encoding variant).
# RelayScrub implements a "Fail-Closed" design:
#   1. PASS 1 (Scrubbing): Detect sensitive spans, replace with placeholders (<CATEGORY-n>).
#   2. PASS 2 (Double Verification): Re-run the detector over the cleaned text.
#      If ANY secret, email, private IP, or path is found, the function DOES NOT
#      return partially cleaned text. It returns None and reports 'verification-failed'.
#   3. PASS 3 (Encoding Invariants): Unquote URL encoding, HTML unescape, and decode
#      Unicode escapes. If an encoded sensitive token is revealed, scrubbing fails closed.
# ==============================================================================

def _scrub(
    text: str,
    data_dir: Optional[Path],
    mapping: RelayMap,
    hosts: Optional[Sequence[str]] = None,
    literals: Optional[Sequence[str]] = None,
):
    if not isinstance(text, str):
        raise ScrubError("input is not text")
    if len(text) > MAX_INPUT:
        raise ScrubError("input too large")

    if hosts is not None or literals is not None:
        det = Detector(hosts or [], literals or [])
    else:
        det = _detector(data_dir if data_dir else DATA_DIR)

    escaped = len(PH_ESC_RX.findall(text))
    text = PH_ESC_RX.sub("‹", text)
    view, idx = normalise(text)
    merged = _merge(det.find(view))
    counts: Dict[str, int] = {}
    pieces: List[str] = []
    pos = 0
    for s, e, cat, key in merged:
        o0, o1 = idx[s], idx[e - 1] + 1
        if o0 < pos:
            o0 = pos
        value = view[s:e]
        k = key if key else cat.lower() + ":" + re.sub(r"[-_\s']+", "-", value.lower())
        ph = mapping.placeholder(cat, k, value)
        counts[cat] = counts.get(cat, 0) + 1
        pieces.append(text[pos:o0])
        pieces.append(ph)
        pos = o1
    pieces.append(text[pos:])
    clean = "".join(pieces)

    # independent second verification
    left = _view_hits(det, clean)
    if left:
        rem: Dict[str, int] = {}
        for _, _, c, _ in left:
            rem[c] = rem.get(c, 0) + 1
        return None, {
            "ok": False, "reason": "verification-failed", "counts": counts,
            "remaining": rem, "placeholders_escaped": escaped
        }

    cv, _ = normalise(clean)
    low = cv.lower()
    squashed = re.sub(r"[^0-9a-z]", "", low)
    for ph, (cat, val) in list(mapping.values.items()):
        vl = val.lower()
        if cat == "MAC":
            h = re.sub(r"[^0-9a-f]", "", vl)
            if len(h) >= 12 and h in squashed:
                return None, {
                    "ok": False, "reason": "verification-failed", "counts": counts,
                    "remaining": {"MAC": 1}, "placeholders_escaped": escaped
                }
        elif cat != "HOST" and len(vl) >= 4 and vl in low and not PH_FULL.search(vl):
            return None, {
                "ok": False, "reason": "verification-failed", "counts": counts,
                "remaining": {cat: 1}, "placeholders_escaped": escaped
            }

    views = {urllib.parse.unquote(clean), html.unescape(clean)}
    if "\\u" in clean or "\\x" in clean:
        try:
            views.add(codecs.decode(clean.encode("utf-8", "ignore"), "unicode_escape"))
        except Exception:
            return None, {
                "ok": False, "reason": "undecodable-escapes", "counts": counts,
                "placeholders_escaped": escaped
            }
    views.discard(clean)
    for dv in views:
        if _view_hits(det, dv):
            return None, {
                "ok": False, "reason": "encoded-identifier", "counts": counts,
                "placeholders_escaped": escaped
            }

    return clean, {
        "ok": True, "reason": None, "counts": counts, "total": sum(counts.values()),
        "placeholders_escaped": escaped, "verified": True
    }


def scrub_with_map(
    text: str,
    data_dir: Optional[Union[str, Path]] = None,
    mapping: Optional[RelayMap] = None,
    hosts: Optional[Sequence[str]] = None,
    literals: Optional[Sequence[str]] = None,
) -> Tuple[Optional[str], dict, RelayMap]:
    """Scrub outbound prompt text using deterministic pattern matching.

    Returns (clean_text | None, report, RelayMap).
    Fails closed on any unexpected error by returning (None, {"ok": False, ...}).
    """
    m = mapping if mapping is not None else RelayMap()
    try:
        clean, rep = _scrub(
            text,
            Path(data_dir) if data_dir else None,
            m,
            hosts=hosts,
            literals=literals,
        )
    except ScrubError as exc:
        return None, {"ok": False, "reason": "scrub-error: %s" % exc, "counts": {}}, m
    except BaseException as exc:  # fail closed on anything, incl. RecursionError/MemoryError
        if isinstance(exc, KeyboardInterrupt):
            raise
        return None, {"ok": False, "reason": "internal-error: %s" % type(exc).__name__, "counts": {}}, m
    return clean, rep, m


def scrub_outbound(
    text: str,
    data_dir: Optional[Union[str, Path]] = None,
    mapping: Optional[RelayMap] = None,
    hosts: Optional[Sequence[str]] = None,
    literals: Optional[Sequence[str]] = None,
) -> Tuple[Optional[str], dict]:
    """Scrub outbound prompt text of all sensitive identifiers and credentials.

    Returns (clean_text | None, report).
    Fails closed (returns None, {"ok": False, ...}) if verification fails.
    """
    clean, rep, _ = scrub_with_map(text, data_dir, mapping, hosts=hosts, literals=literals)
    return clean, rep


def restore_inbound(text: str, mapping: RelayMap) -> str:
    """Swap <HOST-n>/<PATH-n> back to real values (single pass, exact ASCII placeholders only).

    Secrets, MACs, IPs, emails and IDs are NEVER restored.
    """
    if not isinstance(text, str):
        raise TypeError("text required")
    table = mapping.restorable()

    def rep(m):
        return table.get(m.group(0), m.group(0))

    return re.sub(r"<(?:HOST|PATH)-\d+>", rep, text)


# --------------------------------------------------------------------------- CLI
def _write_private(path: str, data: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(data)
    os.chmod(path, 0o600)


def main(argv=None) -> int:
    a = list(sys.argv[1:] if argv is None else argv)
    if not a or a[0] not in ("out", "in"):
        sys.stderr.write("usage: relayscrub-scrub out [--map FILE] < in\n       relayscrub-scrub in --map FILE < in\n")
        return 2
    mode, mpath = a[0], None
    if "--map" in a:
        try:
            mpath = a[a.index("--map") + 1]
        except IndexError:
            sys.stderr.write("--map needs a file\n")
            return 2
    try:
        text = sys.stdin.buffer.read().decode("utf-8")
    except UnicodeDecodeError:
        sys.stderr.write(json.dumps({"ok": False, "reason": "input-not-utf8"}) + "\n")
        return 1
    if mode == "out":
        clean, rep, m = scrub_with_map(text)
        sys.stderr.write(json.dumps(rep, sort_keys=True) + "\n")
        if clean is None:
            return 1
        if mpath:
            try:
                _write_private(mpath, m.dump_restorable())
            except OSError:
                sys.stderr.write(json.dumps({"ok": False, "reason": "map-write-failed"}) + "\n")
                return 1
        sys.stdout.write(clean)
        return 0
    if not mpath:
        sys.stderr.write("in needs --map FILE\n")
        return 2
    try:
        m = RelayMap.load_restorable(Path(mpath).read_text(encoding="utf-8"))
    except (OSError, ValueError, ScrubError):
        sys.stderr.write("cannot load map\n")
        return 1
    sys.stdout.write(restore_inbound(text, m))
    return 0


if __name__ == "__main__":
    sys.exit(main())
