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

# Locate this file so the default data directory can be resolved relative to the package.
# The data dir holds the JSON name lists (hosts, aliases, retired hosts, literals).
SELF = Path(__file__).resolve()
DEFAULT_DATA_DIR = SELF.parent / "data"
# Fall back to a repo-level data/ dir when running from a source checkout
# (package dir has no data/ but the repository root does).
if not DEFAULT_DATA_DIR.exists() and (SELF.parent.parent / "data").exists():
    DEFAULT_DATA_DIR = SELF.parent.parent / "data"
# RELAYSCRUB_DATA_DIR lets callers (and tests) point at a different set of name files.
DATA_DIR = Path(os.environ.get("RELAYSCRUB_DATA_DIR", DEFAULT_DATA_DIR))

# Hard cap on input size (characters). Bounds regex/decoding work and blocks
# resource-exhaustion inputs; larger text is rejected with ScrubError.
MAX_INPUT = 2_000_000
# Categories whose real value may be put back by restore_inbound(). Everything
# else (secrets, MACs, IPs, emails, ids) is one-way: scrubbed and never restored.
RESTORABLE = ("HOST", "PATH")
# All placeholder categories. Order is merge priority: when two detections
# overlap, the category earlier in this tuple wins (SECRET beats HOST, etc.).
CATS = ("SECRET", "EMAIL", "PATH", "MAC", "IP", "HOST", "ID")  # merge priority, high -> low
# Matches an already-formed placeholder such as <HOST-3> (case-sensitive).
PH_RX = re.compile(r"<(?:MAC|HOST|IP|SECRET|EMAIL|PATH|ID)-\d+>")
# Matches the opening '<' of placeholder-looking text in the INPUT. Such '<' are
# neutralised before scrubbing so user text cannot forge a placeholder that
# restore_inbound() would later replace with a real value.
PH_ESC_RX = re.compile(r"<(?=(?:MAC|HOST|IP|SECRET|EMAIL|PATH|ID)-\d+>)", re.I)
# Case-insensitive full placeholder match, used to skip values that are already
# placeholders (avoids re-scrubbing our own output).
PH_FULL = re.compile(r"<(?:MAC|HOST|IP|SECRET|EMAIL|PATH|ID)-\d+>", re.I)

# Linux distro names that are also common English/product words. A host entry
# in this set is only treated as a hostname when context suggests it is one
# (see Detector._distro_ok / _distro_is_host).
DISTRO_WORDS = {
    "fedora", "ubuntu", "debian", "arch", "centos", "rhel", "alpine", "mint", "kali", "nixos",
    "suse", "opensuse", "gentoo", "manjaro", "popos", "rocky", "almalinux"
}
# Words/punctuation near a capitalised distro word that hint it is a machine
# name (ssh, @, .local, 'the box', ...) rather than a mention of the OS.
HOST_CONTEXT = re.compile(
    r"(?i)(ssh|scp|sftp|rsync|ping|host|hostname|machine|\bbox\b|node|server|\bvm\b|laptop|"
    r"@|\.local|\bnamed\b|\bcalled\b|fleet|peer|\bon the\b)"
)


class ScrubError(Exception):
    """Raised when scrubbing data files are corrupted, missing, or an invariant is violated."""
    pass


# --------------------------------------------------------------------------- normalisation
# Confusable-folding tables: _CONF_SRC[i] (Cyrillic/Greek/Latin-extended look-alikes
# and typographic quotes) maps to _CONF_DST[i] (the ASCII it imitates). The two
# strings are concatenated in matching segments so they must stay the same length.
_CONF_SRC = (
    "аеорсху" "іјѕӏһԁԛԝɡɑ" "οανρικτυχϲ" "ոօս"
    "АВЕКМНОРСТХ" "ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ" "ʼ’‘ˈ"
)
_CONF_DST = (
    "aeopcxy" "ijsl" "hdqwga" "oavpiktuxc" "nou"
    "ABEKMHOPCTX" "ABEZHIKMNOPTYX" "''''"
)
# Build the source->ASCII map, then add one-to-many groups below.
CONF = dict(zip(_CONF_SRC, _CONF_DST))
# Assorted Unicode dashes/minus signs -> ASCII hyphen.
CONF.update({c: "-" for c in "‐‑‒–—―−⁃﹘﹣－֊־"})
# Unicode colon look-alikes -> ASCII colon (the replace() drops a stray Georgian letter).
CONF.update({c: ":" for c in "꞉ː∶։：ⴀ".replace("ⴀ", "")})
# Unicode full stops / middle dots -> ASCII period.
CONF.update({c: "." for c in "․‧。．﹒܁܂"})
# Division-slash and fullwidth slash variants -> ASCII slash.
CONF.update({c: "/" for c in "∕⁄／⧸"})
# Fullwidth / small commercial-at -> ASCII at-sign.
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

    # Walk the raw text once, deciding per character what (if anything) enters the view.
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
# Canonicalise a host/literal name: lowercase, trim, and collapse runs of
# '-', '_', whitespace and apostrophes to a single '-' so variants compare equal.
def _norm_name(v: str) -> str:
    return re.sub(r"[-_\s']+", "-", v.strip().lower())


# Read and parse a JSON data file; any I/O or parse failure becomes ScrubError
# (no partial data is ever used - callers fail closed).
def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ScrubError("cannot read %s (%s)" % (path.name, type(exc).__name__))


def load_names(data_dir: Path) -> Tuple[List[str], List[str]]:
    """(host names, literals). Any of the three files missing/corrupt, or zero hosts -> ScrubError (fail closed)."""
    # Hosts are normalised names; literals are exact strings kept verbatim (trimmed).
    hosts: set = set()
    literals: set = set()

    # Names shorter than 3 chars are ignored: too short, they would match inside ordinary words.
    def add(v):
        if isinstance(v, str) and len(v.strip()) >= 3:
            hosts.add(_norm_name(v))

    # 1) public_release_redactions.json: extra hosts plus literal identifiers.
    red = _read_json(data_dir / "public_release_redactions.json")
    if not isinstance(red, dict):
        raise ScrubError("redactions file has wrong shape")
    for x in red.get("hosts", []) if isinstance(red.get("hosts"), list) else []:
        add(x)
    for x in red.get("literals", []) if isinstance(red.get("literals"), list) else []:
        if isinstance(x, str) and x.strip():
            literals.add(x.strip())
    # 2) fleet_roles.json: host keys, their aliases and callsigns.
    fr = _read_json(data_dir / "fleet_roles.json")
    if not isinstance(fr, dict) or not isinstance(fr.get("hosts"), dict):
        raise ScrubError("fleet_roles file has wrong shape")
    for k, v in fr["hosts"].items():
        add(k)
        if isinstance(v, dict):
            for a in v.get("aliases", []) if isinstance(v.get("aliases"), list) else []:
                add(a)
            add(v.get("callsign"))
    # 3) retired_hosts.json: former hosts (dicts with aliases/callsign, or bare strings).
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
    # An empty list would silently disable host scrubbing, so refuse to run.
    if not hosts:
        raise ScrubError("no host names loaded")
    # Longest names first so longer names win over their own prefixes; ties alphabetical for determinism.
    return sorted(hosts, key=lambda s: (-len(s), s)), sorted(literals, key=lambda s: (-len(s), s))


# Compile a case-insensitive regex for one name. Name tokens may be separated by any
# mix of '-', '_', space, apostrophe; a long plural-looking token ending in 's' also matches
# possessive/plural forms ("alphas" ~ "alpha's"). Lookarounds require a non-alphanumeric
# boundary so names are not matched inside bigger words.
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

# Hex digit class used by the MAC patterns.
HEX = "[0-9a-f]"
# Separator between MAC octets: ':' or '-' (with optional spaces), tabs/spaces, or a newline.
MAC_SEP = r"(?:\s*[:\-]\s*|[ \t]+|\r?\n)"
# 6 to 8 hex-pair groups (EUI-48 plus EUI-64 style) with the separators above, not embedded in longer hex.
MAC_RX = re.compile(r"(?<!%s)%s{2}(?:%s%s{2}){5,7}(?!%s)" % (HEX, HEX, MAC_SEP, HEX, HEX), re.I)
# Cisco dotted form: three 4-hex-digit groups joined by '.'.
MAC_CISCO = re.compile(r"(?<!%s)%s{4}(?:\s*\.\s*%s{4}){2}(?!%s)" % (HEX, HEX, HEX, HEX), re.I)
# Bare 12-hex-digit run (no separators). Broad on purpose; fail-closed bias.
MAC_RUN = re.compile(r"(?<!%s)%s{12}(?!%s)" % (HEX, HEX, HEX), re.I)
# mDNS-style '<name>.local' hostnames (but see Detector.find: localhost.local is exempt).
LOCAL_RX = re.compile(r"(?i)(?<![a-z0-9-])[a-z0-9][a-z0-9-]{1,40}\.local(?![a-z0-9-])")
# Tail of a path: further '/segment' parts up to whitespace or a closing/quote character.
_PTAIL = r"(?:/[^\s\\'\"<>;,)\]}|]*)*"
# Filesystem paths that identify a user/machine: Unix home/mount roots, Windows C:\Users,
# '~user/', and spoken forms like 'users then bob'. Alternatives are concatenated below.
HOME_RX = re.compile(
    r"(?i)(?:/Users|/home|/srv|/Volumes|/mnt|/media|/root)/[ \t]{0,3}[^\s/\\'\"<>:;,)\]}|]+" + _PTAIL
    + r"|(?<![A-Za-z0-9])[A-Z]:\\Users\\[^\s/\\'\"<>:;,)\]}|]+(?:\\[^\s\\'\"<>;,)\]}|]*)*"
    + r"|(?<![\w~])~[A-Za-z_][\w.\-]*(?=/)" + _PTAIL
    + r"|\busers[ \t]+(?:then|slash|and then|->)[ \t]+[\w.\-]+"
)
# Permissive e-mail matcher with bounded lengths (keeps regex time linear).
EMAIL_RX = re.compile(r"[A-Za-z0-9._%+\-]{1,128}@[A-Za-z0-9][A-Za-z0-9.\-]{0,255}")
# A dot in an IP, optionally 'defanged' as [.] or (.).
DOT = r"(?:\.|[\[\(]\.[\]\)])"
# Dotted-quad IPv4 (defanged dots allowed); range/privacy is checked in code afterwards.
IPV4_RX = re.compile(r"(?<![\d.])(\d{1,3})%s(\d{1,3})%s(\d{1,3})%s(\d{1,3})(?!\d)" % (DOT, DOT, DOT))
# IPv6 link-local (fe80::/10) and unique-local (fc00::/7) addresses only; public v6 is left alone.
IPV6_RX = re.compile(r"(?i)(?<![0-9a-f:])(?:fe[89ab][0-9a-f]|f[cd][0-9a-f]{2})(?::[0-9a-f]{0,4}){2,7}(?![0-9a-f:])")
# 'password = value' / 'token: value' / 'api key is value' style assignments. The named
# group 'v' captures the value (quoted or bare) so the whole key+value is scrubbed.
KV_RX = re.compile(
    r"(?i)(?<![a-z0-9])(?:password|passwd|passphrase|pwd|pw|pass|secret|token|api[_\- ]?key|apikey|"
    r"access[_\- ]?key|private[_\- ]?key|auth|credential|credentials)[\"']?"
    r"(?:[ \t]*[:=][ \t]*|[ \t]+(?:is|was)[ \t]+)"
    r"(?P<v>\"[^\"\n]*\"|'[^'\n]*'|[^\s\"']\S*)"
)
# Ordered list of high-precision credential shapes. Each is matched over the whole view:
# PEM private-key blocks, Bearer tokens, sk- keys, GitHub tokens, AWS key ids, Google keys,
# Slack tokens, JWTs, SSH public keys, URLs with embedded user:password@, long hex digests,
# and truncated (ellipsised) prefixes of those key shapes.
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
# Any 32+ char run of base64/url-safe characters; filtered by _long_token_ok().
LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")
# Candidate base64 / base64url blob (8+ chars); decoded and rescanned by _blob_hits.
B64_RX = re.compile(r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{8,}={0,6}")
# Base64 wrapped across several lines (e.g. MIME or PEM bodies).
B64_MULTI = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/=]{16,}[ \t]*\r?\n[ \t]*)+[A-Za-z0-9+/=]{4,}")
# Even-length hex run of 8+ digits; decoded and rescanned for hidden secrets.
HEXBLOB = re.compile(r"(?<![0-9a-f])(?:[0-9a-f]{2}){4,}(?![0-9a-f])", re.I)


# Heuristic to cut false positives for LONG_TOKEN: require a digit, then accept
# either a very long token with no '/' (not a path) or one with mixed case or '+'/'=' (base64-ish).
def _long_token_ok(tok: str) -> bool:
    if not any(c.isdigit() for c in tok):
        return False
    if len(tok) >= 40 and "/" not in tok:
        return True
    return (any(c.isupper() for c in tok) and any(c.islower() for c in tok)) or any(c in "+=" for c in tok)


# True for private/non-routable IPv4 ranges given the first two octets:
# 10/8, 172.16/12, 192.168/16, link-local 169.254/16 and CGNAT 100.64/10.
def _private_ipv4(a: int, b: int) -> bool:
    return (
        a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
        or (a == 169 and b == 254) or (a == 100 and 64 <= b <= 127)
    )


# Fraction of characters that are printable text (newline/tab/CR count as printable).
# Used to tell decoded text from decoded binary noise.
def _printable_ratio(s: str) -> float:
    return sum(1 for c in s if c.isprintable() or c in "\n\t\r") / len(s) if s else 0.0


# Return every plausible byte-decoding of a token: base64 (standard and url-safe),
# base32, and hex. Failures are skipped, so the list may be empty.
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


# A detection: (start, end) in VIEW coordinates, category, and a dedup key (key=None means 'derive one').
Span = Tuple[int, int, str, str]  # (start, end) in view coordinates, category, key

# Canonical 8-4-4-4-12 UUID, not embedded in longer hex.
UUID_RX = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])")
# UUID without boundary checks; used on 'joined' variants where separators were stripped.
UUID_J = re.compile(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# Key-shape patterns with BOUNDED lengths for use on obfuscated/joined text, where an
# unbounded match would swallow neighbouring characters. Index 2 (sk-) and 3 (AKIA) are
# referenced by position in Detector._extra - do not reorder.
PREFIX_RES = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,36}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,60}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{10,48}"),
    re.compile(r"(?i)akia[0-9a-z]{16}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{30,40}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,60}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*"),
]
# Translate tables that delete characters used to split a secret across pieces
# (whitespace, quotes, '+', '|', ...). JOIN_DROP2 also drops structural punctuation.
JOIN_DROP = dict.fromkeys(map(ord, " \t\r\n\"'`+|*>,\\"), None)
JOIN_DROP2 = dict(JOIN_DROP)
JOIN_DROP2.update(dict.fromkeys(map(ord, ":{}[]=-;()"), None))
# ROT13 translation table (letters only) for detecting rot13-obfuscated secrets/names.
ROT13 = {}
for _i, _c in enumerate("abcdefghijklmnopqrstuvwxyz"):
    ROT13[ord(_c)] = "abcdefghijklmnopqrstuvwxyz"[(_i + 13) % 26]
    ROT13[ord(_c.upper())] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[(_i + 13) % 26]

# Leet-speak digit->letter maps ('1' read as i vs l) for names written like 'h0st'.
LEET_I = str.maketrans("4301578", "aeoistb")
LEET_L = str.maketrans("4301578", "aeolstb")
# ROT47 over printable ASCII 33..126.
ROT47 = {c: chr(33 + ((c - 33 + 47) % 94)) for c in range(33, 127)}
# One IPv4 octet in decimal or 0x-hex form.
_OCT = r"(?:0x[0-9a-f]{1,2}|\d{1,3})"
# Octet separators seen in obfuscated IPs: '.', ',', '-', spaces, the word 'dot', or [.]/(.).
_SEPI = r"(?:[ \t\r\n]{0,3}\.[ \t\r\n]{0,3}|,|-|[ \t]+dot[ \t]+|[\[\(]\.[\]\)])"
# Four octets (decimal/hex) joined by loose separators -> obfuscated IPv4.
IPX_RX = re.compile(r"(?i)(?<![\w.])(%s)(?:%s(%s)){3}(?![\w])" % (_OCT, _SEPI, _OCT))
# Splits a matched IPX_RX string back into its octet tokens.
IPX_PARTS = re.compile(r"(?i)0x[0-9a-f]{1,2}|\d{1,3}")
# IPv4 written as one 0x-prefixed 32-bit hex number.
IP_HEXINT = re.compile(r"(?i)(?<![\w.])0x([0-9a-f]{8})(?![\w])")
# IPv4 written as one 8-10 digit decimal integer.
IP_DECINT = re.compile(r"(?<![\w.\-])(\d{8,10})(?![\w])")
# IPv4-mapped IPv6 form ::ffff:a:b.
IP_MAPPED = re.compile(r"(?i)(?<![0-9a-f:])::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})(?![0-9a-f:])")
# E-mail spelled out as 'user [at] host dot com' (several bracket/space styles).
EMAIL_AT = re.compile(
    r"(?i)(?<![\w.+\-])[\w.+\-]{1,64}[ \t]{0,3}(?:[\[\(\{<]at[\]\)\}>]|[ \t]at[ \t])[ \t]{0,3}[\w\-]{1,63}"
    r"(?:[ \t]{0,3}(?:\.|[\[\(\{<]dot[\]\)\}>]|[ \t]dot[ \t])[ \t]{0,3}[\w\-]{1,63})+"
)
# Marker tokens ('[at]', '(dot)', ' dot ') - a match must contain one, so plain prose 'a at b' is ignored.
EMAIL_AT_BR = re.compile(r"(?i)[\[\(\{<]at[\]\)\}>]|[\[\(\{<]dot[\]\)\}>]|\sdot\s")
# Generic NAME = VALUE / NAME: VALUE finder; group n is the name, v the value. The name is
# then tested by _kw_name() to decide whether the value is a secret.
ASSIGN_RX = re.compile(
    r"(?<![A-Za-z0-9_])(?P<n>[A-Za-z_][A-Za-z0-9_.\-]{0,60})[\"']?\s{0,40}[:=]\s{0,40}"
    r"(?P<v>\"[^\"\n]*\"|'[^'\n]*'|[^\s\"']\S*)"
)
# Continuation word after an assignment value (secrets with spaces, e.g. 'pass: foo 123').
ASSIGN_TAIL = re.compile(r"[ \t]+(\S+)")
# Candidate tokens for the character-class entropy test.
ENT_RX = re.compile(r"[^\s\"'<>`|]{8,}")
# A 6-byte MAC encoded as 8 base64 chars appearing right after a hint word like 'mac'.
B64_MAC_RX = re.compile(r"(?i)\b(?:mac|hwaddr|hw|ether|bssid|address)\b[^\n]{0,12}?(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{8})(?![A-Za-z0-9+/=])")
# Secret split into 8+ space-separated chunks.
CHUNK_RX = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/=]{4,}[ \t]{1,2}){7,}[A-Za-z0-9+/=]{4,}")
# ARP-table style MACs where octets may have 1 digit (e.g. 0:1a:2b:3:4:5).
ARP_RX = re.compile(r"(?i)(?<![0-9a-z:\-])[0-9a-f]{1,2}(?:[:\-][0-9a-f]{1,2}){5}(?![0-9a-z])")
# MAC as a single decimal integer following a hint word.
MAC_INT_RX = re.compile(r"(?i)\b(?:mac|hwaddr|ether|bssid|address)\b[^\n]{0,24}?(?<![\w.])(\d{9,15})(?![\w.])")
# Alphanumeric token splitter.
TOK_RX = re.compile(r"[0-9A-Za-z]+")
# Substrings that mark a variable name as credential-bearing wherever they appear.
_KW_LONG = ("password", "passwd", "passphrase", "secret", "token", "apikey", "credential", "privatekey")
# Short words that mark a name as a credential only when they are a whole '_'/'-'/'.' part (avoids 'monkey').
_KW_PARTS = {"auth", "pass", "pw", "pwd", "key", "cred", "creds", "login", "pin", "passcode", "bearer"}
# Symbol characters counted by the entropy heuristic.
_SYM = set("!@#$%^&*?~")
# Hex digit characters.
_HEXC = set("0123456789abcdefABCDEF")


# Left word boundary: position s is at the start or preceded by a non-alphanumeric.
def _bl(v: str, s: int) -> bool:
    return s <= 0 or not v[s - 1].isalnum()


# Right word boundary: position e is at the end or followed by a non-alphanumeric.
def _br(v: str, e: int) -> bool:
    return e >= len(v) or not v[e].isalnum()


# True if a variable name looks credential-related (password, token, ...key, auth, pw ...).
def _kw_name(n: str) -> bool:
    ln = n.lower()
    flat = re.sub(r"[_.\-]", "", ln)
    if any(k in flat for k in _KW_LONG):
        return True
    if flat.endswith("key") and len(flat) > 3:
        return True
    return any(p in _KW_PARTS for p in re.split(r"[_.\-]", ln))


# ENV_STYLE values count as secret-like if 8+ chars, no '/', and mixing letters with digits.
def _env_value_entropy(val: str) -> bool:
    return (len(val) >= 8 and "/" not in val and any(c.isdigit() for c in val) and any(c.isalpha() for c in val))


# Password-like token: 8+ chars, no '/', containing upper, lower, digit AND a symbol.
def _entropy_token(tok: str) -> bool:
    if len(tok) < 8 or "/" in tok:
        return False
    return (any(c.isupper() for c in tok) and any(c.islower() for c in tok) and any(c.isdigit() for c in tok)
            and any(c in _SYM for c in tok))


# Dotted string if the four ints are valid octets of a PRIVATE address, else None.
def _ip_from_ints(o: List[int]) -> Optional[str]:
    if len(o) == 4 and all(0 <= x <= 255 for x in o) and _private_ipv4(o[0], o[1]):
        return ".".join(map(str, o))
    return None


# Decode obfuscated octets (decimal/hex). Tries forward order first, then the reversed
# (digits and order reversed) form used by some obfuscations; None if not a private IP.
def _decode_ip_parts(parts: List[str]) -> Optional[str]:
    o = [int(p, 16) if p.lower().startswith("0x") else int(p) for p in parts]
    r = _ip_from_ints(o)
    if r:
        return r
    if all(not p.lower().startswith("0x") for p in parts):
        return _ip_from_ints([int(p[::-1]) for p in reversed(parts)])
    return None


# True if a 32-bit integer corresponds to a private IPv4 address.
def _int_private(n: int) -> bool:
    return _private_ipv4((n >> 24) & 255, (n >> 16) & 255) and n < (1 << 32)


# Build an alternate detection view of text: optionally drop characters (and non-alnum
# non-ASCII), apply ROT13, and/or reverse. Returns the view and an index list mapping each view
# position to the original offset so matches can be projected back.
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


# Merge spans into disjoint sorted intervals; returns parallel lists of starts and ends.
def _cover_index(spans: List[Span]):
    iv = sorted((s, e) for s, e, _, _ in spans)
    merged: List[List[int]] = []
    for s, e in iv:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    return [m[0] for m in merged], [m[1] for m in merged]


# Binary-search whether pos falls inside an interval from _cover_index.
def _covered(cov, pos: int) -> bool:
    import bisect
    starts, ends = cov
    i = bisect.bisect_right(starts, pos) - 1
    return i >= 0 and pos < ends[i]


# Finds sensitive spans in a normalised view.
#
# Holds precompiled host/literal regexes. find() runs the direct patterns plus (at depth 0)
# the obfuscation-aware _extra() pass, and recursively inspects decoded blobs.
class Detector:
    # Pre-compile one regex per host/literal once, up front: find() runs per message
    # and recompiling inside it would dominate the cost. The bool marks hosts that are
    # also ordinary distro words and so need a context check before being treated as a host.
    def __init__(self, hosts: Optional[Sequence[str]] = None, literals: Optional[Sequence[str]] = None):
        self.hosts = [(h, _name_rx(h), h in DISTRO_WORDS) for h in (hosts or [])]
        self.literals = [(l, _name_rx(l)) for l in (literals or [])]

    # Return every Span detected in v. Overlaps are allowed here; _merge() resolves them.
    #
    # depth counts recursion into decoded base64/hex content (max 3 levels).
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

    # Slower, obfuscation-aware detection (only run at depth 0): split/reversed/rot13 key
    # shapes, leet and reversed host names, encoded IPs and MACs, keyword assignments,
    # high-entropy tokens, chunked secrets and spelled-out e-mails.
    def _extra(self, v: str, plain: List[Span]) -> List[Span]:
        out: List[Span] = []
        cov = _cover_index(plain) if plain else ([], [])
        n = len(v)

        # Collect a span in the local result list.
        def add(lo, hi, cat, key):
            out.append((lo, hi, cat, key))

        # Extend a secret's end over up to 40 trailing key characters, since bounded PREFIX_RES
        # matches may stop short of the real token end.
        def sec_extend(hi):
            k = 0
            while hi < n and k < 40 and (v[hi].isalnum() or v[hi] in "-_"):
                hi += 1
                k += 1
            return hi

        # Alternate views: (view, direction). 'f' = forward order (left boundary is checked),
        # 'r' = reversed text (right boundary is checked in original coordinates).
        variants = [
            (_variant(v, JOIN_DROP), "f"), (_variant(v, None, rev=True), "r"),
            (_variant(v, None, rot=True), "f"), (_variant(v, JOIN_DROP, rev=True), "r"),
            (_variant(v, JOIN_DROP, rot=True), "f"), (_variant(v, None, rev=True, rot=True), "r"),
            (_variant(v, JOIN_DROP2), "f")
        ]
        for vi, ((x, xi), direction) in enumerate(variants):
            if not x:
                continue
            # Pattern set per view: key shapes and e-mails everywhere; UUIDs only in view 0.
            rules = list(PREFIX_RES) + [EMAIL_RX]
            if vi == 0:
                rules.append(UUID_J)
            # View 6 (aggressive punctuation dropping) omits the sk- rule: too many false matches.
            if vi == 6:
                rules = [r for r in PREFIX_RES if r is not PREFIX_RES[2]]
            for rx in rules:
                for m in rx.finditer(x):
                    # Project the match back to original offsets through the index map.
                    seg = xi[m.start():m.end()]
                    lo, hi = min(seg), max(seg) + 1
                    # AKIA ids (case-insensitive here) must contain a digit to count.
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
                    # Skip if already caught by the plain pass (IDs excepted so keys still dedupe consistently).
                    if _covered(cov, lo) and cat != "ID":
                        continue
                    add(lo, hi, cat, key or ("sec:" + v[lo:hi]))

        # Name targets for squashed matching: (alnum-only name, category, key, is_distro, forward).
        # Hosts of 5+ chars are also tried reversed and in rot13; literals of 4+ chars as IDs.
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

        # Search squashed (alnum-only, lowercased) text for each target, mapping hits back to the
        # raw offsets through cmap. Leet tables are only applied to forward targets.
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

        # Plain, then both leet readings of the digits.
        scan_names(v, [None, LEET_I, LEET_L])
        # ROT47 view is only worth scanning if the text has printable punctuation.
        if any(33 <= ord(c) <= 126 and not c.isalnum() for c in v):
            scan_names(v.translate(ROT47), [None], only_fwd=True)

        # Obfuscated IPs: loose separators, hex octets, whole-number hex/decimal, v4-mapped v6.
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

        # Detect MACs spelled as a run of separate 1/2/4-digit hex tokens (e.g. split by words/spaces):
        # consecutive same-length tokens, gaps of at most 6 chars, total 12+ hex digits, at least one a-f.
        run: List[Tuple[int, int, str]] = []

        # Emit the accumulated hex run as a MAC if it is long enough, then reset.
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

        # Detect MACs written as 6+ decimal bytes (0-255) separated by one of : , . -;
        # at least two values must be >= 100 so ordinary small-number lists are ignored.
        dec: List[Tuple[int, int, str]] = []

        # Emit the accumulated decimal run as a MAC if it qualifies, then reset.
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

        # ARP-style MACs must contain a hex letter, otherwise they look like times/versions.
        for m in ARP_RX.finditer(v):
            if any(c in "abcdefABCDEF" for c in m.group(0)):
                add(m.start(), m.end(), "MAC", "mac:" + "".join(x.zfill(2) for x in re.split(r"[:\-]", m.group(0).lower())))
        # Integer form must fit in 48 bits.
        for m in MAC_INT_RX.finditer(v):
            if int(m.group(1)) < (1 << 48):
                add(m.start(1), m.end(1), "MAC", "mac:int" + m.group(1))
        # Base64 MAC: must decode to exactly 6 bytes and look mixed-case/digit (not a plain word).
        for m in B64_MAC_RX.finditer(v):
            t = m.group(1)
            if any(c.isdigit() for c in t) or any(c.isupper() for c in t[1:]):
                try:
                    if len(base64.b64decode(t)) == 6:
                        add(m.start(1), m.end(1), "MAC", "mac:b64" + t)
                except (binascii.Error, ValueError):
                    pass

        # Keyword assignments: scrub the value when the name is credential-like, or an
        # UPPER_SNAKE env var whose value has entropy. Up to three following words are absorbed
        # when they look secret-like (digits/symbols/dashes).
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
        # Standalone password-looking tokens.
        for m in ENT_RX.finditer(v):
            tok = m.group(0)
            if _entropy_token(tok):
                add(m.start(), m.end(), "SECRET", "sec:" + tok)
        # Chunked secrets: 48+ chars total and at least 60% of chunks mixed-case.
        for m in CHUNK_RX.finditer(v):
            toks = m.group(0).split()
            if sum(len(t) for t in toks) < 48:
                continue
            mixed = sum(1 for t in toks if any(c.isupper() for c in t[1:]) and any(c.islower() for c in t))
            if mixed * 10 >= len(toks) * 6 and any(c.isdigit() for c in m.group(0)):
                add(m.start(), m.end(), "SECRET", "sec:" + m.group(0))

        # Spelled-out e-mails are only reported if an explicit at/dot marker is present.
        for m in EMAIL_AT.finditer(v):
            g = m.group(0)
            if EMAIL_AT_BR.search(g):
                add(m.start(), m.end(), "EMAIL", "email:" + re.sub(r"[^a-z0-9]", "", g.lower()))
        return out

    @staticmethod
    # For span [s,e): an all-lowercase distro word is accepted as a host; a capitalised one
    # needs nearby host-ish context (24 chars either side).
    def _distro_ok(v: str, s: int, e: int) -> bool:
        raw = v[s:e]
        if raw == raw.lower():
            return True
        ctx = v[max(0, s - 24):s] + " " + v[e:e + 24]
        return bool(HOST_CONTEXT.search(ctx))

    @staticmethod
    # Regex-match version of _distro_ok with identical semantics.
    def _distro_is_host(v: str, m) -> bool:
        raw = m.group(0)
        if raw == raw.lower():
            return True
        ctx = v[max(0, m.start() - 24):m.start()] + " " + v[m.end():m.end() + 24]
        return bool(HOST_CONTEXT.search(ctx))

    # Decode a candidate blob and rescan the plaintext. Short (<24) tokens must decode to
    # printable ASCII to avoid random-decode noise; a decoded PEM key is an immediate hit;
    # otherwise the decoded text is normalised and fed back through find() one level deeper.
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

# In-memory placeholder table kept only on the local machine (see section note above).
#
# by_key: (category, key) -> placeholder, so identical values reuse one placeholder.
# values: placeholder -> (category, real value). counters: next index per category.
class RelayMap:
    """LOCAL ONLY. placeholder <-> real value. Never printed, never in a report."""

    # by_key: (category, normalised value) -> placeholder, so the same value always
    # maps to the same <CAT-n>. values: placeholder -> (category, real value), the
    # only place real values live. counters: next number per category.
    def __init__(self):
        self.by_key: Dict[Tuple[str, str], str] = {}
        self.values: Dict[str, Tuple[str, str]] = {}
        self.counters: Dict[str, int] = {}

    # Never expose real values - only a count.
    def __repr__(self):
        return "<RelayMap entries=%d (values hidden)>" % len(self.values)

    # str() must be just as safe as repr().
    __str__ = __repr__

    # Return the placeholder for (cat, key), allocating <CAT-n> on first use.
    def placeholder(self, cat: str, key: str, value: str) -> str:
        ph = self.by_key.get((cat, key))
        if ph is None:
            n = self.counters.get(cat, 0) + 1
            self.counters[cat] = n
            ph = "<%s-%d>" % (cat, n)
            self.by_key[(cat, key)] = ph
            self.values[ph] = (cat, value)
        return ph

    # Subset of the table safe to restore (HOST and PATH only).
    def restorable(self) -> Dict[str, str]:
        return {p: v for p, (c, v) in self.values.items() if c in RESTORABLE}

    # Serialise only restorable entries (sorted keys: deterministic output).
    def dump_restorable(self) -> str:
        return json.dumps(self.restorable(), sort_keys=True)

    @classmethod
    # Rebuild a map from dump_restorable() output. Entries whose placeholder is not a
    # strict <HOST-n>/<PATH-n> with a string value are ignored; counters resume past the max index.
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


# Cache of compiled Detectors per data directory (compiling many regexes is costly).
_DET_CACHE: Dict[str, Detector] = {}


# Return the cached Detector for data_dir, loading names on first use.
def _detector(data_dir: Path) -> Detector:
    k = str(data_dir)
    if k not in _DET_CACHE:
        hosts, lits = load_names(data_dir)
        _DET_CACHE[k] = Detector(hosts, lits)
    return _DET_CACHE[k]


# Collapse overlapping spans: widest first, highest-priority category wins, and a single
# shared key is kept only if every merged span agreed on it and no widening happened
# (otherwise key is None and the caller derives one from the merged text).
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


# Run detection on the normalised view of text (used for the verification passes).
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

# Core scrub. Returns (clean_text | None, report). None means fail-closed.
#
# Steps: neutralise forged placeholders, normalise, detect, merge, substitute, then verify
# the result three independent ways (re-detect, leaked mapped values, decoded views).
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

    # Defuse placeholder-lookalikes in the input (count reported).
    escaped = len(PH_ESC_RX.findall(text))
    text = PH_ESC_RX.sub("‹", text)
    view, idx = normalise(text)
    merged = _merge(det.find(view))
    counts: Dict[str, int] = {}
    pieces: List[str] = []
    pos = 0
    # Replace each merged span with a placeholder, mapping view offsets back to raw offsets.
    for s, e, cat, key in merged:
        o0, o1 = idx[s], idx[e - 1] + 1
        # Guard against overlap caused by the index mapping.
        if o0 < pos:
            o0 = pos
        value = view[s:e]
        # No explicit key: derive one from category + normalised value so equal values share a placeholder.
        k = key if key else cat.lower() + ":" + re.sub(r"[-_\s']+", "-", value.lower())
        ph = mapping.placeholder(cat, k, value)
        counts[cat] = counts.get(cat, 0) + 1
        pieces.append(text[pos:o0])
        pieces.append(ph)
        pos = o1
    pieces.append(text[pos:])
    clean = "".join(pieces)

    # Check 1: anything still detectable means a leak - withhold all output.
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

    # Check 2: no previously mapped non-host value may still appear in the output.
    # MACs are compared as bare hex so separators/case cannot hide them; HOST is excluded
    # because short host names legitimately occur in text.
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

    # Check 3: re-scan URL-unquoted, HTML-unescaped and unicode-escape-decoded versions of the output.
    views = {urllib.parse.unquote(clean), html.unescape(clean)}
    if "\\u" in clean or "\\x" in clean:
        try:
            views.add(codecs.decode(clean.encode("utf-8", "ignore"), "unicode_escape"))
        except Exception:
            return None, {
                "ok": False, "reason": "undecodable-escapes", "counts": counts,
                "placeholders_escaped": escaped
            }
    # Unchanged views were already checked above.
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


# Scrub and also return the RelayMap.
#
# Returns (clean_text | None, report, RelayMap). Any exception becomes a failed report.
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
    # Catch everything (including RecursionError/MemoryError) so no partial text escapes.
    except BaseException as exc:  # fail closed on anything, incl. RecursionError/MemoryError
        if isinstance(exc, KeyboardInterrupt):
            raise
        return None, {"ok": False, "reason": "internal-error: %s" % type(exc).__name__, "counts": {}}, m
    return clean, rep, m


# Convenience wrapper over scrub_with_map that drops the map.
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


# Replace <HOST-n>/<PATH-n> placeholders in a model reply with local real values.
def restore_inbound(text: str, mapping: RelayMap) -> str:
    """Swap <HOST-n>/<PATH-n> back to real values (single pass, exact ASCII placeholders only).

    Secrets, MACs, IPs, emails and IDs are NEVER restored.
    """
    if not isinstance(text, str):
        raise TypeError("text required")
    table = mapping.restorable()

    # Unknown placeholders are left untouched.
    def rep(m):
        return table.get(m.group(0), m.group(0))

    return re.sub(r"<(?:HOST|PATH)-\d+>", rep, text)


# --------------------------------------------------------------------------- CLI
# Write data to a file created with mode 0600 (owner-only), refusing to follow symlinks.
def _write_private(path: str, data: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(data)
    os.chmod(path, 0o600)


# CLI entry point. 'out' scrubs stdin to stdout (optionally saving the map); 'in' restores
# using a saved map. Exit codes: 0 ok, 1 failure (scrub refused / I/O), 2 usage error.
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
        # Report goes to stderr so stdout carries only scrubbed text.
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
