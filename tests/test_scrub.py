# Program: relayscrub - test_scrub.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Unit tests for scrub.py: checks that secrets, hosts, IPs, MACs, emails and paths (including disguised forms) are scrubbed, placeholders restore safely, and the scrubber fails closed.

"""Unit tests for outbound privacy scrubbing and restoration (run with `python -m unittest`).

Covers Unicode normalisation, secret-token detection, IPv4/IPv6/MAC formats, user paths,
emails, RelayMap restoration and the fail-closed verification. All secrets used here are fake."""

# Standard-library imports only: unittest is the test framework, subprocess runs the command line tool, tempfile makes scratch folders.
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
# Make the project importable even when tests run from another folder.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# R is the module under test.
import relayscrub.scrub as R

# Path of the scrub script, used by the command line tests.
SCRUB_SCRIPT = str(PROJECT_ROOT / "relayscrub" / "scrub.py")

# Build a throwaway data folder with fake host names so the tests never depend on real data files.
TMP = tempfile.mkdtemp()
D = Path(TMP)
(D / "public_release_redactions.json").write_text(json.dumps(
    {"hosts": ["zorbox", "fedora"], "literals": ["boss@example-corp.test", "example-corp.test"]}))
(D / "fleet_roles.json").write_text(json.dumps(
    {"hosts": {"Kraken-Prime": {"aliases": ["krk"], "callsign": "Leviathan"}, "mirandas-laptop": {}}}))
(D / "retired_hosts.json").write_text(json.dumps({"hosts": [{"host": "old-ironbox", "aliases": []}, "Dead_Node"]}))
# Fake MAC and fake API key used as test inputs.
MAC = "00:00:00:00:00:00"
KEYB = "sk-" + "A1b2C3d4E5f6G7h8I9j0"


def S(t, **kw):
    """Shortcut: scrub text using the test data folder."""
    return R.scrub_outbound(t, data_dir=D, **kw)


class TestScrub(unittest.TestCase):
    """Basic scrubbing behaviour tests."""
    def clean(self, t):
        """Scrub t, assert it succeeded and return (clean text, report)."""
        c, rep = S(t)
        self.assertTrue(rep["ok"], rep)
        return c, rep

    # Scrub t, then assert none of the `bad` strings (case-insensitive) remain; returns the cleaned text.
    def gone(self, t, *bad):
        """Scrub t and assert none of the given strings remain in the output (case-insensitive)."""
        c, rep = self.clean(t)
        for b in bad:
            self.assertNotIn(b.lower(), c.lower())
        return c

    # Tests for MAC address variants.
    # ---- MAC
    def test_mac_colon_upper_lower(self):
        """Check: mac colon upper lower."""
        self.gone("x %s y %s" % (MAC, MAC.upper()), MAC)

    def test_mac_separators(self):
        """Check: mac separators."""
        for m in ("00-00-00-00-00-00", "a483.e712.9c5f", "a4 83 e7 12 9c 5f", "00-00-00-00-00-00"):
            self.gone("mac " + m, "9c5f", "9c-5f", "9c 5f")

    def test_mac_12hex_run(self):
        """Check: mac 12hex run."""
        self.gone("id a483e7129c5f end", "a483e7129c5f")
        self.gone("0xA483E7129C5F", "a483e7129c5f")

    def test_mac_zero_width_inside(self):
        """Check: mac zero width inside."""
        self.gone("a4:83:e7\u200b:12:9c\u2060:5f", "12:9c")

    def test_mac_unicode_lookalike_separators(self):
        """Check: mac unicode lookalike separators."""
        self.gone("a4\uff1a83\ua789e7\u02d012:9c:5f", "9c:5f", "9c")
        c, _ = self.clean("a4\u201083\u201187\u201312\u20149c\u22125f")
        self.assertNotIn("9c", c)

    def test_mac_fullwidth_digits(self):
        """Check: mac fullwidth digits."""
        c, _ = self.clean("\uff41\uff14:83:e7:12:9c:5f")
        self.assertIn("<MAC-1>", c)

    def test_mac_split_across_lines(self):
        """Check: mac split across lines."""
        c, _ = self.clean("addr a4:83:e7:\n12:9c:5f ok")
        self.assertNotIn("9c", c)

    def test_mac_stable_placeholder(self):
        """Check: mac stable placeholder."""
        c, rep = self.clean("%s then %s and 00:00:00:00:00:00" % (MAC, MAC.upper().replace(":", "-")))
        self.assertEqual(c.count("<MAC-1>"), 2)
        self.assertIn("<MAC-2>", c)

    # ---- hosts
    def test_host_case_sep(self):
        """Check: host case sep."""
        c = self.gone("ssh KRAKEN_prime and kraken prime, Kraken-Prime; ZORBOX", "kraken", "zorbox")
        self.assertEqual(c.count("<HOST-1>"), 3)

    def test_host_alias_callsign_retired(self):
        """Check: host alias callsign retired."""
        self.gone("krk Leviathan old-ironbox dead node", "krk", "leviathan", "ironbox", "dead node")

    def test_host_apostrophe_and_possessive(self):
        """Check: host apostrophe and possessive."""
        self.gone("Miranda's laptop", "miranda")

    def test_host_not_substring(self):
        """Check: host not substring."""
        c, _ = self.clean("zorboxes and krkx are fine")
        self.assertIn("zorboxes", c)

    def test_host_lookalike_and_zw(self):
        """Check: host lookalike and zw."""
        self.gone("z\u043erb\u043ex and Kra\u200bken-Pri\u200dme", "zorbox", "kraken")

    def test_host_local_generic(self):
        """Check: host local generic."""
        c = self.gone("see host.example now", "weird-thing")

    def test_distro_capitalised_not_host(self):
        """Check: distro capitalised not host."""
        c, _ = self.clean("I installed Fedora last week")
        self.assertIn("Fedora", c)
        c, _ = self.clean("The Fedora release notes")
        self.assertIn("Fedora", c)

    def test_distro_lowercase_or_context_is_host(self):
        """Check: distro lowercase or context is host."""
        self.gone("ssh fedora now", "fedora")
        self.gone("the machine Fedora is down", "fedora")
        self.gone("ping Fedora", "fedora")

    def test_host_split_across_lines(self):
        """Check: host split across lines."""
        self.gone("mirandas-\nlaptop", "mirandas")

    # ---- IP / email / path
    def test_private_ips(self):
        """Check: private ips."""
        c = self.gone("10.1.2.3 172.20.0.9 192.168.1.50 169.254.1.1 100.101.2.3", "10.1.2.3", "192.168", "172.20", "100.101")
        c2, _ = self.clean("public 8.8.8.8 and 172.32.0.1 stay")
        self.assertIn("8.8.8.8", c2)
        self.assertIn("172.32.0.1", c2)

    def test_ip_obfuscated_and_ipv6(self):
        """Check: ip obfuscated and ipv6."""
        self.gone("192[.]168[.]1[.]5 and 192.168\u200b.1.6 and fd12:3456:789a::1 fe80::1ff:fe23", "192", "fd12", "fe80")

    def test_email(self):
        """Check: email."""
        self.gone("mail bob.smith+x@Corp-Mail.org please", "bob.smith")

    def test_literals(self):
        """Check: literals."""
        self.gone("write boss@example-corp.test or example-corp.test", "example-corp")

    def test_home_paths(self):
        """Check: home paths."""
        c = self.gone("cat /Users/jdoe/Documents/a.txt and /home/jdoe/x and C:\\Users\\jdoe\\f", "jdoe")
        self.assertNotIn("Documents", c)

    # ---- secrets
    def test_known_key_shapes(self):
        """Check: known key shapes."""
        t = "%s ghp_%s AKIAIOSFODNN7EXAMPLE Bearer abcdefgh12345678 xoxb-1234567890-abcdef" % (KEYB, "a" * 24)
        c = self.gone(t, KEYB, "ghp_", "AKIAABC", "abcdefgh1234", "xoxb")

    def test_password_forms(self):
        """Check: password forms."""
        c = self.gone('password=hunter2 pwd: s3cr3t "password": "my long pass" the password is swordfish api_key = "k k"',
                      "hunter2", "s3cr3t", "long pass", "swordfish", "k k")
        self.assertNotIn("hunter", c)

    def test_pem_and_ssh(self):
        """Check: pem and ssh."""
        pem = "-----BEGIN OPENSSH PRIVATE-KEY-----\nb3BlbnNzaC1rZXk\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
        c = self.gone("k:\n%s\nafter" % pem, "b3Blbn")
        self.assertIn("after", c)
        self.gone("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc user", "AAAAC3")

    def test_truncated_pem_blocks_rest(self):
        """Check: truncated pem blocks rest."""
        c, rep = self.clean("-----BEGIN RSA PRIVATE-KEY-----\nMIIEpAIBAAKCAQEA")
        self.assertNotIn("MIIE", c)

    def test_base64_of_secret(self):
        """Check: base64 of secret."""
        for payload in ("password=hunter2xyz", MAC, "ssh to zorbox", "token: abcdef"):
            b = base64.b64encode(payload.encode()).decode()
            c, rep = self.clean("blob " + b + " end")
            self.assertNotIn(b, c, payload)

    def test_base64_wrapped_lines_and_nested(self):
        """Check: base64 wrapped lines and nested."""
        b = base64.b64encode(b"the password is correcthorse and more text here").decode()
        c, _ = self.clean("x\n%s\n%s\ny" % (b[:20], b[20:]))
        self.assertNotIn(b[:20], c)
        bb = base64.b64encode(base64.b64encode(("zorbox " + MAC).encode())).decode()
        c, _ = self.clean(bb)
        self.assertNotIn(bb, c)

    def test_hex_encoded_blob(self):
        """Check: hex encoded blob."""
        h = ("password=pw1").encode().hex()
        c, _ = self.clean("h " + h)
        self.assertNotIn(h, c)

    def test_jwt_and_long_token(self):
        """Check: jwt and long token."""
        self.gone("eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4 Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A9", "eyJhbGci", "Zm9vYmFy")

    def test_readable_slug_survives(self):
        """Check: readable slug survives."""
        c, _ = self.clean("see /usr/local/lib/python3/site-packages and agent-asked-known-device-slug")
        self.assertIn("/usr/local/lib", c)

    # ---- attacker/placeholder tricks
    def test_injected_placeholders_defanged(self):
        """Check: injected placeholders defanged."""
        c, rep = self.clean("evil <HOST-1> and <secret-9> <PATH-2>")
        self.assertNotIn("<HOST-1>", c)
        self.assertEqual(rep["placeholders_escaped"], 3)
        m = R.RelayMap()
        c2, _ = S("real zorbox then <HOST-1>", mapping=m)
        back = R.restore_inbound(c2, m)
        self.assertEqual(back.count("zorbox"), 1)

    def test_restore_only_host_path(self):
        """Check: restore only host path."""
        m = R.RelayMap()
        c, rep = S("zorbox %s 10.0.0.9 a@b.org password=zzzz1 /Users/jdoe/x" % MAC, mapping=m)
        back = R.restore_inbound(c + " <SECRET-1> <MAC-1> <IP-1> <EMAIL-1>", m)
        self.assertIn("zorbox", back)
        self.assertIn("/Users/jdoe/x", back)
        for bad in ("zzzz1", MAC, "10.0.0.9", "a@b.org"):
            self.assertNotIn(bad, back)
        self.assertIn("<SECRET-1>", back)

    def test_restore_ignores_forged_and_lookalike(self):
        """Check: restore ignores forged and lookalike."""
        m = R.RelayMap()
        S("zorbox", mapping=m)
        self.assertEqual(R.restore_inbound("<HOST-7> <H\u043eST-1> <HOST-1>x", m).count("zorbox"), 1)

    def test_restore_single_pass(self):
        """Check: restore single pass."""
        m = R.RelayMap()
        m.values["<HOST-1>"] = ("HOST", "<HOST-2>")
        m.values["<HOST-2>"] = ("HOST", "zorbox")
        self.assertEqual(R.restore_inbound("<HOST-1>", m), "<HOST-2>")

    # ---- fail closed / report / map hygiene
    def test_fail_closed_missing_data(self):
        """Check: fail closed missing data."""
        c, rep = R.scrub_outbound("hello", data_dir=Path(TMP) / "nope")
        self.assertIsNone(c)
        self.assertFalse(rep["ok"])

    def test_fail_closed_corrupt_and_empty(self):
        """Check: fail closed corrupt and empty."""
        d = Path(tempfile.mkdtemp())
        for n in ("public_release_redactions", "fleet_roles", "retired_hosts"):
            (d / (n + ".json")).write_text("{not json")
        self.assertIsNone(R.scrub_outbound("hi", data_dir=d)[0])
        for n, v in (("public_release_redactions", {"hosts": []}), ("fleet_roles", {"hosts": {}}), ("retired_hosts", {"hosts": []})):
            (d / (n + ".json")).write_text(json.dumps(v))
        c, rep = R.scrub_outbound("hi", data_dir=d)
        self.assertIsNone(c)
        self.assertFalse(rep["ok"])

    def test_non_text_and_oversize_blocked(self):
        """Check: non text and oversize blocked."""
        self.assertIsNone(S(b"bytes")[0])
        self.assertIsNone(S(None)[0])
        self.assertIsNone(S("a" * (R.MAX_INPUT + 1))[0])

    def test_encoded_identifier_blocks(self):
        """Check: encoded identifier blocks."""
        c, rep = S("host %7a%6f%72box here")
        self.assertIsNone(c)
        self.assertEqual(rep["reason"], "encoded-identifier")

    # Simulates a detector that misses on its first run, to prove the second verification pass fails closed.
    def test_verification_catches_missed_hit(self):
        """Check: verification catches missed hit."""
        orig = R.Detector.find
        calls = {"n": 0}

        def flaky(self, v, depth=0):
            """Fake detector method that finds nothing on the first call and behaves normally afterwards."""
            calls["n"] += 1
            return [] if calls["n"] == 1 else orig(self, v, depth)
        # Temporarily replace the detector's find method, and always restore it in `finally`.
        R.Detector.find = flaky
        try:
            c, rep = S("zorbox")
        finally:
            R.Detector.find = orig
        self.assertIsNone(c)
        self.assertEqual(rep["reason"], "verification-failed")

    def test_report_has_no_values(self):
        """Check: report has no values."""
        c, rep = self.clean("zorbox %s password=hunter2 /Users/jdoe 10.2.3.4 a@b.org" % MAC)
        j = json.dumps(rep)
        for bad in ("zorbox", "a4:83", "hunter2", "jdoe", "10.2.3.4", "a@b.org"):
            self.assertNotIn(bad, j)
        self.assertEqual(set(rep["counts"]), {"HOST", "MAC", "SECRET", "PATH", "IP", "EMAIL"})

    def test_map_repr_hides_values(self):
        """Check: map repr hides values."""
        m = R.RelayMap()
        S("zorbox " + MAC, mapping=m)
        self.assertNotIn("zorbox", repr(m) + str(m))
        self.assertNotIn(MAC, m.dump_restorable())

    def test_deterministic_and_idempotent(self):
        """Check: deterministic and idempotent."""
        t = "zorbox %s 10.0.0.1 password=abc\u200b123" % MAC
        a, _ = S(t)
        b, _ = S(t)
        self.assertEqual(a, b)
        c2, rep = S(a)
        self.assertTrue(rep["ok"])
        self.assertNotIn("zorbox", c2)

    def test_clean_text_untouched(self):
        """Check: clean text untouched."""
        t = "Normal prose, code `x = 1`, version 1.2.3.4 and 8 bytes.\n"
        c, rep = self.clean(t)
        self.assertEqual(c, t)

    # ---- real data + CLI
    def test_real_data_loads_and_blocks_nothing_public(self):
        """Check: real data loads and blocks nothing public."""
        hosts, lits = R.load_names(R.DATA_DIR)
        self.assertTrue(hosts)
        c, rep = R.scrub_outbound("Fedora is a Linux distro; nothing private here.")
        self.assertTrue(rep["ok"], rep)
        self.assertIn("Fedora", c)
        for h in hosts:
            if h in R.DISTRO_WORDS:
                continue
            c, rep = R.scrub_outbound("run on %s today" % h.replace("-", " "))
            self.assertTrue(rep["ok"], rep)
            self.assertNotIn(h.replace("-", " "), c.lower())

    def test_cli_out_blocked_and_ok(self):
        """Check: cli out blocked and ok."""
        p = subprocess.run([sys.executable, "-I", SCRUB_SCRIPT, "out"], input=("hi %s" % MAC).encode(), capture_output=True)
        self.assertEqual(p.returncode, 0)
        self.assertNotIn(MAC.encode(), p.stdout + p.stderr)
        self.assertIn(b"<MAC-1>", p.stdout)
        p = subprocess.run([sys.executable, "-I", SCRUB_SCRIPT, "out"], input=b"\xff\xfe bad", capture_output=True)
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stdout, b"")

    # Runs the real command line tool: scrub with --map, check the map file is private (0o600), then restore with it.
    def test_cli_map_roundtrip_private_mode(self):
        """Check: cli map roundtrip private mode."""
        mp = os.path.join(tempfile.mkdtemp(), "m.json")
        p = subprocess.run([sys.executable, "-I", SCRUB_SCRIPT, "out", "--map", mp], input=b"on /Users/jdoe/x pw=abc12", capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(oct(os.stat(mp).st_mode & 0o777), "0o600")
        self.assertNotIn("abc12", Path(mp).read_text())
        q = subprocess.run([sys.executable, "-I", SCRUB_SCRIPT, "in", "--map", mp], input=p.stdout, capture_output=True)
        self.assertIn(b"/Users/jdoe/x", q.stdout)
        self.assertNotIn(b"abc12", q.stdout)


# --------------------------------------------------------------------------- obfuscation classes (Sentinel-2)
def J(*p):
    """Join the pieces into one string (lets fake secrets be written in parts)."""
    return "".join(p)


# Fake secrets built from pieces so this file itself does not contain a real-looking key.
FGH = J("gh", "p_", "Q7xK2mPz9LrT4vWb8NcY1dHs6JfGa3EoUiZ5")
FAK = J("AK", "IA", "ZQ7XK2MPZ9LRT4VW")
FSK = J("s", "k-", "projAb3dE6gH9jK2mN5pQ8sT1vX4zC7")
FPW = J("Zq9!fake", "Passw0rd-77")
FOCT = ["a4", "83", "e7", "1b", "5c", "9d"]
FUUID = J("7b3f9c1e-5a42-4d8e", "-9f10-2c6ab7e3d581")
FUSER = J("zqplant", "user")


def sq(x):
    """Squash a string to lower-case letters and digits only, for comparisons that ignore punctuation."""
    import re
    return re.sub(r"[^0-9a-z]", "", x.lower())


class TestObfuscation(unittest.TestCase):
    """Tests for disguised secrets: split, reversed, encoded, leetspeak and unusual notations."""
    def out(self, t):
        """Scrub t, assert success and return the cleaned text."""
        c, rep = S(t)
        self.assertTrue(rep["ok"], rep)
        return c

    def gone(self, t, *bad):
        """Scrub t and assert none of the given strings remain, ignoring punctuation and case."""
        c = self.out(t)
        for b in bad:
            self.assertNotIn(sq(b), sq(c), t)
        return c

    def test_key_prefixes_split_spaced_quoted(self):
        """Check: key prefixes split spaced quoted."""
        for t in ("tok %s\n%s" % (FGH[:12], FGH[12:]), "tok %s %s" % (FGH[:20], FGH[20:]),
                  'tok = "%s" + "%s"' % (FGH[:10], FGH[10:]), "tok " + " ".join(FGH),
                  "```\n%s\n%s\n```" % (FGH[:18], FGH[18:]),
                  "| a | %s |\n| b | %s |" % (FGH[:20], FGH[20:])):
            self.gone(t, FGH)
        self.gone("aws %s %s" % (FAK[:8], FAK[8:]), FAK)
        self.gone("aws " + FAK.lower(), FAK)
        self.gone("key %s\n%s" % (FSK[:8], FSK[8:]), FSK)

    def test_reversed_and_rot13(self):
        """Check: reversed and rot13."""
        import codecs
        self.gone("tok " + FGH[::-1], FGH, FGH[::-1])
        self.gone("tok " + codecs.encode(FGH, "rot13"), FGH)
        self.gone("host " + "zorbox"[::-1], "zorbox")
        self.gone("host " + codecs.encode("zorbox", "rot13"), "zorbox")
        self.gone("mail " + "boss@example-corp.test"[::-1], "bossexamplecorp")

    def test_host_names_spaced_split_encoded(self):
        """Check: host names spaced split encoded."""
        self.gone("host " + " ".join("zorbox"), "zorbox")
        self.gone("host zor\nbox", "zorbox")
        self.gone("```\nzor\nbox\n```", "zorbox")
        self.gone("host " + base64.b64encode(b"zorbox").decode(), "zorbox")
        self.gone("host " + b"zorbox".hex(), "zorbox")
        self.gone("host " + base64.b64encode(b"Kraken-Prime").decode(), "krakenprime")

    def test_distro_capitalised_prose_survives(self):
        """Check: distro capitalised prose survives."""
        c = self.out("Fedora 40 was released and I like Arch")
        self.assertIn("Fedora 40", c)
        self.assertNotIn("fedora", self.out("ssh fedora now").lower())
        self.assertNotIn("fedora", self.out("host F E D O R A").lower())

    def test_mac_notations(self):
        """Check: mac notations."""
        h = "".join(FOCT)
        for t in ("b " + ",".join(FOCT), "b " + ".".join(FOCT), "mac " + " ".join(h),
                  "| %s | %s |" % (":".join(FOCT[:3]), ":".join(FOCT[3:])),
                  "mac %s-%s:%s.%s %s_%s" % tuple(FOCT),
                  "mac " + ":".join(str(int(o, 16)) for o in FOCT)):
            c = self.out(t)
            self.assertIn("<MAC-", c, t)
        c = self.out("mac " + base64.b64encode(bytes.fromhex(h)).decode())
        self.assertIn("<MAC-", c)

    def test_ip_notations(self):
        """Check: ip notations."""
        n = (192 << 24) + (168 << 16) + (77 << 8) + 41
        for t in ("192,168,77,41", "192-168-77-41", "192 . 168 . 77 . 41", "192 dot 168 dot 77 dot 41",
                  "192.168.\n77.41", "41.77.168.192".replace("41.77.168.192", "14.77.861.291"), "0xc0.0xa8.0x4d.0x29",
                  str(n), "0xc0a84d29", "::ffff:c0a8:4d29", "[::ffff:c0a8:4d29]:22", "192[.]168[.]77[.]41"):
            c = self.out("ip " + t)
            self.assertTrue("<IP-" in c or "<MAC-" in c, t)
            self.assertNotIn("c0a8", c.lower())
            self.assertNotRegex(c, r"168|0xa8|4d29")
        c = self.out("sizes 10, 20, 30, 40 and 1.2.3.4 and 8080")
        self.assertNotIn("<IP-", c)

    def test_email_obfuscations(self):
        """Check: email obfuscations."""
        for t in ("ethan at twu dot software", "ethan [at] twu [dot] software", "ethan(at)twu.software",
                  "e t h a n @ t w u . s o f t w a r e", "boss at example-corp dot test"):
            c = self.out("mail " + t)
            self.assertNotIn("twu", c.lower().replace("twu.software", ""), t)
            self.assertNotIn("ethan", c.lower(), t)
            self.assertNotIn("boss", c.lower(), t)
        self.assertIn("look at example.com", self.out("look at example.com"))
        self.gone("user boss at example-corp dot test", "example-corp")
        self.gone("see e x a m p l e - c o r p . t e s t", "examplecorp")

    def test_env_and_prose_secrets(self):
        """Check: env and prose secrets."""
        for t in ('export API_SECRET_KEY="%s"' % FPW, "MYAPP_SESSIONKEY=%s" % FPW, "STRIPE_LIVE=%s" % FPW,
                  "DB_PASSWORD\n=\n%s" % FPW, "db:\n  password:\n    %s" % FPW,
                  "log in using %s as the admin login" % FPW, "my login code is " + FPW[::-1],
                  "password=%s %s" % (FPW[:8], FPW[8:]), "pw: %s" % FPW):
            self.gone(t, FPW, FPW[::-1], FPW[8:])
        c = self.out("LOG_LEVEL=debug PORT=8080 PATH=/usr/bin author: Bob key point")
        self.assertIn("LOG_LEVEL=debug", c)

    def test_pem_body_chunked(self):
        """Check: pem body chunked."""
        body = base64.b64encode(b"fake-private-key-material-for-tests-" * 6).decode()
        c = self.out(" ".join(body[i:i + 8] for i in range(0, len(body), 8)))
        self.assertNotIn(body[:40], sq(c).replace(" ", ""))
        self.assertNotIn(sq(body[:24]), sq(c))

    def test_uuid(self):
        """Check: uuid."""
        for t in (FUUID, FUUID.upper(), "{%s}" % FUUID, FUUID.replace("-", ""), "%s %s" % (FUUID[:18], FUUID[18:])):
            self.gone("uuid " + t, FUUID)

    def test_paths_tail_and_forms(self):
        """Check: paths tail and forms."""
        for t in ("at ~%s/x" % FUSER, "at /srv/%s/data" % FUSER, "at /Volumes/%s-ssd/x" % FUSER,
                  "at /private/var/Users/%s/x" % FUSER, 'at "\\/Users\\/%s\\/x"' % FUSER,
                  "at /Users/ %s/x" % FUSER, "the folder Users then %s" % FUSER):
            self.gone(t, FUSER)
        c = self.out("cat /Users/jdoe/Secret-Project/notes.txt now")
        self.assertNotIn("Secret", c)
        self.assertNotIn("notes", c)
        self.assertTrue(c.endswith(" now"))

    # ---- round 2
    def test_split_variants(self):
        """Check: split variants."""
        g = FGH
        for t in ("mail:\n" + "=\n".join(g[i:i + 9] for i in range(0, len(g), 9)),
                  '{"%s": "%s"}' % (g[:18], g[18:]), "- %s\n- %s\n- %s" % (g[:12], g[12:24], g[24:]),
                  "tok=" + " \\\n".join(g[i:i + 12] for i in range(0, len(g), 12)),
                  "tok " + "\U0001F642".join(g[i:i + 4] for i in range(0, len(g), 4))):
            self.gone(t, g[:10], g[10:20], g[20:30], g[28:])

    def test_partial_key_with_ellipsis(self):
        """Check: partial key with ellipsis."""
        self.gone("key %s..." % FGH[:16], FGH[4:16])
        self.gone("key %s\u2026" % FGH[:16], FGH[4:16])
        self.assertIn("sk-... and ghp_ docs", self.out("see sk-... and ghp_ docs"))

    def test_mac_arp_int_json(self):
        """Check: mac arp int json."""
        c = self.out("? (x) at a:83:e7:1:5c:9d on en0")
        self.assertIn("<MAC-", c)
        self.assertNotIn("5c:9d", c)
        n = int("".join(FOCT), 16)
        self.assertIn("<MAC-", self.out("mac as int %d" % n))
        self.assertIn("<MAC-", self.out('{"mac": [164, 131, 231, 27, 92, 157]}'))
        self.assertIn("record 1234567890123 rows", self.out("record 1234567890123 rows"))

    def test_host_base32_leet_rot47(self):
        """Check: host base32 leet rot47."""
        self.gone("host " + base64.b32encode(b"zorbox").decode(), "zorbox")
        self.gone("host " + base64.b32encode(b"Kraken-Prime").decode(), "krakenprime")
        self.gone("host z0rb0x", "z0rb0x")
        self.gone("box kr4k3n-pr1m3", "kr4k3n", "pr1m3")
        r47 = "".join(chr(33 + ((ord(c) - 33 + 47) % 94)) for c in "Kraken-Prime")
        self.gone("host " + r47, r47)
        self.assertNotIn("Kraken", self.out("host " + r47))

    def test_report_has_no_values(self):
        """Check: report has no values."""
        c, rep = S("x %s %s %s" % (FGH, FPW, ",".join(FOCT)))
        blob = repr(rep)
        for v in (FGH, FPW, ",".join(FOCT), "zorbox"):
            self.assertNotIn(v, blob)

    def test_forty_k_single_line_fast(self):
        """Check: forty k single line fast."""
        import time
        for t in ("the quick brown fox 3 " * 1800, "a-" * 20000, "Ab3" * 13000, "/Users/" * 5700, "10.1.1.1 " * 4400,
                  "a at b dot c " * 3000, "f e d o r a " * 3300):
            t0 = time.time()
            S(t[:40000])
            self.assertLess(time.time() - t0, 2.0, t[:12])


# Allow running this file directly.
if __name__ == "__main__":
    unittest.main()
