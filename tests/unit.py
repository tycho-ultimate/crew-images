"""Unit tests for ci/scan.py, ci/entry.py and ci/index.py (stdlib unittest; no docker, no network).

Every canary is built at run time from pieces, so no secret-shaped string is ever written in this repo.
"""
import datetime
import io
import os
import re
import subprocess
import sys
import tarfile
import tomllib
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ci"))
import entry  # noqa: E402
import index  # noqa: E402
import scan  # noqa: E402

FILL = "Q7xk2mPz9LwV4nRt8sYb3cDf6hJg5aEu"     # letters and digits: the body of every canary


def canaries():
    """One string per shape, each as crew's shapes.py would refuse it."""
    return {
        "a PEM private key": "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----\n" + FILL,
        "a GitHub token": "gh" + "p_" + FILL + "1234",
        "a GitLab token": "gl" + "pat-" + FILL[:20],
        "an API key (sk-...)": "s" + "k-" + "proj-" + FILL,
        "an AWS access key": "AK" + "IA" + "QWERTYUIOP234567",
        "a Google API key": "AI" + "za" + FILL + "xyz",
        "a Slack token": "xo" + "xb-" + "1234567890-abcdef",
        "a JSON web token": "ey" + "J" + FILL[:12] + "." + "ey" + "J" + FILL[:12] + "." + FILL[:8],
    }


def tar_of(files):
    """A tar stream: {path: bytes | ("symlink", target)}."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for path, data in files.items():
            info = tarfile.TarInfo(path)
            if isinstance(data, tuple):
                info.type, info.linkname = tarfile.SYMTYPE, data[1]
                t.addfile(info)
            else:
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


class ScanShapes(unittest.TestCase):
    def test_each_shape_is_found_by_its_name(self):
        for what, text in canaries().items():
            with self.subTest(what):
                self.assertEqual(scan.shapes_in(b"x = " + text.encode() + b"\n"), [what])

    def test_github_fine_grained_token(self):
        self.assertEqual(scan.shapes_in(("github" + "_pat_" + FILL + "_" + FILL).encode()), ["a GitHub token"])

    def test_a_letter_or_digit_before_it_is_not_a_match(self):
        # crew's "(?<![A-Za-z0-9])": the lookbehinds here must keep it
        for what, text in canaries().items():
            if what in ("a PEM private key", "a JSON web token"):
                continue
            with self.subTest(what):
                self.assertEqual(scan.shapes_in(("z" + text).encode()), [])
                self.assertEqual(scan.shapes_in(("_" + text).encode()), [what])

    def test_short_bodies_are_not_tokens(self):
        self.assertEqual(scan.shapes_in(("gh" + "p_" + "short").encode()), [])
        self.assertEqual(scan.shapes_in(("s" + "k-" + "abc").encode()), [])
        self.assertEqual(scan.shapes_in(("AK" + "IA" + "QWERTYUIOP2345678").encode()), [])   # 17: not 16 then end

    def test_a_certificate_is_not_a_private_key(self):
        self.assertEqual(scan.shapes_in(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), [])

    def test_the_scanner_source_and_this_file_carry_no_shape(self):
        for p in ("ci/scan.py", "tests/unit.py"):
            with open(os.path.join(ROOT, p), "rb") as f:
                self.assertEqual(scan.shapes_in(f.read()), [], p)


class ScanTar(unittest.TestCase):
    def run_tar(self, files):
        return scan.scan_tar(tar_of(files))

    def test_a_credentials_file_fails(self):
        f, notes, n = self.run_tar({"home/agent/.config/gh/hosts.yml":
                                    ("oauth_token: " + canaries()["a GitHub token"]).encode(),
                                    "etc/os-release": b"ID=debian\n"})
        self.assertEqual(f, [("home/agent/.config/gh/hosts.yml", "a GitHub token")])
        self.assertEqual((notes, n), ([], 2))

    def test_every_shape_fails_in_a_text_file(self):
        for what, text in canaries().items():
            with self.subTest(what):
                f, _, _ = self.run_tar({"root/.env": text.encode()})
                self.assertEqual(f, [("root/.env", what)])

    def test_inside_an_elf_file_it_is_a_note(self):
        f, notes, _ = self.run_tar({"usr/local/bin/tool": scan.ELF + b"\x02\x01" + canaries()["an API key (sk-...)"]
                                   .encode()})
        self.assertEqual((f, notes), ([], [("usr/local/bin/tool", "an API key (sk-...)")]))

    def test_forbidden_programs_by_name(self):
        for path in ("usr/bin/sudo", "usr/sbin/sshd", "usr/bin/doas", "usr/sbin/dropbear"):
            with self.subTest(path):
                f, _, _ = self.run_tar({path: b"#!/bin/sh\n"})
                self.assertEqual(len(f), 1)
                self.assertEqual(f[0][0], path)
        f, _, _ = self.run_tar({"usr/bin/sudo": ("symlink", "/bin/true")})
        self.assertEqual(f, [("usr/bin/sudo", scan.FORBIDDEN["sudo"])])

    def test_names_that_only_contain_the_words_pass(self):
        f, _, _ = self.run_tar({"usr/share/doc/sudo-notes.txt": b"x", "etc/mise/config.toml":
                                b"[settings]\nsystem_packages.sudo = false\n"})
        self.assertEqual(f, [])

    def test_main_exit_codes(self):
        def run(files):
            data = tar_of(files).getvalue()
            return subprocess.run([sys.executable, "-I", os.path.join(ROOT, "ci", "scan.py"), "--tar", "-"],
                                  input=data, capture_output=True)
        clean = run({"etc/hostname": b"box\n"})
        self.assertEqual(clean.returncode, 0, clean.stderr)
        dirty = run({"home/agent/.netrc": canaries()["a GitHub token"].encode()})
        self.assertEqual(dirty.returncode, 1)
        self.assertNotIn(canaries()["a GitHub token"].encode(), dirty.stdout + dirty.stderr)   # never printed
        self.assertEqual(run({}).returncode, 1)                                                   # nothing scanned


class Entry(unittest.TestCase):
    DIGEST = "sha256:" + "ab" * 32

    def spec(self):
        return entry.spec(ROOT, "base")

    def test_the_entries_parse_with_crews_keys(self):
        text = entry.entries("base", self.spec(), self.DIGEST, datetime.date(2026, 10, 6))
        doc = tomllib.loads(text)
        self.assertEqual(list(doc["images"]), ["base-arm64", "base-amd64"])
        keys = {"runtime", "platform", "ref", "digest", "provides", "user", "verify", "signer", "issuer", "built",
                "max_age_days"}
        for name, e in doc["images"].items():
            self.assertEqual(set(e), keys, name)
            self.assertEqual(e["runtime"], "oci")
            self.assertEqual(e["platform"], "linux/" + name.rsplit("-", 1)[1])
            self.assertEqual(e["ref"], "ghcr.io/tycho-ultimate/crew-images/base:main")
            self.assertEqual(e["digest"], self.DIGEST)
            self.assertEqual(e["provides"], ["mise"])
            self.assertEqual(e["user"], "agent")
            self.assertEqual(e["verify"], "cosign")
            self.assertEqual(e["signer"],
                             "https://github.com/tycho-ultimate/crew-images/.github/workflows/build.yml@refs/heads/main")
            self.assertEqual(e["issuer"], "https://token.actions.githubusercontent.com")
            self.assertEqual(e["built"], datetime.date(2026, 10, 6))
            self.assertIs(type(e["built"]), datetime.date)        # a TOML date, not a date-time (crew's rule)
            self.assertEqual(e["max_age_days"], 30)

    def test_the_signer_and_issuer_pass_crews_url_rule(self):
        url = re.compile(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%/@+-]*)?")   # lib/crew/images.py
        self.assertRegex(entry.SIGNER, url)
        self.assertTrue(url.fullmatch(entry.SIGNER) and url.fullmatch(entry.ISSUER))

    def test_refusals(self):
        s = self.spec()
        for digest in ("sha256:" + "AB" * 32, "sha256:abc", "", "sha512:" + "ab" * 32):
            with self.assertRaises(entry.EntryError):
                entry.entries("base", s, digest, datetime.date(2026, 10, 6))
        for k, v in (("user", "root"), ("user", ""), ("provides", "mise"), ("provides", ["Mise"]),
                     ("max_age_days", 0), ("max_age_days", True), ("platforms", ["linux/riscv64"]),
                     ("platforms", ["linux/arm64", "linux/arm64"]), ("platforms", [])):
            with self.subTest((k, v)), self.assertRaises(entry.EntryError):
                entry.entries("base", dict(s, **{k: v}), self.DIGEST, datetime.date(2026, 10, 6))
        with self.assertRaises(entry.EntryError):
            entry.entries("base", s, self.DIGEST, "2026-10-06")
        with self.assertRaises(entry.EntryError):
            entry.spec(ROOT, "../base")


class Index(unittest.TestCase):
    A, B, I = "sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64

    def doc(self, manifests):
        return {"mediaType": "application/vnd.oci.image.index.v1+json", "digest": self.I, "manifests": manifests}

    def m(self, d, arch, os_="linux"):
        return {"digest": d, "platform": {"os": os_, "architecture": arch}}

    def test_exactly_the_pushed_manifests(self):
        want = {"linux/arm64": self.A, "linux/amd64": self.B}
        self.assertEqual(index.check(self.doc([self.m(self.A, "arm64"), self.m(self.B, "amd64")]), want), self.I)
        for bad in ([self.m(self.A, "arm64")],
                    [self.m(self.A, "arm64"), self.m(self.B, "amd64"), self.m(self.I, "unknown", "unknown")],
                    [self.m(self.B, "arm64"), self.m(self.A, "amd64")],
                    [self.m(self.A, "arm64"), self.m(self.A, "arm64"), self.m(self.B, "amd64")]):
            with self.subTest(bad), self.assertRaises(ValueError):
                index.check(self.doc(bad), want)
        with self.assertRaises(ValueError):
            index.check(dict(self.doc([self.m(self.A, "arm64"), self.m(self.B, "amd64")]),
                             mediaType="application/vnd.oci.image.manifest.v1+json"), want)


if __name__ == "__main__":
    unittest.main(verbosity=1)
