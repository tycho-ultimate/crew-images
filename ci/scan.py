"""Secret-shaped strings in an image's filesystem, or in this repo's files (IMG-1, tycho-ultimate/crew#56).

    python3 -I ci/scan.py --tar -          # a `docker export` stream on stdin
    python3 -I ci/scan.py --files a b ...  # files on disk

The shapes are crew's (lib/crew/shapes.py, tycho-ultimate/crew at 2d06b31), rewritten so each starts with its
literal (Python's re then searches fast; the lookbehinds keep crew's "no letter or digit before it"), with three
deliberate differences:

  - crew's two catch-alls (a run of 40+ hex digits; 40+ base64 characters with upper case, lower case and digits)
    are left out. An image is full of legitimate hashes (dpkg's md5sums, apt's indexes, ELF build ids, this repo's
    own pinned checksums) and compressed data, so they would flag every image and say nothing.
  - crew's PEM rule matches any PEM block, certificates included. Here it is narrowed to private keys: an image
    carries the public CA certificates (ca-certificates) by design.
  - A match inside an ELF file (a program or a shared library) is printed as a note and does not fail. Those bytes
    are vendor code fixed by a pinned sha256 (the downloads) or by Debian's signed archive (the packages), and their
    string tables match by shape: PEM header constants in libgnutls and libssh2, OpenSSH's "sk-ecdsa-..." key type
    names, token prefixes next to other strings in gh and codex. A secret left in an image by mistake is a text or
    data file (a credentials file, an env file, a config, a key), and every such file is scanned and fails.

The tar mode also refuses programs an image must not have, by name: sudo (an agent never escalates) and an ssh
server. A finding names the file and the shape, never the matched text. Exit 1 on any finding, 2 on a usage error.
"""
import os
import re
import sys
import tarfile

GITHUB = "a GitHub token"
SHAPES = (
    ("a PEM private key", rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    (GITHUB, rb"gh[pousr]_(?<![A-Za-z0-9]gh[pousr]_)[A-Za-z0-9]{20,}"),
    (GITHUB, rb"github_pat_(?<![A-Za-z0-9]github_pat_)[A-Za-z0-9_]{20,}"),
    ("a GitLab token", rb"gl(?<![A-Za-z0-9]gl)(?:pat|dt|ptt|rt|cbt|oas|ft|imt|agent)-[A-Za-z0-9_-]{16,}"),
    ("an API key (sk-...)", rb"sk-(?<![A-Za-z0-9]sk-)[A-Za-z0-9_-]{20,}"),
    ("an AWS access key", rb"A(?:KI|SI)A(?<![A-Za-z0-9]A[KS]IA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
    ("a Google API key", rb"AIza(?<![A-Za-z0-9]AIza)[0-9A-Za-z_-]{30,}"),
    ("a Slack token", rb"xox[abposr]-(?<![A-Za-z0-9]xox[abposr]-)[A-Za-z0-9-]{10,}"),
    ("a JSON web token", rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."),
)
_COMPILED = tuple((what, re.compile(rx)) for what, rx in SHAPES)
ELF = b"\x7fELF"

# Program names an image must not carry, anywhere in its filesystem.
FORBIDDEN = {"sudo": "sudo (an agent never escalates)", "sudoedit": "sudo (an agent never escalates)",
             "doas": "doas (an agent never escalates)", "sshd": "an ssh server", "dropbear": "an ssh server",
             "tinysshd": "an ssh server"}

MAX_FILE = 1 << 30          # a file bigger than this is a finding, never a silent pass


def shapes_in(data):
    """The names of the shapes found in data (bytes), each once, in SHAPES order."""
    out = []
    for what, rx in _COMPILED:
        if what not in out and rx.search(data):
            out.append(what)
    return out


def classify(path, data, findings, notes):
    for what in shapes_in(data):
        (notes if data[:4] == ELF else findings).append((path, what))


def scan_tar(stream):
    """(findings, notes, files) for a tar stream: secret shapes in regular files, forbidden programs by name."""
    findings, notes, files = [], [], 0
    with tarfile.open(fileobj=stream, mode="r|*") as tar:
        for m in tar:
            name = m.name.removeprefix("./").lstrip("/")
            base = os.path.basename(name)
            if base in FORBIDDEN and (m.isfile() or m.issym() or m.islnk()):
                findings.append((name, FORBIDDEN[base]))
            if not m.isfile():
                continue
            files += 1
            if m.size > MAX_FILE:
                findings.append((name, f"a file of {m.size} bytes, too big to scan"))
                continue
            f = tar.extractfile(m)
            classify(name, f.read() if f is not None else b"", findings, notes)
    return findings, notes, files


def scan_files(paths):
    findings, notes = [], []
    for p in paths:
        with open(p, "rb") as f:
            data = f.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            findings.append((p, "a file too big to scan"))
            continue
        classify(p, data, findings, notes)
    return findings, notes


def main(argv):
    if argv[:1] == ["--tar"] and argv[1:] == ["-"]:
        findings, notes, files = scan_tar(sys.stdin.buffer)
        if files == 0:
            print("scan: the tar stream held no files: nothing was scanned", file=sys.stderr)
            return 1
    elif argv[:1] == ["--files"]:
        findings, notes = scan_files(argv[1:])
        files = len(argv) - 1
    else:
        print("usage: scan.py --tar - | --files <path>...", file=sys.stderr)
        return 2
    for path, shape in notes:
        print(f"scan: note: {path}: {shape}, inside an ELF file (vendor code; not a failure)")
    for path, shape in findings:
        print(f"scan: FOUND {path}: {shape}")
    if findings:
        print(f"scan: {len(findings)} finding(s) in {files} files", file=sys.stderr)
        return 1
    print(f"scan: nothing secret-shaped outside ELF files, and no forbidden program, in {files} files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
