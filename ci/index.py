"""Check a multi-arch index (`docker buildx imagetools inspect --format '{{json .Manifest}}'` on stdin) and print
its digest.

    ... | python3 -I ci/index.py linux/arm64=sha256:<a> linux/amd64=sha256:<b>

The index must hold exactly the given manifests, each for its platform: nothing else (no attestation, no other
platform). Exit 1 otherwise, saying why.
"""
import json
import re
import sys

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def check(doc, want):
    """want: {platform: digest}. Returns the index digest, or raises ValueError."""
    digest = doc.get("digest")
    if not (isinstance(digest, str) and DIGEST_RE.fullmatch(digest)):
        raise ValueError("the index has no sha256 digest")
    if doc.get("mediaType") not in ("application/vnd.oci.image.index.v1+json",
                                    "application/vnd.docker.distribution.manifest.list.v2+json"):
        raise ValueError(f"the tag is not a multi-arch index ({doc.get('mediaType')})")
    have = {}
    for m in doc.get("manifests") or []:
        p = m.get("platform") or {}
        plat = f"{p.get('os')}/{p.get('architecture')}" + (f"/{p['variant']}" if p.get("variant") else "")
        if plat in have:
            raise ValueError(f"the index lists {plat} twice")
        have[plat] = m.get("digest")
    if have != want:
        raise ValueError(f"the index holds {have}, not {want}")
    return digest


def main(argv):
    want = {}
    for a in argv:
        plat, _, d = a.partition("=")
        if not DIGEST_RE.fullmatch(d) or plat in want:
            print(f"index.py: bad argument {a!r} (platform=sha256:<64 hex>, each platform once)", file=sys.stderr)
            return 2
        want[plat] = d
    if not want:
        print("usage: index.py <platform>=<digest>...", file=sys.stderr)
        return 2
    try:
        print(check(json.load(sys.stdin), want))
    except ValueError as e:
        print(f"index.py: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
