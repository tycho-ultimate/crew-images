"""The images.toml entries to propose in crew-fleet for one pushed image (crew's VM-4 format, lib/crew/images.py).

    python3 -I ci/entry.py <image> <index digest> <built YYYY-MM-DD> [<root>]

One entry per platform in images/<image>/image.toml, named <image>-<arch>, all pinned to the same multi-arch
index digest (one digest serves every platform of a tag, as crew's examples/fleet/images.toml shows). The signer
is this workflow on main: the identity `cosign verify` checked in the publish job.
"""
import datetime
import json
import os
import re
import sys
import tomllib

REGISTRY_REPO = "ghcr.io/tycho-ultimate/crew-images"
TAG = "main"
SIGNER = "https://github.com/tycho-ultimate/crew-images/.github/workflows/build.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
PLATFORMS = ("linux/arm64", "linux/amd64")       # what this repo builds: oci images are linux (crew's rule)
NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")   # crew's names.NAME_RE: an images.toml entry's name
USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
CAP_RE = NAME_RE
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
MAX_PROVIDES = 16


class EntryError(ValueError):
    pass


def spec(root, image):
    if not NAME_RE.fullmatch(image):
        raise EntryError(f"image name {image!r}: lowercase letters, digits and dashes")
    with open(os.path.join(root, "images", image, "image.toml"), "rb") as f:
        return tomllib.load(f)


def entries(image, s, digest, built):
    """The TOML text of the entries, from image.toml's parsed spec s."""
    if not DIGEST_RE.fullmatch(digest or ""):
        raise EntryError("the digest must be sha256:<64 lowercase hex>")
    if not isinstance(built, datetime.date):
        raise EntryError("built must be a date")
    provides = s.get("provides")
    if not (isinstance(provides, list) and len(provides) <= MAX_PROVIDES
            and all(isinstance(c, str) and CAP_RE.fullmatch(c) for c in provides)):
        raise EntryError("provides must be a list of capability names")
    user = s.get("user")
    if not (isinstance(user, str) and USER_RE.fullmatch(user)) or user == "root":
        raise EntryError("user must be an unprivileged user name, never root")
    age = s.get("max_age_days")
    if not (isinstance(age, int) and not isinstance(age, bool) and 1 <= age <= 365):
        raise EntryError("max_age_days must be 1 to 365")
    plats = s.get("platforms")
    if not (isinstance(plats, list) and plats and all(p in PLATFORMS for p in plats)
            and len(set(plats)) == len(plats)):
        raise EntryError(f"platforms must be some of {', '.join(PLATFORMS)}, each once")
    out = []
    for p in plats:
        name = f"{image}-{p.split('/')[1]}"
        if not NAME_RE.fullmatch(name):
            raise EntryError(f"{name!r} is too long for an images.toml name (at most 32)")
        q = json.dumps
        out.append("\n".join([
            f"[images.{name}]",
            f'runtime      = "oci"',
            f"platform     = {q(p)}",
            f"ref          = {q(f'{REGISTRY_REPO}/{image}:{TAG}')}",
            f"digest       = {q(digest)}",
            f"provides     = [{', '.join(q(c) for c in provides)}]",
            f"user         = {q(user)}",
            f'verify       = "cosign"',
            f"signer       = {q(SIGNER)}",
            f"issuer       = {q(ISSUER)}",
            f"built        = {built.isoformat()}",
            f"max_age_days = {age}",
        ]))
    return "\n\n".join(out) + "\n"


def main(argv):
    if len(argv) not in (3, 4):
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    image, digest, built = argv[:3]
    root = argv[3] if len(argv) == 4 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        when = datetime.date.fromisoformat(built)
        sys.stdout.write(entries(image, spec(root, image), digest, when))
    except (EntryError, ValueError, OSError) as e:
        print(f"entry.py: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
