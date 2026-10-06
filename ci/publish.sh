#!/bin/sh
# The publish job, for one image: join the two pushed platform digests into one multi-arch index under the tag
# `main`, sign the index and each platform manifest with cosign keyless (this workflow's identity on main), verify
# each signature against that identity, and print the images.toml entries to propose in crew-fleet.
#
#   ci/publish.sh <image>        (reads $RUNNER_TEMP/digests/<image>-amd64 and -arm64, from ci/build.sh push)
#
# Needs a docker login to ghcr.io and an Actions OIDC token (id-token: write): the workflow's publish job only.
set -eu

[ $# -eq 1 ] || { echo "usage: ci/publish.sh <image>" >&2; exit 2; }
image=$1
case $image in ''|-*|*[!a-z0-9-]*) echo "bad image name" >&2; exit 2 ;; esac
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
repo=ghcr.io/tycho-ultimate/crew-images/$image
dir=${RUNNER_TEMP:-/tmp}/digests

const() { python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); import entry; print(getattr(entry, sys.argv[2]))' \
  "$root/ci" "$1"; }
signer=$(const SIGNER)
issuer=$(const ISSUER)
tag=$(const TAG)

# Sign only as this workflow on main: the identity crew-fleet's entries name.
if [ "https://github.com/${GITHUB_WORKFLOW_REF:-}" != "$signer" ]; then
  echo "this run is ${GITHUB_WORKFLOW_REF:-not a workflow run}, not $signer: nothing is published" >&2
  exit 1
fi

digest_of() {
  d=$(cat "$dir/$image-$1")
  printf '%s\n' "$d" | grep -Eqx 'sha256:[0-9a-f]{64}' || { echo "no pushed digest for $image $1" >&2; exit 1; }
  printf '%s\n' "$d"
}
arm=$(digest_of arm64)
amd=$(digest_of amd64)

docker buildx imagetools create --tag "$repo:$tag" \
  --annotation "index:org.opencontainers.image.source=https://github.com/tycho-ultimate/crew-images" \
  --annotation "index:org.opencontainers.image.revision=${GITHUB_SHA:-unknown}" \
  --annotation "index:org.opencontainers.image.description=crew-images/$image: see the README" \
  "$repo@$arm" "$repo@$amd"

# The tag's index must hold exactly the two pushed manifests, each for its platform.
index=$(docker buildx imagetools inspect --format '{{json .Manifest}}' "$repo:$tag" \
  | python3 -I "$root/ci/index.py" "linux/arm64=$arm" "linux/amd64=$amd")

for d in "$index" "$arm" "$amd"; do
  cosign sign --yes "$repo@$d"
done
for d in "$index" "$arm" "$amd"; do
  cosign verify --certificate-identity="$signer" --certificate-oidc-issuer="$issuer" "$repo@$d" > /dev/null
  echo "cosign verify: ok, $repo@$d signed by $signer"
done

entries=$(python3 -I "$root/ci/entry.py" "$image" "$index" "$(date -u +%Y-%m-%d)" "$root")
echo "images.toml entries to propose in crew-fleet for $image:"
printf '%s\n' "$entries"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### $image: $repo:$tag"
    echo
    echo "index $index (linux/arm64 $arm, linux/amd64 $amd), signed and verified."
    echo
    echo "The images.toml entries to propose in crew-fleet:"
    echo
    echo '```toml'
    printf '%s\n' "$entries"
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
fi
