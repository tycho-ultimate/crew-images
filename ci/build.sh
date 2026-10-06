#!/bin/sh
# Build one image for one arch, load it and run its test job (ci/image_test.py); with "push", then push the same
# build to GHCR by digest. Nothing is pushed unless the test passed. The push needs a docker login to ghcr.io
# (the workflow's build job: GITHUB_TOKEN with packages: write); the test needs none.
#
#   ci/build.sh <image> <amd64|arm64> [test|push]
#
# With push, the digest goes to $RUNNER_TEMP/digests/<image>-<arch> for the publish job.
set -eu

usage() { echo "usage: ci/build.sh <image> <amd64|arm64> [test|push]" >&2; exit 2; }
[ $# -ge 2 ] && [ $# -le 3 ] || usage
image=$1 arch=$2 mode=${3:-test}
case $image in ''|-*|*[!a-z0-9-]*) usage ;; esac
case $arch in amd64|arm64) ;; *) usage ;; esac
case $mode in test|push) ;; *) usage ;; esac

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
[ -f "$root/images/$image/Containerfile" ] || { echo "no images/$image/Containerfile" >&2; exit 2; }
repo=ghcr.io/tycho-ultimate/crew-images/$image
tested=crew-images-test/$image:$arch
rev=${GITHUB_SHA:-$(git -C "$root" rev-parse HEAD)}

# The same arguments for both builds, so the push is the tested build, from the builder's cache.
set -- --platform "linux/$arch" --file "$root/images/$image/Containerfile" --provenance=false --sbom=false \
  --label "org.opencontainers.image.revision=$rev" "$root/images/$image"

docker buildx build --load --tag "$tested" "$@"
python3 -I "$root/ci/image_test.py" "$tested" "$image" "$root"
[ "$mode" = push ] || exit 0

out=${RUNNER_TEMP:-/tmp}/digests
mkdir -p "$out"
meta=$(mktemp)
docker buildx build --metadata-file "$meta" \
  --output "type=image,name=$repo,push-by-digest=true,name-canonical=true,push=true" "$@"
digest=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$meta")
rm -f "$meta"
printf '%s\n' "$digest" | grep -Eqx 'sha256:[0-9a-f]{64}' || { echo "no digest from the push" >&2; exit 1; }

# The pushed image's layers must be the tested image's.
layers() { python3 -I -c 'import json, sys; print(" ".join(json.load(sys.stdin)))'; }
want=$(docker image inspect --format '{{json .RootFS.Layers}}' "$tested" | layers)
got=$(docker buildx imagetools inspect --format '{{json .Image.RootFS.DiffIDs}}' "$repo@$digest" | layers)
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "the pushed image's layers are not the tested image's: tested $want, pushed $got" >&2
  exit 1
fi

printf '%s\n' "$digest" > "$out/$image-$arch"
echo "pushed $repo@$digest (linux/$arch), the tested build"
