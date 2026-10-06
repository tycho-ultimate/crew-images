#!/bin/sh
# crew-images' local checks, run before every commit and by the workflow's `tests` job. POSIX sh and stdlib
# Python >= 3.11 only; no docker and no network (the image's own test job is ci/image_test.py, run on a build).
#
#   tests/static.py     the workflows, Containerfiles and image specs (pins, permissions, no sshd, ...)
#   tests/mutations.py  each static check fails on a deliberately broken copy
#   tests/unit.py       ci/scan.py, ci/entry.py and ci/index.py
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

py=${PYTHON:-python3}
if ! "$py" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
  echo "tests/run.sh: needs Python 3.11 or newer (tomllib); set PYTHON" >&2
  exit 1
fi

failed=0
for t in static.py mutations.py unit.py; do
  echo "== tests/$t"
  if ! "$py" -I "$root/tests/$t"; then
    failed=$((failed + 1))
    echo "== tests/$t: FAILED"
  fi
done

# Shell syntax of the scripts the workflow runs.
for s in "$root"/ci/*.sh "$root"/tests/run.sh; do
  sh -n "$s" || { echo "== sh -n $s: FAILED"; failed=$((failed + 1)); }
done

if [ "$failed" -ne 0 ]; then
  echo "tests/run.sh: $failed failed"
  exit 1
fi
echo "tests/run.sh: all green"
