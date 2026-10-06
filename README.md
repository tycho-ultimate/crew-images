# crew-images

crew's curated images: a trusted base for agent runs, pinned by digest in crew-fleet's `images.toml` (crew's VM-4).
GitHub Actions builds them for `linux/arm64` and `linux/amd64`, pushes them to GHCR by digest, signs them with cosign
keyless, and rebuilds them every week ([tycho-ultimate/crew#56](https://github.com/tycho-ultimate/crew/issues/56)).

An image carries only what needs root: system packages, build tools, the runner CLIs, and a pinned mise. A repo's
languages come from the repo's own `mise.toml` (or `.tool-versions`, `rust-toolchain.toml`, ...): mise installs
them as `agent` inside the instance (owner decision T8). So there are no language images here.

## The rule: an image never holds a secret

No token, key, password, login or credential file goes into an image, at build time or any other time. Nothing in
the build uses a secret: the downloads are public, and the only secret the workflow knows is its own `GITHUB_TOKEN`,
used to push. The test job scans every file of each image for crew's secret shapes and refuses `sudo` and an ssh
server (`ci/scan.py`). A run's credentials reach it at run time, never through its image.

## The images

### `base`

`ghcr.io/tycho-ultimate/crew-images/base:main`, from [`images/base/Containerfile`](images/base/Containerfile).

| | |
|---|---|
| Base | `debian:trixie-slim`, pinned by digest |
| Provides (crew capabilities) | `mise` |
| User | `agent` (uid 1000, zsh, no password, no sudo); every exec runs as it |
| Tools | git, gh, jq, zsh, python3 (3.13), build-essential (gcc, make), pkg-config, libssl-dev, zlib1g-dev, curl, ripgrep, unzip, xz-utils, less, procps |
| Runner CLIs | `claude` 2.1.288 and `codex` 0.160.0: crew's agents.toml tested floors |
| mise | 2026.10.3 at `/usr/local/bin/mise`; `/etc/mise/config.toml` sets `system_packages.sudo = false` and no tool versions |
| Not in it | sudo, an ssh server (no sshd, no exposed port), any credential, any language toolchain |

`provides` lists names from fleet.toml's `[capabilities]`: system-level ones, plus `mise`. Languages are never
capabilities (T8). For `base` that is just `mise`; it makes a repo's declared toolchain obtainable inside the image.

## How an image is built and published

[`.github/workflows/build.yml`](.github/workflows/build.yml):

- **On a pull request:** `tests/run.sh`, then each image built natively for each platform (`ubuntu-24.04` and
  `ubuntu-24.04-arm`), its test job (`ci/image_test.py`), and the test job's own mutation runs on broken copies of the
  image (`tests/image_mutations.py`). Nothing is pushed or signed: no job of a pull request can write packages or get
  an OIDC token.
- **On a push to `main`, every Monday (the refresh) and on a manual dispatch on `main`:** the same build and test,
  then the tested build is pushed to GHCR by digest (`ci/build.sh push`, which checks the pushed layers are the
  tested ones), and the publish job (`ci/publish.sh`):
  - joins the two platform digests into one multi-arch index tagged `main`, and checks it holds exactly those two;
  - signs the index and each platform manifest with cosign keyless, as this workflow on `main`;
  - runs `cosign verify` on each against that identity;
  - prints the image's digest and the exact `images.toml` entries to propose, in the log and the run summary.

The weekly rebuild keeps every pin (base digest, tool versions and checksums) and picks up Debian's security updates,
which apt verifies against Debian's signed archive. A new digest each week is for `crew images check` to see and
`crew images bump` to propose; nothing changes in crew-fleet until the owner merges that PR.

Verify an image yourself:

```sh
cosign verify \
  --certificate-identity=https://github.com/tycho-ultimate/crew-images/.github/workflows/build.yml@refs/heads/main \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/tycho-ultimate/crew-images/base@sha256:<digest>
```

The `images.toml` entries (one per platform, both pinned to the index digest) look like this:

```toml
[images.base-arm64]
runtime      = "oci"
platform     = "linux/arm64"
ref          = "ghcr.io/tycho-ultimate/crew-images/base:main"
digest       = "sha256:<the index digest the publish job printed>"
provides     = ["mise"]
user         = "agent"
verify       = "cosign"
signer       = "https://github.com/tycho-ultimate/crew-images/.github/workflows/build.yml@refs/heads/main"
issuer       = "https://token.actions.githubusercontent.com"
built        = 2026-10-06
max_age_days = 30
```

`provides` must name capabilities the fleet's fleet.toml declares, so crew-fleet needs `[capabilities.mise]` (as in
crew's `examples/fleet/fleet.toml`) before these entries pass `crew fleet check`.

## Adding a stack image, or changing one

A stack image is only for what a repo needs at the system level (root-installed libraries, a GPU stack, ...); its
languages stay in the repo's own manifests.

1. **A PR here**: `images/<name>/Containerfile` (base by digest, downloads by version and sha256, `USER agent`, no
   sshd, no sudo, no secret), `images/<name>/mise-config.toml`, `images/<name>/image.toml` (its `provides`, `user`,
   `platforms`, `tools`, `floors`), and `<name>` in the workflow's `image` matrices. `tests/run.sh` must be green,
   and so must the PR's image test jobs.
2. **After the merge**, the workflow on `main` pushes, signs and verifies it and prints its `images.toml` entries.
3. **In crew-fleet**: a new image enters `images.toml` by the owner's own edit, in a PR. An existing entry's digest
   moves with `crew images bump <image>` (a plan; `--apply` under the lease, then `crew fleet propose`).

Bumping a pin (a new base digest, a tool release, a new tested floor in agents.toml) is a PR here that changes the
`FROM` digest or the `ARG ..._VERSION` and `ARG ..._SHA256_*` lines. Take each value from its publisher, never by
hand (see "Pins"), and keep `image.toml`'s `[floors]` equal to agents.toml's `tested`.

## Pins

| Pin | Value | Source |
|---|---|---|
| `debian:trixie-slim` | `sha256:a29215f6...49f11f` (multi-arch index) | `docker buildx imagetools inspect debian:trixie-slim`, 2026-10-06 |
| mise | 2026.10.3 | `SHASUMS256.txt` of [jdx/mise v2026.10.3](https://github.com/jdx/mise/releases/tag/v2026.10.3), which matches GitHub's asset digests |
| gh | 2.102.0 | `gh_2.102.0_checksums.txt` of [cli/cli v2.102.0](https://github.com/cli/cli/releases/tag/v2.102.0), which matches GitHub's asset digests |
| claude | 2.1.288 | `https://downloads.claude.ai/claude-code-releases/2.1.288/manifest.json`, `platforms.linux-{x64,arm64}.checksum` (the URLs Claude Code's own installer uses) |
| codex | 0.160.0 | GitHub's sha256 asset digests of [openai/codex rust-v0.160.0](https://github.com/openai/codex/releases/tag/rust-v0.160.0) (`codex-{x86_64,aarch64}-unknown-linux-musl.tar.gz`) |
| cosign (signing, in the workflow) | v3.1.3 | installed and signature-checked by `sigstore/cosign-installer` |

The full checksums are in the Containerfile. Every `uses:` in the workflow is pinned to a full commit SHA, with its
version in a comment.

## Local checks

```sh
tests/run.sh                      # static checks, their mutation runs, unit tests: stdlib Python >= 3.11, no docker
ci/build.sh base arm64            # build and test one image locally (docker with buildx); never pushes without "push"
```

`tests/static.py` checks: every action pinned by SHA; least-privilege permissions (top level `{}`, writes only
`packages` and `id-token`, only in jobs limited to `main`); no secret but `GITHUB_TOKEN`; no `pull_request_target`
or `workflow_run`; every `FROM` pinned by digest; every download checked with `sha256sum -c` and nothing piped into
a shell; exact versions and 64-hex checksums; the last `USER` is `agent`; no ssh server, no exposed port; no sudo;
mise's config; each image's `provides` in crew's capability vocabulary (`tests/crew-capabilities.txt`); and nothing
secret-shaped in the repo. `tests/mutations.py` breaks a copy of the repo once per guarded property and requires the
named check to fail.
