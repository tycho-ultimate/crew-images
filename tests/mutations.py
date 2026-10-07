"""Mutation runs for tests/static.py: each check that asserts something is absent (or must hold) is shown to fail.

    python3 -I tests/mutations.py

For each mutation: copy this checkout (without .git) to a temporary directory, break one file the way the check
guards against, run every static check on the copy, and require that the named check fails. The unbroken copy must
pass every check first. Prints one line per mutation; exit 1 when a mutation is not caught.
"""
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import static  # noqa: E402

WF = ".github/workflows/build.yml"
CF = "images/base/Containerfile"
MISE = "images/base/mise-config.toml"
SPEC = "images/base/image.toml"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
FROM = "FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f"
TOKEN = "g" + "hp_" + "Q7xk2mPz9LwV4nRt8sYb3cDf6hJg5aEu1234"      # built here, never written in the repo

# (check that must fail, what the mutation does, file, old text, new text). old must occur in the file.
MUTATIONS = (
    ("uses-pinned", "an action pinned by tag", WF, CHECKOUT, "actions/checkout@v7 # v7.0.1"),
    ("uses-pinned", "an action pinned by branch", WF, CHECKOUT, "actions/checkout@main # v7.0.1"),
    ("uses-pinned", "a SHA without its version comment", WF, " # v4.4.1", ""),
    ("uses-pinned", "a short SHA", WF, CHECKOUT, "actions/checkout@3d3c42e # v7.0.1"),
    ("permissions", "no top-level permissions", WF, "permissions: {}\n", ""),
    ("permissions", "top-level write-all", WF, "permissions: {}\n", "permissions: write-all\n"),
    ("permissions", "a job without its own permissions", WF,
     "    timeout-minutes: 10\n    permissions:\n      contents: read\n", "    timeout-minutes: 10\n"),
    ("permissions", "the pull-request job may push packages", WF,
     "    timeout-minutes: 45\n    permissions:\n      contents: read\n    strategy:\n      fail-fast: false",
     "    timeout-minutes: 45\n    permissions:\n      contents: read\n      packages: write\n    strategy:\n"
     "      fail-fast: false"),
    ("permissions", "a write job that also runs on pull requests", WF,
     "    if: ${{ github.event_name != 'pull_request' && github.ref == 'refs/heads/main' }}\n    needs: tests",
     "    if: ${{ always() }}\n    needs: tests"),
    ("permissions", "a write job on any branch", WF,
     "    if: ${{ github.event_name != 'pull_request' && github.ref == 'refs/heads/main' }}\n    needs: build",
     "    if: ${{ github.event_name != 'pull_request' }}\n    needs: build"),
    ("permissions", "contents: write", WF, "      contents: read\n      packages: write\n      id-token: write",
     "      contents: write\n      packages: write\n      id-token: write"),
    ("no-pull-request-target", "pull_request_target", WF, "  pull_request:\n", "  pull_request_target:\n"),
    ("no-pull-request-target", "workflow_run", WF, "  workflow_dispatch:\n",
     "  workflow_dispatch:\n  workflow_run:\n    workflows: [other]\n"),
    ("secrets-only-github-token", "another secret", WF, "secrets.GITHUB_TOKEN }}", "secrets.GHCR_PAT }}"),
    ("secrets-only-github-token", "a secret by index", WF, "secrets.GITHUB_TOKEN }}", "secrets['NPM_TOKEN'] }}"),
    ("from-pinned", "FROM by tag only", CF, FROM, "FROM debian:trixie-slim"),
    ("from-pinned", "FROM with a short digest", CF, FROM, "FROM debian:trixie-slim@sha256:a29215f6"),
    ("downloads-verified", "no sha256sum -c", CF, "| sha256sum --strict -c -;", "| sha256sum;"),
    ("downloads-verified", "one download left out of the check", CF, '"$codex_sha" codex.tar.gz', ""),
    ("downloads-verified", "curl piped into sh", CF, "# mise's system config",
     "RUN curl -fsSL https://mise.run | sh\n# mise's system config"),
    ("downloads-verified", "curl to stdout", CF, "# mise's system config",
     "RUN curl -fsSL https://example.com/x > /tmp/x\n# mise's system config"),
    ("downloads-verified", "wget piped into bash", CF, "# mise's system config",
     "RUN wget -qO- https://example.com/i.sh | bash\n# mise's system config"),
    ("downloads-verified", "ADD of a URL without a checksum", CF, "# mise's system config",
     "ADD https://example.com/tool /usr/local/bin/tool\n# mise's system config"),
    ("pins", "a checksum placeholder", CF, "ARG MISE_SHA256_AMD64=8d48bc51", "ARG MISE_SHA256_AMD64=TODO8d48bc51"),
    ("pins", "a floating version", CF, "ARG MISE_VERSION=2026.10.3", "ARG MISE_VERSION=latest"),
    ("user-agent", "USER root", CF, "USER agent", "USER root"),
    ("user-agent", "no USER", CF, "USER agent\n", ""),
    ("no-sshd", "openssh-server installed", CF, "build-essential ca-certificates",
     "build-essential openssh-server ca-certificates"),
    ("no-sshd", "a port exposed", CF, "USER agent", "EXPOSE 22\nUSER agent"),
    ("no-sudo", "sudo installed", CF, "build-essential ca-certificates", "build-essential sudo ca-certificates"),
    ("no-sudo", "a sudoers entry", CF, "# mise's system config",
     "RUN echo 'agent ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agent\n# mise's system config"),
    ("mise-config", "mise may call sudo", MISE, "system_packages.sudo = false", "system_packages.sudo = true"),
    ("mise-config", "a global tool version", MISE, "system_packages.sudo = false",
     "system_packages.sudo = false\n[tools]\npython = \"3.13\""),
    ("mise-config", "the config not copied in", CF, "COPY mise-config.toml /etc/mise/config.toml", ""),
    ("image-specs", "a language in provides", SPEC, 'provides = ["mise"]', 'provides = ["mise", "python"]'),
    ("image-specs", "a host capability in provides", SPEC, 'provides = ["mise"]', 'provides = ["mise", "vm-host-oci"]'),
    ("image-specs", "a floor that is not the Containerfile's", SPEC, 'claude = "2.1.288"', 'claude = "2.1.200"'),
    ("image-specs", "root as the user", SPEC, 'user = "agent"', 'user = "root"'),
    ("repo-secrets", "a token in a file", "README.md", "# crew-images", "# crew-images\n\ntoken: " + TOKEN),
)


def copy():
    d = tempfile.mkdtemp(prefix="crew-images-mut-")
    dst = os.path.join(d, "repo")
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    return d, dst


def main():
    d, dst = copy()
    try:
        base = static.run(dst)
    finally:
        shutil.rmtree(d)
    if any(base.values()):
        print("FAIL the unbroken copy does not pass:", {k: v for k, v in base.items() if v})
        return 1
    missed = 0
    for check, what, path, old, new in MUTATIONS:
        d, dst = copy()
        try:
            p = os.path.join(dst, path)
            with open(p, encoding="utf-8") as f:
                text = f.read()
            if old not in text:
                print(f"FAIL {check}: {what}: the text to break is not in {path} (update the mutation)")
                missed += 1
                continue
            with open(p, "w", encoding="utf-8") as f:
                f.write(text.replace(old, new, 1))
            res = static.run(dst)
        finally:
            shutil.rmtree(d)
        caught = bool(res.get(check))
        missed += not caught
        print(f"{'ok  ' if caught else 'FAIL'} {check}: {what}: "
              + (res[check][0] if caught else "NOT caught"))
    print(f"mutations: {len(MUTATIONS) - missed} of {len(MUTATIONS)} caught")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
