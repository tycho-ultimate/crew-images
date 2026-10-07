"""Mutation runs for the image test job (ci/image_test.py): each check that asserts something is absent from an
image is shown to fail on a deliberately broken copy of a tested image.

    python3 -I tests/image_mutations.py <tested local image ref> <image name>

Each broken copy is made with docker create, docker cp and docker commit (no builder, no network), tested with
ci/image_test.py's checks, and removed. The canary credential is built at run time, never written in the repo.
Exit 1 when a mutation is not caught. Needs docker; the pull-request job runs it after the image's own test.
"""
import os
import subprocess
import sys
import tempfile
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ci"))
import image_test  # noqa: E402

TOKEN = "g" + "hp_" + "Q7xk2mPz9LwV4nRt8sYb3cDf6hJg5aEu1234"
MISE_SUDO = "[settings]\nsystem_packages.sudo = true\n"
MISE_TOOLS = "[settings]\nsystem_packages.sudo = false\n[tools]\njq = \"1.7.1\"\n"

# (check that must fail, what the mutation does, files to copy in {path: text}, docker commit --change lines)
MUTATIONS = (
    ("scan", "a gh credentials file with a token", {"/home/agent/.config/gh/hosts.yml":
                                                    "github.com:\n  oauth_token: " + TOKEN + "\n"}, []),
    ("scan", "a token in an env file under /etc", {"/etc/profile.d/token.sh": "export GH_TOKEN=" + TOKEN + "\n"}, []),
    ("scan", "a private key in root's home", {"/root/.ssh/id_ed25519": "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n"
                                              "b3BlbnNzaC1rZXktdjEAAAAA\n-----END " + "OPENSSH PRIVATE KEY-----\n"}, []),
    ("scan", "a sudo program", {"/usr/bin/sudo": "#!/bin/sh\nexec \"$@\"\n"}, []),
    ("scan", "an ssh server program", {"/usr/sbin/sshd": "#!/bin/sh\n"}, []),
    ("config-user", "USER root", {}, ["USER root"]),
    ("runs-as-agent", "USER root", {}, ["USER root"]),
    ("runs-as-agent", "USER 0", {}, ["USER 0"]),
    ("no-exposed-port", "EXPOSE 22", {}, ["EXPOSE 22"]),
    ("mise-no-sudo", "mise may call sudo", {"/etc/mise/config.toml": MISE_SUDO}, []),
    ("mise-no-global-tools", "a global tool version", {"/etc/mise/config.toml": MISE_TOOLS}, []),
)


def docker(*args):
    r = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError(f"docker {args[0]} failed: {r.stderr.strip()[:200]}")
    return r.stdout.strip()


def broken(ref, files, changes, n):
    tag = f"crew-images-mutation/{n}:latest"
    cid = docker("create", ref)
    try:
        for path, text in files.items():
            copy_in(ref, cid, path, text)
        args = ["commit"]
        for c in changes:
            args += ["--change", c]
        docker(*args, cid, tag)
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
    return tag


def is_dir(ref, path):
    r = subprocess.run(["docker", "run", "--rm", "--network", "none", "--user", "0", ref, "test", "-d", path],
                       capture_output=True)
    return r.returncode == 0


def copy_in(ref, cid, path, text):
    """docker cp of text to path in the container, making missing parent directories (docker cp cannot): copy a
    tree whose root is the first missing one."""
    parts = path.strip("/").split("/")
    k = len(parts) - 1
    while k > 0 and not is_dir(ref, "/" + "/".join(parts[:k])):
        k -= 1
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, *parts[k:])
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(target, 0o755)
        docker("cp", os.path.join(d, parts[k]), f"{cid}:/" + "/".join(parts[:k]))


def main(argv):
    if len(argv) != 2:
        print("usage: image_mutations.py <tested local image ref> <image name>", file=sys.stderr)
        return 2
    ref, image = argv
    with open(os.path.join(ROOT, "images", image, "image.toml"), "rb") as f:
        spec = tomllib.load(f)
    missed = 0
    for n, (check, what, files, changes) in enumerate(MUTATIONS):
        tag = broken(ref, files, changes, n)
        try:
            results = {name: (ok, why) for name, ok, why in image_test.checks(tag, spec, show=lambda line: None)}
        finally:
            subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)
        ok, why = results.get(check, (True, "the check did not run"))
        missed += ok
        print(f"{'FAIL' if ok else 'ok  '} {check}: {what}: {'NOT caught' if ok else why}")
    print(f"image mutations: {len(MUTATIONS) - missed} of {len(MUTATIONS)} caught")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
