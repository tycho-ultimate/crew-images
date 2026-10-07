"""The test job for one built image (IMG-1, tycho-ultimate/crew#56): run against a local image before any push.

    python3 -I ci/image_test.py <local image ref> <image name> [<root>]

  - the image's configured user is images/<name>/image.toml's (agent), and a container started with no --user runs
    as it, never uid 0;
  - every tool in image.toml's `tools` answers --version as that user, offline (--network none); claude and codex
    report image.toml's [floors]; python3 is 3.11 or newer;
  - mise: system_packages.sudo is false, and it lists no tool versions (no global ones);
  - no sudo and no ssh server anywhere in the filesystem, and nothing secret-shaped (ci/scan.py on `docker export`);
  - no exposed port.

Prints one line per check (ok or FAIL) and exits 1 when any fails.
"""
import json
import os
import subprocess
import sys
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
TIMEOUT = 120


def docker(*args, timeout=TIMEOUT, **kw):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, **kw)


def run_in(ref, *cmd):
    """cmd in a fresh container of ref: no network, the image's own user, removed afterwards."""
    return docker("run", "--rm", "--network", "none", ref, *cmd)


def first_line(text):
    return (text.strip().splitlines() or [""])[0][:120]


def checks(ref, spec, show=print):
    """(name, ok, why) for each check; show(line) gets the scanner's own lines."""
    want_user = spec["user"]
    inspect = docker("image", "inspect", "--format", "{{json .Config}}", ref)
    if inspect.returncode != 0:
        yield "image", False, f"docker image inspect failed: {first_line(inspect.stderr)}"
        return
    config = json.loads(inspect.stdout) or {}
    yield "config-user", config.get("User") == want_user, f"Config.User is {config.get('User')!r}"
    ports = config.get("ExposedPorts") or {}
    yield "no-exposed-port", not ports, f"exposed: {sorted(ports) or 'none'}"

    r = run_in(ref, "sh", "-c", 'printf "%s %s\\n" "$(id -un)" "$(id -u)"')
    name, _, uid = r.stdout.strip().partition(" ")
    yield "runs-as-agent", r.returncode == 0 and name == want_user and uid not in ("", "0"), \
        f"runs as {name or '?'} (uid {uid or '?'})"

    for tool in spec["tools"]:
        r = run_in(ref, tool, "--version")
        yield f"version:{tool}", r.returncode == 0, first_line(r.stdout or r.stderr) or f"exit {r.returncode}"

    for tool, floor in spec.get("floors", {}).items():
        r = run_in(ref, tool, "--version")
        words = r.stdout.replace("(", " ").split()
        yield f"floor:{tool}", r.returncode == 0 and floor in words, \
            f"wants {floor}, has {first_line(r.stdout) or 'nothing'}"

    r = run_in(ref, "python3", "-c", "import sys; print('%d.%d' % sys.version_info[:2]); "
                                     "sys.exit(sys.version_info < (3, 11))")
    yield "python3>=3.11", r.returncode == 0, f"python3 {r.stdout.strip() or '?'}"

    r = run_in(ref, "mise", "settings", "get", "system_packages.sudo")
    yield "mise-no-sudo", r.returncode == 0 and r.stdout.strip() == "false", \
        f"system_packages.sudo = {r.stdout.strip() or first_line(r.stderr) or '?'}"
    r = run_in(ref, "mise", "ls", "--json")
    try:
        tools = json.loads(r.stdout) if r.returncode == 0 else None
    except ValueError:
        tools = None
    yield "mise-no-global-tools", tools == {}, f"mise ls --json: {first_line(r.stdout) or first_line(r.stderr)}"

    yield from scan(ref, show)


def scan(ref, show):
    c = docker("create", ref)
    if c.returncode != 0:
        yield "scan", False, f"docker create failed: {first_line(c.stderr)}"
        return
    cid = c.stdout.strip()
    try:
        exp = subprocess.Popen(["docker", "export", cid], stdout=subprocess.PIPE)
        sc = subprocess.run([sys.executable, "-I", os.path.join(HERE, "scan.py"), "--tar", "-"], stdin=exp.stdout,
                            capture_output=True, text=True, timeout=900)
        exp.stdout.close()
        exp_rc = exp.wait(timeout=60)
    finally:
        docker("rm", "-f", cid)
    for line in sc.stdout.splitlines():
        show(f"  {line}")
    ok = sc.returncode == 0 and exp_rc == 0
    yield "scan", ok, first_line(sc.stdout.splitlines()[-1] if sc.stdout.strip() else sc.stderr) \
        + ("" if exp_rc == 0 else f" (docker export exit {exp_rc})")


def main(argv):
    if len(argv) not in (2, 3):
        print("usage: image_test.py <local image ref> <image name> [<root>]", file=sys.stderr)
        return 2
    ref, image = argv[:2]
    root = argv[2] if len(argv) == 3 else os.path.dirname(HERE)
    with open(os.path.join(root, "images", image, "image.toml"), "rb") as f:
        spec = tomllib.load(f)
    failed = 0
    for name, ok, why in checks(ref, spec):
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {why}")
        failed += not ok
    print(f"image_test {image}: {'all ok' if not failed else f'{failed} failed'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
