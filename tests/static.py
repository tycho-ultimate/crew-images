"""Static checks of this repo (IMG-1, tycho-ultimate/crew#56): the workflows, the Containerfiles, the image specs.

    python3 -I tests/static.py [<root>]      (root: this checkout, or a copy; tests/mutations.py breaks copies)

Each check has a name; the output is one line per check, ok or FAIL with the reasons, and exit 1 when any fails.
Stdlib only: the workflow is read line by line (no YAML library), so its layout is part of the contract (two-space
indentation, one key per line), and a layout these checks cannot read fails rather than passes.
"""
import os
import re
import shlex
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHA_USES = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}")
WRITE_OK = {"packages", "id-token"}            # the only scopes a job may write, and only on main
SCOPES = {"actions", "attestations", "checks", "contents", "deployments", "discussions", "id-token", "issues",
          "models", "packages", "pages", "pull-requests", "repository-projects", "security-events", "statuses"}
MAIN_ONLY = ("github.event_name != 'pull_request'", "github.ref == 'refs/heads/main'")
FROM_RE = re.compile(r"FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*", re.I)
PINNED_IMAGE = re.compile(r"[a-z0-9./_:-]+@sha256:[0-9a-f]{64}")
SHELLS = r"(?:sh|bash|zsh|dash|ksh|fish|python3?|perl|ruby|node)"
PIPE_TO_SHELL = re.compile(r"\|\s*(?:sudo\s+)?(?:env\s+\S+=\S+\s+)?" + SHELLS + r"\b")
SSH_SERVERS = {"openssh-server", "dropbear", "dropbear-bin", "dropbear-run", "tinysshd", "ssh"}
ESCALATION = {"sudo", "sudo-ldap", "doas", "opendoas"}
PLATFORMS = {"linux/arm64", "linux/amd64"}


def read(root, *parts):
    with open(os.path.join(root, *parts), encoding="utf-8") as f:
        return f.read()


def workflows(root):
    d = os.path.join(root, ".github", "workflows")
    return sorted(os.path.join(d, n) for n in os.listdir(d) if n.endswith((".yml", ".yaml")))


def images(root):
    d = os.path.join(root, "images")
    return sorted(n for n in os.listdir(d) if os.path.isfile(os.path.join(d, n, "Containerfile")))


def code(line):
    """A YAML line without its comment (a '#' after a space, outside quotes: good enough for these files)."""
    out, q = [], None
    for i, c in enumerate(line):
        if q:
            q = None if c == q else q
        elif c in "'\"":
            q = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(c)
    return "".join(out).rstrip()


def indent(line):
    return len(line) - len(line.lstrip(" "))


# ── the workflows ───────────────────────────────────────────────────────────
def check_uses_pinned(root):
    bad = []
    for p in workflows(root):
        for n, line in enumerate(read(root, p).splitlines(), 1):
            m = re.match(r"\s*(?:-\s+)?uses:\s*(.*)$", line)
            if not m:
                continue
            rest = m.group(1)
            ref, _, comment = rest.partition("#")
            ref = ref.strip().strip("'\"")
            if not SHA_USES.fullmatch(ref):
                bad.append(f"{os.path.basename(p)}:{n}: {ref!r} is not owner/repo@<40-hex commit SHA>")
            elif not re.match(r"\s*v\d", comment):
                bad.append(f"{os.path.basename(p)}:{n}: {ref} has no '# v<version>' comment")
    return bad


def jobs_of(lines):
    """{job: {"if": text, "permissions": {scope: level} | str | None, "line": n}} from a workflow's lines."""
    jobs, cur, in_jobs, in_perm = {}, None, False, False
    for n, raw in enumerate(lines, 1):
        line = code(raw)
        if not line.strip():
            continue
        ind = indent(line)
        if ind == 0:
            in_jobs = line.strip() == "jobs:"
            cur, in_perm = None, False
            continue
        if not in_jobs:
            continue
        if ind == 2 and line.strip().endswith(":"):
            cur = line.strip()[:-1]
            jobs[cur] = {"if": "", "permissions": None, "line": n}
            in_perm = False
            continue
        if cur is None:
            continue
        if ind == 4:
            in_perm = False
            k, _, v = line.strip().partition(":")
            v = v.strip()
            if k == "if":
                jobs[cur]["if"] = v
            elif k == "permissions":
                if v:
                    jobs[cur]["permissions"] = v
                else:
                    jobs[cur]["permissions"], in_perm = {}, True
        elif in_perm and ind == 6:
            k, _, v = line.strip().partition(":")
            jobs[cur]["permissions"][k.strip()] = v.strip()
        elif in_perm and ind > 6:
            jobs[cur]["permissions"] = f"unreadable (line {n})"
            in_perm = False
    return jobs


def top_permissions(lines):
    """The top-level permissions: "{}" | {scope: level} | None (absent)."""
    for i, raw in enumerate(lines):
        line = code(raw)
        if line.startswith("permissions:"):
            v = line.partition(":")[2].strip()
            if v:
                return v
            out = {}
            for nxt in lines[i + 1:]:
                c = code(nxt)
                if not c.strip():
                    continue
                if indent(c) == 0:
                    break
                k, _, lv = c.strip().partition(":")
                out[k.strip()] = lv.strip()
            return out
    return None


def check_permissions(root):
    bad = []
    for p in workflows(root):
        name = os.path.basename(p)
        lines = read(root, p).splitlines()
        top = top_permissions(lines)
        if top is None:
            bad.append(f"{name}: no top-level permissions (want permissions: {{}})")
        elif top != "{}" and not (isinstance(top, dict) and all(v in ("read", "none") for v in top.values())):
            bad.append(f"{name}: top-level permissions {top!r}: want {{}} (or read only); each job asks for its own")
        jobs = jobs_of(lines)
        if not jobs:
            bad.append(f"{name}: no jobs found (a layout these checks cannot read)")
        for job, j in jobs.items():
            perm = j["permissions"]
            if perm is None:
                bad.append(f"{name}: job {job} has no permissions of its own")
                continue
            if isinstance(perm, str):
                if perm != "{}":
                    bad.append(f"{name}: job {job}: permissions {perm!r}: list each scope (never write-all)")
                continue
            for scope, level in perm.items():
                if scope not in SCOPES:
                    bad.append(f"{name}: job {job}: unknown permission {scope!r}")
                elif level not in ("read", "write", "none"):
                    bad.append(f"{name}: job {job}: {scope}: {level!r} is not read, write or none")
                elif level == "write" and scope not in WRITE_OK:
                    bad.append(f"{name}: job {job}: {scope}: write (only packages and id-token may write)")
                elif level == "write" and not all(c in j["if"] for c in MAIN_ONLY):
                    bad.append(f"{name}: job {job}: {scope}: write without an if that excludes pull requests and "
                               f"other branches ({' && '.join(MAIN_ONLY)})")
    return bad


def check_no_pull_request_target(root):
    bad = []
    for p in workflows(root):
        for n, line in enumerate(read(root, p).splitlines(), 1):
            if "pull_request_target" in code(line) or "workflow_run" in code(line):
                bad.append(f"{os.path.basename(p)}:{n}: pull_request_target or workflow_run (runs with the base "
                           "repo's token on a fork's code)")
    return bad


def check_secrets(root):
    bad = []
    for p in workflows(root):
        for n, line in enumerate(read(root, p).splitlines(), 1):
            c = code(line)
            for m in re.finditer(r"secrets\s*(?:\.\s*([A-Za-z0-9_-]+)|\[\s*['\"]?([^'\"\]]*))", c):
                s = m.group(1) or m.group(2)
                if s != "GITHUB_TOKEN":
                    bad.append(f"{os.path.basename(p)}:{n}: secret {s!r}: the only secret is GITHUB_TOKEN")
            if re.search(r"secrets\s*:\s*inherit", c) or re.search(r"\btoJSON\s*\(\s*secrets\s*\)", c, re.I):
                bad.append(f"{os.path.basename(p)}:{n}: passes every secret on")
    return bad


# ── the Containerfiles ──────────────────────────────────────────────────────
def instructions(text):
    """[(line, KEYWORD, args)] with continuation lines joined and comment lines dropped."""
    out, buf, start = [], [], 0
    for n, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith("#") and not buf:
            continue
        if raw.lstrip().startswith("#"):
            continue                                   # a comment inside a continued instruction
        if not buf:
            start = n
        if raw.rstrip().endswith("\\"):
            buf.append(raw.rstrip()[:-1])
            continue
        buf.append(raw)
        joined = " ".join(x.strip() for x in buf).strip()
        buf = []
        if joined:
            kw, _, args = joined.partition(" ")
            out.append((start, kw.upper(), args.strip()))
    if buf:
        out.append((start, "UNTERMINATED", " ".join(buf)))
    return out


def commands(script):
    """A RUN's shell text split into pipelines of simple commands: [[[word, ...], ...], ...]. Leading VAR=value
    assignments are dropped from each command."""
    lex = shlex.shlex(script, posix=True, punctuation_chars=";&|()")
    lex.whitespace_split = True
    lex.commenters = ""
    pipelines, pipe, cmd = [], [], []
    for tok in lex:
        if tok in ("|",):
            pipe.append(cmd)
            cmd = []
        elif tok and set(tok) <= set(";&|()"):
            pipe.append(cmd)
            pipelines.append(pipe)
            pipe, cmd = [], []
        else:
            cmd.append(tok)
    pipe.append(cmd)
    pipelines.append(pipe)
    out = []
    for p in pipelines:
        q = []
        for c in p:
            while c and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", c[0]):
                c = c[1:]
            if c:
                q.append(c)
        if q:
            out.append(q)
    return out


def download_target(cmd):
    """The file a curl or wget command writes, or None (it writes to stdout)."""
    for i, w in enumerate(cmd):
        if cmd[0] == "curl" and w in ("-o", "--output") and i + 1 < len(cmd):
            return cmd[i + 1]
        if cmd[0] == "curl" and w.startswith("--output="):
            return w.split("=", 1)[1]
        if cmd[0] == "wget" and w in ("-O", "--output-document") and i + 1 < len(cmd):
            return cmd[i + 1]
    return None


def check_from_pinned(root):
    bad = []
    for img in images(root):
        stages = set()
        for n, kw, args in instructions(read(root, "images", img, "Containerfile")):
            if kw != "FROM":
                continue
            m = FROM_RE.fullmatch(args if args.upper().startswith("FROM") else f"FROM {args}")
            ref = m.group(1) if m else args
            if not (m and (PINNED_IMAGE.fullmatch(ref) or ref in stages)):
                bad.append(f"images/{img}/Containerfile:{n}: FROM {ref}: pin the base image by @sha256 digest")
            if m and m.group(2):
                stages.add(m.group(2))
    return bad


def check_downloads_verified(root):
    bad = []
    for img in images(root):
        where = f"images/{img}/Containerfile"
        for n, kw, args in instructions(read(root, "images", img, "Containerfile")):
            if kw == "ADD" and re.search(r"https?://|git@", args) and "--checksum=sha256:" not in args:
                bad.append(f"{where}:{n}: ADD of a URL without --checksum=sha256:")
            if kw != "RUN":
                continue
            if PIPE_TO_SHELL.search(args):
                bad.append(f"{where}:{n}: something is piped into a shell or an interpreter")
            try:
                pipelines = commands(args)
            except ValueError as e:
                bad.append(f"{where}:{n}: a RUN these checks cannot read ({e})")
                continue
            verified = set()
            for p in pipelines:
                if p[-1][0] == "sha256sum" and any(w in ("-c", "--check") for w in p[-1]):
                    for c in p[:-1]:
                        verified.update(c)
            for p in pipelines:
                for i, c in enumerate(p):
                    if c[0] not in ("curl", "wget"):
                        continue
                    if i < len(p) - 1:
                        bad.append(f"{where}:{n}: {c[0]} piped into {p[i + 1][0]}: download to a file, check it")
                        continue
                    target = download_target(c)
                    if target is None:
                        bad.append(f"{where}:{n}: {c[0]} without -o <file>: download to a file, check it")
                    elif target not in verified:
                        bad.append(f"{where}:{n}: {c[0]} -o {target}: not checked by `... | sha256sum -c` in the "
                                   "same RUN")
    return bad


def check_pins(root):
    bad = []
    for img in images(root):
        where = f"images/{img}/Containerfile"
        for n, kw, args in instructions(read(root, "images", img, "Containerfile")):
            if kw != "ARG":
                continue
            k, _, v = args.partition("=")
            if "SHA256" in k and not re.fullmatch(r"[0-9a-f]{64}", v):
                bad.append(f"{where}:{n}: {k} must default to a sha256 (64 lowercase hex), not {v!r}")
            if k.endswith("_VERSION") and not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", v):
                bad.append(f"{where}:{n}: {k} must default to an exact version, not {v!r}")
    return bad


def check_user_agent(root):
    bad = []
    for img in images(root):
        users = [(n, a) for n, kw, a in instructions(read(root, "images", img, "Containerfile")) if kw == "USER"]
        if not users:
            bad.append(f"images/{img}/Containerfile: no USER: the image would run as root")
        elif users[-1][1] != "agent":
            bad.append(f"images/{img}/Containerfile:{users[-1][0]}: the last USER is {users[-1][1]!r}, not agent")
    return bad


def apt_packages(args):
    pkgs = set()
    for p in commands(args):
        for c in p:
            if c[0] in ("apt-get", "apt") and "install" in c:
                pkgs.update(w.split("=")[0] for w in c[c.index("install") + 1:] if not w.startswith("-"))
    return pkgs


def check_no_sshd(root):
    bad = []
    for img in images(root):
        where = f"images/{img}/Containerfile"
        for n, kw, args in instructions(read(root, "images", img, "Containerfile")):
            if kw == "EXPOSE":
                bad.append(f"{where}:{n}: EXPOSE {args}: an image serves nothing")
            if kw == "RUN":
                if apt_packages(args) & SSH_SERVERS:
                    bad.append(f"{where}:{n}: installs an ssh server ({', '.join(sorted(apt_packages(args) & SSH_SERVERS))})")
                if re.search(r"\bsshd\b", args):
                    bad.append(f"{where}:{n}: a RUN mentions sshd")
    return bad


def check_no_sudo(root):
    bad = []
    for img in images(root):
        where = f"images/{img}/Containerfile"
        for n, kw, args in instructions(read(root, "images", img, "Containerfile")):
            if kw == "RUN" and (apt_packages(args) & ESCALATION or re.search(r"sudoers|\busermod\b.*\b-a?G\b", args)):
                bad.append(f"{where}:{n}: gives a way to escalate (sudo, doas, sudoers or an added group)")
    return bad


def check_mise_config(root):
    bad = []
    for img in images(root):
        cf = read(root, "images", img, "Containerfile")
        if not re.search(r"^COPY\s+mise-config\.toml\s+/etc/mise/config\.toml\s*$", cf, re.M):
            bad.append(f"images/{img}/Containerfile: no `COPY mise-config.toml /etc/mise/config.toml`")
            continue
        try:
            with open(os.path.join(root, "images", img, "mise-config.toml"), "rb") as f:
                doc = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError) as e:
            bad.append(f"images/{img}/mise-config.toml: {e}")
            continue
        if doc.get("settings", {}).get("system_packages", {}).get("sudo") is not False:
            bad.append(f"images/{img}/mise-config.toml: settings.system_packages.sudo must be false")
        for k in ("tools", "tool_alias", "alias", "plugins", "tasks", "hooks", "env"):
            if k in doc:
                bad.append(f"images/{img}/mise-config.toml: [{k}]: the image sets no tool versions, hooks or env")
        if re.search(r"\bMISE_SYSTEM_PACKAGES_SUDO\s*=\s*(?!false)", cf):
            bad.append(f"images/{img}/Containerfile: MISE_SYSTEM_PACKAGES_SUDO overrides the setting")
    return bad


def vocabulary(root):
    caps, hosts = set(), set()
    for line in read(root, "tests", "crew-capabilities.txt").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        (hosts if line.startswith("host:") else caps).add(line.removeprefix("host:"))
    return caps, hosts


def check_image_specs(root):
    bad = []
    caps, hosts = vocabulary(root)
    for img in images(root):
        where = f"images/{img}/image.toml"
        try:
            with open(os.path.join(root, "images", img, "image.toml"), "rb") as f:
                spec = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError) as e:
            bad.append(f"{where}: {e}")
            continue
        provides = spec.get("provides")
        if not isinstance(provides, list) or len(provides) > 16:
            bad.append(f"{where}: provides must be a list of at most 16 capability names")
            provides = []
        seen = set()
        for i, c in enumerate(provides):
            if c in hosts:
                bad.append(f"{where}: provides[{i}] {c!r} is a host's capability, never an image's")
            elif c not in caps:
                bad.append(f"{where}: provides[{i}] {c!r} is not in crew's capability vocabulary "
                           f"(tests/crew-capabilities.txt: {', '.join(sorted(caps))})")
            elif c in seen:
                bad.append(f"{where}: provides[{i}] {c!r} twice")
            seen.add(c)
        if spec.get("user") != "agent":
            bad.append(f"{where}: user must be agent (the Containerfile's USER), not {spec.get('user')!r}")
        plats = spec.get("platforms")
        if not (isinstance(plats, list) and plats and set(plats) <= PLATFORMS and len(set(plats)) == len(plats)):
            bad.append(f"{where}: platforms must be some of {', '.join(sorted(PLATFORMS))}")
        cf = read(root, "images", img, "Containerfile")
        for tool, floor in (spec.get("floors") or {}).items():
            m = re.search(rf"^ARG {tool.upper()}_VERSION=(\S+)$", cf, re.M)
            if not m or m.group(1) != floor:
                bad.append(f"{where}: floors.{tool} = {floor!r} but the Containerfile has "
                           f"{m.group(1) if m else 'no'} {tool.upper()}_VERSION")
        for tool in ("claude", "codex", "mise"):
            if tool not in (spec.get("tools") or []):
                bad.append(f"{where}: tools must include {tool} (the test job asks each for --version)")
    return bad


def check_repo_secrets(root):
    sys.path.insert(0, os.path.join(root, "ci"))
    try:
        import scan
    finally:
        sys.path.pop(0)
    paths = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x != ".git"]
        paths += [os.path.join(d, f) for f in files]
    findings, notes = scan.scan_files(sorted(paths))
    return [f"{os.path.relpath(p, root)}: {what}" for p, what in findings + notes]


CHECKS = (
    ("uses-pinned", check_uses_pinned),
    ("permissions", check_permissions),
    ("no-pull-request-target", check_no_pull_request_target),
    ("secrets-only-github-token", check_secrets),
    ("from-pinned", check_from_pinned),
    ("downloads-verified", check_downloads_verified),
    ("pins", check_pins),
    ("user-agent", check_user_agent),
    ("no-sshd", check_no_sshd),
    ("no-sudo", check_no_sudo),
    ("mise-config", check_mise_config),
    ("image-specs", check_image_specs),
    ("repo-secrets", check_repo_secrets),
)


def run(root):
    """{check name: [problems]} for the checkout at root."""
    out = {}
    for name, fn in CHECKS:
        try:
            out[name] = fn(root)
        except (OSError, ValueError, KeyError) as e:
            out[name] = [f"could not run: {e}"]
    return out


def main(argv):
    root = argv[0] if argv else ROOT
    results = run(root)
    for name, problems in results.items():
        print(f"{'ok  ' if not problems else 'FAIL'} {name}")
        for p in problems:
            print(f"       {p}")
    failed = [n for n, p in results.items() if p]
    print(f"static: {len(results) - len(failed)} ok, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
