# eyeline

Prove what the internet can actually reach on a server **you own**.

A firewall can say a port is denied while a container quietly publishes it past
the firewall anyway. eyeline reads the server over your own SSH, then probes its
IP from a *different* machine, and shows you the difference: what the firewall
says, versus what the internet sees.

This is version `0.1.0-slice`. Its core check is a Docker-published port that gets
past the host firewall (UFW, firewalld, or plain nftables); around it sit a few
read-only checks (app auth from config, container privileges, known-exploited
images, SSH password login, no-auth admin routes, secret files in web roots). See
[What it does not do](#what-it-does-not-do).

It reads **UFW, firewalld, and plain nftables.** For a UFW box it reads
`ufw status`; for a firewalld box it reads `firewall-cmd --list-all`; for a box
with a plain nftables input chain it reads that chain's policy and accept rules.
Where the firewall cannot be read at all (no passwordless `sudo -n`, or a
firewall eyeline does not recognize), a port that is open from
the outside is reported as **could not judge** — never as clean. eyeline will
not tell you a port is safe when it could not actually read the rule that would
make it safe.

## What you need

- **Python 3.9+** and **OpenSSH 7.6+** (`ssh`, `ssh-keyscan`) on the machine you
  run eyeline from. Standard library only — nothing to install.
- **SSH access** to the server, ideally with passwordless `sudo -n` (or log in as
  root). Without it eyeline still runs and reports the firewall as "not readable"
  rather than guessing.
- The machine you run from **must not be the server itself.** eyeline probes from
  the outside, so it needs an outside vantage. It refuses to probe if it detects
  it is running on the target (it stops before any SSH login).

## Install

Clone it and run the `./eyeline` script from the clone's root. There is no
install step.

    git clone <repo-url> eyeline && cd eyeline
    ./eyeline --help

To use it as an agent skill, clone it straight into the skills folder, named
`eyeline`, so `SKILL.md` sits at the skill's root (not one folder down):

    git clone <repo-url> ~/.claude/skills/eyeline    # Claude Code, every project
    git clone <repo-url> .claude/skills/eyeline      # Claude Code, this project only

Then ask the agent to check your server. It runs the `eyeline` script in that
folder from your working directory, so the scope file and reports land there.
Tested on Claude Code only. `SKILL.md` uses only the open Agent Skills fields, but
no other agent has been tested. To limit the agent to the engine alone, allow only
its path in your agent's permissions, for example in Claude Code:
`"Bash(/home/you/.claude/skills/eyeline/eyeline *)"`.

## Use it: init → prove → run

### 1. `init` — record the server you own

    ./eyeline init

It asks for a name, your SSH address (a `user@host` or an ssh-config alias), the
server's public IPv4/IPv6, and an **attestation** that you own it: you type the
exact phrase `I own this server`. It writes `eyeline-scope.json` (mode 0600) and
prints an **ownership token**.

Answer **yes** to the all-ports question (or pass `--all-ports`) only if every
port of that IP reaches this one server: the IP is on the server itself (a normal
VPS), or a router forwards *all* ports to it (1:1 NAT / DMZ). Otherwise eyeline
probes only the single port your ownership proof went through.

Non-interactive form:

    ./eyeline init --name vps1 --ssh me@vps1 --ipv4 203.0.113.10 \
                   --ipv6 '' --attest 'I own this server' --all-ports

### 2. `prove` — prove you control the IP

eyeline will not probe an IP until it has proven you control it. Two methods in
this version:

- **HTTP token (preferred):** serve the exact token line `init` printed at
  `http://<ip>/.well-known/eyeline.txt` (it tries port 80, then 443).
- **SSH-read fallback:** if you can't serve the token, eyeline confirms control
  by reading the server over your SSH. It writes nothing.

Then:

    ./eyeline prove vps1

Unproven IPs are **never** probed from outside.

### 3. `run` — read, probe, and show the exposure diff

    ./eyeline run vps1

It reads the server (listeners, firewall rules, Docker-published ports), probes
the proven IP from this machine with plain TCP connects (no banners, no
payloads) plus the HTTP HEAD list below on 80/443, and prints a table: `PORT · LISTENING · FIREWALL SAYS · INTERNET SEES
· VERDICT`. A **GAP** row names the cause, the `docker-compose.yml` file and
line, a printed fix, how to undo it, and a lockout warning. For each port it also
reads **exposure context** — which host-installed reverse proxy (nginx or Caddy;
Traefik upstreams are listed in the JSON report only) forwards to which upstream,
whether a Coolify/Dokploy panel is on it, the effective sshd
settings on the SSH port, and the names in *your own* authoritative DNS zone files
that resolve to this box — stated as facts that never change a verdict. It also
prints a read-only check (snapshots before and after) and every command it sent
over SSH.
A JSON report is written to `eyeline-reports/` (mode 0600) on *your* machine,
never on the server.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No gap, no confirmed finding, and every non-loopback exposed/published port was probed and judged. Exit `0` alone is not a **proven all clear**: the report, HTML and card use that label only for exit `0` with zero could-not-judge items; otherwise they say "not a proven all clear" and list those items. |
| `1`  | At least one **GAP**, or a confirmed finding of any kind: app auth off, an over-privileged reachable container (privileged, dangerous capabilities, a host PID or network namespace, a sensitive mount), a known-exploited image, an origin reachable past Cloudflare or leaked by your own DNS, SSH password authentication on, a no-auth hostname route to an admin app, or a secret-looking file in a web root or served from the internet. An upstream-filter warning or a *could not judge* note alone never sets `1`. `1` wins over `3`: a run can hold both. |
| `3`  | Refused (running on the target), an IP not proven, an exposed port that was not probed, a port open from the outside whose firewall could **not be judged** (no firewall eyeline recognizes was readable, or a rule it does not evaluate may decide the port), or the known-exploited-version catalog could not be loaded while a KEV-tracked image is reachable — a *could not judge* result, which is not clean. Other *could not judge* notes (proxy config, a web root, the HEAD check, an app whose auth could not be read, a host-network container whose ports could not be told) print in the report but do not set `3`. |
| `2`  | Error (bad scope file, SSH failure, …). |
| `130`| Canceled (Ctrl-C / EOF). |

## What it does not do

- It **changes nothing** on the server. Fixes are printed for you to run.
- It contacts **only** IPs proven in this run. Its only outside contact is: plain
  TCP connects (no banners, no payloads); the HTTP token fetch (port 80, then 443);
  if the token fails, the SSH login proof — an `ssh-keyscan` of the IP's ssh port,
  then a pinned login that runs only `true`; and, on ports 80/443 when the probe saw them open, an HTTP
  **HEAD** (headers only, no body read, no redirect followed, no crawl) of this fixed
  list: `/.env`, `/.env.local`, `/.env.production`, `/.env.bak`, `/.git/config`, `/.git/HEAD`, `/backup.sql`, `/dump.sql`, `/database.sql`, `/db.sql`, `/backup.zip`, `/backup.tar.gz`, plus `/eyeline-absent-path-check` (a path that cannot exist, to spot a server that answers 200
  for everything).
- Web-root secret files are listed by **name only**, never opened, in the roots named
  by nginx config (on the host, or bind-mounted into an nginx container); template
  names such as `.env.example` are not reported. Mounted config is read on the host,
  never inside a container; nginx config baked into an image is *could not judge*; Caddy or
  Traefik config inside a container is also *could not judge*. So is nginx config eyeline
  cannot fully read: host `nginx -T` that prints nothing for a non-root login (eyeline
  never runs it with sudo), an included file it did not read, a `proxy_pass` to a
  variable, a mounted file over 256 KiB. So is host Caddy or Traefik config whose routes
  eyeline did not follow (a `reverse_proxy` to a placeholder, Caddy JSON config, an
  `import` of another file, a Traefik provider other than a `file` it read, any
  file-provider `directory`). A web root listing stops at 200 names and 4 levels deep;
  anything past that is *could not judge*.
- The SSH password-auth fix is printed only when eyeline's own login worked without a
  password; eyeline never applies it.
- It does **not** resolve domains, find IPs behind Cloudflare, or probe Cloudflare
  addresses.
- Its core check is Docker-published ports past the host firewall (UFW, firewalld,
  or plain nftables). Its app-auth, blast-radius and known-exploited-version checks
  cover only a few images, run on every port published on a non-loopback address
  (each labeled internet or LAN) and on a host-network container's ports where a host
  listener's process name matches its program (otherwise that container is *could not
  judge*), and are not a vulnerability scan. No HTTPS review.
- Proof shows you can serve or log in **at the IP**. Your attestation carries legal
  ownership — only run eyeline against servers you own or deployed yourself.
- `--all-ports` is *your* statement; eyeline cannot verify that every port of an IP
  reaches one server.
- The same-host guard recognizes common container/VM bridges by interface name
  (docker, br-, lxdbr, lxcbr, incusbr, virbr, podman, cni, veth, vmnet). A guest on
  another bridge (e.g. Proxmox vmbr) is not detected — run eyeline from a machine
  that is not on the target.

## Try it on a lab box

`lab/slice/README.md` sets up a box with the textbook gap (UFW denies 5432, but
Docker publishes postgres on 5432 anyway) so you can see eyeline report exactly
one gap. Deploy it only on a box you own, and tear it down after — the database
is really reachable from the internet while it is up.
