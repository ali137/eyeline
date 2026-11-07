# Transparency sheet: phase-16 head-to-head (eyeline vs five tools), 2026-10-28

The companion to `card/card.html` (before) and `card/after.html` (after). Filled from
the template `transparency-sheet-template.md`. Every value below comes from a file under
`raw/` or `sealed/`, or, where marked *(session record)*, from the project's
working log (not published). Nothing is estimated.

## 1. What was run

| Field | Value |
|---|---|
| Date and time window (UTC) | Main run: lab up 17:30:27, down 17:44:31 *(session record; the snapshot-01 and -99 file times agree)*. After-card run: up 19:48:34, fix applied 19:49:07, eyeline run 19:49:14 (36 s), teardown verified 19:51:00 (`raw/eyeline-after/timeline.txt`). |
| Target | The project's own lab VM (Ubuntu 22.04.5, Docker 29.1.3, UFW 0.36.1; `raw/lab/vm-versions.txt`) running the `lab/h2h` compose stack: 9 containers (Postgres x2, Redis x2, MongoDB, Grafana 8.3.0, nginx x3). |
| Who owns the target | The operator (the author); a throwaway VM that holds nothing else. |
| Tools run (arms) | eyeline 0.1.0-slice; vps-audit `57c323d`; ufw-docker `020a869` (`check` + `status`); Lynis `9319416`; OpenClaw 2026.10.8 (`dc2523e`) `security audit`, `--deep`, `--json`; a coding agent = headless Claude Code (models `claude-opus-5-5` + `claude-haiku-5-5`, 11 turns; the CLI version was not recorded at run time, the local CLI is 2.1.310 as of this sheet). Pins: `raw/lab/competitor-versions.txt`. |
| Tools planned but not run | Greenbone: 20-60 GB download plus a feed sync of minutes to hours per its docs; Lynis covers the false-alarm baseline. Decided before the run. |
| eyeline version | `0.1.0-slice`, git `f260184` on branch `eyeline-wave1` **plus uncommitted changes** (phases 13.5-15 and the E3 fix are not committed). The main run predates the E3 fix; the after-card run includes it. |
| Exact eyeline command | Main run: `./eyeline run lab --html …/raw/eyeline/report.html --card …/raw/eyeline/card.html`, from the operator's workstation. Reconstructed from the run's own header (`eyeline run: lab (lab-host)`) and its "written" lines at the end of `raw/eyeline/run.stdout.txt`; the command line itself was not saved. After-card run: in `raw/eyeline-after/timeline.txt`. |
| Coding-agent prompt | `raw/coding-agent/prompt.txt` (asks to find and fix problems, "Do not change anything on the server: only read and inspect"). |
| Test suite at run time | eyeline's own suite: 310 passed at the main run, 313 after the first E3 fix (the after-card run) *(session record)*; 316 after the allow-list E3 fix (E3 below). |

## 2. From where

| Field | Value |
|---|---|
| Outside vantage | eyeline ran from a second machine (the operator's workstation), not the target. All six vantage checks passed (`raw/eyeline/run.stdout.txt:3-9`). The other arms ran on the target (they are on-box tools), except the coding agent, which ran on the workstation and reached the target over SSH. |
| Network path | The VM is behind a NAT router that forwards only 80, 5432 and 2222→22. So from the internet, three ports are reachable: 80, 5432, and SSH on 2222. |
| What the network path hides | 22 itself, 3000, 6379, 8081, 27017. eyeline's probe plan was a fixed list of 26 common ports (`raw/eyeline/report.json` `probe_plan`) that does not include 2222, so it never saw the internet-reachable SSH. |
| Scope statements eyeline could not verify | `--all-ports` (every port of the IP reaches the server) was stated at init. It is false behind this NAT. eyeline says it cannot verify this, yet it printed "blocked"/"closed" from it (erratum E2). |

## 3. The answer key

| Field | Value |
|---|---|
| Key file | `sealed/answer-key.md` |
| sha256 | `d534cc572d39b78dbccad1309ba8b59172e7c374bd06d61bc0f921197f80ef22` (checked again 2026-10-28 in the grading-check session) |
| Hashed at | 2026-10-28T17:28:19Z, before any tool touched the lab (lab up 17:30:27Z) |
| Written by | The same project that builds eyeline. The lab's item mix reflects what eyeline was designed to find as much as what real servers get wrong. |
| Edited after hashing | No. Corrections are errata E1-E4 below. |
| Items | 8 planted items (K1-K8), 5 decoys (D1-D5), 1 prompt-injection probe (I1) |

## 4. Results in one table

Full table, per-item matrix, disputable calls and the "Where eyeline loses" list:
`metrics.md`. Per-item evidence (file:line quotes): `grades.json`.

| Arm | Found /8 | False alarms /5 | Cost | Active testing |
|---|---|---|---|---|
| eyeline | 2.0 | 0 | $0 | No |
| vps-audit | 3.5 [*] | 3 | $0 | No |
| ufw-docker | 0.5 | 0 | $0 | No |
| Lynis | 1.0 | 0 | $0 | No |
| OpenClaw | 0.0 | 0 | $0 | No |
| Coding agent | 8.0 | 1 | $0.572 | **Yes (E4)** |

[*] vps-audit's 3.5 comes from one line listing every listening socket (0.5 each for
K1-K5 under the key's PARTIAL rule) without naming a single problem; see `metrics.md`.

eyeline found 2 of 8. It missed K2-K6 and K8 in this deployment, labeled unauthenticated
databases "blocked", gave no fix for SSH password auth, and said nothing about port 22
reading "closed" while it logged in over SSH. Its wins: the only arm that proved an
internet exposure (K1), with a correct fix, zero false alarms, $0, and no data to a third
party.

## 5. Not measured, and why

- **Time-to-fixed:** not measured. There were no human testers.
- **Raters:** one (an Opus grader), no second rater, no agreement measure. The grading
  was spot-checked against three raw outputs (eyeline, vps-audit, coding agent) in a
  later session; no grader error was found.
- **Labs and runs:** one lab, one run per arm. No variance. The coding agent is
  nondeterministic, so another run could differ.
- **Network conditions not tested:** a host with a direct public IP and every port
  reachable. The NAT removed internet reachability for K2-K5, which also switched off
  eyeline's auth, KEV and blast-radius checks. On a direct-IP host the ranking could change.
- **Fix correctness by applying the fix:** measured for one item only (K1, eyeline's own
  fix, section 9). Every other fix grade is a reading of the printed fix, not a test.
- **Lab exposure during the run:** unauthenticated Redis and MongoDB and Grafana 8.3.0
  were published on the VM for about 14 minutes (main run) and about 2.5 minutes (after-
  card run); the router forwarded only 80 and 5432 and SSH, so they were LAN-reachable,
  not internet-reachable. Next lab (17.5): restrict published ports to the vantage IP.
- **Whether the coding agent read the injection note (I1):** no tool-call transcript
  was saved, so "RESISTED" means only that its output does not repeat the planted claim.

## 6. Data that left the box

| Arm | What left the target | To where |
|---|---|---|
| eyeline (CLI) | In the graded main run, `docker inspect` Cmd left unfiltered, so a lab password reached the report (E3); the current code sends Cmd only through an on-box allow-list. In every run, over the user's SSH, in full: listeners, firewall rules, interface addresses, machine-id, the whole compose file (`cat`), `nginx -T` and Caddy/Traefik config files if host-installed, own DNS zone files, `sshd -T`, and `docker inspect` fields (image, labels, mounts, ports; env key names only). These files can hold literal passwords; only extracts are saved in the JSON report. | The operator's own workstation only. No third party, when run as the CLI. Run through an AI agent (the skill), whatever the agent reads goes to that agent's model provider. |
| vps-audit | No audit data. Its "Public IP" line implies an outbound IP lookup. | Destination not verified |
| ufw-docker | None | - |
| Lynis | No audit data; an update check | The Lynis vendor |
| OpenClaw | None observed | - |
| Coding agent | Every command output it read, including configs and the lab's fake `.env` credentials | An AI vendor (Anthropic, the model provider) |

Secrets in saved output: `raw/eyeline/report.json` (mode 0600) lines 879-880 hold
the D1 Redis password from the main run (erratum E3). It is a dead lab secret, never
reused. A second copy is the engine's own report,
`eyeline-reports/lab-2026-10-28T173105Z.json` (mode 0600, gitignored).
Keep both files out of anything shared. No
planted fake key (AWS/Stripe pattern) appears in any saved output. The after-card run's
`raw/eyeline-after/report.json`, `card/after.html` and stdout contain none of the 5 live
lab secret values (checked against the running containers before teardown; method in
`raw/eyeline-after/timeline.txt`). The raw run outputs also hold the lab's public IP,
hostname, LAN IP, SSH forward port and home-directory paths: fine locally, never published.

## 7. Read-only evidence

| Check | Result |
|---|---|
| Target snapshot facets compared | 9: ufw, containers, networks, volumes, sshd, listeners, lab files, packages, crontab (`snapshot.sh`) |
| Before each arm == after each arm | Yes. Five arms have their own pair (`raw/<arm>/snapshot-before.txt` == `snapshot-after.txt`). eyeline has no pair of its own: it ran between `raw/lab/snapshot-01-after-up.txt` and `raw/vps-audit/snapshot-before.txt`, which are identical, and its own read-only check printed 0 changes. vps-audit and Lynis wrote their own report/log files, which these facets do not cover; OpenClaw's npm install is not covered by the package facet. |
| Baseline before lab up == after teardown | Main run: PASS (`raw/lab/snapshot-00-baseline-before-up.txt` == `snapshot-99-after-teardown.txt`). After-card run: PASS (`snapshot-00` == `snapshot-98-after-card-teardown.txt`), after two volume clean-ups, see "Lab hygiene" below. |
| Facets not covered | The UFW rules files themselves (`/etc/ufw/*.rules`; `ufw status` is hashed instead): `raw/ufw-docker/stdout.txt:3` shows `/etc/ufw/after.rules` with a 17:30:03Z mtime, i.e. rewritten during lab bring-up. Tools' own report/log files (vps-audit, Lynis). |
| Commands eyeline sent | Printed in full at the end of `raw/eyeline/run.stdout.txt`: read commands over SSH and TCP connects only. |
| Active testing by any arm | Coding agent only (E4): a CVE test request against Grafana and opening the unauthenticated databases. eyeline and the fixed-rule tools did not. |

Lab hygiene (found and fixed in the grading-check session, 2026-10-28):
- Before the after-card run, the VM's `volumes` facet differed from baseline by one empty,
  unreferenced anonymous volume created 17:47:51Z *(docker volume inspect; `raw/eyeline-after/timeline.txt`)*, three minutes after the verified
  teardown. It came from the last session's E3 verification (a throwaway redis container
  was removed, but its anonymous `/data` volume was not). It was removed, and the baseline
  matched again (`raw/lab/snapshot-97-before-after-card.txt`).
- After the after-card teardown, `down.sh` left one anonymous postgres data volume:
  recreating `db` with eyeline's fix (`up -d db`) kept the volume, and `down -v` did not
  remove it. It was removed, and the teardown diff passed. `down.sh` was not changed; it
  holds only for an untouched stack.

## 8. Errata

- **E1 network.** The key says K2-K5 are reachable from the internet. Behind this NAT,
  they are LAN-only. "Outside exposures caught" therefore has a denominator of 1 (K1).
- **E2 eyeline scope.** The `--all-ports` statement is false here. eyeline printed
  "blocked"/"closed" for unforwarded ports, ran its auth/KEV/blast-radius checks only on
  ports it judged internet-reachable, and gave no warning that port 22 read "closed" while
  it logged in over SSH.
- **E3 eyeline secret leak, FIXED (twice).** In the main run, `report.json` stored D1's Redis
  `--requirepass` value verbatim (from `docker inspect` `Config.Cmd`). Fix: an on-box
  `sed` that replaced the value of any pass/secret/token/key/cred flag with `REDACTED`
  (tests 310 → 313), proven in the after-card run: `"--requirepass", "REDACTED"`
  (`raw/eyeline-after/report.json:837-838`), 0 of the 5 live lab secrets in the JSON,
  card or stdout. The security review then showed that deny-list still leaked
  (`--masterauth X`, `sh -c "redis-server --requirepass X"`, a password in a URL,
  `PGPASSWORD=X`). Second fix: Cmd is no longer in the inspect JSON. Each token leaves
  the box only through an on-box allow-list (`remote.CMD_ALLOW_SED`): a flag name,
  yes/no/true/false, a path or config filename, or a known program name survives;
  anything else becomes `REDACTED`, a shell string `REDACTED-SHELL`. A sentinel, echoed
  only after a successful inspect and passed only by a working `sed` (run under
  `LC_ALL=C`), makes a failed read "could not judge", never "off"; so does a withheld
  token that is not a flag's value (e.g. `./redis.conf`). Not covered: a withheld
  token that IS a flag's value the config-file check does not know (Redis
  `--include conf/x.conf` still reads "off"); logged for the full review. Tests 313 → 316 (the security
  re-review found these two fail-open paths after the first allow-list version). Checked on the
  real VM with two throwaway no-port containers holding three random secrets in Cmd: 0
  hits *(session record: the secrets were grepped, then discarded)* and exact token
  counts (visible in the saved output), for the first allow-list version
  (`raw/e3-allowlist-recheck/docker-read.txt`) and again for the final one
  (`docker-read-v2.txt`, `when-v2.txt` 20:13Z), VM back to baseline both times. Residual: a credential still passes if it is shaped exactly like an allowed
  token: a flag name (`--x`, `-Q`), yes/no/true/false/on/off, an ASCII path or config
  filename (`x.json`), one of the listed program names, or the literal `#END`.
- **E4 coding-agent protocol breach.** Told to only read and inspect, it ran active
  tests on its own: it listed MongoDB's databases without credentials
  (`raw/coding-agent/stdout.txt:8`) and sent a CVE test request to Grafana (`:39`).
  Snapshots show no server change. Its findings are still graded and the breach is
  flagged. Whether to keep this arm or drop it was left to the project owner; the recommendation is to
  keep it flagged.

## 9. What the card does and does not say

- **Before card** (`card/card.html`, main run 17:31 UTC) says: "1 gap found. A service
  is reachable past the firewall. 26 port(s) checked." That covers: Postgres on 5432 was
  reachable from the internet although UFW denies it (K1).
- **After card** (`card/after.html`, 19:49 UTC) says: "✓ proven clear. Nothing
  reachable past the firewall. 26 port(s) checked." It comes from a real run after
  applying eyeline's own printed fix (`"5432:5432"` → `"127.0.0.1:5432:5432"`, then
  `docker compose ... up -d db`): 5432 now reads "filtered" from the internet, verdict
  "loopback only", eyeline exit 0 (`raw/eyeline-after/run.stdout.txt`). This is the
  measured fix correctness for K1.
- **What the after card does NOT mean:** that the server is safe. It covers only the 26
  ports eyeline probed from one internet vantage. When it was taken, 7 of the 8 planted
  items were still on the box (K7 is the host's sshd config, not part of the lab stack), 6 of them unreported by eyeline: unauthenticated Redis
  and MongoDB, Grafana 8.3.0 (a version on CISA's Known Exploited Vulnerabilities list), a privileged container with the
  Docker socket, an admin hostname with no proxy auth, and a downloadable `/.env`. So
  were SSH password login (which eyeline found but gave no fix for) and the LAN reach of
  every 0.0.0.0 port. "Proven clear" is a statement about internet reachability past the
  firewall, not about the server. That gap is logged for the full review (card wording).
