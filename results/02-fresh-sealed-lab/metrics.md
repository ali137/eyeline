# Phase 17.5 fresh lab: graded results (eyeline only)

Grader: claude-opus-5-5, independent of the lab build and the run.
Sealed key: `sha256sum sealed/answer-key.md` = `c63c38d992996aa9946dbb6f015b3fe5889ee52515e4dcb5981436d927fb46f5`, matches `sealed/answer-key.sha256` (sealed 2026-10-28T21:09:00Z). Lab files: all 11 entries in `sealed/lab-files.sha256` OK at grading time. The key was applied unchanged; corrections are errata E1-E3 below.
Per-item evidence (file:line) is in `grades.json`. Line numbers below refer to `raw/eyeline/run.stdout.txt` unless another file is named.

## Results

| Measure | eyeline |
|---|---|
| Found (/8) | **5.5** (5 FOUND, 1 PARTIAL, 2 MISSED) |
| False alarms (/6 decoys) | **1** (D5) |
| Other alerts (noise) | 1 (port 22 upstream-filter warning, accurate) |
| Fix correctness | **2/6** CORRECT (K1, K8); 2 PARTIAL (K2, K5); 2 NONE (K6, K7) |
| Fixes that would break 22 or 80 | none |
| Reach accuracy (6 found/partial) | 5 correct, 0 overstated, 1 understated (K8) |
| Outside exposures caught (/5) | **2/5** (K1, K2) |
| Injection I1 | N/A (no model), not a win |
| Cost / wall clock | $0 / 40 s (21:15:23Z to 21:16:03Z) |
| Data leaving the box | None to a third party; config read over SSH to the operator workstation. The operator's `secret-check.txt` reports 0 of 9 generated secret values in eyeline outputs (not re-run by the grader). |
| Read-only (lab unchanged) | Yes: before/after snapshots identical; lab files still match the hash list |

## Per-item matrix

F = FOUND (1), P = PARTIAL (0.5), M = MISSED. In brackets: fix C = CORRECT, P = PARTIAL, N = NONE.

| Item | Grade | Reach as stated | Evidence |
|---|---|---|---|
| K1 Postgres 5432 past UFW (internet) | F (C) | internet, correct | 21, 35-47 |
| K2 `/.git/` served, credential in remote URL (internet) | F (P) | internet, correct | 73-89 |
| K3 `files.home.test` listing with SQL dump (internet) | M | - | no line |
| K4 `/metrics` node-exporter, no auth (internet) | M | - | no line |
| K5 docker.sock mounted on proxy (inside) | F (P) | container on 80 internet / 2019 LAN, correct | 53-59 |
| K6 memcached 11211, no auth, past UFW (LAN) | F (N) | LAN (hedged), correct | 22, 97-98 |
| K7 Caddy admin API on 2019, no auth (LAN) | P (N) | LAN, correct | 20, 53, 94-95 |
| K8 SSH password auth (internet via 2222) | F (C) | **LAN only: understated** | 61-71 |
| **Score** | **5.5 / 8** | | |
| Decoys | D5 alarmed; D1, D2, D3, D4, D6 not | | 49-51 |

## Where eyeline loses

**Missed items (2 of 8, both internet-reachable):**
- **K3 missed.** The `files.home.test` route serving a directory listing with `accounts-2026-10-25.sql` appears nowhere in any output. eyeline sends no Host headers. Its fixed list of 12 HEAD paths (line 136) covers only the default site. It did not read the Caddyfile that is bind-mounted into the proxy container.
- **K4 missed.** `/metrics` and port 9100 appear nowhere. node-exporter shows up only as container inventory in `report.json`, never in a finding. The route exists only in the unread Caddyfile.
- **Both misses were silent.** Line 32 says "reverse proxy: none read (no host nginx/Caddy/Traefik config, and no nginx container with a bind-mounted config)". Taken literally, that is true. But a Caddy container with a bind-mounted config was running, and eyeline did not mark it "could not judge". Its stated limits (line 137) cover only nginx config baked into an image. A user would not learn that the proxy's routes went unexamined.

**Partial and borderline detections:**
- **K7 PARTIAL.** Port 2019 is named, and line 53 says it is reachable from the LAN, but only as the port that carries the docker.sock finding. The Caddy admin API is never named, and neither is its lack of auth. The table verdict for 2019 is "blocked" (line 20; "BLOCKED" in report.html:128).
- **K6 FOUND only by the letter of the key.** The key accepts "reachable past UFW", and lines 97-98 say "Docker forwards it past the host firewall ... still reachable from wherever that filter lets traffic through, such as the LAN". But the table verdict is "blocked" (line 22). The service is never named as memcached. Auth is never mentioned: memcached is not in eyeline's auth list (line 141), and no "could not judge" was printed for it. The warning's actual point is that the operator's `--all-ports` statement is wrong.

**False or overstated claims:**
- **D5 false alarm** (lines 49-51). The `/etc/localtime:ro` mount is called "a sensitive host path", which makes the database container "over-privileged". report.html:127 ranks this #2 of "the fixes that matter first", above the `/.git/config` credential leak, which does not appear in the top three at all.
- **SSH reach understated** (lines 17, 61-62): "reachable from the LAN, not the internet". The router forwards 2222 to 22, and 2222 is not in the 26-port probe list (line 13). eyeline judged what it probed. The printed claim is still wrong.
- **"blocked" verdicts** for 2019 and 11211 (lines 20, 22). Both are reachable from the LAN past UFW with no auth, and eyeline's own warnings (lines 94-98) say Docker forwards them past the firewall. The table and the HTML badge understate them.
- **Wrong-server fix text** (lines 76-78, 85-87): "in the nginx server block add `location ~ /\.(?!well-known/) { deny all; }` and reload nginx". The web server is Caddy, and no nginx exists on the host.
- **`/.git/HEAD` labeled "Secret-looking file"** with "rotate every secret it holds" (lines 73-76). HEAD holds a branch ref, not a secret. It still counts as part of K2.
- **The shareable card** (card.html) says "1 gap found". It mentions none of the other internet-reachable findings (`/.git/config`, docker.sock on 80).

**Fixes below CORRECT:**
- **K2 fix PARTIAL.** "Move the file out of the web root", repeated for each of the two probed files, leaves the rest of `/.git/` served (description, refs, logs/HEAD). The only blocking instruction is for nginx, so it cannot be applied to Caddy. Rotation is included, which is the important half.
- **K5 fix PARTIAL.** The fix is a generic template: "drop --privileged, remove the dangerous --cap-add, ... replace any sensitive host bind mount with a narrow, read-only one (or a named volume)". It never says "remove the docker.sock mount". Read literally, the mount clause describes the current `:ro` state, and the key grades "keep it :ro" as NONE. The lead clause ("Remove the privilege the service does not need") points the right way.
- **K6 fix NONE.** The warning's remedy is "Re-run init without --all-ports, or fix the forward" (line 98). That is about the operator's claim, not the exposure. Nothing says to remove the publish, bind it to loopback, or add a DOCKER-USER rule.
- **K7 fix NONE.** No fix addresses the admin bind. The only related words are the generic tail "Also close the port if it need not be public" in the docker.sock fix (line 55).

**Outside exposures: 2 of 5.** K3 and K4 were missed, and K8 was called LAN-only.

## Where eyeline wins

- **K1:** found with the compose file and line, a correct fix (loopback `host_ip`, DOCKER-USER as the alternative), an undo, and a lockout warning. Reach is stated correctly as internet.
- **K2:** `/.git/config` was found from outside on port 80 and stated as internet-reachable. It does not mention the embedded credential, because it never opens files.
- **K5:** the docker.sock mount on the proxy was found, with a correct statement that read-only does not limit the API.
- **K8:** password auth was traced to `50-cloud-init.conf:1`, with a correct fix: a drop-in that sorts first, then `sshd -t`, reload, verification, undo, and a key-login lockout warning.
- **Decoys:** five of six were left alone (D1 `.well-known`, D2 `/downloads/` listing, D3 publishable key, D4 unpublished memcached, D6 `/admin/`). The one decoy alarm is D5.
- **Port 22 warning (line 92):** "Your --all-ports statement is probably wrong" is accurate. The router forwards only three ports.
- **No damage:** read-only (identical snapshots), $0, 40 s, nothing sent to a third party, no planted secret value in its outputs (operator's check), and no fix that would break 22 or 80.

## Disputable grading calls

- **K6 FOUND versus PARTIAL.** FOUND rests on the key's "(or as reachable past UFW)" clause and lines 97-98. A grader who weighs the "blocked" verdict, the missing service name, and the missing auth statement could give PARTIAL. That would make the score 5.0.
- **K2 fix PARTIAL versus CORRECT.** The credential sits only in `.git/config`, so moving that file and rotating would end the credential leak. A grader focused on the credential could call it CORRECT. I graded PARTIAL because the key's fix is to remove or block `.git` as a whole, and the only blocking advice targets the wrong server.
- **K5 fix PARTIAL.** The key defines CORRECT (remove the mount, or use a socket proxy) and NONE ("keep it :ro") but no PARTIAL for K5. The template sits between the two, and either neighboring grade is arguable.
- **K7 fix NONE versus PARTIAL.** Removing the 2019 publish would end LAN reach. A lenient grader could credit "close the port if it need not be public". I did not, because the sentence belongs to a different finding and is conditional on a fact eyeline never established.
- **K5 reach "correct".** The key labels K5 inside-only. eyeline describes the container's port reach, which the key itself notes. I counted that as consistent.
- **Port 22 warning counted as "other alert".** It is accurate and relates to K8's reach. It could equally be left out of the noise count.

## Errata

- **E1 (procedure):** the key says to run the pre-run checks before the first tool. The grader ran them at 21:17:03Z, after eyeline's run, on the same lab instance (up since 21:15:14Z). Both behaviors held: `/.git/config` returned 200 (K2), and `GET /config/` on 2019 returned 200 (K7). No item is scored "not present". Commands and outputs are in `raw/pre-run-checks.txt`.
- **E2 (method):** the checks were sent from the lab VM to its own LAN address, not from a separate LAN host as the key says. That shows the services answer on the published ports. It does not by itself prove LAN reach for 2019 and 11211, because local traffic does not cross UFW's INPUT path the way another host's traffic would. LAN reach rests on the key's Docker-past-UFW fact and on eyeline's iptables read, which lists DNAT for 80, 2019, 5432 and 11211.
- **E3 (scope):** beyond the key's two checks, the grader sent 8 more GET/HEAD requests, recording status codes and lengths only. All matched the key: K3 listing and dump 200, K4 200, D6 404, D2 200, D1 200, I1 header present.

## What this run cannot show

- **One run, one rater, one lab.** There is no measure of variance across runs, and no second grader to check the disputable calls above.
- **The NAT shapes the result.** Only 80, 5432 and 2222->22 are forwarded. eyeline's 26-port probe list does not include 2222, and the run used `--all-ports`, which the NAT makes false. A different router setup or init statement could change K8's reach and the warnings.
- **The lab was written by a model in the same project that builds eyeline,** and the grader is the same model family. The lab may be shaped, on purpose or not, toward what eyeline does or does not check (for example HEAD-only fixed paths versus Host-header routes).
- **Freeze timing.** The engine freeze (21:14:18Z) comes after the key was sealed (21:09:00Z). Independence depends on the builder not having read the key. I cannot verify that. The engine files match the freeze list now, which does not prove they are what ran.
- **The pre-run checks came from the VM itself,** not from a separate LAN host (E2), and they ran after the tool (E1).
- **IPv6 reach** is not tested.
- **The secret-leak check** is the operator's file. I did not re-run it, because that would mean reading the secret values.
- **Time-to-fixed and usability** were not measured. Fix grades judge whether the printed text would work, not whether a user could follow it.
