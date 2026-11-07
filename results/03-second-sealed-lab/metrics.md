# Phase 17-b fresh sealed lab 2: graded results (eyeline only, blind by procedure; see errata)

Grader: claude-opus-5-5. I did not build the lab, write the key, or run eyeline.
Sealed key: `sha256sum sealed/answer-key.md` = `70a9534c99c448c099ab5902df0da913fcdc72a3b01b9bbbb4876a347febc40e`. This matches `sealed/answer-key.sha256` and `SEALED.txt` (sealed 2026-10-29T19:53:03Z). Lab files: `sealed/lab-files.sha256` (`3e23a6ff…9e43190`) had all 10 entries OK on the workstation at stage 1 and 10/10 OK on the VM after the run. The key was applied unchanged; corrections are errata E-a to E-f below.
Per-item evidence (file:line) is in `grades.json`. Line numbers refer to `raw/eyeline/run.stdout.txt` unless another file is named.

## Results

| Measure | eyeline |
|---|---|
| Found, planted (/8) | **3.5** (1 FOUND, 5 PARTIAL, 2 MISSED) |
| Found incl. pre-existing K9 (/9) | **4.5** (C2: passwordauthentication yes) |
| False alarms (/7 decoys) | **1** (D3) |
| Other alerts (noise) | 1 (port 22 upstream-filter warning, accurate) |
| Fix correctness | **2/7** CORRECT (K3, K9); 0 PARTIAL; 5 NONE (K4, K5, K6, K7, K8) |
| Fixes that would break 22, 80 or D2 | none |
| Reach accuracy (7 found/partial) | 6 correct, 0 overstated, 1 understated (K9) |
| Outside exposures caught (/3) | **0/3** (K1, K2 missed; K9 called LAN only) |
| Coverage (a) outside plan has 80, 5432, 2222 | 80 yes, 5432 yes, **2222 no** |
| Coverage (b) inside read lists all 9 listeners | yes |
| Injection I1 | N/A (no model), not a win |
| Cost / wall clock | $0 / 45 s (21:26:52Z to 21:27:37Z), exit 1 |
| Data leaving the box | None to a third party; config read over SSH to the operator workstation |
| Secrets in outputs | **0** of 8 generated values in all 8 output files (`raw/eyeline/secret-check.txt`, run by the grader) |
| Read-only (lab unchanged) | Yes: snapshot 01 = before-run = after-run = grader's snapshot 02 (9 facets), 0 restarts, lab files 10/10, outside view unchanged (`raw/after-run-checks.txt`); teardown 99 = 00 |

## Per-item matrix

F = FOUND (1), P = PARTIAL (0.5), M = MISSED. Fix grade in brackets: C = CORRECT, P = PARTIAL, N = NONE. Reach is per the key: I = internet, L = LAN only, H = host-local.

| Item | Grade | Reach as stated | Evidence |
|---|---|---|---|
| K1 backup tarball in web root (I) | M | - | no line; report.json:1415 `"names": []`, :2376 |
| K2 `metrics.office.test` → Prometheus, no auth (I) | M | - | no line; only the Traefik could-not-judge at 36 |
| K3 Traefik API on 8080, `api.insecure` (L) | F (C) | LAN, correct | 43-45, 79 |
| K4 Gitea installer open on 3000 (L) | P (N) | LAN hedged, correct | 20, 62-63 |
| K5 Ollama 11434, no auth (L) | P (N) | LAN hedged, correct | 25, 74-75 |
| K6 Glances host PID/net + `/:/rootfs` (H) | P (N) | "blocked", correct | 27, 80 |
| K7 MariaDB `root`/`root` on 3306 (L) | P (N) | LAN hedged, correct | 21, 65-66 |
| K8 Jenkins 2.426.2, CVE-2024-23897 KEV (L) | P (N) | LAN hedged, correct | 24, 71-72 |
| **Planted score** | **3.5 / 8** | | |
| K9 SSH password auth, pre-existing (I via 2222) | F (C) | **LAN only: understated** | 17, 32, 47-57 |
| **Total** | **4.5 / 9** | | |
| Decoys | D3 alarmed; D1, D2, D4, D5, D6, D7 not | | 39-41, 22 |

## Where eyeline loses

**Missed items (2 of 8, both internet-reachable):**
- **K1 missed, silently.** The archive name appears nowhere in any output. eyeline read the right web root (report.json:1413-1414, served by `fresh17b-site-1`). Its name patterns (line 108: `.env`, `*.sql`, `*.bak`, `*.backup`, `backup.*`, `dump.*` …) do not match `site-backup-2026-10-24.tar.gz`, so the list is empty (report.json:1415). The outside HEAD list tried only `/backup.tar.gz` (404, report.json:2376). No could-not-judge was printed, so a user reads "no secret files in the web root".
- **K2 missed.** `metrics.office.test`, Prometheus and its admin/lifecycle APIs appear in no finding. eyeline did say so honestly: "reverse proxy in container fresh17b-traefik-1: could not judge (it runs Traefik; eyeline reads proxy config inside containers only for nginx)" (line 36; also report.html:131-132 "Could not judge"). That is better than 17.5's silent Caddy miss. Still, it names no route or app and states no missing auth, so it does not reach the key's PARTIAL ("a route without auth middleware"). The dynamic config was bind-mounted from `~/lab-host/fresh17b/traefik/dynamic.yml`. eyeline's revproxy read looked only at host paths under `/etc/traefik/` (line 106).

**Partial detections (5), all on LAN-only or host-local items, none with a working fix:**
- **K4, K5, K7, K8: port only.** Each appears as a table row "not reached" (lines 20, 21, 24, 25) and as the same WARNING: "Docker forwards it past the host firewall … It is still reachable from wherever that filter lets traffic through, such as the LAN. Your --all-ports statement is probably wrong" (lines 62-75). Gitea, Ollama, MariaDB and Jenkins are never named in stdout, report.html or card.html. They appear only as report.json inventory. Nothing is said about the open installer, Ollama having no auth, MariaDB's `root` password, or Jenkins 2.426.2's KEV-listed CVE:
  - Ollama and MariaDB are outside eyeline's auth list (line 122), and no could-not-judge was printed for them.
  - eyeline did `cat` the compose file that holds `MYSQL_ROOT_PASSWORD: root` (line 103) but never used it.
  - The Jenkins image tag is in report.json:487, but the KEV map covers only Grafana (line 123), so `"kev": []` (report.json:2416), again with no could-not-judge.
- **K6: could-not-judge only.** Line 80: "container fresh17b-glances-1 … shares the host network, so Docker records no port for it, and no host listener runs as its program (glances, sh); its auth, blast-radius and KEV checks could not be judged". eyeline had the facts: `"pid_mode": "host"` (report.json:1279) and a bind of `/` to `/rootfs` (report.json:1283-1287). Yet `"blast": []` (report.json:2415). The note is misleading: literally true that no listener's program name is glances or sh, but the same run's table shows 61208 held by `python3.14` (line 27), which is Glances' own web server, and eyeline did not connect the two.

**False or overstated claims:**
- **D3 false alarm, ranked #1.** Lines 39-41: "Traefik on port 80 has authentication OFF (reachable from the internet) … --api.insecure=true exposes the Traefik dashboard/API with no auth. It is reachable from the internet." On port 80 the dashboard is served only through the D3 router, which returned 401 without credentials (pre-run O3). `api.insecure` serves the API on 8080 only. The finding happens because eyeline repeats the container's auth state for every port the container publishes (report.json:2395-2414). report.html:128 ranks it #1 in "Start here", and it is counted among the 3 findings on card.html:140.
- **SSH reach understated** (lines 47, 17): "reachable from the LAN, not the internet". The router forwards 2222 to 22, and 2222 is not in the 28-port plan (line 13). This is the same loss as 17.5.
- **The only remedy for four LAN-exposed services** is "Re-run init without --all-ports, or fix the forward" (lines 63-75). That is accurate about the operator's statement, but it is not a fix for any exposure.
- **The card** (card.html:140) shows "3 findings … A confirmed exposure". One of the three is the false port-80 finding. Neither internet-reachable planted item (K1, K2) is among them.

**Fixes below CORRECT:** K4, K5, K6, K7, K8 all NONE. No fix text addresses them; the --all-ports remedy is the same NONE call 17.5 made for its K6.

**Outside exposures: 0 of 3.** K1 and K2 were missed, and K9 was called LAN-only.

**Coverage gap (a):** the outside plan probed 80 and 5432 but not 2222, the only internet path to sshd.

## Where eyeline wins

- **K3:** found with the right cause (`--api.insecure=true`), the right reach (LAN, not internet), and the key's CORRECT fix (remove the flag; the authenticated D3 route keeps the dashboard).
- **K9:** traced to `50-cloud-init.conf:1`. The fix uses a drop-in that sorts first, then `sshd -t`, reload, verify, undo, and a lockout warning.
- **D1 resisted:** 5432 is shown as "loopback only" (line 22). This is the Docker-past-UFW look without the gap, and it did not fool eyeline.
- **Six of seven decoys left alone:** D1, D2, D4, D5, D6 and D7. In particular, D5's `cap_drop: ALL` was not flagged; 17.5 flagged its D5.
- **Inside coverage complete:** all nine listeners read, with compose file:line for every published port (report.json:880-916).
- **Honest could-not-judge for the Traefik proxy and the host-network container** (lines 36, 80; report.html:131-132), which 17.5 lacked for Caddy.
- **No damage:** read-only (identical snapshots, 0 restarts, lab files intact), $0, 45 s, nothing sent to a third party, no generated secret in any output, and no fix that breaks 22, 80 or D2.

## Disputable grading calls

- **D3 alarmed versus not.** I counted the port-80 Traefik finding as the D3 false alarm: it states exactly the claim D3 baits ("Traefik dashboard … no auth" on port 80, from the internet), and the claim is false. A lenient reading calls it a mis-attributed duplicate of K3 that never judged the D3 route. That reading gives **0/7 false alarms**, but then eyeline states K3 both as "reachable from the internet" (39-40, 78) and as "LAN, not the internet" (43-44, 79): a contradiction, which the key counts as overstated. Reach accuracy becomes **5 correct / 1 overstated / 1 understated**.
- **K4, K5, K7, K8 PARTIAL versus MISSED.** I met the key's PARTIAL threshold ("port named as reachable"), consistent with 17.5's K7 (port 2019). The strict reading: these warnings are about the operator's `--all-ports` statement and name neither the service nor a problem. Under it the score is **1.5/8 (2.5/9)**, with fixes 2/3 CORRECT.
- **K2 MISSED versus PARTIAL.** A lenient grader could credit the Traefik could-not-judge (line 36) as naming the proxy, for +0.5.
- **K6 PARTIAL versus FOUND.** Line 80 does say "shares the host network", which the key lists as an over-privilege. But it says so only as the reason it could not judge, and the key explicitly grades a could-not-judge as PARTIAL. A lenient reading gives +0.5.
- **Lenient total:** K2 P and K6 F give **4.5/8 (5.5/9)**, with 0/7 false alarms and reach 5 correct / 1 overstated / 1 understated if D3 is also read leniently.
- **K6 reach "correct".** The table says "blocked" (line 27), and report.json:2393 says "LAN reachability not shown (the host firewall decides)". With C1's UFW baseline, host-local is right.
- **K9 fix CORRECT.** It disables password login with a lockout warning. This is the same call as 17.5; not counted as breaking 22.
- **Port 22 warning counted as an "other alert".** It is accurate and relates to K9's reach. It could equally be left out of the noise count.

## Procedure log

| Order | Step | Time (UTC) | Record |
|---|---|---|---|
| 1 | Key sealed | 2026-10-29T19:53:03Z | sealed/SEALED.txt |
| 2 | Engine frozen (552 tests passed) | 21:01:59Z | raw/engine-freeze.sha256 footer |
| 3 | Lab copied to VM; snapshot 00 | 21:08:32Z | raw/snapshot-00-before-up.txt (mtime) |
| 4 | `sh up.sh` started | 21:08:32Z | raw/lab-up-time.txt, raw/up.log |
| 5 | up.sh "lab ready" | 21:21:24Z | raw/up.log |
| 6 | Snapshot 01 | 21:21:49Z | raw/snapshot-01-after-up.txt, snapshot-01-time.txt |
| 7 | Grader stage 1: seal check + 20 pre-run checks (11 inside, 9 outside) | 21:22:22Z-21:24:16Z | raw/pre-run-checks.txt (last modified 21:26:25Z, E-f) |
| 8 | Engine verified 23/23 against the freeze | before 21:26:52Z, exact time not recorded | coordinator's statement |
| 9 | eyeline `./eyeline run lab` | 21:26:52Z-21:27:37Z, exit 1 | raw/eyeline/timing.txt, run.stdout.txt |
| 10 | Snapshot after run | 21:27:40Z (mtime) | raw/eyeline/snapshot-after-run.txt |
| 11 | Grader stage 2: A1-A3, A4 (+ extra A4 pass 21:31:14Z) | 21:28:07Z-21:31:14Z | raw/after-run-checks.txt, raw/eyeline/secret-check.txt |
| 12 | `sh down.sh` | done 21:31:52Z, exit 0 | raw/down.log, raw/lab-down-time.txt |
| 13 | Snapshot 99 | 21:31:55Z (mtime) | raw/snapshot-99-after-teardown.txt |
| 14 | Grader stage 3: cmp 99 = 00; engine 23/23 re-check; grading | from 21:32:13Z | this file, grades.json (cmp and re-check: grader's statement, no transcript saved) |

## Port plan

eyeline probed 28 ports (line 13; report.json:1460): its 25 fixed ports plus the inside listeners 8081, 11434 and 61208 (`eyeline_engine/probe.py:18-31`). The router forwards only these three:

| Forwarded | To | In eyeline's plan | What eyeline saw |
|---|---|---|---|
| TCP 80 | VM:80 | yes | open (correct) |
| TCP 5432 | VM:5432 | yes | filtered, "loopback only" (correct, D1) |
| TCP 2222 | VM:22 | **no** | never probed; port 22 reported closed from the internet, SSH called LAN-only |

## Errata

- **E-a (blindness):** up.sh's final `sudo docker compose -p fresh17b ps` printed every container name, image and tag into the building session's output. That includes `jenkins/jenkins:2.426.2-lts-jdk17`, `nicolargo/glances:4.5.7-full`, mariadb, gitea, ollama and prometheus (raw/up.log, just before "lab ready at 2026-10-29T21:21:24Z"). The engine was frozen at 21:01:59Z, before up.sh started, and was verified 23/23 before the run, so this output could not shape the engine. The record does not say whether the building session read the lab files' contents while copying them (grader's statement).
- **E-b (blindness):** my stage-1 report to the building session said:
  - the total scores out of 9, and K9 concerns sshd `passwordauthentication`;
  - the UFW baseline holds, and one item's reach resolves host-local;
  - 10 containers were up, and a loopback-only DNAT rule was confirmed.

  All of this came after the engine freeze (21:01:59Z), and no engine change followed: 23/23 verified before the run (coordinator), and 23/23 again at grading (grader's statement).
- **E-c (record):** the stage-2 message described a "26-port plan, same as 17.5". The run's own plan is 28 ports. The settings were the same; the count follows the lab's listeners (17.5 added 2019 to the same 25 fixed ports).
- **E-d (method):** the O8 and A3 port loops print "closed" both for a refused connection and for one that timed out (5 s timeout, not the key's 4 s), so they do not tell closed from filtered. eyeline saw 5432 as "filtered". Both say it is not reachable from the internet.
- **E-e (method):** A4 departs from the key's procedure in two ways, both stricter:
  - The values stayed in a Python process's memory instead of the key's umask-077 `/tmp` file.
  - The search covered first-16-character prefixes and case, HTML-entity, JSON and whitespace variants.

  The result is the same: 0.
- **E-f (record):** `raw/pre-run-checks.txt` was last modified at 21:26:25Z, before the run started (21:26:52Z). The change was two command-text-only edits (O8 and O9 written out in full after an independent review). No recorded result changed (grader's statement; no earlier copy of the file was saved; only the mtime is on record).

## What this run cannot show

- **One run, one rater, one lab.** There is no variance across runs and no second grader for the disputable calls.
- **The NAT shapes the result.** The run used `--all-ports`, which this NAT makes false, and 2222 was not probed. A different router or init statement would change K9's reach and the five upstream-filter warnings.
- **Same model family.** The lab, the key, the engine and this grader are all from the same model family in the same project. The lab was written without reading eyeline's engine, but I cannot verify that.
- **Independence rests on the record.** The engine freeze (21:01:59Z) comes after the key seal (19:53:03Z). Independence depends on the builder not having read the key, which I cannot verify. The files matching the freeze now does not prove they are what ran. E-a and E-b reached the building session after the freeze.
- **LAN reach was not tested from a separate LAN host.** It rests on C1 (UFW) and C4 (DNAT), plus loopback answers from the VM itself.
- **IPv6 reach** is not tested.
- **Time-to-fixed and usability** were not measured. Fix grades judge whether the printed text would work.

## Changelog

- 2026-10-29, after an independent review (not published): "blind" reworded to "blind by procedure"; the K6 note on line 80 reworded from "wrong on its face" to "misleading"; "one of the 3 findings" reworded to "counted among"; the `raw/after-run-checks.txt` header end time corrected to 21:31:14Z. Wording only: no grade, number or citation changed.
