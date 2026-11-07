# RETEST, NOT BLIND: phase 17.5 fresh lab, eyeline rerun of 2026-10-29

> **RETEST, NOT BLIND.** The sealed key has been known since the 2026-10-28 grading, and later fixes respond to it. This score **never replaces the recorded 5.5/8**, which belongs to the frozen engine of 2026-10-28 (21:14:18Z). It shows what the 2026-10-29 engine does on the same lab, against the same key and rubric.

Grader: claude-opus-5-5. This is the same model that graded 17.5. It knew the 17.5 result and the key before grading.
- **Sealed key:** `sha256sum sealed/answer-key.md` = `c63c38d992996aa9946dbb6f015b3fe5889ee52515e4dcb5981436d927fb46f5`, which matches `sealed/answer-key.sha256` (sealed 2026-10-28T21:09:00Z). The key was applied unchanged. Deviations from its procedure are errata R1-R4 below.
- **Lab files:** all 11 entries in `sealed/lab-files.sha256` were OK on the VM after the run. This is the grader's statement: no transcript was saved. The on-record evidence is the snapshot `labfiles` facet, which is identical before and after the run. The local `lab/` copy also verifies 11/11.
- **Engine:** frozen 2026-10-29T21:01:59Z, 552 tests passed (`raw/engine-freeze.sha256`; project log:2766). The 23 hashed files in the repo match it (23/23) at grading time. That does not prove they are what ran.
- **Evidence:** per-item file:line evidence is in `grades.json`. Line numbers refer to `raw/eyeline/run.stdout.txt` unless another file is named. 17.5 line numbers are marked "17.5".

## Side by side

| Measure | 17.5 (2026-10-28, engine frozen 21:14:18Z, 352 tests) | Retest (2026-10-29, engine frozen 21:01:59Z, 552 tests) |
|---|---|---|
| Found (/8; FOUND 1, PARTIAL 0.5) | **5.5** (5 F, 1 P, 2 M) | **5.5** (5 F, 1 P, 2 M) |
| False alarms (/6 decoys) | 1 (D5) | **0** |
| Other alerts (noise) | 1 (port 22 upstream-filter, accurate) | 1 (same, line 78-79) |
| Fix correctness (of 6 found/partial) | 2 CORRECT / 2 PARTIAL / 2 NONE | **3 CORRECT / 1 PARTIAL / 2 NONE** |
| Fixes that would break 22 or 80 | none | none |
| Outside exposures caught (/5: K1, K2, K3, K4, K8) | 2/5 (K1, K2) | 2/5 (K1, K2) |
| Reach accuracy (6 found/partial) | 5 correct, 0 overstated, 1 understated (K8) | 5 correct, 0 overstated, 1 understated (K8) |
| Injection I1 | N/A (no model) | N/A (no model) |
| Cost / wall clock | $0 / 40 s | $0 / 41 s (21:05:52Z to 21:06:33Z) |
| Read-only proof | before/after snapshots identical; lab files match | before/after snapshots byte-identical (9 facets, including `labfiles`); lab files 11/11 on the VM (grader's statement, no transcript saved); teardown snapshot byte-identical to the before-up snapshot (grader `cmp`) |
| Secrets in outputs | 0 of 9 (operator's check, not re-run by the grader) | **0 of 9** per raw/eyeline/secret-check.txt. That file is a one-line count and does not record who ran it or the 16-character prefix test. Both are this grader's statement: the grader ran the check, values were never printed, and it found 0 full matches and 0 matches on each value's first 16 characters. |
| Data leaving the box | none to a third party | none to a third party |

The found score is unchanged. All the movement is in false alarms, fixes and honesty: one decoy alarm and two wrong labels are gone, one fix (K5) went to CORRECT, and two silent misses now print "could not judge". **Nothing moved on the four outside-reach losses** (K3, K4, K8 reach, plus K6/K7 auth).

## Per-item matrix

F = FOUND (1), P = PARTIAL (0.5), M = MISSED. In brackets: fix C = CORRECT, P = PARTIAL, N = NONE.

| Item | 17.5 | Retest | Reach as stated (retest) | Evidence (retest) |
|---|---|---|---|---|
| K1 Postgres 5432 past UFW (internet) | F (C) | F (C) | internet, correct | 21, 35-47, 88; report.json:1592; report.html:128 |
| K2 `/.git/` served, credential in remote URL (internet) | F (P) | F (P) | internet, correct | 69-76; report.json:1639-1648, 1821-1822 |
| K3 `files.home.test` listing with SQL dump (internet) | M | M | - | no line (could-not-judge at 32) |
| K4 `/metrics` node-exporter, no auth (internet) | M | M | - | no line (could-not-judge at 32) |
| K5 docker.sock on proxy (inside) | F (P) | F (**C**) | container on 80 internet / 2019 LAN, correct | 49-51, 53-55; report.json:1606, 1616 |
| K6 memcached 11211, no auth, past UFW (LAN) | F (N) | F (N) | LAN (hedged), correct | 22, 84-85; report.json:1672 |
| K7 Caddy admin API 2019, no auth (LAN) | P (N) | P (N) | LAN, correct | 20, 49-51, 81-82; report.json:1662 |
| K8 SSH password auth (internet via 2222) | F (C) | F (C) | **LAN only: understated** | 17, 28, 57-67; report.json:1626 |
| **Score** | **5.5 / 8** | **5.5 / 8** | | |
| Decoys | D5 alarmed | **none alarmed** | | D5: `localtime` only in report.json mount inventory (e.g. :365) |

## Every loss in the retest

**Missed (2 of 8, both internet-reachable):**
- **K3 MISSED.** No output mentions `files.home.test`, `accounts-2026`, the files listing, or any Host header. eyeline sends no Host headers, and its HEAD list is 12 fixed default-site paths (line 123).
  - The miss is no longer silent. Line 32 says: "reverse proxy in container fresh17-proxy-1: could not judge (it runs Caddy; eyeline reads proxy config inside containers only for nginx)". report.html:132 says: "Could not judge 1 item(s) ... None of them is a clean result."
  - By the key, that names neither the route nor the dump, so it does not earn a PARTIAL.
- **K4 MISSED.** `/metrics` and `9100` appear nowhere. node-exporter appears only as container inventory in report.json. The same could-not-judge note covers it.

**Partial and borderline:**
- **K7 PARTIAL, fix NONE.** Port 2019 is named. It is stated as LAN-reachable (line 49) and past the firewall (line 82). But the Caddy admin API and its lack of auth are never named ("admin API": 0 hits). No fix addresses `admin 0.0.0.0:2019`. The only related words are "Also close the port if it need not be public" at the end of the docker.sock fix (line 51).
- **K6 FOUND only by the letter, fix NONE.**
  - It earns FOUND through the key's "or as reachable past UFW" clause (lines 84-85).
  - memcached is never named in stdout, HTML or card, and auth is never stated. The App authentication block (lines 87-88) lists only PostgreSQL, and memcached is outside the auth list (line 128). No auth "could not judge" is printed for it.
  - The fix, "Re-run init without --all-ports, or fix the forward", corrects the operator's statement, not the exposure.

**Fixes below CORRECT:**
- **K2 fix PARTIAL** (same as 17.5). "Move the file out of the web root" names only `/.git/config`, which leaves description, refs and logs/HEAD served. The only concrete blocking syntax is nginx. Rotation is included.
- **K6 and K7 fix NONE** (see above).

**Wrong or understated claims:**
- **SSH reach understated** (line 57): "reachable from the LAN, not the internet". The router forwards 2222 to 22, and 2222 is not in the probe plan (see "Port plan" below).
- **K2's only concrete blocking syntax is nginx** (lines 71-74: "for nginx, add to the server block ... and reload nginx"). The web server is Caddy. The nginx text is now framed as an example ("in your web server; for nginx,"). The generic "stop serving dotfiles" clause was already in 17.5 (17.5 lines 76, 85), so the evidence is the same and the fix stays PARTIAL. "Move the file out of the web root" still names only `/.git/config`. See "Disputable calls".
- **"No such file was found in a web root eyeline read (an app may generate it)"** (line 70). eyeline read no web root on this host, because the Caddy config was unjudged (line 32). The hint at a generated file has no basis. This is minor.

**Presentation:**
- **report.html "Start here" (report.html:128):**
  - The top 3 are the 5432 GAP, docker.sock via 2019 (LAN), and docker.sock via 80.
  - The same docker.sock issue fills two of the three slots.
  - The internet-reachable `/.git/config` credential leak is not in the top 3. That was also true in 17.5, where the D5 alarm held #2.
- **The card** (card.html:140) says "1 gap found + 4 findings / A service is reachable past the firewall." It now counts findings, but it still names only the 5432 gap.

**Outside exposures: 2 of 5**, unchanged. K3 and K4 were missed, and K8 was called LAN-only.

## What changed versus 17.5, and the likely cause

The causes cite the project's working log (not published; the line numbers refer to it), the record of fixes made after the graded run. Anything marked GUESS has no record I could find.

| Item | Change | Plausible cause |
|---|---|---|
| D5 | Alarmed (17.5 lines 49-51, ranked #2 in report.html) → not alarmed | `riders.BENIGN_RO_FILES` treats a read-only `/etc/localtime` bind as benign: project log:2235, and :2254-2255 "Changed AFTER the graded run ... D5 false alarm removed" |
| K2 | Fix wording reframed ("in your web server; for nginx,"), grade unchanged (P). The `/.git/HEAD` "Secret-looking file ... rotate every secret it holds" overstatement is gone (HEAD still returned 200, report.json:1822, and is not reported) | project log:2255-2256 ".git one finding; secret-file fix text not nginx-only" |
| K3, K4 | Still MISSED. "reverse proxy: none read" (17.5 line 32) became an explicit Caddy could-not-judge | project log:2255 "Caddy container now 'could not judge' instead of 'none read'". Host-header routes and a /metrics check are logged as not fixed: :2261 |
| K5 | Fix PARTIAL → CORRECT ("remove the Docker socket mount (read-only still gives full control of the Docker API)") | project log:2440 "The blast fix says 'remove the Docker socket mount'" |
| K6, K7 | Grades unchanged. The table verdict "blocked" became "not reached" (lines 20, 22; report.html:129), which is accurate for the internet view and no longer contradicts the warnings | project log:2441 "'not reached' replaces 'blocked' when DNAT is seen". No memcached or Caddy-admin auth rider: logged at :2260-2261. The Caddy admin bind is "out of class" at :2680-2681 |
| K8 | Grade, fix and understated reach unchanged. The lockout wording changed ("worked with password prompts disabled (BatchMode), which normally means a key") | GUESS: the [cyber] S3 "BatchMode non-key logins" item (project log:2268). The 26-port plan missing 2222 is logged, not fixed: :2263 |
| Card | "1 gap found" → "1 gap found + 4 findings" | project log:2428 "The card counts findings" |
| K1 | No change | - |

## Port plan versus forwarded ports

The plan is 26 ports (report.json:1059 `probe_plan`; run.stdout.txt:13): 21, 22, 25, 53, 80, 110, 143, 443, 2019, 2375, 2376, 3000, 3306, 5000, 5432, 5672, 6379, 8000, 8080, 8443, 9000, 9090, 9200, 10250, 11211, 27017.

| Forwarded by the router | In the plan? | Outside result |
|---|---|---|
| TCP 80 | yes | open |
| TCP 5432 | yes | open |
| TCP 2222 → 22 | **no** | not probed. Port 22 is in the plan and reads "closed", which leads to the "LAN, not the internet" SSH claim (K8 reach understated) |

2019 and 11211 are in the plan and read "closed" from outside. That is correct, because neither is forwarded.

## Disputable grading calls

- **K2 fix PARTIAL versus CORRECT** (same call as 17.5, on the same evidence). The generic "stop serving dotfiles" clause and rotation appear in both runs (17.5 lines 85-87; retest lines 72-74). The only actionable syntax in both is nginx, and "move the file" names only `/.git/config`. A grader focused on the credential could call it CORRECT in both runs. If CORRECT, fixes are 4 / 0 / 2.
  - A literal all-dotfiles block in Caddy, without the nginx example's `.well-known` exception, would also hide D1 and eyeline's own ownership token.
- **K6 FOUND versus PARTIAL** (same call as 17.5). If PARTIAL, the score is 5.0.
- **K7 fix NONE versus PARTIAL** (same call as 17.5). "Close the port if it need not be public" belongs to another finding and is conditional.
- **K5 reach "correct"** (same call as 17.5). The key labels K5 inside-only, and eyeline states the container's port reach.
- **Could-not-judge earns no found credit.** The key scores what is named. Line 32 is an honesty improvement and is reported as one, not scored.

## Procedure log (UTC)

| # | Time | Step | Record |
|---|---|---|---|
| 1 | 2026-10-29T21:01:59Z | Engine frozen, 23 files, 552 tests passed | raw/engine-freeze.sha256; project log:2766 |
| 2 | before 21:02:26Z | Baseline snapshot before lab up | raw/snapshot-00-before-up.txt |
| 3 | 21:02:26Z | `up.sh` (images cached, no pull) | raw/lab-up-time.txt, raw/up.log |
| 4 | 21:02:42Z | Snapshot after up (also used as eyeline's before-run snapshot) | raw/snapshot-01-after-up.txt = raw/eyeline/snapshot-before-run.txt |
| 5 | 21:02:58Z | Grader verifies the key hash | raw/pre-run-checks.txt header |
| 6 | 21:03:21Z-21:03:35Z | Grader pre-run checks, BEFORE eyeline: K2 from outside 200/287 B and VM-local 200/287 B; K7 VM-local 200/1201 B | raw/pre-run-checks.txt |
| 7 | 21:05:52Z-21:06:33Z | `./eyeline run lab` from the workstation, exit 1 (run by the coordinator) | raw/eyeline/timing.txt, run.stdout.txt, report.json |
| 8 | right after 7 | Snapshot after run, byte-identical to step 4 | raw/eyeline/snapshot-after-run.txt |
| 9 | 21:07:06Z-21:07:37Z | Grader after-run read-only check: snapshots `cmp` identical; lab files 11/11 OK on the VM, plus 8 extras from up.sh (7 generated, `.well-known/eyeline.txt` copied); no transcript saved, grader's statement. Secret check: 9 values, 0 in outputs; the file records only the count | raw/eyeline/secret-check.txt |
| 10 | 21:08:06Z | `down.sh`, exit 0 (coordinator); containers, volume and network removed | raw/lab-down-time.txt, raw/down.log |
| 11 | after 10 | Teardown snapshot, byte-identical to step 2 (grader `cmp` at 21:08:34Z) | raw/snapshot-99-after-teardown.txt |
| 12 | 21:08:34Z onward | Grading (this file, grades.json) | - |

## Errata

- **R1 (vantage).** The key says to run both checks from a LAN machine.
  - K2 ran from outside (198.51.100.118 → 203.0.113.71) and from the VM to its own LAN IP.
  - K7 ran only from the VM to its own LAN IP, because 2019 is not forwarded. As with 17.5 E2, this shows the admin API answers on the published port. It does not by itself prove another LAN host's reach past UFW.
  - Both behaviors were present, so no item is scored "not present".
  - 17.5 E1 (checks after the run) and E3 (extra requests) were not repeated.
- **R2 (snapshot timing).** The before-run snapshot (21:02:42Z) predates the grader's pre-run GETs, so the before/after pair covers those GETs as well as the run. GETs cannot change the 9 facets, and the pair is identical.
- **R3 (baseline differs between days).** This retest's before-up snapshot differs from the 17.5 one only in the `labfiles` facet. GUESS: the second fresh lab's files were on the VM (`~/lab-host/fresh17b/`, project log:2769). It does not affect either day's before/after comparison.
- **R4 (run not observed by the grader).** The command, settings and times come from the coordinator and `timing.txt`. report.json `started`/`finished` agree, and line 13 confirms `--all-ports` and 26 ports.

## What this retest cannot show

- **It is not blind.** The key, the 17.5 losses and this grader's 17.5 reasoning were all known to the people who made the fixes. Gains on exactly the 17.5 losses are expected and say little about unseen labs. The blind measure is the separate fresh sealed lab.
- **The fixes may fit this lab.** The changes since 17.5 (D5, the K2 fix wording and the dropped /.git/HEAD finding, K5 fix, the verdict label, the card, the Caddy could-not-judge) all respond to 17.5's written losses. None of the items needing new probing (Host-header routes, /metrics, memcached auth, Caddy admin API, port 2222) changed.
- **One run, one rater, the same rater as 17.5.** There is no variance measure and no second grader.
- **The NAT shapes the result.** Only 80, 5432 and 2222→22 are forwarded, and the run used `--all-ports`, which this NAT makes false.
- **Engine identity.** The files match the freeze list now. That does not prove they are what ran.
- **IPv6, time-to-fixed and usability** were not measured.

## Changelog

- 2026-10-29, revised after an independent review (not published):
  - K2 fix CORRECT → PARTIAL. The generic dotfiles clause was already in 17.5, so the 17.5 call stands on the same evidence. Fixes are now 3/1/2.
  - The secret check and the VM lab-file check are now marked as the grader's statement; the saved files record only the count and the snapshot facet.
  - Citation fixes: probe_plan → report.json:1059; .well-known/eyeline.txt is copied, not generated.
