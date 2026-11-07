# eyeline

[![Status: archived](https://img.shields.io/badge/status-archived-lightgrey?style=flat)](#status)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat)](LICENSE)

eyeline tried to show what the internet can actually reach on a server you own, against what the
server's firewall says it allows. It is an **archived, failed experiment**. This README explains what was
tried, how it was tested, the measured scores, and why it was stopped.

eyeline is defensive and read-only. It was built for servers you own, and only for those.

## The idea

There are two ways to look at a server's exposure:

- **The inside view.** Read the firewall rules, the listening ports, the Docker config. This trusts the config.
- **The outside view.** Connect to the server's public IP from another machine and see what answers.

The two can disagree. The textbook case: UFW denies port 5432, but Docker publishes Postgres on 5432 past
the firewall, so the database is reachable from the internet anyway. Tools that read the box from the inside
trust the config. eyeline read the server over your own SSH, probed its IP from a second machine, and printed
the difference as a table: what the firewall says, what the internet sees, and for each gap the cause,
the file and line, a fix, an undo, and a lockout warning. It never changed the server.

Around that core sat a few read-only checks: app auth read from container config, over-privileged
containers, known-exploited images (Grafana only), SSH password login, no-auth admin routes, and secret-looking
file names in web roots. Before probing, it required an ownership attestation and a proof that you control
the IP.

## How it was tested

Each test was a lab: a Docker Compose stack on a throwaway VM owned by the operator, holding a set of
planted misconfigurations (8 per lab) and decoys (5 to 7) built to look like problems but not be problems.

- **Sealed answer key.** The key's sha256 hash was recorded before any tool touched the lab. For the two
  fresh labs, a fresh-context agent wrote it, kept from the building session (the graders note they cannot
  verify the builder never read it). The key was applied unchanged; later corrections are listed as errata.
- **Frozen engine.** For the later labs, eyeline's files were hashed and frozen before the lab went up.
- **Separate grader.** A grader agent that did not build the lab or run the tool scored each item:
  FOUND = 1, PARTIAL = 0.5, MISSED = 0. A false alarm is an alarm raised on a decoy. Fixes were graded
  CORRECT, PARTIAL, WRONG or NONE.
- **Read-only proof.** The server was snapshotted on 9 facets (firewall, containers, networks, volumes,
  sshd, listeners, lab files, packages, crontab) before and after each run, and at teardown.
- **Secret check.** In the later labs, generated secret values were searched for in every eyeline output.

Three labs were run, plus one retest:

1. **Head-to-head.** eyeline against five other tools on the same lab: vps-audit, ufw-docker, Lynis,
   OpenClaw `security audit`, and a general coding agent (headless Claude Code, prompted to find and fix
   problems and told to change nothing on the server, only read and inspect). Greenbone was planned but
   not run (a 20-60 GB download).
2. **Fresh sealed lab 1.** A new lab and key after a round of coverage fixes aimed at the head-to-head misses.
3. **Retest of lab 1, NOT BLIND.** The same lab and key, run again on a later engine. The key had been
   known since the first grading and later fixes responded to it, so this score never replaces the first one.
4. **Fresh sealed lab 2, blind by procedure.** A new lab with different misconfigurations. After the engine
   freeze, the building session saw the lab's container names and a few grader remarks; no engine file
   changed after the freeze, so these could not shape the result. Both are recorded as errata.

Limits that apply to every run: one run per lab, one grader, no variance measure. The lab, the key, the
engine and the grader all came from the same model family in the same project. The VM sat behind a NAT
router that forwarded only three ports, which shaped what was reachable. No human testers, so time to fix
was not measured.

## Results

eyeline's scores, straight from each lab's `metrics.md`:

| Run | Found (of 8) | False alarms | Correct fixes | Outside exposures caught | Wall time |
|---|---|---|---|---|---|
| Head-to-head (2026-10-28) | 2.0 | 0 of 5 | 1 of 2 | 1 of 1 | 38 s |
| Fresh sealed lab 1 (2026-10-28) | 5.5 | 1 of 6 | 2 of 6 | 2 of 5 | 40 s |
| Lab 1 retest, NOT BLIND (2026-10-29) | 5.5 | 0 of 6 | 3 of 6 | 2 of 5 | 41 s |
| Fresh sealed lab 2 (2026-10-29) | 3.5 | 1 of 7 | 2 of 7 | 0 of 3 | 45 s |

- Lab 2 also had a ninth, pre-existing item (SSH password login); counting it, 4.5 of 9. The grader's
  strict reading gives 1.5 of 8, the lenient reading 4.5 of 8.
- Lab 1 has a disputed call (one item FOUND versus PARTIAL); the alternative score is 5.0.

The head-to-head, all arms:

| Arm | Found (of 8) | False alarms (of 5) | Correct fixes | Cost |
|---|---|---|---|---|
| eyeline | 2.0 | 0 | 1 of 2 | $0 |
| vps-audit | 3.5 | 3 | 1 of 6 | $0 |
| ufw-docker | 0.5 | 0 | 0 of 1 | $0 |
| Lynis | 1.0 | 0 | 0 of 1 | $0 |
| OpenClaw `security audit` | 0.0 | 0 | none found | $0 |
| Coding agent (headless Claude Code) | 8.0 | 1 | 8 of 8 | $0.572 |

The coding agent's caveat: told to only read and inspect, it ran active tests on its own (it listed
MongoDB's databases without credentials and sent a CVE test request to Grafana). The snapshots show no server change,
and its findings were still graded, with the breach flagged. It also sent every command output it read,
including the lab's fake credentials, to its model provider. Of vps-audit's 3.5, 2.5 comes from one line that
lists every listening socket, which earns 0.5 per item under the key's rules without naming a problem;
the other 1.0 is SSH password login, with a correct fix.

## Why it failed

After the lab 2 result, Ali's call was that eyeline was "never going to work". The records behind that call:

- **A general agent did the job better.** On the one head-to-head, the coding agent found 8 of 8 with 8
  correct fixes; eyeline found 2. eyeline had much of the evidence in its own JSON report (Redis with no
  password, MongoDB with no credentials, Grafana 8.3.0, a privileged container with the Docker socket) and
  printed none of it, because its checks only ran on ports it judged reachable from the internet.
- **Fixes closed the last lab's misses, not the next lab's.** After coverage fixes, lab 1 scored 5.5. Lab 2,
  with different misconfigurations, scored 3.5 and caught 0 of 3 internet-reachable items. The problems it did not
  name sat just outside the fixed rules: a backup archive whose name its patterns did not match, a route in a
  Traefik config mounted into a container (marked "could not judge"), a Jenkins version on the
  known-exploited list that its catalog (Grafana only) did not cover, and a MariaDB `root` password
  in a compose file it had read but not checked.
- **It reassured when it should not have.** It labeled LAN-reachable, unauthenticated services "blocked" or
  "closed". In the head-to-head its after-fix card said "proven clear" while 7 of the 8 planted items were
  still on the box. In all three labs its fixed list of probe ports missed the router's forwarded SSH port,
  so it reported internet-reachable SSH as "closed" or "LAN only".
- **It leaked a secret once.** In the head-to-head, its report stored a decoy's Redis password verbatim from
  a container's command line. This was fixed twice (the first fix, a deny-list, still leaked other shapes)
  and the later labs found 0 secrets in its outputs.
- **No real users ever ran it.** The plan was to put an early version in front of about 10 strangers. That
  step was skipped in favor of the internal lab exams, so the product's usage bar was never tested.

## What worked, and what is reusable

- **The sealed-lab method.** Hash the key first, freeze the engine, grade with a separate agent, publish
  errata instead of editing the key, and list every loss next to every win. The lab reports in `results/`
  follow this format.
- **Read-only held.** In every graded run the before and after snapshots matched, and eyeline ran no
  active tests. It was the only arm in the head-to-head that proved an exposure from the internet, with a
  correct fix that was then applied on the lab and confirmed by a re-run.
- **Few false alarms** (0, 1, 0 and 1 across the four runs), $0 per run, nothing sent to a third party.
- **No secrets out, after the fix:** 0 of 9, 0 of 9 and 0 of 8 generated secret values in its outputs.
- **Fail closed.** Where the firewall cannot be read, an open port is reported as "could not judge", never
  as clean. The nftables parser refuses rules it does not model instead of guessing.
- **Tests.** 552 passing at the final engine freeze.

## Built with Claude Code

eyeline was built with Claude Code under Ali's direction. AI agents wrote the engine and the tests, built
the labs, wrote the sealed answer keys, graded the runs, and reviewed the changes in separate spec and
security reviews, one project phase per session. Ali made the calls: the scope rules, skipping real users
for lab exams, the coverage-fix round after the head-to-head, and stopping the project. The general agent
that won the head-to-head was Claude Code itself.

## Running it anyway

It still runs. Use it only on a server you own, from a different machine. You need Python 3.9+ and
OpenSSH 7.6+ on the machine you run it from; the standard library only, no install step. SSH access to the
server, ideally with passwordless `sudo -n`, lets it read the firewall.

    git clone https://github.com/ali137/eyeline && cd eyeline
    ./eyeline init          # record the server and attest you own it
    ./eyeline prove <name>  # prove you control the IP
    ./eyeline run <name>    # read, probe, and print the exposure diff

Read [EYELINE.md](EYELINE.md) first, especially "What it does not do". A clean run means nothing in the
probed ports is reachable past the firewall. It does not mean the server is secure. `lab/slice/README.md`
sets up a box with the textbook gap; while it is up, the database is really reachable, so tear it down after.

## Repository layout

| Path | What it is |
|---|---|
| `eyeline` | The launcher script |
| `eyeline_engine/` | The engine: scope gate, inside read, outside probe, diff, checks, report |
| `tests/` | The test suite (`python3 -m pytest tests/ -q`, or `python3 -m unittest discover -s tests` without pytest) |
| `lab/` | Lab stacks: the slice demo and the head-to-head lab |
| `results/01-head-to-head/` | Head-to-head: metrics, transparency sheet, grades |
| `results/02-fresh-sealed-lab/` | Fresh sealed lab 1 and its not-blind retest |
| `results/03-second-sealed-lab/` | Fresh sealed lab 2 |
| `EYELINE.md` | Full user guide |
| `SKILL.md` | Thin Claude Code skill front end over the engine |
| `LICENSE` | MIT |

## Status

Archived: no support, no further releases. MIT licensed ([LICENSE](LICENSE)), provided as is, without warranty.
