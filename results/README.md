# Results

Graded evidence from three lab runs of eyeline. Each lab was a throwaway VM owned by
the author, with planted problems (K items) and decoys (D items) listed in an answer
key that was sealed (hashed) before the run. Every number below is copied from the
folder's `metrics.md`; per-item evidence is in its `grades.json`.

| Folder | What it is | eyeline score |
|---|---|---|
| `01-head-to-head/` | Phase 16 (2026-10-28): eyeline against five other tools on one lab (vps-audit, ufw-docker, Lynis, OpenClaw, and a headless coding agent). Includes the transparency sheet, its blank template, and the before/after share cards (`card/`). | **2.0 / 8** found, 0 / 5 false alarms. Others: coding agent 8.0 (1 false alarm), vps-audit 3.5 (3), Lynis 1.0, ufw-docker 0.5, OpenClaw 0.0. |
| `02-fresh-sealed-lab/` | Phase 17.5 (2026-10-28): a fresh lab with a new sealed key, eyeline only. | **5.5 / 8** found, 1 / 6 false alarms, fixes 2 CORRECT / 2 PARTIAL / 2 NONE, outside exposures 2 / 5. |
| `02-fresh-sealed-lab/retest-2026-10-29/` | The same lab and key, rerun a day later with the fixed engine. **Not blind**: the key was known when the fixes were made. It never replaces the 5.5 above. | **5.5 / 8** found, 0 / 6 false alarms, fixes 3 CORRECT / 1 PARTIAL / 2 NONE, outside exposures 2 / 5. |
| `03-second-sealed-lab/` | Phase 17-b (2026-10-29): a second fresh sealed lab, blind by procedure (see its errata), eyeline only. | **3.5 / 8** found (4.5 / 9 with a pre-existing SSH item), 1 / 7 false alarms, fixes 2 CORRECT / 0 PARTIAL / 5 NONE, outside exposures 0 / 3. Strict reading 1.5 / 8, lenient 4.5 / 8. |

One run per lab, one grader per run (an AI model, named in each file), no human testers.
Each `metrics.md` lists its disputable grading calls and what the run cannot show.

## What is not published

- `raw/` (tool outputs, snapshots, logs) and `sealed/` (answer keys). The raw outputs hold
  the lab's real addresses and host details, and one phase-16 report holds a leaked
  (dead) lab password, the defect described as erratum E3. File:line citations into
  `raw/` and `sealed/` are kept as they were graded.
- The project's working log and the internal reviews of the grading. Where a file cites
  them, the citation says so.

## Placeholders

Host details were replaced consistently in this folder and in the test fixtures:
public IPv4 addresses with documentation addresses (203.0.113.0/24, 198.51.100.0/24),
the public IPv6 address with 2001:db8::/32, the lab LAN subnet with
192.168.56.0/24, the router's SSH forward port with 2222, the SSH host alias with
`lab-host`, and home directories with `/home/user`.
