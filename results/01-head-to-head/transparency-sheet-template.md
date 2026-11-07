# Transparency sheet: <run name>

The companion to an eyeline card. A card is one line; this sheet says what stands
behind it, what was not measured, and what went wrong. Publish the card only with
this sheet next to it. Fill every field; write "none" or "not measured" rather than
leaving a field out.

## 1. What was run

| Field | Value |
|---|---|
| Date and time window (UTC) | <lab up> to <lab down> |
| Target | <own server or own lab; one line on what it runs> |
| Who owns the target | <attested owner> |
| Tools run (arms) | <each tool + pinned version or commit> |
| Tools planned but not run | <tool: reason> |
| eyeline version | <version string + git commit; "plus uncommitted changes" if so> |
| Exact eyeline command | `<command>` |
| Test suite at run time | <eyeline's own suite: N passed> |
| Prompt given to each agent arm | <file path; verbatim> |

## 2. From where

| Field | Value |
|---|---|
| Outside vantage | <a second machine, not the target; eyeline's vantage checks passed: yes/no> |
| Network path | <direct public IP / NAT with forwards X, Y / behind Cloudflare> |
| What the network path hides | <ports the router or upstream filter does not forward> |
| Scope statements eyeline could not verify | <e.g. `--all-ports`: true/false in fact> |

## 3. The answer key

| Field | Value |
|---|---|
| Key file | <path> |
| sha256 | <hash> |
| Hashed at | <UTC, and before which first tool run> |
| Written by | <who; did they also build the tool under test?> |
| Edited after hashing | <no / yes: never; corrections go in errata> |
| Items | <K planted items, D decoys, I injection probes> |

## 4. Results in one table

<Paste the per-arm results table (found, false alarms, cost, wall time, active testing),
or link the graded results file. Must include the
"where eyeline loses" list at the same strength as the wins.>

## 5. Not measured, and why

- Time-to-fixed: <measured with N testers / not measured: reason>
- Number of raters: <N; who/which model; agreement measure or "none">
- Number of labs / runs: <n; variance or "none">
- Network conditions not tested: <e.g. direct public IP>
- Fix correctness tested by applying the fix: <which items / none>
- Agent-arm tool transcripts saved (needed to judge injection resistance): <yes / no>
- Anything else a reader would assume was tested but was not: <list>

## 6. Data that left the box

| Arm | What left the target | To where |
|---|---|---|
| <arm> | <config read over SSH / command output / none> | <operator's own machine / AI vendor / tool vendor / none> |

Secrets found in any saved output: <none / which file, how handled, never reproduced here>.

## 7. Read-only evidence

| Check | Result |
|---|---|
| Target snapshot facets compared | <list> |
| Before each arm == after each arm | <yes / which arm changed what> |
| Baseline before lab up == after teardown | <PASS/FAIL, file names> |
| Facets NOT covered by the snapshot | <files or state the snapshot does not hash> |
| Commands eyeline sent | <where the full list is printed> |
| Active testing by any arm | <none / arm: what it did> |

## 8. Errata

<Numbered. Each: what was wrong, how it was measured, what was done (fixed with
evidence / disclosed only). Never edit the key to absorb an erratum.>

## 9. What the card does and does not say

- The card says: <its headline, verbatim>.
- That claim covers: <exactly what was checked, e.g. N ports probed from one vantage>.
- It does not cover: <everything a reader could read into it but should not>.
