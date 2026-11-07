"""Frozen pre-13.5 nft-input parsers, reconstructed so the phase-13.5 regression
tests can reproduce each historical false-clean on a faithful reconstruction of the
buggy code it came from
(the "scratch-revert check" the phase prompt requires), without reaching into git.

Each of the three functions below is the `parse_nft_input` as it stood when one of
the three historical false-cleans was live (before that specific fix landed). They
are not imported by the engine; they exist only for test_inside.py to assert that the
buggy form read a drop/jump/firewalld ruleset as readable+allow (a false-clean) while
the current engine refuses or denies it. Only the parts relevant to each bug differ
from the shipped parser; the rest is reconstructed from that era's parser.
"""
import re

from eyeline_engine.inside import _nft_dports


def _nft_rule_is_unconditional(rule, pm):
    before = rule[:pm.start()]
    return not re.search(r"\b(ip6?\s+saddr|iif|iifname|meta\s+iif)\b", before)


def parse_nft_input_13a_family_bug(text):
    """13a: the firewalld-table guard matched only the `inet` family, so firewalld on
    the iptables backend (`table ip/ip6 firewalld`) was read as a plain nft chain and
    its `policy accept` produced a clean verdict for ports its real rules governed."""
    res = {"readable": False, "policy": None, "accepts": [], "rules": []}
    if not text or "table " not in text:
        return res
    # BUG: inet only.
    if re.search(r"\bufw-[\w-]+\b", text) or re.search(r"\btable\s+inet\s+firewalld\b", text):
        return res
    return _read_input_chain(text, res, jump_re=r"\b(?:jump|goto)\s+\S+",
                             spec_re=r"(tcp|udp)\s+dport\s+(\{[^}]*\}|[\d,\s:-]+?)\s+"
                                     r"(?:[^{}]*?\s+)?(accept|drop|reject)\b")


def parse_nft_input_13a_jump_bug(text):
    """13a: the base-chain jump refusal used anchored `re.match`, so the real
    `counter packets N bytes M jump X` spelling (jump not at line start) was not
    refused; the line was skipped and the chain policy decided -> a false-clean."""
    res = {"readable": False, "policy": None, "accepts": [], "rules": []}
    if not text or "table " not in text:
        return res
    if re.search(r"\bufw-[\w-]+\b", text) or re.search(r"\btable\s+(?:ip6?|inet)\s+firewalld\b", text):
        return res
    # BUG: anchored match (^) instead of search, so `counter ... jump` is missed.
    return _read_input_chain(text, res, jump_re=r"^(?:jump|goto)\s+\S+", anchored_jump=True,
                             spec_re=r"(tcp|udp)\s+dport\s+(\{[^}]*\}|[\d,\s:-]+?)\s+"
                                     r"(?:[^{}]*?\s+)?(accept|drop|reject)\b")


def parse_nft_input_13b_counter_dport_bug(text):
    """13b: the per-port dport spec capture was greedy (`.+?`), so it swallowed the
    `counter packets N bytes M` clause; _nft_dports then parsed no valid port and the
    whole rule was dropped, so a `tcp dport 5432 counter ... drop` read as open."""
    res = {"readable": False, "policy": None, "accepts": [], "rules": []}
    if not text or "table " not in text:
        return res
    if re.search(r"\bufw-[\w-]+\b", text) or re.search(r"\btable\s+(?:ip6?|inet)\s+firewalld\b", text):
        return res
    # BUG: greedy `.+?` spec that swallows the counter clause.
    return _read_input_chain(text, res, jump_re=r"\b(?:jump|goto)\s+\S+",
                             spec_re=r"(tcp|udp)\s+dport\s+(\{[^}]*\}|.+?)\s+(accept|drop|reject)\b")


def _read_input_chain(text, res, jump_re, spec_re, anchored_jump=False):
    depth, chain, chain_depth, in_input = 0, None, 0, False
    for line in text.splitlines():
        s = re.sub(r"\s*#.*$", "", line).strip()
        m = re.match(r"chain\s+(\S+)\s*\{", s)
        if m:
            chain, chain_depth, in_input = m.group(1), depth + 1, False
        elif chain:
            hook = re.match(r"type\s+\w+\s+hook\s+input\b.*policy\s+(\w+)", s)
            if hook:
                in_input, res["readable"], res["policy"] = True, True, hook.group(1)
            elif in_input and s and not s.startswith(("type ", "policy ", "}")):
                jump_hit = re.match(jump_re, s) if anchored_jump else re.search(jump_re, s)
                if jump_hit:
                    return {"readable": False, "policy": None, "accepts": [], "rules": []}
                pm = re.search(spec_re, s)
                if pm and _nft_rule_is_unconditional(s, pm):
                    proto, spec, verb = pm.group(1), pm.group(2), pm.group(3)
                    verdict = "allow" if verb == "accept" else "deny"
                    for lo, hi in _nft_dports(spec):
                        res["rules"].append((lo, hi, proto, verdict))
                        if verdict == "allow":
                            res["accepts"].append((lo, hi, proto))
        depth += s.count("{") - s.count("}")
        if chain and depth < chain_depth:
            chain, in_input = None, False
    return res
