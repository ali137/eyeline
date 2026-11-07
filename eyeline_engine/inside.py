"""Inside read: what the target says about itself, read over the READ_ONLY
commands in remote.py. Pure parsers, read(), and the before/after snapshots
behind the zero-writes claim. Anything unreadable comes back None ("not
readable"); nothing is guessed.
"""
import fnmatch
import ipaddress
import json
import re

from .remote import READ_ONLY

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _run(remote, name, arg=None):
    """stdout if the command exited 0, else None. RemoteError (ssh down) propagates."""
    code, out = remote.run(name, arg)
    return out if code == 0 else None


# --- listeners (ss) --------------------------------------------------------

def parse_ss(text):
    """`ss -H -tln[p]` -> [{addr, port, process}]. None in, None out."""
    if text is None:
        return None
    out = []
    for line in text.splitlines():
        f = line.split()
        if f and f[0] in ("tcp", "udp"):  # Netid column, if present
            f = f[1:]
        if len(f) < 4 or f[0] != "LISTEN":
            continue
        host, _, port = f[3].rpartition(":")
        if not port.isdigit():
            continue
        m = re.search(r'users:\(\("([^"]+)"', line)
        out.append({"addr": host.strip("[]").split("%")[0], "port": int(port),
                    "process": m.group(1) if m else None})
    return out


def is_loopback(addr):
    """127.x, ::1, and ::ffff:127.x. "*" and anything unparsable are not loopback."""
    try:
        ip = ipaddress.ip_address(addr.strip("[]").split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback


# --- UFW --------------------------------------------------------------------

_RULE = re.compile(r"^(?P<to>.+?)\s+(?P<action>ALLOW|DENY|REJECT|LIMIT)(?:\s+(?P<dir>IN|OUT|FWD))?"
                   r"\s+(?P<frm>.+?)\s*(?:#.*)?$")
_V6 = re.compile(r"\s*\(v6\)")
_PORTS = re.compile(r"^(\d+(?::\d+)?(?:,\d+(?::\d+)?)*)(?:/(tcp|udp))?$")


def _ufw_ports(to):
    """UFW "To" column -> ([(lo, hi)], proto), or (None, None) if not resolvable
    here (destination address, interface, an app name with no resolved ports)."""
    if to == "Anywhere":
        return [(1, 65535)], None
    m = _PORTS.match(to)
    if not m:
        return None, None
    ports = []
    for part in m.group(1).split(","):
        lo, _, hi = part.partition(":")
        ports.append((int(lo), int(hi or lo)))
    return ports, m.group(2)


def _split_rule(line):
    m = _RULE.match(line)
    if not m:
        return None
    to, frm = m.group("to"), m.group("frm")
    frm = re.sub(r"\s*\((?:log|log-all)\)\s*$", "", frm)  # ufw appends a rule's log attribute
    # Verbose app rules: "22/tcp (OpenSSH)", v6 inside the parentheses: "22/tcp (OpenSSH (v6))".
    a = re.match(r"^(.+?) \((.+)\)$", _V6.sub("", to))
    return {"to": a.group(1) if a else _V6.sub("", to), "app": a.group(2) if a else None,
            "from": _V6.sub("", frm), "v6": "(v6)" in to, "action": m.group("action").lower(),
            "dir": m.group("dir") or "IN"}


def parse_ufw(text):
    """`ufw status verbose` -> {active, default_incoming, rules, unresolved}.
    Only incoming rules are kept. Each rule and unresolved line has a position
    ("pos", "unresolved_at") so firewall_says can apply UFW's first-match order."""
    res = {"active": None, "default_incoming": None, "rules": [], "unresolved": [], "unresolved_at": []}
    if not text or "Status:" not in text:
        return res
    in_rules, pos = False, 0
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Status:"):
            res["active"] = s.split(":", 1)[1].strip() == "active"
        elif s.startswith("Default:"):
            m = re.search(r"(\w+) \(incoming\)", s)
            if m and m.group(1) in ("deny", "allow", "reject"):
                res["default_incoming"] = m.group(1)
        elif s.startswith("--"):
            in_rules = True
        elif in_rules and s:
            r = _split_rule(s)
            if not r or r["dir"] != "IN":
                continue
            pos += 1
            ports, proto = _ufw_ports(r["to"])
            if ports is None:
                res["unresolved"].append(s)
                res["unresolved_at"].append(pos)
            else:
                res["rules"].append({"ports": ports, "proto": proto, "action": r["action"],
                                     "v6": r["v6"], "from": r["from"], "app": r["app"],
                                     "raw": s, "pos": pos})
    return res


def firewall_says(ufw, port, proto="tcp", v6=False):
    """What UFW decides for this port from the internet -> (deny|allow|unknown, reason).
    Only rules from Anywhere decide for the internet. First match wins. An allow
    from a specific source ahead of the deciding deny makes the answer unknown."""
    if not ufw or ufw.get("active") is None:
        return "unknown", "UFW status not readable (no passwordless sudo, or UFW not installed)"
    if not ufw["active"]:
        return "unknown", "UFW is inactive; other firewall rules are not evaluated here"
    items = [(r["pos"], r) for r in ufw["rules"]]
    items += list(zip(ufw.get("unresolved_at") or [0] * len(ufw["unresolved"]), ufw["unresolved"]))
    src, verdict = None, None
    for _, r in sorted(items, key=lambda x: x[0]):
        if isinstance(r, str):
            u = _split_rule(r)
            if u and u["v6"] == v6 and u["from"] == "Anywhere":
                return "unknown", ("UFW rule '%s' names %r, an app profile/address/interface "
                                   "this tool does not resolve; it may decide port %d" % (r, u["to"], port))
            continue
        if r["v6"] != v6 or r["proto"] not in (None, proto) or not any(
                lo <= port <= hi for lo, hi in r["ports"]):
            continue
        allow = r["action"] in ("allow", "limit")
        if r["from"] != "Anywhere":
            src = src or (r["from"] if allow else None)
            continue
        verdict = ("allow" if allow else "deny"), "UFW rule: %s" % r["raw"]
        break
    d = ufw["default_incoming"]
    if verdict is None and d is None:
        return "unknown", "no UFW rule matches and the default incoming policy was not read"
    verdict = verdict or (("allow" if d == "allow" else "deny"),
                          "no UFW rule matches; default incoming is %s" % d)
    if src and verdict[0] == "deny":
        return "unknown", "allowed only from %s: a probe from that source reaches it by design" % src
    return verdict


# --- firewalld --------------------------------------------------------------

# A firewalld service name -> the (port, proto) pairs it opens, from the shipped
# /usr/lib/firewalld/services/*.xml. Only the common ones are mapped; an unknown
# service in the zone makes the answer "unknown" (it may open the port).
FIREWALLD_SERVICE_PORTS = {
    "ssh": [(22, "tcp")], "http": [(80, "tcp")], "https": [(443, "tcp")],
    "dhcpv6-client": [(546, "udp")], "dns": [(53, "tcp"), (53, "udp")],
    "mdns": [(5353, "udp")], "dhcp": [(67, "udp")], "ntp": [(123, "udp")],
    "samba-client": [(137, "udp"), (138, "udp")], "cockpit": [(9090, "tcp")],
    "postgresql": [(5432, "tcp")], "mysql": [(3306, "tcp")], "redis": [(6379, "tcp")],
    "mongodb": [(27017, "tcp")], "ftp": [(21, "tcp")], "smtp": [(25, "tcp")],
    "imaps": [(993, "tcp")], "pop3s": [(995, "tcp")],
}

# A default-zone target that is not an explicit accept means unmatched incoming
# traffic is refused: "default" rejects (ICMP admin-prohibited), "%%REJECT%%"
# rejects, "DROP" drops. Only "ACCEPT" lets unmatched traffic in.


def parse_firewalld(text):
    """The 'firewalld' command's output -> {active, zone, target, ports, services, rich}.
    `ports` is [(lo, hi, proto)] from `ports:`; `services` is the service-name list
    from `services:`; `rich` is True when the zone has any rich rules (which
    firewalld_says does not evaluate, so it returns unknown). active is None when
    firewalld was not readable (not installed, not running, or no permission).
    None in, not-readable out."""
    res = {"active": None, "zone": None, "target": None, "ports": [], "services": [],
           "rich": False}
    if not text or "#--list-all--" not in text:
        return res
    zone_part, _, all_part = text.partition("#--list-all--")
    res["zone"] = (zone_part.replace("#--zone--", "").strip() or None)
    res["active"] = True
    section = None  # track multi-line fields (rich rules / forward-ports follow their label)
    for line in all_part.splitlines():
        s = line.strip()
        label = re.match(r"^([\w][\w -]*):\s*(.*)$", s)
        if label and not line.startswith(("\t", "    ")):
            section, rest = label.group(1), label.group(2)
            if section == "target":
                res["target"] = rest
            elif section == "ports":
                for tok in rest.split():
                    m = re.match(r"^(\d+)(?:-(\d+))?/(tcp|udp)$", tok)
                    if m:
                        res["ports"].append((int(m.group(1)), int(m.group(2) or m.group(1)), m.group(3)))
            elif section == "services":
                res["services"] = rest.split()
            elif section == "rich rules" and rest:
                res["rich"] = True
        elif section == "rich rules" and s:  # a rich rule on its own (tab-indented) line
            res["rich"] = True
    return res


def firewalld_says(fwd, port, proto="tcp", v6=False):
    """What firewalld decides for this port from the internet -> (deny|allow|unknown, reason).
    A direct `ports:` entry or a known service opens the port (allow). Otherwise the
    zone target decides: ACCEPT -> allow, default/%%REJECT%%/DROP/missing(None) -> deny.
    Returns unknown (the port may be open, so never counted clean) when: firewalld is
    not readable; the zone lists a service this tool does not map to ports; the zone
    has rich rules (the `rich` flag), which this tool does not evaluate; or the target
    is an unrecognized value."""
    if not fwd or fwd.get("active") is None:
        return "unknown", "firewalld status not readable (not installed, not running, or no permission)"
    zone = fwd["zone"] or "?"
    for lo, hi, pr in fwd["ports"]:
        if pr == proto and lo <= port <= hi:
            return "allow", "firewalld: port %d/%s is open in zone %s" % (port, proto, zone)
    unknown_svc = []
    for svc in fwd["services"]:
        if svc not in FIREWALLD_SERVICE_PORTS:
            unknown_svc.append(svc)
            continue
        if (port, proto) in FIREWALLD_SERVICE_PORTS[svc]:
            return "allow", "firewalld: service '%s' opens %d/%s in zone %s" % (svc, port, proto, zone)
    if unknown_svc:
        return "unknown", ("firewalld zone %s allows service(s) %s this tool does not map to ports; "
                           "one may open port %d/%s" % (zone, ", ".join(unknown_svc), port, proto))
    if fwd.get("rich"):
        return "unknown", ("firewalld zone %s has rich rules this tool does not evaluate; one may open "
                           "port %d/%s" % (zone, port, proto))
    target = fwd["target"]
    if target == "ACCEPT":
        return "allow", "firewalld zone %s target is ACCEPT: all incoming is allowed" % zone
    if target in ("default", "%%REJECT%%", "DROP", None):
        return "deny", ("no firewalld port or service opens %d/%s; zone %s target %s refuses it"
                        % (port, proto, zone, target or "default"))
    return "unknown", "firewalld zone %s has target %r this tool does not recognize" % (zone, target)


# --- nftables (plain, no ufw/firewalld): the input base chain -----------------

def _is_docker_nat_chain(chain, table):
    """True for a nat chain/table whose dnat forwards parse_docker_nat (`_nft`) actually
    READS. parse_nft_input exempts a dnat/redirect from its refuse-what-you-don't-model
    rule ONLY when this is true, so the two parsers share ONE predicate: a forward is
    trusted away by the filter reader exactly when the Docker reader will surface its port.
    If this were broader than what `_nft` reads (e.g. any chain merely starting with
    "DOCKER", such as Swarm's DOCKER-INGRESS), a forward would be exempted here yet read by
    nobody -> a false-clean (security re-review, 2026-10-28). Keep this and `_nft`'s
    condition identical."""
    return chain == "DOCKER" or "docker" in (table or "")


def parse_nft_input(text):
    """`nft list ruleset` -> the input base chain's policy + accept rules, or
    {readable: False} when the box is not a plain nftables input chain we FULLY model
    (so the caller falls back to "could not judge" rather than a wrong verdict).

    Hardening (phase 13.5): the parser REFUSES WHAT IT DOES NOT FULLY MODEL. Three
    times a real rule carried a shape the old line-by-line regex did not anticipate (a
    counter prefix, a qualifier, a table family) and the rule was silently skipped so
    the chain policy decided -> a wrong, sometimes CLEAN, verdict. For a security tool
    that is the worst failure. So every rule line inside the input base chain must now
    match exactly ONE modeled shape; a line matching none refuses the whole ruleset
    (-> {readable: False} -> "could not judge"), never a guess. The modeled shapes are
    enumerated in _nft_classify_rule. Anything outside them -- a jump/goto, a vmap, an
    unrecognized match or qualifier, a bare verdict -- refuses.

    We also refuse up front when the ruleset carries ufw-* chains or a `<family>
    firewalld` table (UFW/firewalld are read by their own parsers), and when more than
    one input base chain exists (we model a single input chain; two would need the
    priority order we do not read).

    -> {readable, policy, accepts, rules, family}. `family` is the modeled input chain's
    table family ("inet"/"ip"/"ip6", or None when nothing was read). `rules` is the ordered list of every
    `tcp/udp dport ...` rule read, as (lo, hi, proto, verdict): "allow" for an
    unconditional accept, "deny" for an unconditional drop/reject. A dport rule scoped by
    a provably-narrow source address does not decide for the internet, so it is dropped
    (the chain policy decides); a rule scoped by a `daddr`, an interface, or a
    universal/set/@name source is NOT soundly modeled and refuses the whole ruleset
    instead. First match wins in nft_input_says. `accepts` is the
    (lo, hi, proto) subset with verdict "allow", kept for callers that read only the
    opened ports."""
    refused = {"readable": False, "policy": None, "accepts": [], "rules": [], "family": None}
    if not text or "table " not in text:
        return refused
    # Not a plain-nftables box: ufw (iptables-nft backend) and firewalld both install a
    # base input chain that only jumps into their own managed chains, so reading it
    # directly would miss their accepts and give a wrong verdict. Their status is read
    # by parse_ufw/parse_firewalld instead; here we refuse. firewalld names its table
    # `<family> firewalld` on every backend (inet on the nft backend, ip/ip6 on the
    # iptables backend), so match any family, not just inet.
    if re.search(r"\bufw-[\w-]+\b", text) or re.search(r"\btable\s+(?:ip6?|inet)\s+firewalld\b", text):
        return refused
    # The mutable accumulator; its own fresh lists (not shared with `refused`, which stays
    # the constant refusal value returned on any unmodeled shape). `family` records which
    # IP family the modeled input chain actually covers ("inet" = both, "ip" = v4 only,
    # "ip6" = v6 only), so nft_input_says can answer "unknown" for the family a single-
    # family table does not filter rather than misapply a v4 verdict to a v6 probe.
    res = {"readable": False, "policy": None, "accepts": [], "rules": [], "family": None}
    depth, chain, chain_depth, in_input = 0, None, 0, False
    table_family, table_name = None, None
    for line in text.splitlines():
        # A rule `comment "..."` string can contain `#`, `{` or `}`. Those must not be
        # read as an nft comment, a brace for depth-counting, or get the line truncated:
        # a `}` inside a comment once closed the input chain early so every following
        # open-port rule was silently dropped -> a blocked/clean verdict for a port nft
        # actually ACCEPTS (security review round 7, 2026-10-28). Mask quoted-string
        # contents LENGTH-PRESERVINGLY (so masked offsets line up with the original) before
        # the `#`-strip and the brace count; the rule classifier still sees the ORIGINAL
        # line (`s_raw`), so a real comment -- `#`, `{`/`}` and all -- is still read.
        masked = re.sub(r'"[^"]*"', lambda m: '"' + "x" * (len(m.group(0)) - 2) + '"', line)
        cut = re.search(r"\s*#", masked)  # a `#` comment OUTSIDE any quoted string
        s_raw = (line[:cut.start()] if cut else line).strip()  # real comment kept, `# handle N` gone
        s = (masked[:cut.start()] if cut else masked).strip()  # braces masked, comment gone
        tbl = re.match(r"table\s+(\S+)\s+(\S+)\s*\{", s)
        if tbl:
            table_family, table_name = tbl.group(1), tbl.group(2)
        m = re.match(r"chain\s+(\S+)\s*\{", s)
        if m:
            chain, chain_depth, in_input = m.group(1), depth + 1, False
        elif chain:
            # A port-exposing NAT forward (dnat/redirect/tproxy) on a port whose filter
            # verdict we read makes that port reachable even with no accept -- e.g. `tcp
            # dport 8080 redirect to :22`. We model only the filter input chain, not nat, so
            # such a forward is invisible and would let us read 8080 as "deny" while the
            # internet reaches it -> refuse. The ONLY exemption is a forward that
            # parse_docker_nat actually surfaces, and the exemption's verb AND shape must not
            # exceed what a reader surfaces, or the port is trusted away by one parser and
            # read by nobody -> a false-clean (review rounds, 2026-10-28). Both Docker
            # readers (`_nft`, `_iptables`) surface only a DNAT that carries a numeric
            # `dport` (`_nft` needs `\bdport \d+`), so:
            #   - `redirect` and `tproxy` are surfaced by NO reader -> ALWAYS refuse, even in
            #     a Docker chain;
            #   - a `dnat` is exempt only in a Docker chain/table AND only when it carries a
            #     numeric dport (a dport-less 1:1 `ip daddr X dnat to Y` is not surfaced).
            # snat/masquerade are NOT port-exposers (they rewrite the SOURCE of egress
            # packets in postrouting); refusing on them buys no soundness and would turn
            # every Docker host / NAT gateway into "could not judge", so they are not matched.
            if re.search(r"\b(?:redirect|tproxy)\b", s):
                return refused
            if re.search(r"\bdnat\b", s) and not (
                    _is_docker_nat_chain(chain, table_name) and re.search(r"\bdport \d", s)):
                return refused
            # Only a `filter` hook decides whether a packet is accepted or dropped; a
            # `nat`/`route`/`mangle` hook input chain does not filter, so matching it as
            # the firewall would misread. Restrict to the filter family.
            hook = re.match(r"type\s+filter\s+hook\s+input\b.*policy\s+(\w+)", s)
            if hook:
                # Only an IP-layer table filters IP traffic: a `bridge`/`arp`/`netdev`
                # input chain filters L2/device frames, NOT the IP stack a probe rides, so
                # reading its policy as the firewall for a TCP/UDP port is wrong. Skip a
                # non-IP-family input chain (the IP stack stays unfiltered by it); if the
                # box has ONLY such chains, no input chain is read -> refuse (review round,
                # 2026-10-28).
                if table_family not in ("ip", "ip6", "inet"):
                    continue
                # A second IP-layer input base chain means two policies and a priority
                # order we do not read; we model exactly one, so refuse rather than guess
                # which wins (real multi-table boxes emit a second `hook input`).
                if res["readable"]:
                    return refused
                in_input, res["readable"], res["policy"] = True, True, hook.group(1)
                res["family"] = table_family
            elif in_input and s and not s.startswith(("type ", "policy ", "}")):
                parsed = _nft_classify_rule(s_raw)
                if parsed is None:
                    # An unmodeled rule shape on the input chain (jump/goto, vmap, an
                    # unrecognized match or qualifier, a bare verdict): we cannot say
                    # what it does to the internet, so refuse the whole ruleset ->
                    # "could not judge", never a silent policy-decides verdict.
                    return refused
                for lo, hi, proto, verdict in parsed:
                    res["rules"].append((lo, hi, proto, verdict))
                    if verdict == "allow":
                        res["accepts"].append((lo, hi, proto))
        depth += s.count("{") - s.count("}")
        if chain and depth < chain_depth:
            chain, in_input = None, False
    return res


# The tail nft may print after `reject`: `with <what> [detail]`, e.g. `with icmp
# port-unreachable`, `with icmpx admin-prohibited`, `with tcp reset`. nft v1.x collapses
# the older 3-token `with icmp type port-unreachable` to 2 tokens, so up to two tokens
# covers current output; an unrecognized longer tail fail-closed refuses.
_NFT_REJECT_TAIL = r"(?:\s+with\s+\S+(?:\s+\S+)?)?"
# A terminal verdict we understand on the input chain. jump/goto are deliberately NOT
# here: they hide the real decision in another chain we do not follow, so a rule ending
# in one refuses the whole ruleset.
_NFT_VERDICT = r"(?:accept|drop|reject%s)" % _NFT_REJECT_TAIL
# Qualifiers that may sit between the dport spec and the verdict without changing which
# port the rule governs or whether it fires for everyone: a counter or a log. (A
# `comment "..."` is printed by nft AFTER the verdict, not here, so it is matched by a
# separate post-verdict clause.) Anything else here (a limit, a meta match, a second
# dport) is unmodeled -> refuse.
_NFT_TRAILER = (r"(?:counter(?:\s+packets\s+\d+\s+bytes\s+\d+)?"
                r"|log(?:\s+(?:prefix\s+\"[^\"]*\"|level\s+\S+|flags\s+\S+|group\s+\d+|"
                r"snaplen\s+\d+|queue-threshold\s+\d+))*)")
# nft prints a rule comment AFTER the verdict: `tcp dport 22 accept comment "ssh"`.
_NFT_COMMENT = r"(?:\s+comment\s+\"[^\"]*\")?"
# An operand for a source-address match: a `{ ... }` set, a `@name` set reference, or a
# single non-brace token (an address, CIDR, or range). It consumes exactly its own
# operand -- no wildcard -- so no unmodeled match can hide inside a prefix.
# NEGATED matches (`!=`): a positive source match (`ip saddr 10/8`) restricts the rule to
# that source (non-deciding for the internet), but a negated one (`ip saddr != 10/8`)
# fires for almost EVERYONE, including the internet -- the opposite meaning. Treating them
# alike silently dropped a negated-source drop/accept so the policy decided, giving a
# wrong (even allow-for-a-blocked-port) verdict (security review 2026-10-28). This
# operand regex does not itself exclude `!=` (the bare-token branch would match it); the
# explicit `"!=" in s` guard in _nft_classify_rule is what refuses any negated rule (and
# even without that guard, the real operand stranded after `!=` breaks the dport match).
_NFT_OPERAND = r"(?:\{[^}]*\}|@\w+|[^\s{}]+)"
# Prefix matches that scope a dport rule by FAMILY/PROTOCOL only -- they do not restrict
# it to a source, so a rule carrying only these still decides for the internet. nft
# emits these ahead of a dport (`meta l4proto tcp tcp dport ...`, `meta nfproto ipv4
# tcp dport ... reject`).
_NFT_FAMILY_ATOM = r"(?:meta\s+l4proto\s+(?:tcp|udp)|meta\s+nfproto\s+(?:ipv4|ipv6))"
# Prefix matches that RESTRICT a rule to a source, so it does not prove the port is open
# to everyone: the rule is modeled but does not decide for the internet. Each consumes
# its own operand so nothing unmodeled can ride along. ONLY a source-ADDRESS match
# (`ip/ip6 saddr`) qualifies. Deliberately excluded, because each would make a rule
# NON-deciding when it actually decides the port's internet exposure (the same
# half-modeled defect that leaked three times -- security review, 2026-10-28):
#   - `daddr`: on an input chain the destination is the SERVER'S OWN address, so
#     `ip daddr <ip> tcp dport N accept` OPENS port N to every internet host reaching
#     that IP; we cannot know the box's IPs (127.0.0.1 vs a public IP vs 0.0.0.0/0).
#   - interface atoms (`iif`/`iifname`/`meta iif[name]`): a non-`lo` interface name
#     usually means the WAN, so `iifname "eth0" tcp dport 443 accept` OPENS 443 to the
#     internet; we cannot know which interface faces the internet. The benign loopback
#     case `iif[name] "lo"` is NOT lost -- it is matched by a separate literal-"lo"
#     housekeeping branch below, and "lo" is universally non-internet.
# A dport rule carrying any of these falls through to None -> refuse, never [].
_NFT_RESTRICT_ATOM = r"(?:ip6?\s+saddr\s+%s)" % _NFT_OPERAND
# The full prefix: a sequence of ONLY modeled atoms (family/proto or restrict), each
# ending in whitespace, with no gap for an unmodeled token. _nft_classify_rule then asks
# whether any restrict atom is present to decide if the rule governs the internet.
_NFT_PREFIX = r"(?P<prefix>(?:(?:%s|%s)\s+)*)" % (_NFT_FAMILY_ATOM, _NFT_RESTRICT_ATOM)
# The dport spec is ONLY numeric ports: a single port, a range, a comma list, or a
# `{ ... }` set of those. A non-numeric member (a service name like `ssh`, which older
# nft prints) is NOT modeled -- the spec regex will not match it, so the rule falls
# through to refuse rather than silently reading only the numeric members (review
# 2026-10-28). The verb NAME is captured separately (to read allow vs deny), with the
# shared `reject with ...` tail after it and an optional post-verdict `comment "..."`.
_NFT_PORTSET = r"\{\s*\d+(?:-\d+)?(?:\s*,\s*\d+(?:-\d+)?)*\s*\}"
_NFT_RE_DPORT = re.compile(
    r"^%s"
    r"(?P<proto>tcp|udp)\s+dport\s+(?P<spec>%s|\d+(?:-\d+)?(?:,\s*\d+(?:-\d+)?)*)"
    r"(?:\s+%s)*\s+(?P<verb>accept|drop|reject)%s%s$" % (
        _NFT_PREFIX, _NFT_PORTSET, _NFT_TRAILER, _NFT_REJECT_TAIL, _NFT_COMMENT))
# Housekeeping rules that never open an internet-reachable tcp/udp port and are safe to
# ignore: loopback accepts, conntrack-state rules, and ICMP/IGMP protocol rules. Each is
# matched whole (anchored both ends) so an unexpected trailing token makes it unmodeled.
# The optional `comment "..."` tail applies to ALL THREE branches (it is appended once,
# after the alternation): nft commonly carries a comment on a loopback or conntrack rule
# (`iifname "lo" accept comment "..."`), and leaving the comment off those branches made
# an ordinary commented ruleset over-refuse (security review round 8, 2026-10-28).
# The ct-state branch admits ONLY the return-traffic states `established`/`related` with
# ANY verdict: those let back replies to connections the box itself started and never open
# a port to the internet. `ct state new accept` (or `untracked`), by contrast, ACCEPTS
# brand-new inbound connections on EVERY port -- a universal opener -- so it must NOT read
# as benign housekeeping (security review round 9, 2026-10-28, proven on real nft:
# `ct state new accept` accepted a new connection to a closed-by-policy port). A separate
# branch admits `ct state invalid drop/reject` (the very common first line): dropping
# invalid packets never changes a real port's reachability. `ct state invalid accept` is
# NOT admitted (an accept could matter), and `ct state new drop` is not either (it would
# wrongly read a port blocked under policy accept). The ICMP branch's type clause may be a
# brace set of type names (`icmpv6 type { nd-router-advert, ... } accept`, the standard
# IPv6 idiom nft prints). The optional `comment "..."` tail applies to ALL branches (it is
# appended once, after the alternation): nft commonly carries a comment on a loopback or
# conntrack rule, and leaving it off those branches over-refused (round 8).
_NFT_ICMP_TYPE = r"(?:\{\s*[\w-]+(?:\s*,\s*[\w-]+)*\s*\}|[\w-]+)"
_NFT_RE_HOUSEKEEP = re.compile(
    r"^(?:"
    r"(?:iifname|iif)\s+\"lo\"\s+(?:%(tr)s\s+)*%(v)s"
    r"|ct\s+state\s+(?:established|related)(?:\s*,\s*(?:established|related))*"
    r"\s+(?:%(tr)s\s+)*%(v)s"
    r"|ct\s+state\s+invalid\s+(?:%(tr)s\s+)*(?:drop|reject%(rej)s)"
    r"|(?:(?:ip6?\s+\w+|meta\s+nfproto\s+\w+)\s+)*"
    # At least ONE ICMP/IGMP atom (a protocol clause OR a type clause) is MANDATORY: the
    # branch admits ICMP/IGMP housekeeping, not a bare `meta nfproto ipvN accept`, which
    # would be a universal opener. Making the atom required (not just whitespace spacing)
    # closes that (final review round, 2026-10-28).
    r"(?:"
    r"(?:ip\s+protocol\s+(?:icmp|igmp)|ip6\s+nexthdr\s+(?:icmpv6|ipv6-icmp)"
    r"|meta\s+l4proto\s+(?:icmp|icmpv6|ipv6-icmp|igmp))"
    r"(?:\s+(?:icmp6?\s+type\s+%(it)s|icmpv6\s+type\s+%(it)s))?"
    r"|(?:icmp6?\s+type\s+%(it)s|icmpv6\s+type\s+%(it)s)"
    r")"
    r"(?:\s+code\s+[\w-]+)?\s+(?:%(tr)s\s+)*%(v)s"
    r")%(c)s$" % {"v": _NFT_VERDICT, "tr": _NFT_TRAILER, "c": _NFT_COMMENT,
                  "rej": _NFT_REJECT_TAIL, "it": _NFT_ICMP_TYPE})


def _nft_classify_rule(s):
    """Classify one input-base-chain rule line against the FULLY-MODELED shapes.
    -> a list of (lo, hi, proto, verdict) the rule contributes (possibly empty, for a
    modeled rule that does not decide for the internet), or None when the shape is not
    one we model (-> parse_nft_input refuses the whole ruleset).

    Modeled shapes:
    - a dport rule: [family/proto or ip/ip6 saddr prefixes] (tcp|udp) dport
      <numeric ports|range|set> [counter|log]* (accept|drop|reject [with ...]) [comment].
      A source-ADDRESS prefix whose operand is PROVABLY a strict subset of the address
      family makes the rule non-deciding for the internet -> contributes nothing ([]). A
      `daddr`, an interface match, or a universal/set/@name saddr is NOT modeled as a
      restriction (it can open the port) -> None (refuse); so is a non-numeric port spec.
    - housekeeping that never opens an internet tcp/udp port: loopback, conntrack-state,
      ICMP/IGMP -> contributes nothing ([]).
    Everything else (jump/goto, vmap, meta mark, tcp flags, limit, a bare verdict, a
    negated match, any unrecognized token) -> None."""
    # A negated match (`!=`) inverts a match's meaning, so a negated source/interface
    # restriction fires for almost everyone INCLUDING the internet (the opposite of a
    # positive one). We do not model that; the _NFT_OPERAND regex does not itself exclude
    # `!=`, so guard explicitly: any rule carrying `!=` refuses rather than risk a wrong
    # verdict. Check only the MATCH part, not a trailing rule comment (a `!=` inside
    # `comment "..."` is inert and must not force a needless refuse).
    if "!=" in re.sub(r'\s+comment\s+"[^"]*"\s*$', "", s):
        return None
    m = _NFT_RE_DPORT.match(s)
    if m:
        prefix = m.group("prefix")
        saddrs = re.findall(r"\bip6?\s+saddr\s+(%s)" % _NFT_OPERAND, prefix)
        if saddrs:
            # The rule is scoped by a source address. It is non-deciding for the internet
            # only if that source is PROVABLY non-global -- a private / LAN / VPN / ULA /
            # link-local / loopback / CGNAT range that NO routable internet host falls in.
            # A `saddr` operand can still reach the internet: an all-family CIDR
            # (0.0.0.0/0, ::/0), the full dashed range nft prints for a 0/0 set element
            # (`0.0.0.0-255.255.255.255` or the IPv6 `::-ffff:...:ffff` it does NOT
            # collapse), ANY globally-routable CIDR (1.0.0.0/8, 2000::/3 -- the latter is
            # the entire routable IPv6 internet), any brace set (a member could be global),
            # or a `@name` set whose contents we cannot see. Any of those can open the port
            # to internet hosts, so we must NOT read it as a restriction -- we refuse
            # (final review round, 2026-10-28: a public but non-universal saddr accept was
            # reading as "deny"; review rounds 4+5 for the universal spellings). A /1-pair
            # that together spans the family is an accepted limitation -- each rule alone is
            # globally routable, so each now refuses on its own.
            if any(not _nft_saddr_is_concrete(a) for a in saddrs):
                return None
            return []  # source-restricted to a provably-narrow range: non-deciding
        ports = _nft_dports(m.group("spec"))
        if not ports:
            return None  # a spec that yields no numeric port is not a shape we model
        proto, verdict = m.group("proto"), ("allow" if m.group("verb") == "accept" else "deny")
        return [(lo, hi, proto, verdict) for lo, hi in ports]
    if _NFT_RE_HOUSEKEEP.match(s):
        return []
    return None


def _nft_saddr_is_concrete(operand):
    """True when an `ip/ip6 saddr` operand is PROVABLY non-global -- every address it
    covers is outside the globally-routable internet (private/RFC1918, CGNAT, link-local,
    ULA, loopback, documentation, etc.), so a rule scoped by it does not decide the port's
    internet exposure. False for anything that reaches even one routable internet host --
    which must make the rule refuse rather than read as a restriction.

    This is STRONGER than "not the entire family": a public but non-universal CIDR such as
    1.0.0.0/8 (16M routable hosts, incl. 1.1.1.1) or 2000::/3 (the ENTIRE routable IPv6
    internet) is NOT a restriction -- port 22 scoped to it is open to internet hosts, and
    reading it as non-deciding let the chain policy produce a false "deny" (final review
    round, 2026-10-28). We decide by COMPUTING with ipaddress (`is_global`), not by string-
    matching spellings; this also subsumes the universal forms (0.0.0.0/0, ::/0, and the
    dashed full ranges nft does NOT collapse) since those are global too. A `{ ... }` set
    or a `@name` set reference is never provably non-global (a member / the set's contents
    could be global), so it is False. Anything we cannot parse is False -> refuse."""
    op = operand.strip()
    if op.startswith(("@", "{")):
        return False  # named set (unknowable) or brace set (a member could be global)
    try:
        if "-" in op:  # a numeric range `A-B`: non-deciding only if EVERY address in it
            lo, _, hi = op.partition("-")  # is non-global. Checking only the endpoints is
            a, b = ipaddress.ip_address(lo.strip()), ipaddress.ip_address(hi.strip())
            if a.version != b.version or int(a) > int(b):
                return False  # unsound: 0.0.0.0-255.255.255.255 has non-global ENDS yet
            # spans the whole routable internet. Summarize the span into CIDRs and require
            # all non-global, so the full range (and any public block) refuses.
            return all(not n.is_global for n in ipaddress.summarize_address_range(a, b))
        net = ipaddress.ip_network(op, strict=False)
        return not net.is_global  # any globally-routable source can reach from the internet
    except ValueError:
        return False  # unparseable source -> cannot prove it is non-global -> refuse


def _nft_dports(spec):
    """An nft dport spec -> [(lo, hi)]. "22" / "80-90" / "{ 80, 443, 8000-8010 }"."""
    out = []
    for part in spec.strip().strip("{}").split(","):
        p = part.strip()
        m = re.match(r"^(\d+)(?:-(\d+))?$", p)
        if m:
            out.append((int(m.group(1)), int(m.group(2) or m.group(1))))
    return out


def nft_input_says(nftin, port, proto="tcp", v6=False):
    """What a plain-nftables input base chain decides for this port -> (deny|allow|unknown).
    nft is first-match-wins, so the first UNCONDITIONAL dport rule that matches the
    port decides: an accept -> allow, a drop/reject -> deny. With no matching rule the
    chain policy decides (accept -> allow, drop/reject -> deny). Not readable -> unknown."""
    if not nftin or not nftin.get("readable"):
        return "unknown", "no nftables input base chain was read"
    # A single-family table only filters its own family: an `ip` table says nothing about
    # IPv6 (and `ip6` nothing about IPv4). Applying a v4 policy to a v6 probe would be a
    # wrong verdict, so answer "unknown" for the family this chain does not cover; `inet`
    # (or a pre-family-tracking read) covers both.
    fam = nftin.get("family")
    if fam == "ip" and v6:
        return "unknown", "the nftables input chain is an `ip` (IPv4-only) table; it does not filter IPv6"
    if fam == "ip6" and not v6:
        return "unknown", "the nftables input chain is an `ip6` (IPv6-only) table; it does not filter IPv4"
    for lo, hi, pr, verdict in nftin.get("rules") or []:
        if pr == proto and lo <= port <= hi:
            if verdict == "allow":
                return "allow", "nftables input chain accepts %s dport %d" % (proto, port)
            return "deny", "nftables input chain drops/rejects %s dport %d" % (proto, port)
    if nftin["policy"] == "accept":
        return "allow", "nftables input chain has no rule for %d/%s; chain policy is accept" % (port, proto)
    return "deny", ("nftables input chain has no accept rule for %d/%s; chain policy is %s"
                    % (port, proto, nftin["policy"]))


# --- the firewall the box actually uses (dispatch) ----------------------------

def firewall_verdict(firewall, port, proto="tcp", v6=False):
    """What the box's firewall decides for `port` from the internet -> (deny|allow|unknown, reason).
    `firewall` is read()'s unified {kind, ...}. UFW routes through firewall_says so UFW
    behavior is unchanged. firewalld and plain-nftables get a real verdict; anything
    unreadable falls back to 'unknown' (the 12.5 'could not judge' behavior)."""
    kind = (firewall or {}).get("kind")
    if kind == "ufw":
        return firewall_says(firewall["ufw"], port, proto, v6)
    if kind == "firewalld":
        return firewalld_says(firewall["firewalld"], port, proto, v6)
    if kind == "nftables":
        return nft_input_says(firewall["nft_input"], port, proto, v6)
    return "unknown", "no firewall could be read (not UFW, firewalld, or a plain nftables input chain)"


# --- sshd (exposure context on the SSH port) --------------------------------

def parse_sshd(text):
    """`sshd -T` -> {port, password_auth, root_login, pubkey_auth, kbd_auth, challenge_auth,
    other_auth}, or None when
    sshd was not readable (absent, or no root to dump the effective config). sshd -T
    prints one lowercased `keyword value` per line. port may repeat (ListenAddress);
    the first Port wins, as sshd uses its first-listed port for a bare connection."""
    if text is None or "port " not in text:
        return None
    res = {"port": None, "password_auth": None, "root_login": None, "pubkey_auth": None,
           "kbd_auth": None, "challenge_auth": None, "other_auth": None}
    other = {}  # the non-key, non-prompt methods a BatchMode login could also have used
    kbd = {}
    for line in text.splitlines():
        k, _, v = line.strip().partition(" ")
        v = v.strip()
        if k == "port" and res["port"] is None and v.isdigit():
            res["port"] = int(v)
        elif k == "passwordauthentication":
            res["password_auth"] = (v == "yes")
        elif k == "permitrootlogin":
            res["root_login"] = v  # yes / no / prohibit-password / without-password / forced-commands-only
        elif k == "pubkeyauthentication":
            res["pubkey_auth"] = (v == "yes")
        elif k in ("kbdinteractiveauthentication", "challengeresponseauthentication"):
            # OpenSSH < 8.7 prints challengeresponseauthentication, and there a yes turns
            # keyboard-interactive on whatever kbdinteractive says: on if either is yes.
            kbd[k] = (v == "yes")
        elif k in ("gssapiauthentication", "hostbasedauthentication", "permitemptypasswords"):
            other[k] = (v == "yes")
    if kbd:
        res["kbd_auth"] = any(kbd.values())
        res["challenge_auth"] = kbd.get("challengeresponseauthentication")
    # True: one may be on; False: all three read and off; None: not all read.
    res["other_auth"] = (any(other.values()) if any(other.values()) or len(other) < 3 else False)
    if len(other) < 3 and not any(other.values()):
        res["other_auth"] = None
    return res


def parse_sshd_files(text):
    """The 'sshd_files' command's output (`file:line:text` grep hits for Include /
    Match / the password keywords, then `#--ok--` only if every file was read) ->
    {lines: [{file, line, text}], dropins: bool}, or None when not fully read.
    `dropins` = /etc/ssh/sshd_config includes sshd_config.d, so a drop-in there is read."""
    if not text or "#--ok--" not in text.splitlines():
        return None
    lines = []
    for raw in text.splitlines():
        m = re.match(r"^(/[^:]+):(\d+):(.*)$", raw)
        if m:
            lines.append({"file": m.group(1), "line": int(m.group(2)), "text": m.group(3).strip()})
    dropins = any(l["file"] == "/etc/ssh/sshd_config" and re.match(r"(?i)include\s+\S*sshd_config\.d/", l["text"])
                  for l in lines)
    return {"lines": lines, "dropins": dropins}


def sshd_context(sshd, port):
    """Exposure context for the SSH port -> [str], or [] when this port is not sshd's
    or sshd was not read. States only facts; it never changes a verdict."""
    if not sshd or sshd.get("port") != port:
        return []
    out = ["sshd listens here (effective `sshd -T`)"]
    if sshd["password_auth"] is True:
        out.append("password authentication is ON (brute-force exposure; key-only is safer)")
    root = sshd["root_login"]
    if root == "yes":
        out.append("root login is permitted with a password (PermitRootLogin yes)")
    elif root in ("prohibit-password", "without-password"):
        out.append("root may log in with a key only (PermitRootLogin %s)" % root)
    return out


# --- reverse proxy (which upstream host:port each publishes) -----------------

def parse_revproxy(text):
    """The 'revproxy' command's output (nginx -T / Caddyfile / Traefik config, each
    behind a marker) -> [{tool, listen, server_name, upstream, source}]. One entry per
    (listen, upstream) a proxy publishes. None in -> []. Only the fields needed to
    explain why a port is reachable; no secrets are read."""
    files = _revproxy_files(text)
    out = _parse_nginx("".join("\n".join(lines) + "\n" for t, _, lines in files if t == "nginx"))
    out += [e for t, f, lines in files if t == "caddyfile" and f
            for e in _caddy_walk("\n".join(lines), f)[0]]
    out += [e for t, f, lines in files if t == "traefik" and f for e in _parse_traefik("\n".join(lines))]
    return out


# The 'revproxy' command's section markers and its `# file` headers (Caddy / Traefik).
_REVPROXY_SPLIT = re.compile(r"(?=#--(?:nginx|caddyfile|traefik)--$|# file /etc/(?:caddy|traefik)/)")


def _revproxy_files(text):
    """The 'revproxy' output -> [(tool, file, [line])], one per section marker and per
    Caddy/Traefik `# file` header (file None for a section's lines before any header).
    `cat` adds no newline, so a file whose last line has none glues the next marker or
    header onto that line: both are found anywhere in a line and split there. Only "\n"
    ends a line (Caddy reads a form feed or U+2028 as space; str.splitlines does not)."""
    files = []
    raws = (text or "").split("\n")
    for raw in raws[:-1] if raws[-1] == "" else raws:
        parts = _REVPROXY_SPLIT.split(raw[:-1] if raw.endswith("\r") else raw)
        line = parts.pop(0)
        while parts and parts[0].startswith("# file") and (not files or files[-1][0] == "nginx"):
            line += parts.pop(0)  # nginx text naming such a path is not a header
        if files and (line or not parts):
            files[-1][2].append(line)
        for p in parts:  # a marker or header runs to the end of its line
            m = re.match(r"#--(\w+)--$", p)
            files.append((m.group(1), None, []) if m else (files[-1][0], p[len("# file "):].strip(), []))
    return files


_UPSTREAM = re.compile(r"https?://([^/\s;]+)")


def _host_port(authority, default_port=None):
    """`host:port`, `[v6]:port`, `:port` (any host), or `host` -> (host, port or default).
    Any `user:pass@` userinfo is dropped so a credential in an upstream URL is never
    carried into the report."""
    authority = authority.strip().strip("'\"")
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if authority.startswith("["):
        host, _, rest = authority[1:].partition("]")
        port = rest.lstrip(":")
        return host, (int(port) if port.isdigit() else default_port)
    host, sep, port = authority.rpartition(":")
    if sep and port.isdigit():  # host may be "" for a port-only address like ":8080"
        return host, int(port)
    return authority, default_port


# One nginx token, read the way nginx reads it: a quoted string, a comment, `;` `{` `}`,
# or a bare word. `#` starts a comment only where a word could start (never inside
# quotes), and `${` keeps its brace inside the word. A quote never closed is `bad`.
_NGX_TOKEN = re.compile(r'''"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*'|(?P<c>#[^\n]*)|(?P<t>[;{}])'''
                        r'''|(?:\\[\s\S]|\$\{|[^\s;{}#"'\\])(?:\\[\s\S]|\$\{|[^\s;{\\])*|(?P<bad>\S)''')


def _nginx_files(text):
    """nginx config text -> [(file, [(line, raw, words, end)])], one statement per
    directive (`end` ';'), block open ('{') or block close ('}'); `end` None is a
    statement nginx would refuse (no closing `;`, a stray quote). Directives may share
    a line or span lines: `nginx -T` and read_mount both dump files verbatim, so a
    hand-written one-line `location / { proxy_pass ...; }` is a shape they emit. A
    `# configuration file X:` (nginx -T) or `# file X` (read_mount) header starts file
    X; `file` is None before any header and `line` counts within the file."""
    chunks = [(None, [])]
    for raw in (text or "").splitlines():
        m = re.match(r"^# (?:configuration )?file (/.+?):?$", raw)
        if m:
            chunks.append((m.group(1), []))
        else:
            chunks[-1][1].append(raw)
    out = []
    for f, lines in chunks:
        body, stmts, words, first, n, pos = "\n".join(lines), [], [], None, 1, 0
        for m in _NGX_TOKEN.finditer(body):
            n, pos = n + body.count("\n", pos, m.start()), m.start()
            if m.group("c"):
                continue
            if m.group("bad") or (m.group("t") == "}" and words):
                stmts.append((first or n, lines[(first or n) - 1], words, None))
                words, first = [], None
                if m.group("bad"):
                    break
            if m.group("t"):
                stmts.append((first or n, lines[(first or n) - 1], words, m.group("t")))
                words, first = [], None
            else:
                words.append(m.group(0))
                first = first or n
        if words:
            stmts.append((first, lines[first - 1], words, None))
        out.append((f, stmts))
    return out


def _denies_all(acl):
    """allow/deny rules, first match wins -> True when a `deny all` decides before any
    allow-everyone rule (eyeline's own fix: `allow <ip>; deny all;`)."""
    for verb, arg in acl:
        if verb == "allow" and arg in ("all", "0.0.0.0/0", "::/0"):
            return False
        if verb == "deny" and arg == "all":
            return True
    return False


def _nginx_walk(text):
    """nginx config text -> (proxy_pass entries, [problem]). A problem is a spot whose
    routes cannot be read: a statement nginx would refuse, an unbalanced brace in a
    file, a `location`/`proxy_pass` outside any server block (an included snippet,
    whose listen and server_name live in another file), a `proxy_pass` whose
    upstream is a variable (resolved per request, so it names no container or port),
    a unix socket, an `upstream {}` block (not resolved here), or has no http(s)://,
    a server block with routes but no `listen` (nginx then picks the port itself), or a
    `listen` with no TCP port read. A block with several `listen`s gives an entry per port."""
    pending, problems, upstreams = [], [], set()
    for f, stmts in _nginx_files(text):
        stack = []
        for n, raw, words, end in stmts:
            at = "%s:%d" % (f, n) if f else "line %d" % n
            name = words[0] if words else ""
            srv = next((b for b in stack if b["name"] == "server"), None)
            if end is None or (end == "}" and not stack):
                problems.append("a statement nginx would refuse at %s" % at)
                continue
            if end == "}":
                stack.pop()
                continue
            if name in ("location", "proxy_pass") and srv is None:
                problems.append("a %s outside any server block at %s" % (name, at))
            if end == "{":
                if name == "upstream" and len(words) > 1:
                    upstreams.add(words[1].strip("'\""))
                stack.append({"name": name, "auth_basic": None, "auth_basic_user_file": None,
                              "auth_request": None, "acl": [], "satisfy": None,
                              "listens": [], "listened": False,
                              "names": None, "at": at, "where": {"file": f, "line": n, "text": raw}})
                continue
            if srv is None:
                continue
            arg = words[1].strip("'\"") if len(words) > 1 else ""
            if name == "listen" and arg:
                _, lp = _host_port(arg) if ":" in arg else (None, arg)
                srv["listened"] = True
                if str(lp).isdigit():  # every listen serves the block's routes
                    srv["listens"].append(int(lp))
                else:
                    problems.append("a listen eyeline could not read at %s" % at)
            elif name == "server_name" and arg:
                srv["names"] = " ".join(words[1:])
                srv["where"] = {"file": f, "line": n, "text": raw}
            elif name in ("auth_basic", "auth_request") and arg:
                stack[-1][name] = arg != "off"  # an inner `off` cancels the outer one
            elif name == "auth_basic_user_file" and arg:
                stack[-1][name] = True
            elif name in ("allow", "deny") and arg:
                stack[-1]["acl"].append((name, arg))
            elif name == "satisfy" and arg:
                stack[-1]["satisfy"] = arg == "any"  # an inner `satisfy all` resets it
            elif name == "proxy_pass":
                up = _UPSTREAM.match(arg)
                if "$" in (up.group(1) if up else arg):
                    problems.append("a proxy_pass to a variable upstream at %s" % at)
                elif not up:
                    problems.append("a proxy_pass eyeline could not read at %s" % at)
                elif up.group(1).lower().startswith("unix:"):
                    problems.append("a proxy_pass to a unix socket at %s" % at)
                else:
                    host, p = _host_port(up.group(1), 80)
                    pending.append(("%s:%s" % (host, p), list(stack), stack.index(srv), host, at))
        if stack:
            problems.append("a block left open at the end of %s" % (f or "the config"))
    out = []
    for upstream, chain, i, host, at in pending:  # read once every block closed: order inside a block is free
        if host in upstreams:  # its servers live in the upstream block, not resolved here
            problems.append("a proxy_pass to an upstream block at %s" % at)
            continue
        srv = chain[i]
        bad = "a server block with no listen at %s (nginx then uses port 80 as root, 8000 otherwise)" % srv["at"]
        if not srv["listened"] and bad not in problems:  # nginx binds *:80 as root, *:8000 otherwise
            problems.append(bad)
        acl = next((b["acl"] for b in reversed(chain) if b["acl"]), [])
        on = {k: next((b[k] for b in reversed(chain[i:]) if b[k] is not None), False)
              for k in ("auth_basic", "auth_basic_user_file", "auth_request")}
        # auth_basic with no user file in effect asks no login: nginx lets the request through.
        # Under `satisfy any` an allow rule that matches skips the login, so only the allow
        # list counts; with no allow/deny at all the access module declines and the login decides.
        login = (on["auth_basic"] and on["auth_basic_user_file"]) or on["auth_request"]
        if acl and next((b["satisfy"] for b in reversed(chain) if b["satisfy"] is not None), False):
            login = False
        out += [{"tool": "nginx", "listen": port, "server_name": srv["names"],
                 "upstream": upstream, "source": "nginx -T", "where": srv["where"],
                 "auth": login or _denies_all(acl)} for port in sorted(set(srv["listens"])) or [None]]
    return out, problems


# The Traefik files the 'revproxy' command reads (when present), as glob patterns.
_TRAEFIK_READ = re.findall(r"/etc/traefik/[\w.*/]+", READ_ONLY["revproxy"])
# Every key a `providers` section may hold when its only provider is `file`.
_FILE_PROVIDER_KEYS = {"providers", "file", "filename", "directory", "watch",
                       "providersthrottleduration", "debugloggeneratedtemplate"}
# A belt under _traefik_plain's walk: any other provider's name used as a key anywhere in
# the file, v1's top-level tables (`[docker]`) included (an entryPoint so named over-flags,
# the safe direction).
_OTHER_PROVIDER = re.compile(r"(?i)\b(docker|swarm|kubernetes(crd|ingress|gateway)?|consul(catalog)?|nomad|ecs"
                             r"|etcd|zookeeper|redis|rest|marathon|rancher|plugin|mesos|eureka|boltdb|dynamodb"
                             r"|servicefabric)\s*[:=.\]]")


def _host_proxy_problems(text):
    """The Caddyfile / Traefik part of the 'revproxy' output -> [problem] for config that
    was read but whose routes are not followed here, judged per `# file`: a file that
    came back empty (unreadable, or a 0-byte file), a Caddyfile problem (_caddy_walk),
    a Traefik file with a Go template, or one with config in it but no route read,
    unless it cannot publish a route itself (_traefik_plain)."""
    files = _revproxy_files(text)
    read = [f for t, f, _ in files if t == "traefik" and f]
    problems = []
    for tool, f, lines in files:
        body = "\n".join(lines)
        if not f or tool == "nginx":
            continue
        if not body.strip():
            problems.append("an empty read of %s" % f)
        elif tool == "caddyfile":
            problems += _caddy_walk(body, f)[1]
        elif "{{" in body or not (_parse_traefik(re.sub(r"(?m)#.*$", "", body))  # {{ }}: a Go template
                                  or _traefik_plain(body, read)):
            problems.append("a Traefik file whose routes were not read (%s)" % f)
    return problems


def _traefik_plain(text, read):
    """A Traefik file that cannot publish a route by itself -> True: one that names no
    routers, services, providers or file-provider path, or a static config whose providers
    are only `file` with a `filename` this read covered (`read`: the `# file` paths; v1's
    top-level `[file]` too). Fails closed: no other provider's name is a key anywhere
    (_OTHER_PROVIDER), every key under `providers` (YAML block or flow, TOML tables or
    dotted keys) must be a file-provider key, and every mention of `providers` one of
    those forms."""
    body = re.sub(r"(?m)#.*$", "", text).replace('"', "").replace("'", "")
    if _OTHER_PROVIDER.search(body):
        return False
    if not re.search(r"(?i)\b(routers|services|providers|filename|directory)\b", body):
        return True
    # One shape per statement: `[ providers . docker ]` -> `[providers.docker]`, and a YAML
    # flow mapping continued on later lines joined until its brackets balance.
    body = re.sub(r"(?m)^(\s*\[+)([^\]\n]*)", lambda m: m.group(1) + re.sub(r"\s+", "", m.group(2)), body)
    lines, buf = [], ""
    for line in body.splitlines():
        buf = buf + " " + line.strip() if buf else line
        if buf.count("{") + buf.count("[") <= buf.count("}") + buf.count("]"):
            lines.append(buf)
            buf = ""
    body = "\n".join(lines + [buf])
    keys, mode, ind, found = [], None, 0, 0
    for line in body.splitlines():
        if not line.strip():
            continue
        lead = len(line) - len(line.lstrip())
        toml = re.match(r"\s*\[+\s*([\w.]+)", line)
        if toml or (mode == "yaml" and lead <= ind):
            mode = None
        yaml = re.match(r"(?i)\s*providers\s*:(.*)", line)
        if yaml:
            mode, ind, found, line = "yaml", lead, found + 1, yaml.group(1)
        elif re.match(r"(?i)providers\b", toml.group(1) if toml else line.strip()):
            mode, found = "toml" if toml else mode, found + 1
            line = toml.group(1) if toml else line
        elif not mode:
            continue
        words = re.findall(r"([\w.-]+)\s*[:=]", line) + ([line] if toml else [])
        keys += [k for w in words for k in w.split(".") if k] + (["*"] if "*" in line else [])  # a YAML alias
    paths = re.findall(r"(?i)\b(filename|directory)\s*[:=]\s*[\"']?([^\"'\s,}]+)", body)
    return (found == len(re.findall(r"(?i)\bproviders\b", body)) and bool(paths)
            and all(k.lower() in _FILE_PROVIDER_KEYS for k in keys)
            and all(k.lower() == "filename" and _traefik_covered(p, read) for k, p in paths))


def _traefik_covered(path, read):
    """A file provider's `filename` -> True when this read followed it: a file read here,
    or one the command reads when present (absent when no `# file` came back for it; the
    shell glob skips dotfiles). Never a `directory`: Traefik also loads its *.toml files
    and subdirectories, which the command does not read."""
    return path in read or (not path.rpartition("/")[2].startswith(".") and any(
        fnmatch.fnmatch(path, g) and path.count("/") == g.count("/") for g in _TRAEFIK_READ))


def _bad_reason(bad):
    """_nginx_walk's problems -> the could-not-judge reason the notes print."""
    return ("its nginx config has %s%s, which eyeline could not read, so its routes could not be "
            "judged" % (bad[0], " (and %d more)" % (len(bad) - 1) if len(bad) > 1 else ""))


def _parse_nginx(text):
    """nginx config dump -> proxy_pass upstreams with their server's listen port + name.
    Block-tracked over _nginx_files' statements: a `server {}` block's `listen` and
    `server_name` apply to every `proxy_pass` nested in it. `auth` is True when the
    server or an enclosing location carries auth_basic (not off, with an
    auth_basic_user_file in effect) / auth_request, outside `satisfy any` with an
    allow/deny list, or the innermost allow/deny list denies all after its specific
    allows. Enrichment
    only: a missed route never changes a verdict."""
    return _nginx_walk(text)[0]


def nginx_roots(text):
    """Every `root` directive's path in an nginx config dump -> sorted list. Phase
    17.5 fix 5: the served web roots, listed for secret-looking file NAMES only."""
    return sorted({w[1].strip("'\"") for _, stmts in _nginx_files(text) for _, _, w, end in stmts
                   if end == ";" and len(w) > 1 and w[0] == "root"})


def _parse_caddyfile(text):
    """Caddyfile -> reverse_proxy upstreams with the site block's listen port.
    A site header like `shop.example.com:8443 {` gives the name and listen port
    (default 443 for https names, 80 otherwise, matching Caddy's automatic-HTTPS, or the
    global options' https_port / http_port).
    Auth covers the site's routes only at site level with no matcher; a path-scoped
    or nested basic_auth/forward_auth leaves them None (could not judge). A route in a
    handle_errors block of a site with a login is None unless that block itself holds a
    login with no matcher at its top: Caddy runs it after the site's basic_auth has
    failed (401)."""
    return _caddy_walk(text)[0]


def _caddy_sites(head, ports):
    """A Caddy site header's addresses -> [(name, listen)], one per address (spaces or
    commas between them): scheme and path dropped, `:port` wins, else http -> http_port
    and https or no scheme -> https_port (`ports`, the global options' or 80/443), with
    or without a name: Caddy serves `localhost`, an IP and `https://` over HTTPS
    (caddyserver.com/docs/caddyfile/concepts#addresses); name None for a port-only
    `:8080`, listen None for a port that is a {placeholder}."""
    out = []
    for a in filter(None, re.split(r"[,\s]+", head)):
        scheme, _, a = a.rpartition("://")
        name, p = _host_port(a.split("/")[0], None)
        out.append((name or None, None if re.search(r":[^:]*\{", a) else p or ports[
            "http" if scheme.lower() == "http" else "https"]))
    return out


# One Caddyfile token, read the way Caddy's lexer reads it: a newline, a comment (`#` only
# where a token starts), a heredoc opener `<<MARKER` at the end of its line, a quoted or
# backtick token (either may span lines), or a bare word. `{` and `}` are structure only
# as whole words: `x{`, `}y` and `{$X}` are words. A quote never closed is `bad`.
_CADDY_TOKEN = re.compile(r'(?P<nl>\n)|[^\S\n]+|(?P<c>#.*)|<<(?P<here>[\w-]+)(?=[^\S\n]*\n)'
                          r'|"(?:\\[\s\S]|[^"\\])*"|`[^`]*`|(?P<bad>["`])|\S+')


# Caddy v2's standard directives (caddyserver.com/docs/caddyfile/directives) that send no
# request to an upstream or another process, plus the old names basicauth and skip_log.
# reverse_proxy is read; php_fastcgi (a reverse_proxy shortcut), v1's `proxy` and plugins
# are not on it.
_CADDY_LOCAL = frozenset(
    "abort acme_server basic_auth basicauth bind encode error file_server forward_auth fs handle "
    "handle_errors handle_path header import intercept invoke log log_append log_skip skip_log "
    "log_name map method metrics push redir request_body request_header respond rewrite root route "
    "templates timeouts tls tracing try_files uri vars".split())


def _caddy_walk(text, f=None):
    """Caddyfile text (one file) -> (reverse_proxy entries, [problem]), like _nginx_walk.
    Read as Caddy reads it: tokens (_CADDY_TOKEN), one statement per line of tokens, a
    block opened by a `{` that ends its line and closed by a `}` alone on one. Upstreams
    are read inline (`reverse_proxy [matcher] up...`) or from `to` lines in its block;
    each gives an entry per site address only when both are whole (a site with a listen
    port, an http/https/h2c `host:port` upstream; `:3000` is localhost). Anything else
    is a problem: a {placeholder}, a unix socket, a port range, another scheme, a route
    in no site (a snippet's too), a reverse_proxy with no upstream, an `import` of
    anything but a snippet `(name) {}` defined in this file, a brace Caddy would refuse,
    an open quote, heredoc or block, a line ending in `\\`, a reverse_proxy `dynamic`
    upstream source, a site port or global http_port/https_port that is not a number, and
    Caddy JSON. An address list may continue over lines ending in `,`, and its `{` may
    sit on the next line. Caddy's single-site form
    needs no braces: an address with no `{` after it opens a site running to the end of
    the file, a problem when a site came before it or a later line is no directive (a
    second site's header). Belt: every `reverse_proxy` in the file's tokens (quoted or in
    a heredoc too) must be a statement read here, else its line is a problem; and every
    directive in a site, snippet or handle/handle_path/handle_errors/route block (not in
    another directive's own block) must be reverse_proxy or one on _CADDY_LOCAL."""
    def where(n):
        return "%s:%d" % (f, n) if f else "line %d" % n
    if re.match(r'\s*(\[|\{\s*")', text):
        return [], ["a Caddy JSON config, not followed, in %s" % (f or "the Caddyfile")]
    lines, problems, pos, n, cur = [], [], 0, 1, None
    while pos < len(text):
        m = _CADDY_TOKEN.match(text, pos)
        tok, pos, here = m.group(0), m.end(), m.group("here")
        if here:  # its body runs to the marker, which only spaces may precede on its line
            end = text.find(here, pos)
            here = end >= 0 and not text[text.rfind("\n", 0, end) + 1:end].strip()
            tok, pos = text[m.start():end + len(m.group("here"))], end + len(m.group("here"))
        if m.group("bad") or here is False:
            problems.append("an open quote or heredoc at %s" % where(n))
            break
        if m.group("nl"):
            cur = None
        elif tok.strip() and not m.group("c"):
            if cur is None:
                cur = [n, []]
                lines.append(cur)
            cur[1].append(tok)
        n += tok.count("\n")
    out, pending, sites, auth, rp = [], [], [], False, None  # rp: [depth inside, any upstream, at]
    errs, perr = [], []  # open handle_errors blocks [depth inside, own login]; per pending entry
    depth, braceless, addr, seen, snips, imports, used = 0, 0, [], False, set(), [], set()
    dirs = set()  # the depths whose lines are directives (_CADDY_LOCAL)
    ports = {"http": 80, "https": 443}  # the global options' http_port / https_port
    for i, (n, toks) in enumerate(lines):
        at = where(n)
        if toks[-1].endswith("\\"):  # a line continued with `\` is not read here
            problems.append("a line ending in \\ at %s" % at)
        if depth == 0 and addr:  # an address list continued after `,`, or its `{` on this line
            if addr[-1].endswith(",") or toks == ["{"]:
                toks, addr = addr + toks, []
            else:  # Caddy's single-site form: the rest of the file is this site's
                if seen:
                    problems.append("a site with no braces after another site at %s" % at)
                sites, depth, braceless, seen, addr = _caddy_sites(" ".join(addr), ports), 1, 1, True, []
                dirs = {1}
        if toks.count("{") + toks.count("}") > (toks[-1] == "{" or toks == ["}"]) or (depth and toks[0] == "{"):
            problems.append("a brace Caddy would refuse at %s" % at)
        if depth == 0:
            if toks == ["}"]:
                problems.append("a } with no block open at %s" % at)
            elif toks[0] == "import":
                imports.append(((toks[1:] or [""])[0], at))
            elif toks[-1] != "{":
                addr = toks
            elif toks[0].startswith("("):  # a snippet: it serves nothing itself
                snips.add(toks[0].strip("()"))
                sites, depth, dirs = [], 1, {1}
            else:  # a site, or the global options block (no address, so no site; before any site)
                if toks == ["{"] and seen:
                    problems.append("a block with no site address at %s" % at)
                sites, depth, auth, seen = _caddy_sites(" ".join(toks[:-1]), ports), 1, False, seen or len(toks) > 1
                dirs = {1} if len(toks) > 1 else set()  # the global options are no directives
            continue
        if braceless and depth == 1 and not re.fullmatch(r"[a-z_][a-z0-9_]*|@\S+", toks[0]):
            problems.append("a line Caddy would not read as a directive in a single-site file at %s" % at)
        name, args = toks[0], [t for t in toks[1:] if t != "{"]
        if depth in dirs and toks != ["}"] and not name.startswith("@") and name != "reverse_proxy":
            if name not in _CADDY_LOCAL:
                problems.append("a %s directive at %s" % (name, at))
            elif toks[-1] == "{" and name in ("handle", "handle_path", "handle_errors", "route"):
                dirs.add(depth + 1)
        if re.fullmatch(r"basic_?auth|forward_auth", name):
            # A matcher (/path, @name, *) or a nested block scopes it to some requests only.
            scoped = (args or [""])[0].strip('"`').startswith(("/", "@", "*"))
            if errs and depth == errs[-1][0] and not scoped:
                errs[-1][1] = True
            auth = True if auth or not (scoped or depth > 1) else None
        elif name == "import":
            imports.append(((args or [""])[0], at))
        elif name in ("http_port", "https_port"):
            if len(args) == 1 and args[0].isdigit():
                ports[name[:-5]] = int(args[0])
            else:
                problems.append("an %s eyeline could not read at %s" % (name, at))
        elif rp and depth == rp[0] and name == "dynamic":  # upstreams looked up at run time
            problems.append("a reverse_proxy with dynamic upstreams at %s" % at)
        elif name == "reverse_proxy" or (rp and depth == rp[0] and name == "to"):
            used.add(i)
            if name == "reverse_proxy" and args and (args[0].startswith(("/", "@")) or args[0] == "*"):
                args = args[1:]  # a request matcher, not an upstream
            for x in args:
                scheme, _, x = x.strip("'\"`").rpartition("://")
                host, p = _host_port(x, 443 if scheme == "https" else 80)
                up = "%s:%s" % (host or "localhost", p)  # `:3000` dials this host
                site_ok = sites and None not in [listen for _, listen in sites]
                if not site_ok or scheme not in ("", "http", "https", "h2c") or not re.fullmatch(
                        r"([\w.-]+|[\da-fA-F:.]+):\d+", up):
                    problems.append("a reverse_proxy %s at %s" % (
                        "to an upstream eyeline could not read" if site_ok else "in no site eyeline could read", at))
                    continue
                pending += [{"tool": "caddy", "listen": listen, "server_name": site, "upstream": up,
                             "source": "Caddyfile", "auth": False, "where": {
                                 "file": f, "line": n, "text": text.split("\n")[n - 1]}}
                            for site, listen in sites]
                perr += [list(errs)] * len(sites)
            if name == "to":
                rp[1] = rp[1] or bool(args)
            elif rp:
                problems.append("a reverse_proxy inside a reverse_proxy block at %s" % at)
            elif toks[-1] == "{":
                rp = [depth + 1, bool(args), at]
            elif not args:
                problems.append("a reverse_proxy with no upstream eyeline could read at %s" % at)
        if name == "handle_errors" and toks[-1] == "{":
            errs.append([depth + 1, False])
        depth += (toks[-1] == "{") - (toks == ["}"])
        dirs = {d for d in dirs if d <= depth}
        errs = [b for b in errs if b[0] <= depth]
        if depth < braceless:
            problems.append("a } with no block open at %s" % at)
        if rp and depth < rp[0]:
            if not rp[1]:
                problems.append("a reverse_proxy with no upstream eyeline could read at %s" % rp[2])
            rp = None
        if depth <= 0:
            for e, bl in zip(pending, perr):
                e["auth"] = auth if not bl or auth is False or any(b[1] for b in bl) else None
            out += pending
            pending, perr, sites, depth, auth = [], [], [], 0, False
    for e, bl in zip(pending, perr):
        e["auth"] = auth if not bl or auth is False or any(b[1] for b in bl) else None
    out += pending
    if depth != braceless:
        problems.append("a block left open at the end of %s" % (f or "the Caddyfile"))
    problems += ["a reverse_proxy eyeline did not follow at %s" % where(n) for i, (n, toks) in enumerate(lines)
                 if sum(t.count("reverse_proxy") for t in toks) > (i in used)]
    return out, problems + ["a Caddyfile import of %s at %s" % (x, at) for x, at in imports if x not in snips]


def _parse_traefik(text):
    """Traefik file-provider config (YAML, no library) -> loadBalancer upstream URLs.
    The listen port is not resolved here (it maps through router entryPoints to the
    static config); Traefik entries report the upstream and leave listen None."""
    out = []
    for m in re.finditer(r"url\s*[:=]\s*[\"']?(https?://[^\s\"']+)", text):  # YAML or TOML
        up = _UPSTREAM.match(m.group(1))
        if up:
            host, p = _host_port(up.group(1), 80)
            # Traefik auth lives in middlewares linked to routers; this upstream-only
            # read cannot confirm which router (and thus which auth middleware) fronts
            # a given service, so auth is left unknown (fail closed -> "could not judge").
            out.append({"tool": "traefik", "listen": None, "server_name": None,
                        "upstream": "%s:%s" % (host, p), "source": "Traefik file provider",
                        "auth": None})
    return out


def revproxy_context(revproxy, port):
    """Exposure context for a listen `port` -> [str]: which upstream each proxy on this
    port forwards to. Entries whose listen port is unknown (Traefik) are not attached
    to a specific port. Facts only; never changes a verdict."""
    out = []
    for e in revproxy or []:
        if e["listen"] == port:
            name = (" for %s" % e["server_name"]) if e["server_name"] else ""
            out.append("%s publishes this port%s -> proxies to %s (%s)"
                       % (e["tool"], name, e["upstream"], e["source"]))
    return out


# --- panel (Coolify / Dokploy) ----------------------------------------------

# A management panel is identified by its container/compose name, not a fixed port
# (ports collide: Coolify's dashboard default 8000 is also a common app port).
PANEL_NAMES = {"coolify": "Coolify", "dokploy": "Dokploy"}


def detect_panels(published):
    """parse_docker_inspect() output -> [{panel, port, container, service}] for any
    published port whose container or compose service is a known panel. [] when none.
    Reuses the docker read already done; no new command, no image/Env read."""
    out = []
    for p in published or []:
        name = (p.get("container") or "").lower()
        svc = (p.get("service") or "").lower()
        for key, label in PANEL_NAMES.items():
            if name == key or name.startswith(key + "-") or svc == key:
                out.append({"panel": label, "port": p["host_port"],
                            "container": p["container"], "service": p["service"]})
                break
    return out


def panel_context(panels, port):
    """Exposure context for a port a management panel publishes -> [str]. Facts only."""
    out = []
    for p in panels or []:
        if p["port"] == port:
            out.append("%s management panel exposes this port (container %s); a panel reachable "
                       "from the internet is a high-value target - bind it to localhost or put it "
                       "behind a VPN/allowlist" % (p["panel"], p["container"] or "?"))
    return out


# --- the user's own DNS (records they control pointing at the box) -----------

def parse_dns_zones(text, box_ips):
    """The 'dns_zones' command's output (the box's own authoritative zone files, each
    behind `# zonefile <path>`) -> [{name, type, value, zonefile}] for A/AAAA records
    whose value is one of the box's own IPs (box_ips: the set of IP strings on the
    box's interfaces). Only the user's own records that point AT this box are kept;
    nothing is resolved and no third-party zone is read. [] when nothing matches.

    A zone file is bind/RFC-1035 syntax: `<owner> [ttl] [class] <type> <rdata>`, with
    $ORIGIN/$TTL directives, `@` for the origin, and a blank owner meaning 'repeat the
    previous owner'. Only enough of that grammar is handled to attribute A/AAAA records."""
    if not text:
        return []
    box = set(box_ips or [])
    out, zonefile, origin, last_owner = [], None, None, None
    for raw in text.splitlines():
        fm = re.match(r"^#\s*zonefile\s+(\S+)", raw)
        if fm:
            zonefile, origin, last_owner = fm.group(1), None, None
            continue
        line = re.sub(r";.*$", "", raw).rstrip()  # strip comments
        if not line.strip():
            continue
        d = re.match(r"\$ORIGIN\s+(\S+)", line.strip())
        if d:
            origin = d.group(1).rstrip(".")
            continue
        if line.strip().startswith("$"):  # $TTL and other directives: not records
            continue
        # owner is present when the line does not start with whitespace
        indented = line[0] in " \t"
        fields = line.split()
        if not fields:
            continue
        if indented:
            owner = last_owner
        else:
            owner = fields.pop(0)
            last_owner = owner
        rtype, value = _zone_record(fields)
        if rtype not in ("A", "AAAA") or value is None:
            continue
        if value not in box:
            continue  # only records pointing at THIS box
        out.append({"name": _fqdn(owner, origin), "type": rtype, "value": value,
                    "zonefile": zonefile})
    return out


def _zone_record(fields):
    """Resource-record fields (class/ttl already variable) -> (type, rdata) for A/AAAA,
    else (None, None). Skips optional TTL and class (IN) tokens before the type."""
    i = 0
    while i < len(fields) and (fields[i].isdigit() or fields[i].upper() in ("IN", "CH", "HS")):
        i += 1
    if i + 1 < len(fields) and fields[i].upper() in ("A", "AAAA"):
        return fields[i].upper(), fields[i + 1]
    return None, None


def _fqdn(owner, origin):
    """A zone owner name -> its FQDN (no trailing dot). Without an $ORIGIN (the zone's
    origin lives in named.conf, which this collector does not read), a relative name is
    returned with a trailing dot-origin marker so it is never shown as a bare label that
    could be mistaken for a full hostname."""
    if owner in ("@", None):
        return origin or "@ (zone apex)"
    if owner.endswith("."):
        return owner.rstrip(".")
    return "%s.%s" % (owner, origin) if origin else "%s.<zone>" % owner


def dns_context(dns_records, port):
    """Exposure context for a port -> [str]: the user's own hostnames that resolve to
    this box. DNS is box-wide (not per-port), so these attach to every exposed row once;
    the caller passes port only for signature symmetry. Facts only."""
    if not dns_records:
        return []
    names = sorted({r["name"] for r in dns_records})
    return ["your own DNS points %s at this box (%s); these names resolve a stranger straight here"
            % (", ".join(names[:6]) + (" +%d more" % (len(names) - 6) if len(names) > 6 else ""),
               dns_records[0]["zonefile"] or "zone file")]


# --- Docker NAT (iptables-save / nft) --------------------------------------

_LOOP_DST = re.compile(r"(-d|daddr)\s+(127\.|::1\b)")


def _iptables(text):
    if not text or not any(l.startswith("*") for l in text.splitlines()):
        return None
    ports, filtering, table = set(), False, None
    for line in text.splitlines():
        if line.startswith("*"):
            table = line[1:].strip()
        elif table == "nat" and line.startswith("-A DOCKER ") and "-j DNAT" in line:
            m = re.search(r"--dport (\d+)(?::(\d+))?", line)
            if m and not _LOOP_DST.search(line):
                ports.update(range(int(m.group(1)), int(m.group(2) or m.group(1)) + 1))
        elif table == "filter" and line.startswith("-A DOCKER-USER "):
            filtering = filtering or line.split(None, 2)[2].strip() != "-j RETURN"
    return ports, filtering


def _nft(text):
    if not text or "table " not in text:
        return None
    ports, filtering, depth, table, chain, chain_depth = set(), False, 0, "", None, 0
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"table\s+\S+\s+(\S+)\s*\{", s)
        if m and depth == 0:
            table = m.group(1)
        m = re.match(r"chain\s+(\S+)\s*\{", s)
        if m:
            chain, chain_depth = m.group(1), depth + 1
        elif chain and s and not s.startswith(("#", "}", "type ", "policy ")):
            if _is_docker_nat_chain(chain, table) and re.search(r"\bdnat\b", s):
                d = re.search(r"\bdport (\d+)(?:-(\d+))?", s)
                if d and not _LOOP_DST.search(s):
                    ports.update(range(int(d.group(1)), int(d.group(2) or d.group(1)) + 1))
            elif chain == "DOCKER-USER":
                filtering = filtering or not re.fullmatch(r"(counter( packets \d+ bytes \d+)?\s+)?return", s)
        depth += s.count("{") - s.count("}")
        if chain and depth < chain_depth:
            chain = None
    return ports, filtering


def parse_docker_nat(iptables_text, nft_text):
    """-> {dnat_ports, docker_user_filtering}: host ports Docker DNATs from off-box
    (loopback-only DNATs excluded), and whether DOCKER-USER holds any rule other
    than RETURN. None when neither source is readable."""
    found = [r for r in (_iptables(iptables_text), _nft(nft_text)) if r is not None]
    if not found:
        return {"dnat_ports": None, "docker_user_filtering": None}
    return {"dnat_ports": set().union(*(p for p, _ in found)),
            "docker_user_filtering": any(f for _, f in found)}


# --- Docker inspect + compose ----------------------------------------------

def _split_auth_env(json_text):
    """Split the docker command's output into the JSON body and the auth-env map.
    The trailer, after a `#--auth_env--` marker, is lines `#auth <id> KEY=value` (a
    non-secret auth-signal key) or `#auth <id> KEY` (a password key, PRESENCE only,
    no value). -> (json_text, {full_or_short_id: {KEY: value|None}}). A KEY with no
    value maps to None (present, value not transported)."""
    if json_text is None:
        return None, {}
    marker = "#--auth_env--"
    if marker not in json_text:
        return json_text, {}
    body, _, trailer = json_text.partition(marker)
    env = {}
    for line in trailer.splitlines():
        line = line.strip()
        if not line.startswith("#auth "):
            continue
        parts = line[len("#auth "):].split(None, 1)
        if not parts:
            continue
        cid = parts[0]
        kv = parts[1] if len(parts) > 1 else ""
        key, sep, val = kv.partition("=")
        if key:
            env.setdefault(cid, {})[key] = val if sep else None
    return body, env


def _cmd_by_id(text):
    """The `#cmd <id> <json-string>` trailer -> {id: (tokens, ended)}. `ended` is True
    only if the `"#END"` sentinel came through the on-box allow-list sed; without it
    the Cmd was not read safely and must be treated as unread (fail closed)."""
    out = {}
    for line in (text or "").splitlines():
        if not line.startswith("#cmd "):
            continue
        parts = line[len("#cmd "):].split(" ", 1)
        if len(parts) != 2:
            continue
        try:
            tok = json.loads(parts[1])
        except ValueError:
            continue
        toks, ended = out.get(parts[0], ([], False))
        if tok == "#END":
            ended = True
        elif isinstance(tok, str):
            toks.append(tok)
        out[parts[0]] = (toks, ended)
    return out


def _container_env(env_by_id, full_id):
    """The auth-env map for a container, matched by the short id (first 12 chars of
    the full Id) the docker command emits, or the full id."""
    if full_id in env_by_id:
        return env_by_id[full_id]
    return env_by_id.get((full_id or "")[:12], {})


def parse_docker_inspect(json_text):
    """`docker inspect` output -> published host ports with their compose labels,
    plus (phase 15) the image, Cmd, the blast-radius fields (privileged, cap_add,
    security_opt, pid_mode, network_mode, mounts) and the allow-listed auth-signal
    env (no secret value). Accepts a JSON list, one JSON object per line (inspect -f),
    optionally followed by the `#--auth_env--` trailer."""
    containers = docker_containers(json_text)
    if containers is None:
        return None
    out = []
    for c in containers:
        shared = {k: v for k, v in c.items() if k != "ports"}
        for b in c["ports"]:
            out.append(dict(shared, **b))
    return out


def docker_containers(json_text):
    """Every running container (published or not) -> [{container, service, project,
    image, mounts, ..., ports: [{host_ip, host_port, container_port, proto}]}], or None
    when docker was not readable. Phase 17.5: an nginx upstream (`dash:3000`) can name
    a container that publishes nothing, so routes need the whole list."""
    if json_text is None:
        return None
    cmd_by_id = _cmd_by_id(json_text)
    json_text, env_by_id = _split_auth_env(json_text)
    try:
        data = json.loads(json_text) if json_text.strip() else []
    except ValueError:
        try:
            data = [json.loads(l) for l in json_text.splitlines() if l.strip()]
        except ValueError:
            return None
    data = [data] if isinstance(data, dict) else data  # one container: one object
    if not isinstance(data, list):
        return None
    out = []
    for c in data:
        if not isinstance(c, dict):
            continue
        config = c.get("Config") or {}
        labels = config.get("Labels") or {}  # a label the box lacks arrives as "" -> None below
        hostcfg = c.get("HostConfig") or {}
        files = labels.get("com.docker.compose.project.config_files") or ""
        auth_env = _container_env(env_by_id, c.get("Id"))
        # Cmd comes from the `#cmd` trailer (allow-listed on the box). A JSON Cmd is
        # accepted too (fixtures). No Cmd key and no #END sentinel -> unread.
        cmd_unread = False
        if "Cmd" in config:
            cmd = config.get("Cmd") if isinstance(config.get("Cmd"), list) else None
        else:
            toks, ended = _container_env(cmd_by_id, c.get("Id")) or ([], False)
            cmd, cmd_unread = (toks or None, False) if ended else (None, True)
        shared = {
            "container": (c.get("Name") or "").lstrip("/"),
            "service": labels.get("com.docker.compose.service") or None,
            "project": labels.get("com.docker.compose.project") or None,
            "compose_files": [f.strip() for f in files.split(",") if f.strip()],
            "working_dir": labels.get("com.docker.compose.project.working_dir") or None,
            "image": config.get("Image"),
            "cmd": cmd,
            "cmd_unread": cmd_unread,
            "privileged": hostcfg.get("Privileged"),
            "cap_add": hostcfg.get("CapAdd") or [],
            "security_opt": hostcfg.get("SecurityOpt") or [],
            "pid_mode": hostcfg.get("PidMode") or "",
            "network_mode": hostcfg.get("NetworkMode") or "",
            "mounts": c.get("Mounts") if isinstance(c.get("Mounts"), list) else [],
            "auth_env": auth_env,
        }
        ports = []
        for key, binds in sorted(((c.get("NetworkSettings") or {}).get("Ports") or {}).items()):
            cport, _, proto = key.partition("/")
            for b in binds or []:
                try:
                    host_port = int(b.get("HostPort"))
                except (TypeError, ValueError, AttributeError):
                    continue
                ports.append({"host_ip": b.get("HostIp") or "0.0.0.0", "host_port": host_port,
                              "proto": proto or "tcp",
                              "container_port": int(cport) if cport.isdigit() else None})
        out.append(dict(shared, ports=ports))
    return out


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _content(line):
    s = line.strip()
    return bool(s) and not s.startswith("#")


def _key(line, name):
    return re.match(r"""^\s*(["']?)%s\1\s*:(\s|$)""" % re.escape(name), line)


def _block(lines, start, indent, dash_ok=False):
    """Line indexes after `start` (a key at `indent`) nested under it. dash_ok: a
    YAML list may sit at the key's own indent."""
    end = start + 1
    while end < len(lines):
        ln = lines[end]
        if _content(ln) and (_indent(ln) < indent or (_indent(ln) == indent and not (
                dash_ok and ln.strip().startswith("-")))):
            break
        end += 1
    return range(start + 1, end)


def _hits(spec, port):
    """"5432" or "8000-8010" covers port?"""
    lo, _, hi = spec.strip().strip("\"'").partition("-")
    return lo.isdigit() and int(lo) <= port <= int(hi if hi.isdigit() else lo)


def _short_hits(value, port):
    """Short port syntax: does its HOST side cover port? ("127.0.0.1:6379:6379" -> 6379)."""
    parts = value.strip().strip("\"'").split("/")[0].rsplit(":", 2)
    return len(parts) >= 2 and _hits(parts[-2], port)


def _find_port(lines, k, indent, port):
    rest = lines[k].split(":", 1)[1].strip()
    if rest.startswith("["):  # flow list: ports: ["80:80"]
        if any(_short_hits(v, port) for v in rest.strip("[]").split(",")):
            return k + 1, lines[k].strip()
        return None
    block = _block(lines, k, indent, dash_ok=True)
    for n in block:
        s = lines[n].strip()
        if not s.startswith("-"):
            continue
        value = re.sub(r"\s+#.*$", "", s[1:].strip())
        if not re.match(r"[A-Za-z_]+\s*:", value):
            if _short_hits(value, port):
                return n + 1, s
            continue
        item = [n] + [m for m in _block(lines, n, _indent(lines[n])) if m in block]
        for m in item:
            t = lines[m].strip().lstrip("-").strip()
            kv = re.match(r"published\s*:\s*([^#]+)", t)
            if kv and _hits(kv.group(1), port):
                return m + 1, lines[m].strip()
    return None


def locate_compose_port(text, service, port):
    """The `ports:` line in `service` whose host side is `port` -> (line_no, text) or None.
    No YAML library: walks indentation. `expose:` and other services never match."""
    lines = (text or "").splitlines()
    top = next((i for i, l in enumerate(lines) if _indent(l) == 0 and _key(l, "services")), None)
    if top is None:
        return None
    svc_block = _block(lines, top, 0)
    svc_indent = next((_indent(lines[i]) for i in svc_block if _content(lines[i])), None)
    j = next((i for i in svc_block if _indent(lines[i]) == svc_indent and _key(lines[i], service)), None)
    if j is None:
        return None
    body = _block(lines, j, svc_indent)
    child = next((_indent(lines[i]) for i in body if _content(lines[i])), None)
    for k in body:
        if _indent(lines[k]) == child and _key(lines[k], "ports"):
            return _find_port(lines, k, child, port)
    return None


def _safe_compose_path(p):
    return (isinstance(p, str) and p.startswith("/") and p.endswith((".yml", ".yaml"))
            and not any(c in p for c in "\n\r\0"))


# --- the read ---------------------------------------------------------------

def read(remote, scope_ips=()):
    """Everything the target says about its exposure. Only READ_ONLY commands.
    scope_ips: the target's attested public IP strings, added to the DNS self-match
    set so a 1:1-NAT box (public IP not on any interface) still matches its own
    records pointing at it."""
    notes = []
    listeners = parse_ss(_run(remote, "listeners"))
    if listeners is None:
        notes.append("listeners: not readable (ss failed)")
    elif listeners and all(l["process"] is None for l in listeners):
        notes.append("listeners: process names not readable (no passwordless sudo)")
    ufw = parse_ufw(_run(remote, "ufw"))
    _, ipt = remote.run("iptables")  # exit code is ip6tables-save's; the parser checks v4 itself
    nft_text = _run(remote, "nft")
    nat = parse_docker_nat(ipt, nft_text)
    if nat["dnat_ports"] is None:
        notes.append("docker NAT rules: not readable (iptables-save/nft need passwordless sudo)")
    # Which firewall the box actually uses. UFW first (if active); else firewalld
    # (if running); else a plain-nftables input base chain; else none readable.
    firewalld = parse_firewalld(_run(remote, "firewalld"))
    nft_input = parse_nft_input(nft_text)
    if ufw["active"]:
        firewall = {"kind": "ufw", "ufw": ufw}
    elif firewalld["active"]:
        firewall = {"kind": "firewalld", "firewalld": firewalld}
        notes.append("firewall: read via firewalld (zone %s)" % (firewalld["zone"] or "?"))
    elif nft_input["readable"]:
        firewall = {"kind": "nftables", "nft_input": nft_input}
        notes.append("firewall: read via the nftables input chain (policy %s)" % nft_input["policy"])
    else:
        firewall = {"kind": None}
        notes.append("firewall: could not judge (not UFW/firewalld/plain-nftables, or none readable "
                     "without a password); ports open from outside are reported 'could not judge'")
    docker_code, docker_out = remote.run("docker")
    published = parse_docker_inspect(docker_out if docker_code == 0 else None)
    containers = docker_containers(docker_out if docker_code == 0 else None) or []
    if published is None:
        notes.append("docker: command not found (no Docker; a podman-only box is not read here)"
                     if docker_code == 127 else
                     "docker: not readable (installed but no access without a password)")
    compose, cache = {}, {}
    for p in published or []:
        key = (p["service"], p["host_port"])
        if not p["service"] or key in compose:
            continue
        compose[key] = None
        for f in p["compose_files"]:
            if not _safe_compose_path(f):
                notes.append("compose file %r not read: not an absolute .yml/.yaml path" % f)
                continue
            if f not in cache:
                cache[f] = _run(remote, "read_compose", f)
                if cache[f] is None:
                    notes.append("compose file %s: not readable" % f)
            loc = locate_compose_port(cache[f], p["service"], p["host_port"]) if cache[f] else None
            if loc:
                compose[key] = {"file": f, "line": loc[0], "text": loc[1]}
                break

    # Exposure context (never changes a verdict; explains why a port is reachable).
    sshd = parse_sshd(_run(remote, "sshd"))
    sshd_files = None
    if sshd is None:
        notes.append("sshd config: not readable (sshd -T needs root, or sshd is absent)")
    elif sshd["password_auth"]:
        sshd_files = parse_sshd_files(_run(remote, "sshd_files"))
    revproxy_text = _run(remote, "revproxy")
    revproxy = parse_revproxy(revproxy_text)
    host_nginx = (revproxy_text or "").split("#--caddyfile--")[0]
    host_unjudged, host_bad = None, _nginx_walk(host_nginx)[1]
    other_bad = _host_proxy_problems((revproxy_text or "")[len(host_nginx):])
    for tool in ("caddy", "traefik"):  # running, but configured elsewhere or by flags only
        if any(l["process"] == tool for l in listeners or []) and not any(
                f and f.startswith("/etc/%s/" % tool) for _, f, _ in _revproxy_files(revproxy_text)):
            other_bad.append("a listening %s process whose config is not in /etc/%s" % (tool, tool))
    if revproxy_text is None:  # the read failed or timed out: not the same as "no proxy"
        host_unjudged = ("the proxy config read failed or timed out, so its routes and their auth "
                         "could not be read")
    elif re.search(r"(?m)^#--nginx-unread--$", host_nginx):
        host_unjudged = ("nginx is installed but `nginx -T` printed no config (eyeline never runs it "
                         "with sudo: as root its test mode can write files), so its routes and their auth could not be read")
    elif host_bad:
        host_unjudged = _bad_reason(host_bad)
    if other_bad:
        host_unjudged = "; ".join(filter(None, [host_unjudged, "its Caddy/Traefik config has %s, which "
                                                "eyeline does not follow, so its routes could not be "
                                                "judged" % ", ".join(other_bad)]))
    if host_unjudged:
        notes.append("reverse proxy on the host: could not judge (%s)" % host_unjudged)
    webroots = [(r, "host nginx") for r in nginx_roots(host_nginx) if r.startswith("/")]
    for r in nginx_roots(host_nginx):
        if not r.startswith("/"):
            notes.append("host nginx web root %r is relative (or uses a variable); its files could "
                         "not be listed" % r)
    cproxy, croots, unjudged = _container_nginx(remote, containers)
    revproxy += cproxy
    webroots += croots
    for u in unjudged:
        notes.append("reverse proxy in container %s: could not judge (%s)" % (u["container"], u["reason"]))
    if not revproxy and not unjudged and not host_unjudged:
        notes.append("reverse proxy: none read (no host nginx/Caddy/Traefik config, and no nginx "
                     "container with a bind-mounted config)")
    secret_files = _webroot_names(remote, webroots, notes)
    panels = detect_panels(published)
    box_ips = {str(i.ip) for _, i in _box_addrs(remote)} | {str(ip) for ip in scope_ips if ip}
    dns_text = _run(remote, "dns_zones")
    dns = parse_dns_zones(dns_text, box_ips)
    if dns_text is None:  # a failed read is not "no zone file"
        notes.append("own DNS zone files: not readable (the read failed or timed out)")
    elif not dns:
        notes.append("own DNS: no local authoritative zone file points a name at this box (a zone "
                     "hosted at a third-party DNS provider is not read)")

    return {"listeners": listeners, "ufw": ufw, "firewall": firewall, "nat": nat,
            "published": published, "compose": compose, "sshd": sshd, "revproxy": revproxy,
            "panels": panels, "dns": dns, "containers": containers, "sshd_files": sshd_files,
            "revproxy_unjudged": unjudged, "secret_files": secret_files,
            "notes": list(dict.fromkeys(notes))}


# --- phase 17.5: nginx config mounted into containers; web-root file names -----

NGINX_DEFAULT_ROOT = "/usr/share/nginx/html"  # the official nginx image's web root
# Names that are templates by convention (phase-16 decoy D4: an empty .env.example).
ENV_TEMPLATES = (".env.example", ".env.sample", ".env.dist", ".env.template", ".env.tpl",
                 ".env.default", ".env.defaults")
# The same name patterns the on-box `find` in 'webroot_names' uses (-iname), re-checked
# here on the lowercased name.
SECRET_NAMES = (".git", ".env", ".env.*", "*.sql", "*.sql.gz", "*.dump", "*.bak", "*.backup",
                "backup.*", "dump.*")


def _safe_host_path(p):
    return (isinstance(p, str) and p.startswith("/") and len(p) < 4096
            and not any(ord(c) < 32 or ord(c) == 127 for c in p))


def _is_nginx(image):
    repo = (image or "").rsplit("@", 1)[0]
    last = repo.rsplit("/", 1)[-1].split(":", 1)[0]
    return last in ("nginx", "nginx-unprivileged")


def _is_other_proxy(image):
    """'Caddy' / 'Traefik' for those proxy images, else None."""
    repo = (image or "").rsplit("@", 1)[0]
    last = repo.rsplit("/", 1)[-1].split(":", 1)[0]
    return {"caddy": "Caddy", "traefik": "Traefik"}.get(last)


def _binds(c):
    return [m for m in c.get("mounts") or [] if isinstance(m, dict) and m.get("Type") == "bind"]


def host_path(c, path):
    """A path inside container `c` -> the host path behind its bind mount, or None
    when the path is not under any bind mount (it lives in the image)."""
    best = None
    for m in _binds(c):
        d = (m.get("Destination") or "").rstrip("/")
        if d and (path == d or path.startswith(d + "/")) and (best is None or len(d) > len(best[0])):
            best = (d, m.get("Source") or "")
    return None if best is None else best[1].rstrip("/") + path[len(best[0]):]


# Data files every nginx package and image ships (type maps, parameter lists, charset
# tables), included by the stock nginx.conf. Never a route, so an include of one is not
# "unread config" even when it lives in the image (a design call, open to revision).
NGINX_STOCK_INCLUDES = ("mime.types", "fastcgi_params", "fastcgi.conf", "scgi_params",
                        "uwsgi_params", "proxy_params", "koi-utf", "koi-win", "win-utf")


def _unread_includes(c, text, srcs):
    """Fix 2: each `include` target in mounted nginx text that 'read_mount' did not read
    -> [target]. A target must map through a bind mount to a file that was read; a glob
    counts only where read_mount's find takes every match (a *.conf pattern, or below
    sites-enabled, within its depth of 3). Relative targets resolve against /etc/nginx."""
    # A `# file X` line inside a file's own text is a comment, not a header: it counts
    # only where read_mount's find would have listed X (#16).
    read = {p for p in re.findall(r"(?m)^# file (/.+)$", text) if _find_reads(p, srcs)}
    out = []
    for t in [w[1].strip("'\"") for _, stmts in _nginx_files(text) for _, _, w, end in stmts
              if end == ";" and len(w) > 1 and w[0] == "include"]:
        if ".." in t.split("/"):  # resolves outside what the path mapping can show
            out.append(t)
            continue
        if t.rsplit("/", 1)[-1] in NGINX_STOCK_INCLUDES:
            continue
        h = host_path(c, t if t.startswith("/") else "/etc/nginx/" + t)
        if h in read or (h and any(ch in t for ch in "*?[") and _find_reads(h, srcs)):
            continue
        out.append(t)
    return out


def _find_reads(h, srcs):
    """Whether read_mount's find lists host path h: a mounted file itself, or a *.conf,
    *.template or sites-enabled file within depth 3 of a mounted directory."""
    return any(h == s.rstrip("/") or (h.startswith(s.rstrip("/") + "/")
               and len(h[len(s.rstrip("/")) + 1:].split("/")) <= 3
               and (h.endswith((".conf", ".template")) or "/sites-enabled/" in h))
               for s in srcs if s)


def _container_nginx(remote, containers):
    """Fix 2: an nginx container's config, read on the HOST at its bind-mount Source
    over ssh (never `docker exec`). -> (revproxy entries, [(host web root, served by)],
    [{container, reason}] could-not-judge). Config baked into the image is not read:
    its routes are 'could not judge', never 'no route'."""
    entries, roots, unjudged = [], [], []
    for c in containers:
        name = c.get("container")
        if _is_other_proxy(c.get("image")):
            unjudged.append({"container": name, "reason": "it runs %s; eyeline reads proxy config "
                             "inside containers only for nginx" % _is_other_proxy(c.get("image"))})
            continue
        if not _is_nginx(c.get("image")):
            continue
        conf = [m for m in _binds(c) if (m.get("Destination") or "").rstrip("/") == "/etc/nginx"
                or (m.get("Destination") or "").startswith("/etc/nginx/")]
        text, unread = "", []
        for m in conf:
            src = m.get("Source")
            out = _run(remote, "read_mount", src) if _safe_host_path(src) else None
            if out is None or "#--unread--" in out or "# file " not in out:
                unread.append(src)
            text += out or ""
        parsed, bad = _nginx_walk(text)
        if not conf:
            unjudged.append({"container": name, "reason": "its nginx config is baked into the image, "
                             "not bind-mounted, so its routes and their auth could not be read"})
        elif unread:
            unjudged.append({"container": name, "reason": "mounted nginx config not readable: "
                             + ", ".join(map(str, unread))})
        else:
            missed = _unread_includes(c, text, [m.get("Source") for m in conf])
            if missed:
                unjudged.append({"container": name, "reason": "its nginx config includes "
                                 + ", ".join(missed) + ", which eyeline did not read (not "
                                 "mounted, or not a .conf file), so its routes could not be judged"})
            if bad:
                unjudged.append({"container": name, "reason": _bad_reason(bad)})
            if parsed and (c.get("network_mode") or "").startswith("container:"):
                unjudged.append({"container": name, "reason": "it shares the network of %s, so the "
                                 "host port its routes listen on could not be read"
                                 % c["network_mode"]})
        host_ports = {}
        for p in c.get("ports") or []:
            if p.get("proto") == "tcp" and not is_loopback(p.get("host_ip") or "0.0.0.0"):
                host_ports.setdefault(p.get("container_port"), p.get("host_port"))
        # On the host network the container's listen port is the host's. In another
        # container's namespace (`container:<id>`) the host port is not read: listen None.
        for e in parsed:
            e.update(listen=e["listen"] if c.get("network_mode") == "host"
                     else host_ports.get(e["listen"]), tool="nginx (container %s)" % name,
                     source="config mounted into the container", container=name,
                     project=c.get("project"), service=c.get("service"),
                     compose_files=c.get("compose_files") or [])
            entries.append(e)
        for r in nginx_roots(text) or [NGINX_DEFAULT_ROOT]:
            h = host_path(c, r)
            if h:
                roots.append((h, "nginx container %s (%s)" % (name, r)))
            elif conf:  # config read, but the web root lives in the image (no docker exec)
                unjudged.append({"container": name, "reason": "web root %s is inside the image, "
                                 "not bind-mounted, so its files could not be listed" % r})
    return entries, roots, unjudged


def _webroot_names(remote, roots, notes):
    """Fix 5 inside: secret-looking file NAMES in each served web root (never a value,
    never a file opened). -> [{root, served_by, names}]; names None = not readable."""
    out, seen = [], set()
    for root, by in roots:
        root = root.rstrip("/") or "/"
        if root in seen or not _safe_host_path(root):
            continue
        seen.add(root)
        txt = _run(remote, "webroot_names", root)
        if txt is None:
            notes.append("web root %s (%s): not readable; secret files there could not be judged"
                         % (root, by))
            out.append({"root": root, "served_by": by, "names": None})
            continue
        rows = [l for l in txt.splitlines() if l != "#--deeper--"]
        if len(rows) > 200:  # the on-box head printed a 201st line: the list was cut
            notes.append("web root %s (%s): more than 200 secret-looking names, list cut at 200; "
                         "secret files past the cut could not be judged" % (root, by))
            rows = rows[:200]
        if "#--deeper--" in txt.splitlines():
            notes.append("web root %s (%s): has folders more than 4 levels deep, which were not "
                         "listed; secret files there could not be judged" % (root, by))
        names = [l for l in rows if l.startswith(root.rstrip("/") + "/")
                 and l.rsplit("/", 1)[-1].lower() not in ENV_TEMPLATES
                 and any(fnmatch.fnmatchcase(l.rsplit("/", 1)[-1].lower(), n) for n in SECRET_NAMES)]
        out.append({"root": root, "served_by": by, "names": names})
    return out


def _box_addrs(remote):
    """[(ifname, ip_interface)] from `ip -o addr show`, for DNS self-match. Empty on
    read failure (DNS then matches nothing, which is the safe side)."""
    code, text = remote.run("addrs")
    if code != 0:
        return []
    out = []
    for line in text.splitlines():
        m = re.match(r"^\d+:\s+(\S+?)(?:@\S+)?\s+inet6?\s+(\S+)", line)
        if m:
            try:
                out.append((m.group(1), ipaddress.ip_interface(m.group(2))))
            except ValueError:
                pass
    return out


# --- zero-writes snapshots ---------------------------------------------------

def _parse_units(text):
    """`systemctl show -p Id -p InvocationID` blocks -> {unit: invocation_id}.
    None if no unit carries an InvocationID (old systemd: cannot check)."""
    if text is None:
        return None
    units = {}
    for block in re.split(r"\n\s*\n", text.strip()):
        kv = dict(l.split("=", 1) for l in block.splitlines() if "=" in l)
        if kv.get("Id"):
            units[kv["Id"]] = kv.get("InvocationID", "")
    return units if not units or any(units.values()) else None


def snapshot(remote):
    """Package-list hash, running services' InvocationIDs, running containers' StartedAt."""
    out = _run(remote, "snap_packages")
    h = (out or "").split()[:1]
    packages = h[0] if h and re.fullmatch(r"[0-9a-f]{64}", h[0]) and h[0] != EMPTY_SHA256 else None
    out = _run(remote, "snap_containers")
    containers = None if out is None else dict(
        l.split() for l in out.splitlines() if len(l.split()) == 2)
    return {"packages": packages, "services": _parse_units(_run(remote, "snap_services")),
            "containers": containers}


def _changes(b, a):
    same = [k for k in b if k in a]
    return (sorted(k for k in same if b[k] != a[k]), sorted(set(a) - set(b)), sorted(set(b) - set(a)))


def compare_snapshots(before, after):
    """None = not checked (a snapshot was unreadable), never 0. A user@N.service
    with a new InvocationID is the SSH login's own session manager starting again,
    so it is listed under new_units, not counted as a restart."""
    res = {"packages_changed": None, "services_restarted": None, "restarted_units": [],
           "new_units": [], "stopped_units": [], "containers_restarted": None,
           "new_containers": [], "stopped_containers": []}
    if before["packages"] is not None and after["packages"] is not None:
        res["packages_changed"] = int(before["packages"] != after["packages"])
    if before["services"] is not None and after["services"] is not None:
        restarted, new, stopped = _changes(before["services"], after["services"])
        login = [u for u in restarted if re.fullmatch(r"user@\d+\.service", u)]
        res["restarted_units"] = [u for u in restarted if u not in login]
        res["new_units"] = sorted(new + login)
        res["stopped_units"] = stopped
        res["services_restarted"] = len(res["restarted_units"])
    if before["containers"] is not None and after["containers"] is not None:
        restarted, res["new_containers"], res["stopped_containers"] = _changes(
            before["containers"], after["containers"])
        res["containers_restarted"] = len(restarted)
    return res
