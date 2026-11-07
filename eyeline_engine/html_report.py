"""Render a run report dict as a single self-contained HTML file, plus a small
shareable before/after card.

The view READS the report dict the engine produced; it never recomputes or
softens a verdict. A "could not judge" or a GAP reads as not-clean here exactly
as it does in the terminal (render_text). No external reference is emitted: no
http(s):// link, no //cdn, no webfont -- everything is inline, so the file opens
with nothing but a browser. The shareable card redacts IPs, hostnames, and file
paths to placeholders by default: it must never leak what it warns about.
"""
import datetime
import html

from .riders import FINDING_KINDS
from .run import exit_code, proven_all_clear, unjudged
import re

from .report import _internet_sees

# Verdict -> (glyph, display label, severity class). The glyph + the uppercase
# word carry the meaning; color is only a third, redundant channel, so the page
# survives grayscale (the accessibility rule). Ranked like diff.ORDER: GAP and
# "could not judge" are the two not-clean states and get the alarm/unresolved
# shapes; the rest share one calm grammar but keep distinct glyph+word.
_VERDICT = {
    "GAP":             ("▲", "GAP",            "v-gap"),      # filled triangle
    "could not judge": ("◇", "COULD NOT JUDGE", "v-unknown"),  # hollow diamond, dashed
    "intended":        ("●", "INTENDED",       "v-calm"),     # filled dot
    "blocked":         ("▬", "BLOCKED",        "v-calm"),     # bar
    "closed":          ("○", "CLOSED",         "v-calm"),     # hollow dot
    "not reached":     ("·", "NOT REACHED",    "v-muted"),    # mid dot
    "loopback only":   ("⟲", "LOOPBACK ONLY",  "v-calm"),     # loop
    "not probed":      ("–", "NOT PROBED",     "v-muted"),    # en dash, dashed
    # Rider findings are not per-port row verdicts; this badge is used only by the
    # finding block, never as a row verdict, so it does not affect row ordering.
    "finding":         ("▲", "FINDING",        "v-gap"),
}

# Verdicts that are NOT a clean result. Kept here only to decide presentation
# (which rows lead, whether an all-clear artifact may show); never to re-derive
# a verdict. A row's own rep["verdict"] is always what is displayed.
_NOT_CLEAN = ("GAP", "could not judge", "not probed")


def _e(text):
    """HTML-escape any value from the report (which may carry text read off the
    target). html.escape also neutralizes quotes, so nothing breaks an attribute
    or injects markup."""
    return html.escape("" if text is None else str(text))


def _badge(verdict):
    glyph, label, cls = _VERDICT.get(verdict, ("–", verdict.upper(), "v-muted"))
    return ('<span class="badge %s"><span class="g" aria-hidden="true">%s</span>%s</span>'
            % (cls, glyph, _e(label)))


def _date(stamp):
    """The run's UTC day, for the dateline and the all-clear artifact."""
    try:
        return datetime.datetime.fromisoformat(stamp).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return _e(stamp)


def _vantage_line(rep):
    v = rep.get("vantage") or {}
    if v.get("verdict") == "same-host":
        return "same host as the target - outside probe refused"
    return "a different machine from the target"


def _top3(rep):
    """The 'where do I start' answer: up to three fixes, GAPs first, then any
    'could not judge' row. Ranked by severity exactly as the rows are ordered; no
    verdict is recomputed. Each item links to its finding block when it has one."""
    gaps = [r for r in rep["rows"] if r["verdict"] == "GAP"]
    unknown = [r for r in rep["rows"] if r["verdict"] == "could not judge"]
    # GAP rows first, then any could-not-judge row, then the confirmed rider findings
    # (auth off, blast radius, KEV hit, origin reachable/leaked). kev-unjudged stays
    # out of the Top-3 action list (it is a could-not-judge, surfaced in its block).
    rider_fs = [f for f in rep.get("findings") or [] if f.get("kind") in FINDING_KINDS]
    ranked = ([("row", r) for r in gaps + unknown] + [("finding", f) for f in rider_fs])[:3]
    if not ranked:
        return ""
    # Map the first firewall-GAP finding per port (the ones without an explicit kind).
    find_by_port = {f["port"]: f for f in reversed(rep.get("findings") or []) if not f.get("kind")}
    items = []
    for i, (what, obj) in enumerate(ranked, 1):
        if what == "finding":
            port = obj["port"]
            problem = _e(obj["title"])
            action = "See the fix below."
            link = ' <a class="jump" href="#finding-%s-%d">full finding &rarr;</a>' % (
                _e(obj["kind"]), port)
            badge = _badge("finding")
            port_label = port if port else "-"
            items.append(
                '<li><span class="rank">%d</span><div class="t3body">'
                '<div class="t3problem">%s</div>'
                '<div class="t3action">&rarr; %s%s</div>'
                '<div class="t3badge">%s &middot; port %s</div>'
                '</div></li>' % (i, problem, action, link, badge, port_label))
            continue
        r = obj
        port = r["port"]
        f = find_by_port.get(port)
        if r["verdict"] == "GAP" and f:
            problem = _e(f["title"])
            action = "Close it: see the fix below."
        elif r["verdict"] == "GAP":
            problem = "Port %d is open to the internet although the firewall says deny." % port
            action = "Find what routes past the firewall; see the finding below."
        else:  # could not judge
            problem = ("Port %d is open from the internet and eyeline could not tell what the "
                       "firewall says about it (this is NOT a clean result)." % port)
            action = "Confirm this port is meant to be open, then verify the firewall by hand."
        link = (' <a class="jump" href="#finding-%s-%d">full finding &rarr;</a>'
                % (_finding_kind(f), port)) if f else ""
        items.append(
            '<li><span class="rank">%d</span><div class="t3body">'
            '<div class="t3problem">%s</div>'
            '<div class="t3action">&rarr; %s%s</div>'
            '<div class="t3badge">%s &middot; port %s</div>'
            '</div></li>' % (i, problem, action, link, _badge(r["verdict"]), port))
    return ('<section class="card"><h2>Start here</h2>'
            '<p class="section-note">The fixes that matter first, worst to least.</p>'
            '<ol class="top3">%s</ol></section>' % "".join(items))


def _internet_cell(r):
    """Per-family INTERNET SEES, reusing the engine's own text builder so the
    HTML and the terminal say exactly the same thing. A blank probe result reads
    as 'not probed', never as empty (empty would read as 'fine')."""
    if not r["internet"]:
        return '<span class="muted">not probed</span>'
    return _e(_internet_sees(r["internet"]))


def _table(rep):
    rows = rep["rows"]
    if not rows:
        return ""
    # Worst verdict first, so dangerous rows sit above the fold; the per-row
    # verdict itself is unchanged, only the display order.
    order = list(_VERDICT)
    ordered = sorted(rows, key=lambda r: order.index(r["verdict"]) if r["verdict"] in order else 99)
    body = []
    for r in ordered:
        fw = _e(r["firewall"])
        if r["firewall"] == "unknown" and r.get("firewall_reason"):
            fw = '%s<span class="fw-why"> (%s)</span>' % (fw, _e(r["firewall_reason"]))
        reason = ""
        if r["verdict"] == "not probed" and r.get("not_probed_reason"):
            reason = '<div class="row-reason">%s</div>' % _e(r["not_probed_reason"])
        body.append(
            '<tr><td class="c-port">%s</td><td class="c-listen">%s</td>'
            '<td class="c-fw">%s</td><td class="c-sees">%s</td>'
            '<td class="c-verdict">%s%s</td></tr>'
            % (r["port"], _e(r["listening"]), fw, _internet_cell(r), _badge(r["verdict"]), reason))
    return ('<section class="card"><h2>Exposure diff</h2>'
            '<p class="section-note">What the box listens on, what its firewall says, and what '
            'the internet actually reaches &mdash; one row per port.</p>'
            '<div class="tablewrap"><table class="diff"><thead><tr>'
            '<th>Port</th><th>Listening</th><th>Firewall says</th>'
            '<th>Internet sees</th><th>Verdict</th></tr></thead>'
            '<tbody>%s</tbody></table></div></section>' % "".join(body))


def _context_block(rep):
    ctx = [(r["port"], r["context"]) for r in rep["rows"] if r.get("context")]
    if not ctx:
        return ""
    items = []
    for port, lines in ctx:
        items.append('<div class="ctx-port"><span class="ctx-num">port %d</span><ul>%s</ul></div>'
                     % (port, "".join("<li>%s</li>" % _e(c) for c in lines)))
    return ('<section class="card"><h2>Exposure context</h2>'
            '<p class="section-note">What publishes each port. This does not change the verdict.</p>'
            '%s</section>' % "".join(items))


def _notes_block(rep):
    notes = (rep.get("inside") or {}).get("notes") or []
    if not notes:
        return ""
    return ('<section class="card"><h2>Notes from the server read</h2>'
            '<p class="section-note">What could not be read (nothing was guessed).</p>'
            '<ul class="notes">%s</ul></section>'
            % "".join("<li>%s</li>" % _e(n) for n in notes))


def _finding_block(f):
    port = f["port"]
    kind = _finding_kind(f)
    # Firewall-GAP findings keep the GAP badge; rider findings carry their own badge
    # (a confirmed rider exposure, or a could-not-judge for a KEV the catalog could
    # not clear). The anchor id includes the kind so two findings on one port are
    # distinct links.
    badge_verdict = {"docker": "GAP", "other": "GAP", "kev-unjudged": "could not judge",
                     "upstream-filter": "warning"}.get(kind, "finding")
    anchor = "finding-%s-%d" % (kind, port)
    parts = ['<section class="card finding" id="%s">' % _e(anchor)]
    parts.append('<div class="finding-head"><h3>%s</h3>%s</div>'
                 % (_e(f["title"]), _badge(badge_verdict)))
    parts.append('<div class="f-row"><span class="f-label">What</span>'
                 '<div class="f-val">%s</div></div>' % _e(f["cause"]))
    loc = f.get("location")
    if loc:
        parts.append(
            '<div class="f-row"><span class="f-label">Evidence</span><div class="f-val">'
            '<pre class="evidence">%s</pre>'
            '<div class="evidence-src">%s:%s</div></div></div>'
            % (_e(loc["text"].strip()), _e(loc["file"]), _e(loc["line"])))
    if f.get("fix"):
        parts.append('<div class="f-row"><span class="f-label">Fix</span>'
                     '<div class="f-val"><pre class="fix">%s</pre>'
                     '<div class="fix-note">Printed, not run. Nothing here changed the server.</div>'
                     '</div></div>' % _e(f["fix"]))
    if f.get("undo"):
        parts.append('<div class="f-row"><span class="f-label">Undo</span>'
                     '<div class="f-val"><pre class="fix undo">%s</pre></div></div>' % _e(f["undo"]))
    if f.get("lockout"):
        parts.append('<div class="f-row lockout"><span class="f-label">'
                     '<span aria-hidden="true">⚠</span> Warning</span>'
                     '<div class="f-val">%s</div></div>' % _e(f["lockout"]))
    why = _WHY.get(_finding_kind(f))
    if why:
        parts.append('<div class="f-row why"><span class="f-label">Why it matters</span>'
                     '<div class="f-val why-prose">%s</div></div>' % why)
    parts.append('</section>')
    return "".join(parts)


def _finding_kind(f):
    """Which hand-written 'why it matters' a finding gets. Rider findings carry an
    explicit `kind`; the firewall-GAP findings do not, so they resolve to 'docker'
    (a Docker-published port past the firewall) or the generic 'other'."""
    if f.get("kind"):
        return f["kind"]
    return "docker" if f.get("location") or "Docker publishes port" in f.get("title", "") else "other"


# Hand-written, per finding kind (the brief asks for a human sentence, not a
# generated one). Plain prose, set apart from the machine text.
_WHY = {
    "docker": ("A service you believed was private is answering the open internet. Anyone who finds "
               "the port can keep guessing its password for as long as they like &mdash; most "
               "databases and caches impose no lockout &mdash; and a weak or reused one falls. The "
               "firewall's deny is real; Docker simply forwards the traffic to the container before "
               "that rule ever sees it, so the deny was never doing what you thought."),
    "other": ("This port answers the internet even though the firewall is set to deny it. Something "
              "else &mdash; another rule, a forward, a second layer &mdash; is letting it through. "
              "Until you know what, you cannot trust that the firewall protects anything behind it."),
    "auth": ("A service with authentication off is open to anyone who can reach the port: from "
             "the internet, or from any machine on the LAN, including a compromised neighbor. This "
             "was read from the service's own configuration &mdash; eyeline never tried to log in &mdash; so the fix is to turn authentication on and, ideally, to "
             "stop publishing the port at all."),
    "blast": ("A reachable container that is also over-privileged turns a single service compromise "
              "into host compromise: privileged mode, a dangerous capability, a shared host namespace "
              "or a sensitive host mount all let an attacker who breaks the service reach the host "
              "itself. Reachable and powerful is the dangerous pair."),
    "kev": ("This service is reachable (see the label: internet or LAN) and runs a version "
            "listed in CISA's "
            "Known-Exploited-Vulnerabilities catalog &mdash; a vulnerability confirmed exploited in "
            "the wild, not a theoretical one. Upgrade to the fixed version."),
    "kev-unjudged": ("A service that CISA KEV tracks is exposed, but its exact version or the catalog "
                     "could not be read, so eyeline cannot say whether a known-exploited vulnerability "
                     "applies. This is NOT a clean result &mdash; confirm the version by hand."),
    "sshd-password": ("With password login on, anyone who reaches SSH can keep guessing; bots do this "
                      "to every reachable server all day. With keys only, a guessed password is worth "
                      "nothing. Make sure your key works before you switch passwords off."),
    "admin-route": ("An admin app behind a public hostname with no login in front leaves its own login "
                    "page as the only barrier, and admin apps are where known exploits and default "
                    "passwords land first. Restricting the route to your address removes it from "
                    "everyone else's reach."),
    "secret-file": ("A .env file, a .git directory or a database dump inside a web root is one "
                    "download away from everyone: these files typically hold database passwords and "
                    "API keys. eyeline listed names only; it never opened the file."),
    "upstream-filter": ("Something between the internet and this server filters the port, so the "
                        "outside view depends on that filter, not on the server. If you told eyeline "
                        "every port reaches this server (--all-ports), that statement is probably "
                        "wrong."),
    "cloudflare-b13": ("If this site is meant to sit behind Cloudflare, an origin that answers "
                       "directly lets an attacker skip Cloudflare entirely &mdash; its WAF, "
                       "rate-limiting and DDoS protection never see the request. Lock the origin to "
                       "Cloudflare's IPs or use a tunnel."),
    "cloudflare-b14": ("A public DNS record that resolves straight to your origin IP hands an attacker "
                       "the origin for free: they never have to unmask it. Proxy the record through "
                       "Cloudflare or stop publishing a name that points at the real origin."),
}


def _scope(rep):
    """(probed port count, IP families) -- what the all-clear and the card claim."""
    probed = {p for states in ((rep.get("probe") or {}).get("results") or {}).values() for p in states}
    families = sorted({"IPv6" if ":" in ip else "IPv4"
                       for r in rep["rows"] for ip in r["internet"]})
    return len(probed), " and ".join(families) if families else "the probed family"


def _all_clear(rep):
    """The positive, dated proven-all-clear artifact, shown only when the engine's
    exit is 0 AND nothing could not be judged. Never an empty page. The per-port table
    renders above it, so the claim is backed by visible per-port evidence."""
    probed, fam = _scope(rep)
    return ('<section class="card allclear"><div class="ac-mark" aria-hidden="true">✓</div>'
            '<h2>Proven all clear</h2>'
            '<p class="ac-lead">No internet-reachable service was found past the firewall.</p>'
            '<dl class="ac-fields">'
            '<dt>Vantage</dt><dd>%s</dd>'
            '<dt>Checked</dt><dd>%d port(s) over %s</dd>'
            '<dt>As of</dt><dd>%s</dd>'
            '</dl>'
            '<p class="ac-caveat">This proves what that vantage could reach at that time. It is '
            'not a permanent guarantee &mdash; re-run after any change to the server or its '
            'firewall.</p></section>'
            % (_vantage_line(rep), probed, fam, _date(rep.get("started"))))


def _unjudged_block(rep):
    """Every could-not-judge item of the run (run.unjudged, the list the text report
    and the card read). On an exit-0 run it says why this is not a proven all clear."""
    items = unjudged(rep)
    if not items:
        return ""
    if exit_code(rep) == 0:
        head = "Not a proven all clear"
        note = ("No confirmed exposure, but %d item(s) could not be judged. This is NOT a clean "
                "result." % len(items))
    else:
        head = "Could not judge"
        note = "%d item(s) could not be judged. None of them is a clean result." % len(items)
    return ('<section class="card unjudged"><h2>%s</h2><p class="section-note">%s</p>'
            '<ul class="notes">%s</ul></section>'
            % (head, note, "".join("<li>%s</li>" % _e(u) for u in items)))


def _readonly_block(rep):
    ro = rep.get("readonly") or {}

    def line(key, noun):
        v = ro.get(key)
        return "%s: %s" % (noun, "not checked" if v is None else v)
    items = [
        "files written by eyeline: 0 (every command it sent only reads)",
        line("packages_changed", "packages changed"),
        line("services_restarted", "services restarted"),
        line("containers_restarted", "containers restarted"),
    ]
    extra = []
    for key, label in (("restarted_units", "restarted"), ("stopped_units", "stopped since the start"),
                       ("new_containers", "containers new since the start"),
                       ("stopped_containers", "containers gone since the start"),
                       ("new_units", "units new since the start")):
        if ro.get(key):
            extra.append("%s: %s" % (label, ", ".join(ro[key])))
    body = "".join("<li>%s</li>" % _e(x) for x in items + extra)
    return ('<section class="card"><h2>Read-only guarantee</h2>'
            '<p class="section-note">Snapshots before and after this run. "not checked" means a '
            'snapshot could not run on this box (for example Alpine/OpenRC), shown honestly rather '
            'than as a zero.</p><ul class="ro">%s</ul></section>' % body)


def _not_done_block(rep):
    nd = rep.get("not_done") or []
    if not nd:
        return ""
    return ('<section class="card"><h2>What this does not do</h2>'
            '<ul class="notdone">%s</ul></section>'
            % "".join("<li>%s</li>" % _e(n) for n in nd))


def _grade_headline(rep):
    """Only shown if the engine put a grade in the dict (it does not today). The
    headline always carries mode + the not-judged count, so two grades are never
    read as equal; a non-zero not-judged count marks the grade incomplete."""
    g = rep.get("grade")
    if not g:
        return ""
    not_judged = sum(1 for r in rep["rows"] if r["verdict"] in ("could not judge", "not probed"))
    mode = _e(g.get("mode", "default"))
    if not_judged:
        return ('<div class="grade incomplete">Grade %s <span class="grade-ctx">&middot; %s mode '
                '&middot; <span class="grade-warn">%d port(s) NOT JUDGED</span></span></div>'
                % (_e(g.get("letter", "?")), mode, not_judged))
    return ('<div class="grade">Grade %s <span class="grade-ctx">&middot; %s mode &middot; all '
            'ports judged</span></div>' % (_e(g.get("letter", "?")), mode))


def render_html(rep):
    """The whole report as one self-contained HTML string."""
    same_host = (rep.get("vantage") or {}).get("verdict") == "same-host"
    # The all-clear reads the engine's own gate (run.proven_all_clear: exit 0 and no
    # could-not-judge item), never a re-derived one, so the view, the text report and
    # the card can never disagree.
    clean = not same_host and proven_all_clear(rep)

    body = ['<header class="report-head"><div class="brand">eyeline '
            '<span class="sub">run report</span></div>'
            '<div class="meta">%s &middot; vantage: %s &middot; %s</div>%s</header>'
            % (_e(rep["target"]), _vantage_line(rep), _date(rep.get("started")),
               _grade_headline(rep))]

    if same_host:
        body.append('<section class="card refused"><h2>Refused</h2><p>%s</p></section>'
                    % _e(rep.get("refused") or "This machine is the target; nothing was probed."))
    else:
        body.append(_top3(rep))
        body.append(_table(rep))
        body.append(_context_block(rep))
        body.append(_notes_block(rep))
        body.append(_unjudged_block(rep))
        if clean:
            body.append(_all_clear(rep))
        for f in rep.get("findings") or []:
            body.append(_finding_block(f))
        body.append(_readonly_block(rep))
    body.append(_not_done_block(rep))

    return _PAGE % {"title": _e("eyeline report: %s" % rep["target"]),
                    "css": _CSS, "body": "\n".join(b for b in body if b)}


# ---- the shareable card ---------------------------------------------------

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_HEXTOKEN = re.compile(r"\b[0-9a-fA-F]{24,}\b")


def _redact(text, host):
    """Replace anything that could identify the server or leak a secret with a
    placeholder: IPs (v4 and v6), the target's own name/ssh label, and long hex
    strings (tokens). The card never carries what it warns about."""
    if text is None:
        return ""
    s = str(text)
    s = _IPV6.sub("[address redacted]", s)
    s = _IPV4.sub("[address redacted]", s)
    s = _HEXTOKEN.sub("[redacted]", s)
    if host:
        s = re.sub(re.escape(str(host)), "[server]", s, flags=re.IGNORECASE)
    return s


def render_card(rep, redact=True):
    """A small before/after card for sharing. Redaction is ON by default: the
    headline counts gaps and findings, never names the host, the IP, or a path. The
    counts come straight from the rows and findings; nothing is recomputed."""
    gaps = sum(1 for r in rep["rows"] if r["verdict"] == "GAP")
    unknown = sum(1 for r in rep["rows"] if r["verdict"] == "could not judge")
    found = sum(1 for f in rep.get("findings") or [] if f.get("kind") in FINDING_KINDS)
    items = unjudged(rep)
    probed, fam = _scope(rep)

    def red(text):
        if not redact:
            return _e(text)
        return _e(_redact(text, None))  # label only; host/ip never placed in the card below anyway

    plus = " + %d finding%s" % (found, "" if found == 1 else "s") if found else ""
    if gaps:
        tone = "card-gap"
        big = "%d" % gaps
        big_label = "gap%s found%s" % ("" if gaps == 1 else "s", plus)
        line = ("A service is reachable past the firewall." if gaps == 1
                else "%d services are reachable past the firewall." % gaps)
    elif found:
        tone = "card-gap"
        big = "%d" % found
        big_label = "finding%s" % ("" if found == 1 else "s")
        line = "A confirmed exposure: see the full report for each fix."
    elif unknown:
        tone = "card-unknown"
        big = "%d" % unknown
        big_label = "port%s could not be judged" % ("" if unknown == 1 else "s")
        line = "Open from outside, firewall not readable. NOT a clean result."
    elif rep.get("refused") or not rep["proof"] or not all(r["proven"] for r in rep["proof"]):
        # The engine does not call this clean (exit 3), so the shareable card must not either.
        tone = "card-unknown"
        big = "–"
        big_label = "not judged"
        line = ("This run could not judge the server (%s). NOT a clean result."
                % ("refused: run on the target" if rep.get("refused") else "an IP not proven"))
    elif proven_all_clear(rep):
        tone = "card-clear"
        big = "✓"
        big_label = "proven all clear"
        line = "Nothing reachable past the firewall."
    elif items:
        tone = "card-unknown"
        big = "%d" % len(items)
        big_label = "item%s could not be judged" % ("" if len(items) == 1 else "s")
        line = ("No confirmed exposure, but %d item%s could not be judged - not a proven all "
                "clear. See the full report." % (len(items), "" if len(items) == 1 else "s"))
    else:
        tone = "card-unknown"
        big = "–"
        big_label = "not judged"
        line = "No port was read or probed. NOT a clean result."

    sub = "vantage: %s &middot; %d port(s) checked over %s &middot; %s" % (
        _vantage_line(rep), probed, fam, _date(rep.get("started")))
    inner = ('<div class="shcard %s"><div class="sh-brand">eyeline</div>'
             '<div class="sh-big">%s</div><div class="sh-biglabel">%s</div>'
             '<div class="sh-line">%s</div><div class="sh-sub">%s</div>'
             '<div class="sh-foot">read-only &middot; host redacted</div></div>'
             % (tone, big, big_label, red(line), sub))
    return _PAGE % {"title": "eyeline card", "css": _CSS + _CARD_CSS,
                    "body": '<div class="card-stage">%s</div>' % inner}


# ---- static shell + styles (all inline; no external reference) ------------

_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(title)s</title>
<style>
%(css)s
</style>
</head>
<body>
<main class="wrap">
%(body)s
</main>
</body>
</html>
"""

_CSS = """
:root{
  --bg:#fafafa; --surface:#ffffff; --text:#171717; --muted:#5c5c5c;
  --border:#ebebeb; --border-strong:#a1a1a1;
  --danger:#c50000; --danger-tint:#f7d4d6; --warn:#ab570a; --warn-tint:#ffefcf;
  --ok:#1e7a34; --link:#0070f3; --neutral:#5c5c5c;
  --mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
}
:root:not([data-theme="light"]) { }
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --bg:#010102; --surface:#0f1011; --text:#f7f8f8; --muted:#8a8f98;
    --border:#23252a; --border-strong:#34343a;
    --danger:#ff2047; --danger-tint:#2a0d12; --warn:#ffc53d; --warn-tint:#2a2008;
    --ok:#27a644; --link:#3b9eff; --neutral:#8a8f98;
  }
}
:root[data-theme="dark"]{
  --bg:#010102; --surface:#0f1011; --text:#f7f8f8; --muted:#8a8f98;
  --border:#23252a; --border-strong:#34343a;
  --danger:#ff2047; --danger-tint:#2a0d12; --warn:#ffc53d; --warn-tint:#2a2008;
  --ok:#27a644; --link:#3b9eff; --neutral:#8a8f98;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);
  font-size:16px;line-height:1.5;font-variant-numeric:tabular-nums;}
.wrap{max-width:960px;margin:0 auto;padding:24px 16px 96px;}
h2{font-size:20px;line-height:1.4;font-weight:600;margin:0 0 4px;}
h3{font-size:16px;line-height:1.4;font-weight:600;margin:0;}
.section-note{color:var(--muted);font-size:13px;margin:0 0 16px;}
a{color:var(--link);}
.report-head{padding:8px 0 24px;border-bottom:1px solid var(--border-strong);margin-bottom:24px;}
.brand{font-size:28px;font-weight:600;letter-spacing:-0.02em;}
.brand .sub{color:var(--muted);font-weight:400;font-size:18px;letter-spacing:0;}
.meta{color:var(--muted);font-size:13px;margin-top:8px;font-family:var(--mono);}
.grade{margin-top:12px;font-weight:600;font-size:18px;}
.grade-ctx{color:var(--muted);font-weight:400;font-size:14px;}
.grade.incomplete .grade-warn{color:var(--warn);font-weight:600;}
.grade.incomplete{border-bottom:2px dashed var(--warn);display:inline-block;padding-bottom:2px;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:20px;margin:0 0 16px;}
/* Top 3 */
.top3{list-style:none;margin:0;padding:0;}
.top3 li{display:flex;gap:16px;padding:16px 0;border-top:1px solid var(--border);}
.top3 li:first-child{border-top:none;}
.rank{flex:0 0 auto;width:28px;height:28px;border-radius:9999px;border:1.5px solid var(--border-strong);
  display:flex;align-items:center;justify-content:center;font-weight:600;font-size:14px;}
.t3body{min-width:0;}
.t3problem{font-weight:600;}
.t3action{color:var(--text);margin-top:4px;}
.t3badge{margin-top:8px;color:var(--muted);font-size:13px;}
.jump{font-size:13px;white-space:nowrap;}
/* table */
.tablewrap{overflow-x:auto;}
table.diff{border-collapse:collapse;width:100%;font-family:var(--mono);font-size:13px;}
table.diff th{text-align:left;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;
  font-size:11px;color:var(--muted);padding:8px 12px;border-bottom:1px solid var(--border-strong);}
table.diff td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top;}
table.diff tbody tr:nth-child(even){background:color-mix(in srgb,var(--text) 3%,transparent);}
.c-port{white-space:nowrap;font-weight:600;}
.c-verdict{white-space:nowrap;width:1%;}
.c-sees{white-space:nowrap;}
.fw-why{color:var(--muted);}
.row-reason{color:var(--muted);margin-top:4px;white-space:normal;}
.muted{color:var(--muted);}
/* badges: shape(glyph) + word + color; survives grayscale */
.badge{display:inline-flex;align-items:center;gap:6px;font-family:var(--sans);
  font-size:11px;font-weight:600;letter-spacing:0.05em;text-transform:uppercase;
  padding:3px 10px;border-radius:9999px;white-space:nowrap;border:1px solid var(--border-strong);}
.badge .g{font-size:11px;line-height:1;}
.v-gap{background:var(--danger);color:#fff;border-color:var(--danger);}
.v-unknown{border:1.5px dashed var(--warn);color:var(--warn);background:transparent;}
.v-calm{border:1px solid var(--border-strong);color:var(--text);background:transparent;}
.v-muted{border:1px dashed var(--border-strong);color:var(--muted);background:transparent;}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]) .v-gap{color:#0b0b0c;}}
:root[data-theme="dark"] .v-gap{color:#0b0b0c;}
/* context / notes / not-done */
.ctx-port{padding:8px 0;border-top:1px solid var(--border);}
.ctx-port:first-child{border-top:none;}
.ctx-num{font-family:var(--mono);font-weight:600;font-size:13px;}
.ctx-port ul,.notes,.ro,.notdone{margin:4px 0 0;padding-left:20px;}
.notes li,.ro li,.notdone li,.ctx-port li{margin:4px 0;}
.ro,.notdone{font-size:14px;}
/* findings */
.finding{border-color:var(--border-strong);}
.finding-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;
  padding-bottom:12px;margin-bottom:8px;border-bottom:1px solid var(--border);}
.f-row{display:flex;gap:16px;padding:10px 0;border-top:1px solid var(--border);}
.f-row:first-of-type{border-top:none;}
.f-label{flex:0 0 96px;color:var(--muted);font-size:12px;text-transform:uppercase;
  letter-spacing:0.05em;font-weight:600;padding-top:2px;}
.f-val{min-width:0;flex:1;}
pre.evidence,pre.fix{font-family:var(--mono);font-size:13px;line-height:1.5;margin:0;
  background:color-mix(in srgb,var(--text) 5%,transparent);border:1px solid var(--border);
  border-radius:6px;padding:10px 12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;}
.evidence-src{font-family:var(--mono);font-size:12px;color:var(--muted);margin-top:4px;}
.fix-note{font-size:12px;color:var(--muted);margin-top:4px;}
.lockout .f-label{color:var(--warn);}
.lockout .f-val{border-left:3px solid var(--warn);padding-left:12px;background:var(--warn-tint);
  border-radius:0 6px 6px 0;padding:10px 12px;}
.why-prose{font-family:var(--sans);line-height:1.6;}
/* all clear */
.allclear{border-color:var(--ok);}
.ac-mark{width:40px;height:40px;border-radius:9999px;background:var(--ok);color:#fff;
  display:flex;align-items:center;justify-content:center;font-size:24px;margin-bottom:12px;}
.ac-lead{font-size:16px;font-weight:600;margin:0 0 16px;}
.ac-fields{display:grid;grid-template-columns:auto 1fr;gap:4px 16px;margin:0 0 16px;font-size:14px;}
.ac-fields dt{color:var(--muted);}
.ac-fields dd{margin:0;}
.ac-caveat{color:var(--muted);font-size:13px;margin:0;}
.refused{border-color:var(--warn);}
.unjudged{border-color:var(--warn);}
"""

_CARD_CSS = """
.card-stage{display:flex;justify-content:center;padding:32px 0;}
.shcard{width:480px;max-width:100%;aspect-ratio:1.91/1;border-radius:16px;padding:32px;
  display:flex;flex-direction:column;border:1px solid var(--border-strong);background:var(--surface);}
.sh-brand{font-weight:600;font-size:18px;letter-spacing:-0.01em;}
.sh-big{font-size:72px;font-weight:700;line-height:1;margin-top:auto;}
.sh-biglabel{font-size:18px;font-weight:600;text-transform:uppercase;letter-spacing:0.04em;}
.sh-line{margin-top:12px;font-size:15px;}
.sh-sub{margin-top:auto;color:var(--muted);font-size:13px;font-family:var(--mono);}
.sh-foot{color:var(--muted);font-size:12px;margin-top:8px;}
.card-gap .sh-big{color:var(--danger);}
.card-unknown .sh-big{color:var(--warn);}
.card-clear .sh-big{color:var(--ok);}
"""


def write_html(rep, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(rep))
    return path


def write_card(rep, path, redact=True):
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_card(rep, redact=redact))
    return path
