"""Alert channels, standard library only (ARCHITECTURE section 1: Python 3.9+,
stdlib only - a hard decision, 2026-10-27). section 8's "Apprise" mention is
resolved in favor of the stdlib-only runtime: email over smtplib/email and a
generic JSON webhook over urllib.request. The JSON webhook covers Slack, Discord,
Mattermost, and most services that accept a POSTed JSON body.

Redaction is ON and not optional: the alert body is built from watch's
redaction-safe signature (port, verdict, firewall word, port families, process
names - no IP, host, token, or env). The raw report never reaches a channel.
"""
import json
import smtplib
import ssl
import urllib.parse
import urllib.request
from email.message import EmailMessage

from .report import _clean


def render_alert(target_name, alerts):
    """A plain-text alert body from watch's decision. Only redaction-safe fields.
    `alerts` is decision["alerts"] from watch.classify."""
    lines = ["eyeline watch: new internet exposure on %s" % target_name, ""]
    for a in alerts:
        fam = ", ".join("%s %s" % (f, "/".join(s)) for f, s in sorted(a["families"].items())) or "-"
        procs = ", ".join(a["processes"]) or "unknown process"
        lines.append("  port %d - %s (%s)" % (a["port"], a["kind"], a["verdict"]))
        lines.append("      internet sees: %s;  firewall: %s;  listener: %s"
                     % (fam, a["firewall"], procs))
        if a.get("accepted_overridden"):
            lines.append("      NOTE: this port had an accepted-risk record, but its "
                         "evidence signature changed - re-alerting.")
    lines += ["", "Run `eyeline run %s` for the full, un-redacted local report." % target_name]
    return _clean("\n".join(lines))  # process names come from the target


def send_email(body, *, host, port, sender, to, subject, user=None, password=None,
               use_tls=True, timeout=30, _smtp=None):
    """Send over SMTP. No message content beyond the redacted body is added."""
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(to) if isinstance(to, (list, tuple)) else to
    msg["Subject"] = subject
    msg.set_content(body)
    smtp = _smtp or smtplib.SMTP(host, port, timeout=timeout)
    try:
        if use_tls:
            smtp.starttls(context=ssl.create_default_context())
        if user:
            smtp.login(user, password or "")
        smtp.send_message(msg)
    finally:
        smtp.quit()


def send_webhook(body, *, url, alerts=None, target_name=None, timeout=30,
                 allow_insecure=False, _opener=None):
    """POST a JSON body to a generic webhook. The payload carries the redacted
    text under both `text` and `content` so Slack and Discord both render it.

    HTTPS is required by default: the redacted body still names ports and
    verdicts, and must not travel in clear text. An `http://` URL is refused
    unless the channel sets `allow_insecure: true` (or the caller passes it) -
    an explicit, documented opt-in for a trusted local collector only."""
    scheme = (urllib.parse.urlparse(url).scheme or "").lower()
    if scheme != "https" and not (scheme == "http" and allow_insecure):
        raise ValueError("refused: webhook URL must be https:// (got %r). The alert body "
                         "names ports and verdicts; set allow_insecure: true on the channel "
                         "only for a trusted local http:// collector." % scheme)
    payload = {"text": body, "content": body}
    if target_name is not None:
        payload["target"] = target_name
    if alerts is not None:
        # redaction-safe structured copy (no IPs/host/token in a watch alert entry)
        payload["ports"] = [{"port": a["port"], "kind": a["kind"],
                             "verdict": a["verdict"], "firewall": a["firewall"],
                             "families": a["families"],
                             "processes": [_clean(p) for p in a["processes"]]}
                            for a in alerts]
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    opener = _opener or urllib.request.urlopen
    with opener(req, timeout=timeout) as resp:
        return getattr(resp, "status", None) or resp.getcode()


def deliver(target_name, alerts, channels):
    """Send one alert over each configured channel. `channels` is a list of
    {type: email|webhook, ...}. Returns per-channel results; a channel that
    raises is recorded, not fatal, so one bad channel never drops the others."""
    body = render_alert(target_name, alerts)
    results = []
    for ch in channels:
        kind = ch.get("type")
        try:
            if kind == "email":
                send_email(body, host=ch["host"], port=ch.get("port", 587),
                           sender=ch["from"], to=ch["to"],
                           subject="eyeline: new exposure on %s" % target_name,
                           user=ch.get("user"), password=ch.get("password"),
                           use_tls=ch.get("use_tls", True))
                results.append({"type": "email", "ok": True})
            elif kind == "webhook":
                status = send_webhook(body, url=ch["url"], alerts=alerts,
                                      target_name=target_name,
                                      allow_insecure=ch.get("allow_insecure", False))
                results.append({"type": "webhook", "ok": True, "status": status})
            else:
                results.append({"type": kind, "ok": False, "error": "unknown channel type"})
        except Exception as e:  # a channel failure must not crash the watch run
            results.append({"type": kind, "ok": False, "error": str(e)})
    return results
