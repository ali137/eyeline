"""IP-literal checks. eyeline probes only an IP the user supplies; it never
resolves a domain to find one, and never touches a Cloudflare address."""
import ipaddress

# Cloudflare's published ranges (https://www.cloudflare.com/ips-v4, /ips-v6).
# A Cloudflare IP is Cloudflare's host, not the user's, so it is never probed.
CLOUDFLARE_RANGES_FETCHED = "2026-10-27"
CLOUDFLARE_RANGES = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)]


class Refused(Exception):
    """A rule refused the request. The message says which rule and why."""


def is_cloudflare(ip):
    return any(ip.version == n.version and ip in n for n in CLOUDFLARE_RANGES)


# IPv6 forms that carry an IPv4 address inside them. Refused outright, so a v4
# address (a Cloudflare one, say) cannot be smuggled in as "IPv6".
_V6_EMBEDS_V4 = [ipaddress.ip_network(n) for n in (
    "::/96", "::ffff:0:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48")]


def parse_target_ip(text, version):
    """Return a single IP of the given version, or raise Refused."""
    if not isinstance(text, str):
        raise Refused("%r is not an IP address." % (text,))
    text = text.strip()
    if "/" in text:
        raise Refused("%r is a range. eyeline probes one IP you own, never a range." % text)
    if "%" in text:
        raise Refused("%r carries an IPv6 scope id; give the plain global address." % text)
    try:
        ip = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        raise Refused(
            "%r is not an IP address. eyeline probes only an IP you supply; it does not "
            "resolve or discover addresses from a domain." % text)
    if ip.version != version:
        raise Refused("%s is not an IPv%d address." % (ip, version))
    if ip.version == 6 and (ip.ipv4_mapped or ip.sixtofour or ip.teredo
                            or any(ip in n for n in _V6_EMBEDS_V4)):
        raise Refused("%s embeds an IPv4 address; give the IPv4 address as ipv4." % ip)
    if is_cloudflare(ip):
        raise Refused(
            "%s is a Cloudflare address (Cloudflare's host, not yours). eyeline never "
            "port-scans it. Supply your server's own IP." % ip)
    if (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local
            or ip.is_reserved):
        raise Refused("%s is a loopback/unspecified/multicast/link-local/reserved address, "
                      "not a server's address." % ip)
    return ip
