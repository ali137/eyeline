"""Same-host guard. Probing a box's own public IP from the box itself (or from a
container/VM on it) goes over loopback or a bridge, skips the firewall path, and
reads falsely clean. Every check here returns same_host True / False / None
("not checked"); the verdict is same-host if ANY check says True. A None check
never by itself proves "different machine"; it is listed in the notes.
"""
import ipaddress
import re
import socket
import subprocess

from .gate import parse_addrs

REFUSAL_TEXT = (
    "Outside probe refused: this machine is the target, or a container/VM running on "
    "it. Probing a box's own public IP from itself (or from a guest on it) travels over "
    "loopback or a local bridge, skips the firewall path the internet takes, and reads "
    "falsely clean (or falsely open). Run eyeline from a second machine, such as your "
    "laptop or another VPS.")

# Target interfaces whose subnet holds containers/VMs running ON the target.
BRIDGE_NAME = re.compile(r"^(docker|br-|lxdbr|virbr|cni|podman|veth|lxcbr|incusbr|vmnet)")
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
MACHINE_ID_PATHS = ("/etc/machine-id", "/var/lib/dbus/machine-id")


def _ip(x):
    """ipaddress object (v4-mapped v6 folded to v4). Bad input raises ValueError."""
    ip = x if isinstance(x, (ipaddress.IPv4Address, ipaddress.IPv6Address)) \
        else ipaddress.ip_address(str(x).strip("[]").split("%")[0])
    return ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip


def _check(name, same, detail):
    return {"check": name, "same_host": same, "detail": detail}


def parse_ifconfig(text):
    """`ifconfig -a` (macOS, BSD, Linux net-tools old and new) -> [(ifname, ip_interface)]."""
    out, name = [], None
    for line in text.splitlines():
        if line and not line[0].isspace():
            name = line.split()[0].rstrip(":")
            continue
        m = re.match(r"\s+inet6?\s+(?:addr:\s*)?(\S+)(.*)", line)
        if not (m and name):
            continue
        addr, rest = m.group(1).split("%")[0], m.group(2)
        if "/" not in addr:
            mask = re.search(r"(?:netmask|Mask:)\s*(\S+)", rest)
            plen = re.search(r"prefixlen\s+(\d+)", rest)
            if plen:
                addr += "/" + plen.group(1)
            elif mask and mask.group(1).lower().startswith("0x"):
                addr += "/%d" % bin(int(mask.group(1), 16)).count("1")
            elif mask:
                addr += "/" + mask.group(1)
        try:
            out.append((name, ipaddress.ip_interface(addr)))
        except ValueError:
            pass
    return out


def local_addrs():
    """[(ifname, ip_interface)] of THIS machine, or None if no tool could list them."""
    for argv, parse in ((["ip", "-o", "addr", "show"], parse_addrs),
                        (["ifconfig", "-a"], parse_ifconfig)):
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            continue
        addrs = parse(p.stdout) if p.returncode == 0 else []
        if addrs:
            return addrs
    return None


def udp_source(ip):
    """The source address the kernel picks to reach `ip`. A UDP connect() only
    selects a route; no packet is sent. None on any error (e.g. no route)."""
    ip = _ip(ip)
    try:
        s = socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return None
    try:
        s.connect((str(ip), 9))
        return _ip(s.getsockname()[0])
    except (OSError, ValueError):
        return None
    finally:
        s.close()


def read_machine_id(paths=MACHINE_ID_PATHS):
    for path in paths:
        try:
            with open(path) as f:
                value = f.read().strip()
        except OSError:
            continue
        if value:
            return value
    return ""


def _mid(value):
    """A usable machine-id (32 hex) or None. "uninitialized" or junk on both sides
    must not compare equal and fake a same-host match, nor a different one."""
    value = (value or "").strip().lower()
    return value if re.fullmatch(r"[0-9a-f]{32}", value) else None


def read_boot_id(path=BOOT_ID_PATH):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def _bid(value):
    """A usable boot_id (a UUID) or None."""
    value = (value or "").strip().lower()
    return value if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                                 value) else None


def local_checks(ip, addrs=local_addrs, source=udp_source):
    """Checks that need no ssh and send nothing to the target."""
    ip = _ip(ip)
    checks = []
    la = addrs()
    if la is None:
        # None: udp-source below still catches any address this kernel delivers locally.
        checks.append(_check("local-interface", None,
                             "not checked: could not list this machine's interfaces (ip/ifconfig)"))
    else:
        hit = [n for n, a in la if _ip(a.ip) == ip]
        checks.append(_check("local-interface", bool(hit),
                             "%s is on local interface %s" % (ip, hit[0]) if hit
                             else "%s is not on any local interface" % ip))
    src = source(ip)
    if src is None:
        # None: no route from here, so the probe cannot take a same-host shortcut either.
        checks.append(_check("udp-source", None, "not checked: no route from this machine to %s" % ip))
    else:
        src = _ip(src)
        checks.append(_check("udp-source", src == ip,
                             "the kernel would send to %s from %s%s" % (
                                 ip, src, " (itself: a local address)" if src == ip else "")))
    return checks


def _usable(ip):
    return not (ip.is_loopback or ip.is_link_local or ip.is_unspecified)


def remote_checks(ip, remote_addrs_text, remote_machine_id, local_addrs_list=None,
                  local_machine_id=None, source=udp_source, remote_boot_id=None, local_boot_id=None):
    """Checks that compare this machine with what ssh read on the target.
    Defaults read this machine's machine-id, interfaces and route source."""
    ip = _ip(ip)
    checks = []
    lm = _mid(read_machine_id() if local_machine_id is None else local_machine_id)
    rm = _mid(remote_machine_id)
    if lm is None or rm is None:
        # None: containers often have no machine-id; absence proves nothing either way.
        checks.append(_check("machine-id", None, "not checked: machine-id empty or unreadable on %s"
                             % " and ".join(s for s, v in (("this machine", lm), ("the target", rm))
                                            if v is None)))
    else:
        checks.append(_check("machine-id", lm == rm, "machine-id %s the target's"
                             % ("equals" if lm == rm else "differs from")))

    # Containers and network namespaces share the kernel, so they share its boot_id
    # even when machine-id is empty or differs (a host-network container on the target).
    lb = _bid(read_boot_id() if local_boot_id is None else local_boot_id)
    rb = _bid(remote_boot_id)
    if lb is None or rb is None:
        checks.append(_check("boot-id", None, "not checked: boot_id unreadable on %s"
                             % " and ".join(s for s, v in (("this machine", lb), ("the target", rb))
                                            if v is None)))
    else:
        checks.append(_check("boot-id", lb == rb, "this machine runs %s"
                             % ("the same kernel as the target (boot_id equal)" if lb == rb
                                else "a separate boot from the target (boot_id differs)")))

    la = local_addrs() if local_addrs_list is None else local_addrs_list
    # The route source is the address the probe would leave from; it is known even
    # in a minimal container that has neither `ip` nor `ifconfig`.
    src = source(ip)
    mine = {_ip(a.ip) for _, a in (la or [])} | ({_ip(src)} if src is not None else set())
    mine = {a for a in mine if _usable(a)}
    target = parse_addrs(remote_addrs_text or "")

    if not target:
        # Fail CLOSED: every Linux box lists at least lo, so an empty list means the
        # read failed, and this is the only check that sees a container/VM on the target.
        checks.append(_check("guest-of-target", True, "fail closed: the target's interface list "
                             "was unreadable, so this machine cannot be ruled out as its guest"))
    elif not mine:
        checks.append(_check("guest-of-target", None,
                             "not checked: no non-loopback address known for this machine"))
    else:
        # A twin of the target bridge's own address (172.17.0.1 on a laptop that also
        # runs Docker) is not a guest: a guest can never hold its host bridge's address.
        hits = ["%s in %s %s" % (a, n, i.network) for n, i in target
                if BRIDGE_NAME.match(n) and _usable(i.ip) for a in mine
                if a.version == i.version and a in i.network and a != i.ip]
        checks.append(_check("guest-of-target", bool(hits),
                             "this machine is a guest of the target: " + "; ".join(hits) if hits
                             else "no local address inside a target bridge subnet"))

    if not target or not mine:
        checks.append(_check("target-interface-same", None,
                             "not checked: interface list missing on one side"))
    else:
        shared = sorted(str(a) for a in mine & {_ip(i.ip) for _, i in target} if a.is_global)
        checks.append(_check("target-interface-same", bool(shared),
                             "global address on both machines: " + ", ".join(shared) if shared
                             else "no global address shared with the target"))
    return checks


def verdict(checks):
    """-> ("same-host", [reasons]) or ("different", [notes on unchecked checks]).
    Fails closed: a check whose same_host is not exactly False/None counts as
    same host, and an empty check list proves nothing."""
    if not checks:
        return "same-host", ["no vantage check ran; refusing rather than assume a different machine"]
    same = [c for c in checks if c.get("same_host", True) not in (False, None)]
    if same:
        return "same-host", ["%s: %s" % (c.get("check"), c.get("detail")) for c in same]
    return "different", ["%s: %s" % (c.get("check"), c.get("detail"))
                         for c in checks if c.get("same_host") is None]
