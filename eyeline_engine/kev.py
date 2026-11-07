"""KEV-on-exposed-service: map a service that is reachable from the internet to a
CISA Known-Exploited-Vulnerabilities entry, socket -> package -> version -> KEV ->
fix-exists. Read-only: the version comes from the Docker image tag already read
over SSH (no banner grab, no request to the service).

Fail-closed is the whole point. Every step that cannot be read with certainty
yields "could not judge", never "no known vuln". A KEV id is shipped only when
BOTH the product matches a hand-verified KEV entry AND the running version falls
in that entry's hand-verified affected range (checked against NVD when the entry
was added here). No CVE id is invented and none is emitted from a guess.

The KEV catalog ships as a bundled snapshot (data/kev_snapshot.json), fetched and
verified from CISA's official feed. `load_catalog()` can refresh it over stdlib
urllib if asked, but the default path reads the bundled copy so the engine works
offline and never depends on a network call it cannot make.
"""
import json
import os
import re
import urllib.request

CISA_KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")
_SNAPSHOT = os.path.join(os.path.dirname(__file__), "data", "kev_snapshot.json")


def load_catalog(path=_SNAPSHOT, url=None, timeout=30):
    """-> (catalog_dict, source_str) or (None, reason). When `url` is given, fetch
    the live feed over https; otherwise read the bundled snapshot. A fetch or parse
    failure returns (None, reason) so the caller fails closed."""
    if url:
        if not url.startswith("https://"):
            return None, "KEV feed URL is not https"  # check BEFORE any fetch
        try:
            raw = urllib.request.urlopen(url, timeout=timeout).read()  # noqa: S310 (https only)
            cat = json.loads(raw)
            return cat, "CISA live feed %s (version %s)" % (url, cat.get("catalogVersion"))
        except Exception as e:  # network, TLS, JSON - all fail closed
            return None, "KEV feed unreachable: %s" % e
    try:
        with open(path, encoding="utf-8") as f:
            cat = json.loads(f.read())
    except (OSError, ValueError) as e:
        return None, "KEV snapshot unreadable: %s" % e
    if not isinstance(cat, dict) or not isinstance(cat.get("vulnerabilities"), list):
        return None, "KEV snapshot is not a catalog"
    return cat, "bundled CISA KEV snapshot (version %s)" % cat.get("catalogVersion")


def _ver_tuple(v):
    """A dotted version -> a tuple of ints for comparison. Non-numeric tails are
    dropped; returns None when no numeric version can be read (fail closed)."""
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums) if nums else None


def _in_range(version, lo, hi):
    """lo <= version <= hi, each a dotted string bound (inclusive). Fail closed:
    an unreadable version is not 'in range'."""
    vt, lot, hit = _ver_tuple(version), _ver_tuple(lo), _ver_tuple(hi)
    if vt is None or lot is None or hit is None:
        return False
    n = max(len(vt), len(lot), len(hit))
    vt, lot, hit = (t + (0,) * (n - len(t)) for t in (vt, lot, hit))
    return lot <= vt <= hit


# Hand-verified product -> KEV mappings. EACH entry was checked against the live
# CISA KEV feed (field values copied verbatim) and against NVD for the affected
# version range on the date noted. `image_re` matches the Docker image repository
# (not the tag); `affected(version)` decides whether the running tag is in range.
# A product with a KEV entry but NO safe way to bound the version by image tag is
# NOT listed here: that is reported "could not judge", never a bare CVE id.
#
# Sources (verified 2026-10-28 against https://www.cisa.gov/.../known_exploited_vulnerabilities.json
# version 2026.10.27, and NVD services.nvd.nist.gov):
#   CVE-2021-43798  Grafana Labs / Grafana / "Grafana Path Traversal Vulnerability"
#                   dateAdded 2025-10-09. NVD: the affected set is DISJOINT, not one span:
#                   8.0.1-8.0.6, 8.1.0-8.1.7, 8.2.0-8.2.6, the 8.0.0-betaN tags, and 8.3.0
#                   exact; fixed in 8.0.7 / 8.1.8 / 8.2.7 / 8.3.1. A single inclusive
#                   8.0.0..8.3.0 bound wrongly flagged the PATCHED tags (8.0.7, 8.1.8,
#                   8.2.7, 8.2.8, 8.2.9) and 8.0.0 GA as known-exploited -- a fabricated-
#                   applicability false positive (security review, 2026-10-28, checked
#                   against NVD). We now carry the three real sub-ranges + 8.3.0 exact. The
#                   8.0.0-betaN prerelease tags are deliberately NOT carried (our numeric
#                   version tuple cannot separate `8.0.0-beta1` from `8.0.0` GA, which is
#                   NOT affected; under-claiming a near-extinct beta tag is the safe
#                   direction for a credibility-critical false positive).
#   CVE-2021-39226  Grafana Labs / Grafana / "Grafana Authentication Bypass Vulnerability"
#                   dateAdded (KEV). NVD: snapshot panel auth bypass, fixed in 8.1.6 / 7.5.11;
#                   affected < 8.1.6 (and the 7.x line < 7.5.11). We bound 8.0.0 <= v <= 8.1.5
#                   for the 8.x line only, to stay strictly inside a verified range.
KEV_PRODUCTS = [
    {"image_re": re.compile(r"(^|/)grafana/grafana$|(^|/)grafana$"),
     "cve": "CVE-2021-43798",
     "ranges": [("8.0.1", "8.0.6"), ("8.1.0", "8.1.7"), ("8.2.0", "8.2.6"),
                ("8.3.0", "8.3.0")],
     "fix": "Upgrade Grafana to 8.3.1 or later (the first release with the path-traversal fix; "
            "8.2.7 / 8.1.8 / 8.0.7 also carry the backport). Pin the new tag in the compose "
            "file and recreate the container.",
     "source": "CISA KEV (added 2025-10-09); NVD affected 8.0.1-8.0.6, 8.1.0-8.1.7, "
               "8.2.0-8.2.6, 8.3.0"},
    {"image_re": re.compile(r"(^|/)grafana/grafana$|(^|/)grafana$"),
     "cve": "CVE-2021-39226", "ranges": [("8.0.0", "8.1.5")],
     "fix": "Upgrade Grafana to 8.1.6 or later (fixes the snapshot authentication bypass). "
            "Pin the new tag in the compose file and recreate the container.",
     "source": "CISA KEV; NVD affected < 8.1.6 (8.x line)"},
]


def _image_version(image):
    """A Docker image ref -> (repository, tag). `grafana/grafana:8.3.0` ->
    ('grafana/grafana', '8.3.0'); a digest-pinned or tagless ref -> tag None.
    A registry host with a port (`host:5000/img:tag`) is handled: only the LAST
    colon after the final slash is the tag separator."""
    if not image:
        return None, None
    ref = image.rsplit("@", 1)[0]  # drop any @sha256:... digest
    name, slash, rest = ref.rpartition("/")
    if ":" in rest:
        tag = rest.rsplit(":", 1)[1]
        repo = (name + slash + rest.rsplit(":", 1)[0]) if slash else rest.rsplit(":", 1)[0]
    else:
        tag, repo = None, ref
    return repo, tag


def match(image):
    """A Docker image ref -> a list of KEV hits for it. Each hit is
    {cve, version, fix, source}. Fail closed: when the image has a KEV product but
    the tag is unreadable (missing, 'latest', a digest, a non-numeric tag), returns
    [{unjudged: reason}] so the caller reports 'could not judge', never 'clean'."""
    repo, tag = _image_version(image)
    products = [p for p in KEV_PRODUCTS if p["image_re"].search(repo or "")]
    if not products:
        return []  # not a product we carry a verified KEV mapping for
    if not tag or _ver_tuple(tag) is None:
        return [{"unjudged": "image %r has a KEV-tracked product (%s) but its version could not be "
                 "read from the tag (%s); the running version decides whether a KEV applies, so this "
                 "is not clean" % (image, repo, tag or "no tag")}]
    hits = []
    for p in products:
        if any(_in_range(tag, lo, hi) for lo, hi in p["ranges"]):
            hits.append({"cve": p["cve"], "version": tag, "fix": p["fix"], "source": p["source"]})
    return hits


def check(published, exposed_ports, catalog_source):
    """published: parse_docker_inspect() output (each carries 'image' and 'host_port').
    exposed_ports: the set of host ports reachable from the internet in this run
    (GAP or open). catalog_source: the string load_catalog returned (for provenance).

    -> a list of rider results, one per published container whose port is exposed and
    whose image maps to a KEV product. kind: 'kev' (a confirmed KEV hit, -> a finding),
    or 'kev-unjudged' (a KEV product at an unreadable version, -> 'could not judge').
    Nothing is emitted for a service with no KEV-tracked product."""
    out = []
    seen = set()
    for c in published or []:
        port = c.get("host_port")
        if port not in exposed_ports:
            continue
        image = c.get("image")
        key = (c.get("container"), image, port)
        if key in seen:
            continue
        seen.add(key)
        for hit in match(image):
            if "unjudged" in hit:
                out.append({"kind": "kev-unjudged", "port": port, "image": image,
                            "container": c.get("container"), "reason": hit["unjudged"],
                            "source": catalog_source})
            else:
                out.append({"kind": "kev", "port": port, "image": image,
                            "container": c.get("container"), "cve": hit["cve"],
                            "version": hit["version"], "fix": hit["fix"],
                            "evidence_source": hit["source"], "catalog": catalog_source})
    return out
