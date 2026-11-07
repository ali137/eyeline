import json
import os
import shutil
import subprocess
import unittest

from eyeline_engine import inside, kev, remote, report, riders, run

HERE = os.path.dirname(os.path.abspath(__file__))
SNAPSHOT = os.path.join(HERE, "..", "eyeline_engine", "data", "kev_snapshot.json")


def pub(**kw):
    """A published-container dict in parse_docker_inspect's shape, with defaults."""
    base = {"host_ip": "0.0.0.0", "host_port": 5432, "proto": "tcp", "container": "c",
            "service": None, "project": None, "compose_files": [], "working_dir": None,
            "image": None, "cmd": None, "privileged": False, "cap_add": [], "security_opt": [],
            "pid_mode": "", "network_mode": "", "mounts": [], "auth_env": {}}
    base.update(kw)
    return base


# --- reachability -----------------------------------------------------------

class Reachable(unittest.TestCase):
    def test_gap_and_open_and_unjudged_are_reachable(self):
        rows = [{"port": 1, "verdict": "GAP", "internet": {}},
                {"port": 2, "verdict": "could not judge", "internet": {}},
                {"port": 3, "verdict": "intended", "internet": {"1.2.3.4": "open"}},
                {"port": 4, "verdict": "blocked", "internet": {"1.2.3.4": "closed"}},
                {"port": 5, "verdict": "loopback only", "internet": {}}]
        self.assertEqual(riders._reachable_ports(rows), {1, 2, 3})

    def test_not_reachable_is_not_included(self):
        rows = [{"port": 9, "verdict": "closed", "internet": {"1.2.3.4": "closed"}}]
        self.assertEqual(riders._reachable_ports(rows), set())


# --- auth from config (ZERO bytes to the service) ---------------------------

class AuthRedis(unittest.TestCase):
    def test_no_password_is_off(self):
        got = riders.auth_from_config([pub(host_port=6379, image="redis:7-alpine",
                                           cmd=["redis-server", "--protected-mode", "no"])], {6379})
        self.assertEqual(got[0]["state"], "off")

    def test_requirepass_is_on(self):
        got = riders.auth_from_config([pub(host_port=6379, image="redis:7-alpine",
                                           cmd=["redis-server", "--requirepass", "s3cret"])], {6379})
        self.assertEqual(got[0]["state"], "on")

    def test_redis_password_env_is_on(self):
        got = riders.auth_from_config([pub(host_port=6379, image="redis:7",
                                           auth_env={"REDIS_PASSWORD": None})], {6379})
        self.assertEqual(got[0]["state"], "on")

    def test_default_image_no_config_is_off(self):
        got = riders.auth_from_config([pub(host_port=6379, image="redis:7-alpine", cmd=None)], {6379})
        self.assertEqual(got[0]["state"], "off")

    # --- D2 (false "off" when auth could be in an unread config/secret/image) ---
    def test_config_file_in_cmd_is_unknown(self):
        # requirepass is normally set in exactly that config file, which eyeline does not read.
        got = riders.auth_from_config([pub(host_port=6379, image="redis:7",
                                           cmd=["redis-server", "/usr/local/etc/redis/redis.conf"])], {6379})
        self.assertEqual(got[0]["state"], "unknown")

    def test_non_official_image_is_unknown(self):
        got = riders.auth_from_config([pub(host_port=6379, image="bitnami/redis:7.2", cmd=None)], {6379})
        self.assertEqual(got[0]["state"], "unknown")

    def test_password_file_secret_is_unknown(self):
        got = riders.auth_from_config([pub(host_port=6379, image="redis:7", cmd=None,
                                           auth_env={"REDIS_PASSWORD_FILE": None})], {6379})
        self.assertEqual(got[0]["state"], "unknown")

    def test_canonical_official_image_names_are_still_judged_off(self):
        # security re-review (2026-10-28): the official-image check matched the RAW
        # repo, so the canonical / registry-prefixed spellings of the SAME official image
        # (docker.io/library/redis, library/redis, docker.io/redis -- emitted by compose,
        # Podman, registry mirrors) were judged "not official" -> "unknown", HIDING a real
        # no-auth exposure (exit 1->0) AND printing a false "this is not the official image"
        # claim. All canonical forms of the official library image must still read "off";
        # a genuine namespace (bitnami, a private registry) must stay non-official.
        for img in ("redis", "redis:7", "library/redis:7",
                    "docker.io/library/redis:7", "docker.io/redis:7"):
            got = riders.auth_from_config([pub(host_port=6379, image=img, cmd=None)], {6379})
            self.assertEqual(got[0]["state"], "off", "%s should be off (official, no auth)" % img)
        for img in ("bitnami/redis:7.2", "myregistry.io/team/redis:7"):
            got = riders.auth_from_config([pub(host_port=6379, image=img, cmd=None)], {6379})
            self.assertEqual(got[0]["state"], "unknown", "%s should be unknown (non-official)" % img)
        # Only Docker Hub carries the Official Library. An image on ANY other registry is
        # third-party/private whatever its path and must NOT be judged as the official bare
        # default -- both the `library/`-namespaced form AND the bare registry-root form
        # (quay.io/redis, a host:port private registry). Each was a false positive caught in
        # the security re-review rounds (2026-10-28): judging it official prints a false
        # "defaults to no auth" claim about an image whose defaults are unknown.
        for img in ("quay.io/library/redis", "ghcr.io/library/redis",
                    "quay.io/redis", "ghcr.io/redis", "192.168.1.5:5000/redis",
                    "localhost:5000/redis", "registry.gitlab.com/redis"):
            got = riders.auth_from_config([pub(host_port=6379, image=img, cmd=None)], {6379})
            self.assertEqual(got[0]["state"], "unknown", "%s must be non-official" % img)


class AuthPostgres(unittest.TestCase):
    def test_trust_is_off(self):
        got = riders.auth_from_config([pub(image="postgres:16",
                                           auth_env={"POSTGRES_HOST_AUTH_METHOD": "trust"})], {5432})
        self.assertEqual(got[0]["state"], "off")

    def test_password_is_on(self):
        got = riders.auth_from_config([pub(image="postgres:16-alpine",
                                           auth_env={"POSTGRES_PASSWORD": None})], {5432})
        self.assertEqual(got[0]["state"], "on")

    def test_neither_is_unknown_not_clean(self):
        got = riders.auth_from_config([pub(image="postgres:16", auth_env={})], {5432})
        self.assertEqual(got[0]["state"], "unknown")  # fail closed, never "on"


class AuthMongo(unittest.TestCase):
    def test_noauth_flag_is_off(self):
        got = riders.auth_from_config([pub(host_port=27017, image="mongo:7",
                                           cmd=["mongod", "--noauth"])], {27017})
        self.assertEqual(got[0]["state"], "off")

    def test_both_root_env_is_on(self):
        got = riders.auth_from_config([pub(host_port=27017, image="mongo:7",
                                           auth_env={"MONGO_INITDB_ROOT_USERNAME": "admin",
                                                     "MONGO_INITDB_ROOT_PASSWORD": None})], {27017})
        self.assertEqual(got[0]["state"], "on")

    def test_default_no_env_is_off(self):
        got = riders.auth_from_config([pub(host_port=27017, image="mongo:7", auth_env={})], {27017})
        self.assertEqual(got[0]["state"], "off")  # Mongo default: authorization disabled

    # --- D2 (false "off" when auth could be in an unread config/secret/image) ---
    def test_config_file_flag_is_unknown(self):
        # security.authorization lives in that config file, which eyeline does not read.
        for flag in ("--config", "-f"):
            got = riders.auth_from_config([pub(host_port=27017, image="mongo:7",
                                               cmd=["mongod", flag, "/etc/mongod.conf"])], {27017})
            self.assertEqual(got[0]["state"], "unknown", flag)

    def test_non_official_image_is_unknown(self):
        got = riders.auth_from_config([pub(host_port=27017, image="bitnami/mongodb:7.0", cmd=None)], {27017})
        self.assertEqual(got[0]["state"], "unknown")

    def test_root_password_file_secret_is_unknown(self):
        got = riders.auth_from_config([pub(host_port=27017, image="mongo:7", cmd=None,
                                           auth_env={"MONGO_INITDB_ROOT_PASSWORD_FILE": None})], {27017})
        self.assertEqual(got[0]["state"], "unknown")


class AuthGrafana(unittest.TestCase):
    def test_anonymous_enabled_is_off(self):
        got = riders.auth_from_config([pub(host_port=3000, image="grafana/grafana:10.0.0",
                                           auth_env={"GF_AUTH_ANONYMOUS_ENABLED": "true"})], {3000})
        self.assertEqual(got[0]["state"], "off")

    def test_not_enabled_is_unknown_not_on(self):
        # admin/admin and grafana.ini are not read, so we cannot clear it as "on".
        got = riders.auth_from_config([pub(host_port=3000, image="grafana/grafana:10.0.0",
                                           auth_env={})], {3000})
        self.assertEqual(got[0]["state"], "unknown")


class AuthTraefikPortainer(unittest.TestCase):
    def test_traefik_api_insecure_is_off(self):
        got = riders.auth_from_config([pub(host_port=8080, image="traefik:v3.0",
                                           cmd=["traefik", "--api.insecure=true"])], {8080})
        self.assertEqual(got[0]["state"], "off")

    def test_traefik_default_is_unknown(self):
        got = riders.auth_from_config([pub(host_port=8080, image="traefik:v3.0", cmd=["traefik"])], {8080})
        self.assertEqual(got[0]["state"], "unknown")

    def test_portainer_unknown_from_config(self):
        got = riders.auth_from_config([pub(host_port=9000, image="portainer/portainer-ce",
                                           cmd=[])], {9000})
        self.assertEqual(got[0]["state"], "unknown")

    def test_portainer_admin_password_is_on(self):
        got = riders.auth_from_config([pub(host_port=9000, image="portainer/portainer-ce",
                                           cmd=["--admin-password", "$2y$..."])], {9000})
        self.assertEqual(got[0]["state"], "on")


class AuthScope(unittest.TestCase):
    def test_only_reachable_ports_are_judged(self):
        # a redis with auth off but NOT reachable -> no finding at all
        got = riders.auth_from_config([pub(host_port=6379, image="redis:7", cmd=None)], set())
        self.assertEqual(got, [])

    def test_unknown_image_is_ignored(self):
        got = riders.auth_from_config([pub(host_port=80, image="nginx:alpine")], {80})
        self.assertEqual(got, [])

    def test_no_secret_value_is_ever_needed(self):
        # auth_env for password keys is presence-only (value None); state still decides.
        got = riders.auth_from_config([pub(image="postgres:16", auth_env={"POSTGRES_PASSWORD": None})], {5432})
        self.assertEqual(got[0]["state"], "on")


# --- blast radius -----------------------------------------------------------

class Blast(unittest.TestCase):
    def test_privileged_and_reachable(self):
        got = riders.blast_radius([pub(privileged=True)], {5432})
        self.assertEqual(len(got), 1)
        self.assertTrue(any("privileged" in r for r in got[0]["reasons"]))

    def test_privileged_but_not_reachable_is_not_a_finding(self):
        self.assertEqual(riders.blast_radius([pub(privileged=True)], set()), [])

    def test_dangerous_cap(self):
        got = riders.blast_radius([pub(cap_add=["CAP_SYS_ADMIN"])], {5432})
        self.assertTrue(any("SYS_ADMIN" in r for r in got[0]["reasons"]))

    def test_benign_cap_only_is_not_a_finding(self):
        self.assertEqual(riders.blast_radius([pub(cap_add=["CAP_CHOWN"])], {5432}), [])

    def test_docker_socket_mount(self):
        got = riders.blast_radius([pub(mounts=[{"Type": "bind", "Source": "/var/run/docker.sock",
                                                "Destination": "/var/run/docker.sock", "RW": True}])], {5432})
        self.assertTrue(any("Docker socket" in r for r in got[0]["reasons"]))

    def test_root_fs_rw_mount(self):
        got = riders.blast_radius([pub(mounts=[{"Type": "bind", "Source": "/", "Destination": "/host",
                                                "RW": True}])], {5432})
        self.assertTrue(any("read-write" in r for r in got[0]["reasons"]))

    def test_readonly_sensitive_mount_still_flagged(self):
        got = riders.blast_radius([pub(mounts=[{"Type": "bind", "Source": "/etc", "Destination": "/etc",
                                                "RW": False}])], {5432})
        self.assertTrue(any("read-only" in r for r in got[0]["reasons"]))

    def test_host_namespaces(self):
        got = riders.blast_radius([pub(pid_mode="host", network_mode="host")], {5432})
        self.assertTrue(any("PID" in r for r in got[0]["reasons"]))
        self.assertTrue(any("network" in r for r in got[0]["reasons"]))

    def test_plain_container_no_finding(self):
        self.assertEqual(riders.blast_radius([pub()], {5432}), [])


# --- KEV --------------------------------------------------------------------

class Kev(unittest.TestCase):
    def test_snapshot_loads(self):
        cat, src = kev.load_catalog(SNAPSHOT)
        self.assertIsNotNone(cat)
        self.assertIn("vulnerabilities", cat)
        self.assertIn("bundled CISA KEV snapshot", src)

    def test_unreadable_snapshot_fails_closed(self):
        cat, src = kev.load_catalog("/nonexistent/kev.json")
        self.assertIsNone(cat)
        self.assertIn("unreadable", src)

    def test_non_https_url_refused(self):
        cat, src = kev.load_catalog(url="http://example.com/kev.json")
        self.assertIsNone(cat)

    def test_grafana_in_range_matches(self):
        hits = kev.match("grafana/grafana:8.3.0")
        cves = {h.get("cve") for h in hits}
        self.assertIn("CVE-2021-43798", cves)

    def test_grafana_out_of_range_no_match(self):
        self.assertEqual(kev.match("grafana/grafana:9.5.0"), [])  # fixed version: no hit

    def test_patched_grafana_tags_are_not_flagged_for_43798(self):
        # security review (2026-10-28): the CVE-2021-43798 affected set is DISJOINT
        # (8.0.1-8.0.6, 8.1.0-8.1.7, 8.2.0-8.2.6, 8.3.0), not an inclusive 8.0.0..8.3.0
        # span. A single (lo,hi) bound falsely flagged PATCHED tags as known-exploited --
        # a fabricated-applicability false positive, corrosive to a tool whose whole value
        # is "no fabricated facts". These patched/unaffected tags must NOT carry 43798.
        for tag in ("8.0.7", "8.1.8", "8.2.7", "8.2.8", "8.2.9", "8.3.1"):
            cves = {h.get("cve") for h in kev.match("grafana/grafana:%s" % tag)}
            self.assertNotIn("CVE-2021-43798", cves,
                             "patched grafana %s wrongly flagged for CVE-2021-43798" % tag)
        # and the genuinely-affected tags MUST still carry it (the fix did not over-narrow):
        for tag in ("8.0.1", "8.0.6", "8.1.0", "8.1.7", "8.2.0", "8.2.6", "8.3.0"):
            cves = {h.get("cve") for h in kev.match("grafana/grafana:%s" % tag)}
            self.assertIn("CVE-2021-43798", cves,
                          "affected grafana %s no longer flagged for CVE-2021-43798" % tag)

    def test_grafana_latest_tag_is_unjudged_not_clean(self):
        hits = kev.match("grafana/grafana:latest")
        self.assertEqual(len(hits), 1)
        self.assertIn("unjudged", hits[0])  # could not read version -> fail closed

    def test_grafana_no_tag_is_unjudged(self):
        hits = kev.match("grafana/grafana")
        self.assertIn("unjudged", hits[0])

    def test_redis_alpine_is_not_mapped_to_debian_kev(self):
        # CVE-2022-0543 is Debian-specific; redis:7-alpine must NOT be mapped to it.
        self.assertEqual(kev.match("redis:7-alpine"), [])

    def test_postgres_has_no_kev_mapping(self):
        self.assertEqual(kev.match("postgres:16-alpine"), [])

    def test_check_only_exposed_ports(self):
        published = [pub(host_port=3000, image="grafana/grafana:8.3.0", container="graf")]
        cat, src = kev.load_catalog(SNAPSHOT)
        self.assertEqual(kev.check(published, set(), src), [])  # not exposed -> no result
        res = kev.check(published, {3000}, src)
        self.assertEqual(res[0]["kind"], "kev")
        self.assertEqual(res[0]["cve"], "CVE-2021-43798")

    def test_rider_kev_catalog_unreachable_fails_closed(self):
        published = [pub(host_port=3000, image="grafana/grafana:8.3.0", container="graf")]
        out, src = riders.kev(published, {3000}, url="http://bad.invalid/x.json")
        self.assertEqual(out[0]["kind"], "kev-unjudged")

    def test_shipped_cve_ids_are_in_the_real_feed(self):
        # every CVE id this engine can ship must exist in the bundled CISA KEV feed.
        cat, _ = kev.load_catalog(SNAPSHOT)
        feed_ids = {v["cveID"] for v in cat["vulnerabilities"]}
        for p in kev.KEV_PRODUCTS:
            self.assertIn(p["cve"], feed_ids, "%s not in the KEV feed" % p["cve"])


# --- Cloudflare B13 / B14 (no origin discovery) -----------------------------

class Cloudflare(unittest.TestCase):
    # A target the user STATED sits behind Cloudflare -> the checks apply.
    cf_target = {"name": "t", "ipv4": "203.0.113.9", "ipv6": None, "behind_cloudflare": True}
    # A normal target the user did NOT say is behind Cloudflare -> the checks do not apply.
    plain_target = {"name": "t", "ipv4": "203.0.113.9", "ipv6": None}

    # --- D1 (false positive on a box not behind Cloudflare): these must stop firing ---
    def test_b13_does_not_fire_without_the_flag(self):
        # a normal self-hosted box whose origin answers 443 directly is the INTENDED
        # setup, not a finding; without behind_cloudflare, B13 emits nothing.
        probe = {"203.0.113.9": {443: "open", 80: "open"}}
        out = riders.cloudflare(self.plain_target, [], probe, [])
        self.assertEqual(out["b13"], [])

    def test_b14_does_not_fire_without_the_flag(self):
        # a self-hosted zone's own A record pointing at its box is DNS working as
        # intended; without behind_cloudflare, B14 emits nothing.
        dns = [{"name": "origin.example.com", "type": "A", "value": "203.0.113.9",
                "zonefile": "/etc/bind/db.example.com"}]
        out = riders.cloudflare(self.plain_target, [], {}, dns)
        self.assertEqual(out["b14"], [])

    # --- the checks still fire for a target the user SAID is behind Cloudflare ---
    def test_b13_fires_when_behind_cloudflare_and_origin_answers(self):
        probe = {"203.0.113.9": {443: "open", 80: "closed"}}
        out = riders.cloudflare(self.cf_target, [], probe, [])
        self.assertEqual(len(out["b13"]), 1)
        self.assertEqual(out["b13"][0]["port"], 443)

    def test_b13_ignores_an_ip_not_in_scope(self):
        # defense in depth: a probe result for an IP the user did NOT supply is ignored
        probe = {"198.51.100.7": {443: "open"}}
        out = riders.cloudflare(self.cf_target, [], probe, [])
        self.assertEqual(out["b13"], [])

    def test_b13_closed_web_port_no_finding(self):
        probe = {"203.0.113.9": {443: "closed", 80: "filtered"}}
        out = riders.cloudflare(self.cf_target, [], probe, [])
        self.assertEqual(out["b13"], [])

    def test_b14_flags_own_dns_record_pointing_at_origin(self):
        dns = [{"name": "origin.example.com", "type": "A", "value": "203.0.113.9",
                "zonefile": "/etc/bind/db.example.com"}]
        out = riders.cloudflare(self.cf_target, [], {}, dns)
        self.assertEqual(len(out["b14"]), 1)
        self.assertEqual(out["b14"][0]["value"], "203.0.113.9")

    def test_b14_ignores_a_record_pointing_elsewhere(self):
        dns = [{"name": "x.example.com", "type": "A", "value": "8.8.8.8", "zonefile": "z"}]
        out = riders.cloudflare(self.cf_target, [], {}, dns)
        self.assertEqual(out["b14"], [])


# --- hostname-route auth coverage -------------------------------------------

class HostnameAuth(unittest.TestCase):
    def test_passes_through_auth_state(self):
        rp = [{"tool": "nginx", "server_name": "a.example.com", "listen": 443,
               "upstream": "1.2.3.4:3000", "auth": True},
              {"tool": "nginx", "server_name": "b.example.com", "listen": 443,
               "upstream": "1.2.3.4:3001", "auth": False},
              {"tool": "traefik", "server_name": None, "listen": None,
               "upstream": "1.2.3.4:3002", "auth": None}]
        got = riders.hostname_auth(rp)
        self.assertEqual({(e["server_name"], e["auth"]) for e in got},
                         {("a.example.com", True), ("b.example.com", False), (None, None)})

    def test_empty(self):
        self.assertEqual(riders.hostname_auth(None), [])


# --- findings assembly ------------------------------------------------------

class Findings(unittest.TestCase):
    def test_auth_off_becomes_a_finding_on_unknown_does_not(self):
        r = {"auth": [{"service": "Redis", "container": "c", "port": 6379, "image": "redis:7",
                       "state": "off", "reason": "no password"},
                      {"service": "PostgreSQL", "container": "d", "port": 5432, "image": "postgres:16",
                       "state": "unknown", "reason": "pg_hba not read"}]}
        fs = riders.findings_from_riders(r)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["kind"], "auth")
        self.assertEqual(fs[0]["port"], 6379)

    def test_kev_unjudged_is_a_finding_marked_could_not_judge(self):
        r = {"kev": [{"kind": "kev-unjudged", "port": 3000, "image": "grafana/grafana:latest",
                      "container": "g", "reason": "version unreadable", "source": "snap"}]}
        fs = riders.findings_from_riders(r)
        self.assertEqual(fs[0]["kind"], "kev-unjudged")
        self.assertIsNone(fs[0]["fix"])

    def test_b14_finding_has_port_zero(self):
        r = {"cloudflare": {"b13": [], "b14": [{"name": "o.example.com", "type": "A",
             "value": "203.0.113.9", "zonefile": "z", "detail": "leak", "fix": "proxy it"}]}}
        fs = riders.findings_from_riders(r)
        self.assertEqual(fs[0]["kind"], "cloudflare-b14")
        self.assertEqual(fs[0]["port"], 0)


@unittest.skipUnless(shutil.which("sed"), "needs sed")
class CmdSecretRedactionOnBox(unittest.TestCase):
    """Phase-16 head-to-head found `redis-server --requirepass X` stored verbatim in the
    JSON report (docker inspect sent Config.Cmd off the box). A first deny-list fix
    still leaked `--masterauth`, `sh -c "..."`, URL passwords, `PGPASSWORD=X` (phase-16
    [cyber] review). Cmd now leaves the box only through the CMD_ALLOW_SED allow-list;
    these run that exact expression (GNU sed, and busybox sed when present)."""

    SEDS = ["sed"] + (["busybox sed"] if shutil.which("busybox") else [])

    def _redact(self, cmd, sed="sed"):
        # docker inspect -f ends the template output with a blank line
        inp = "".join(json.dumps(t) + "\n" for t in cmd) + '\n"#END"\n'
        out = subprocess.run(["sh", "-c", sed + " -E " + remote.CMD_ALLOW_SED], input=inp,
                             capture_output=True, text=True, check=True).stdout
        toks = [json.loads(l) for l in out.splitlines()]
        self.assertEqual(toks[-1], "#END")
        return toks[:-1]

    def test_docker_read_sends_cmd_only_through_the_allow_list(self):
        d = remote.READ_ONLY["docker"]
        self.assertNotIn(".Config.Cmd}}}", d)  # Cmd is not in the inspect JSON
        self.assertIn("\" && echo '\"#END\"'; } | LC_ALL=C sed -E " + remote.CMD_ALLOW_SED + " | sed ", d)
        self.assertEqual(d.count(".Config.Cmd"), 1)

    def test_no_credential_shape_survives(self):
        leaks = [["redis-server", "--requirepass", "S9"], ["redis-server", "--masterauth", "S9"],
                 ["x", "--auth", "S9"], ["sh", "-c", "redis-server --requirepass S9"],
                 ["app", "--db-url", "postgres://u:S9@h/db"], ["x", "-u", "user:S9"],
                 ["env", "PGPASSWORD=S9", "app"], ["x", "-p", "S9"], ["x", "-pS9"],
                 ["x", "--requirepass=S9"], ["x", "p\\q\"S9"], ["x", "caf\u00e9S9"], ["x", "a\nS9"]]
        for sed in self.SEDS:
            for cmd in leaks:
                out = self._redact(cmd, sed)
                self.assertFalse(any("S9" in t for t in out), (sed, cmd, out))
                self.assertEqual(len(out), len(cmd))
        self.assertEqual(self._redact(["sh", "-c", "a b"]), ["REDACTED", "-c", "REDACTED-SHELL"])
        self.assertEqual(self._redact(["x", "--requirepass=S9"]), ["REDACTED", "--requirepass=REDACTED"])

    def test_what_the_riders_read_survives(self):
        for cmd in (["mongod", "--noauth", "--bind_ip_all"], ["mongod", "--keyFile", "/etc/k"],
                    ["traefik", "--api.insecure=true"], ["redis-server", "--protected-mode", "no"],
                    ["redis-server", "/usr/local/etc/redis/redis.conf"], ["redis-server", "--requirepass", ""],
                    ["mongod", "--config=/etc/mongod.conf"]):
            self.assertEqual(self._redact(cmd), cmd)
        red = self._redact(["redis-server", "--requirepass", "zzz"])
        self.assertEqual(riders._auth_redis({"cmd": red, "image": "redis:7-alpine"})[0], "on")

    def _parsed(self, trailer):
        body = json.dumps({"Id": "abc123", "Name": "/r", "Config": {"Image": "redis:7-alpine"},
                           "NetworkSettings": {"Ports": {"6379/tcp": [{"HostIp": "0.0.0.0",
                                                                       "HostPort": "6379"}]}}})
        return inside.parse_docker_inspect(body + "\n#--auth_env--\n#--cmd--\n" + trailer)[0]

    def test_trailer_round_trip_and_fail_closed(self):
        c = self._parsed('#cmd abc123 "redis-server"\n#cmd abc123 "--protected-mode"\n'
                         '#cmd abc123 "no"\n#cmd abc123 "#END"\n')
        self.assertEqual(c["cmd"], ["redis-server", "--protected-mode", "no"])
        self.assertEqual(riders._auth_redis(c)[0], "off")
        # sed failed: no #END -> unread -> could not judge, never "off"
        c = self._parsed('#cmd abc123 "redis-server"\n')
        self.assertTrue(c["cmd_unread"])
        self.assertEqual(riders._auth_redis(c)[0], "unknown")
        self.assertEqual(riders._auth_mongo(dict(c, image="mongo:7"))[0], "unknown")
        # a shell command line may hide --requirepass -> could not judge
        c = self._parsed('#cmd abc123 "REDACTED"\n#cmd abc123 "-c"\n'
                         '#cmd abc123 "REDACTED-SHELL"\n#cmd abc123 "#END"\n')
        self.assertEqual(riders._auth_redis(c)[0], "unknown")

    def test_withheld_bare_token_is_never_judged_off(self):
        # `./redis.conf` (relative) and a tab-split shell line arrive as bare REDACTED
        for cmd in (["redis-server", "REDACTED"], ["REDACTED", "-c", "REDACTED"]):
            self.assertEqual(riders._auth_redis({"cmd": cmd, "image": "redis:7"})[0], "unknown")
            self.assertEqual(riders._auth_mongo({"cmd": cmd, "image": "mongo:7"})[0], "unknown")
        # a flag's value withheld is fine: still judged
        self.assertEqual(riders._auth_redis({"cmd": ["redis-server", "--protected-mode", "no",
                                                     "--save", "REDACTED"],
                                             "image": "redis:7"})[0], "off")

    def test_empty_requirepass_is_no_password(self):
        for cmd in (["redis-server", "--requirepass", ""], ["redis-server", "--requirepass="]):
            self.assertEqual(riders._auth_redis({"cmd": cmd, "image": "redis:7-alpine"})[0], "off")


# --- host-network containers (Docker records no port binding for them) -----

def hostnet(**kw):
    """A container as docker_containers() returns it, on the host network."""
    return dict(pub(container="cache", image="redis:7", cmd=["redis-server"], privileged=True,
                    network_mode="host", mounts=[{"Type": "bind", "Source": "/var/run/docker.sock",
                                                  "Destination": "/var/run/docker.sock", "RW": True}]),
                **kw)


def hostnet_riders(containers, listeners):
    rows = [{"port": 6379, "verdict": "intended", "internet": {"203.0.113.9": "open"},
             "firewall": "allow", "published": []}]
    ins = {"published": [], "containers": containers, "listeners": listeners}
    return run.run_riders({"rows": rows}, ins, {}, {"name": "lab"})


REDIS_LISTENER = [{"addr": "0.0.0.0", "port": 6379, "process": "redis-server"}]


class HostNetwork(unittest.TestCase):
    def test_host_network_redis_reaches_auth_and_blast(self):
        # r6: --network host --privileged redis:7, no password, docker.sock mounted.
        rid = hostnet_riders([hostnet()], REDIS_LISTENER)
        self.assertEqual([(a["port"], a["state"]) for a in rid["auth"]], [(6379, "off")])
        self.assertTrue(any("--network=host" in r for r in rid["blast"][0]["reasons"]))
        self.assertEqual(sorted((f["kind"], f["port"]) for f in riders.findings_from_riders(rid)),
                         [("auth", 6379), ("blast", 6379)])
        self.assertEqual(rid["host_network_unjudged"], [])

    def test_host_network_kev_hit(self):
        rid = hostnet_riders([hostnet(image="grafana/grafana:8.3.0", cmd=None)],
                             [{"addr": "0.0.0.0", "port": 6379, "process": "grafana-server"}])
        self.assertIn("CVE-2021-43798", [k.get("cve") for k in rid["kev"]])

    def test_unreadable_process_names_is_could_not_judge(self):
        rid = hostnet_riders([hostnet()], [{"addr": "0.0.0.0", "port": 6379, "process": None}])
        self.assertEqual((rid["auth"], rid["blast"]), ([], []))
        self.assertEqual(len(rid["host_network_unjudged"]), 1)
        self.assertIn("process names could not be read", rid["host_network_unjudged"][0])
        self.assertTrue(any("host-network container could not judge: container cache" in l
                            for l in report._riders_text(rid)))

    def test_no_listener_runs_as_its_program_is_could_not_judge(self):
        rid = hostnet_riders([hostnet(image="example/app:1", cmd=None)],
                             [{"addr": "0.0.0.0", "port": 6379, "process": "redis-server"}])
        self.assertEqual(rid["blast"], [])
        self.assertIn("no host listener runs as its program", rid["host_network_unjudged"][0])

    def test_two_containers_same_program_is_could_not_judge(self):
        rid = hostnet_riders([hostnet(), hostnet(container="cache2")],
                             REDIS_LISTENER + [{"addr": "0.0.0.0", "port": 6380, "process": "redis-server"}])
        self.assertEqual((rid["auth"], rid["blast"]), ([], []))
        self.assertEqual(len(rid["host_network_unjudged"]), 2)

    def test_bridge_container_is_not_matched_by_process_name(self):
        rid = hostnet_riders([hostnet(network_mode="bridge")], REDIS_LISTENER)
        self.assertEqual((rid["auth"], rid["host_network_unjudged"]), ([], []))


if __name__ == "__main__":
    unittest.main()
