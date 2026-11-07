"""Review tier E (2026-10-29, round 3): host Caddy/Traefik config that eyeline read but
whose routes it did not follow is could-not-judge, never the fact "reverse proxy: none
read" (which lets a run read proven all clear and recheck read an admin route FIXED).
Caddy `reverse_proxy` upstreams in a block's `to` lines are read; a placeholder, unix
socket or missing upstream is a problem. Traefik files are judged per `# file` by one
structural rule: config in a file that gave no route is a problem unless the file
cannot publish one itself. Same-file Caddy snippet imports are followed."""
import json
import unittest
from unittest import mock

from eyeline_engine import inside, recheck, report, riders, scope
from tests.test_recheck import ADMIN, GRAF, admin_inside, rep, run_cli
from tests.test_shipped_reads import HOST_NOTE, gate, host_notes
from eyeline_engine import run

NONE_READ = "reverse proxy: none read"
GRAF_PUB = dict(GRAF, ports=[{"host_ip": "127.0.0.1", "host_port": 3000, "container_port": 3000,
                              "proto": "tcp"}])


def caddy(text):
    return "#--nginx--\n#--caddyfile--\n# file /etc/caddy/Caddyfile\n%s#--traefik--\n" % text


def traefik(*files):
    return "#--nginx--\n#--caddyfile--\n#--traefik--\n" + "".join("# file %s\n%s" % f for f in files)


def site(body, name="admin.example"):
    return "%s {\n%s}\n" % (name, body)


class Flags(unittest.TestCase):
    def assertFlagged(self, text):
        notes = host_notes(text)
        self.assertTrue(any(n.startswith(HOST_NOTE) for n in notes), text)
        self.assertFalse(any(n.startswith(NONE_READ) for n in notes), text)
        self.assertFalse(run.proven_all_clear(gate([n for n in notes if n.startswith(HOST_NOTE)])))
        self.assertEqual(run.exit_code(gate(notes)), 0)          # note 6: exit unchanged

    def assertNotFlagged(self, text):
        notes = host_notes(text)
        self.assertFalse(any(n.startswith(HOST_NOTE) for n in notes), (text, notes))

    def recheck(self, text, port=443):
        """The prior no-auth Grafana route on admin.example:`port`, re-read from `text`."""
        ins = inside.read(_remote(text))
        new = rep([(port, "intended")], inside=admin_inside(ins["revproxy"], (GRAF_PUB,), ins["notes"]))
        prior = rep([(port, "intended")], [dict(ADMIN, port=port)])
        return recheck.compare(prior, new)["findings"], run_cli(prior, new)[0]


def _remote(text):
    from tests.test_coverage_175 import Remote
    return Remote({"revproxy": (0, text)})


# --- finding 1: Caddy reverse_proxy with no inline upstream (f2 G1, G2, G4) --------

class CaddyUpstreamForms(Flags):
    def got(self, text):
        return [(e["listen"], e["server_name"], e["upstream"], e["auth"])
                for e in inside._parse_caddyfile(text)]

    def test_block_form_to_upstreams_are_read(self):
        self.assertEqual(self.got(site("  reverse_proxy {\n    to 127.0.0.1:3000\n  }\n")),
                         [(443, "admin.example", "127.0.0.1:3000", False)])               # f2 G1
        self.assertEqual(self.got(site("  basic_auth {\n    u hash\n  }\n  reverse_proxy /api/* {\n"
                                       "    to 127.0.0.1:3000 127.0.0.1:3001\n    lb_policy first\n  }\n")),
                         [(443, "admin.example", "127.0.0.1:3000", True),
                          (443, "admin.example", "127.0.0.1:3001", True)])
        # A file with an inline route keeps reading the block-form one too.
        self.assertEqual(self.got(site("  reverse_proxy 127.0.0.1:8080\n") +
                                  site("  reverse_proxy {\n    to 127.0.0.1:3000\n  }\n", "g.example")),
                         [(443, "admin.example", "127.0.0.1:8080", False),
                          (443, "g.example", "127.0.0.1:3000", False)])

    def test_inline_matcher_and_scheme_are_not_the_upstream(self):
        self.assertEqual(self.got(site("  reverse_proxy /api/* http://127.0.0.1:3000\n")),
                         [(443, "admin.example", "127.0.0.1:3000", False)])
        self.assertEqual(self.got(site("  reverse_proxy @adm https://grafana.internal\n")),
                         [(443, "admin.example", "grafana.internal:443", False)])

    def test_unread_upstream_is_could_not_judge(self):
        for body in ("  reverse_proxy {$GRAFANA_UP}\n",                                    # f2 G2
                     "  reverse_proxy {env.UP}\n",
                     "  reverse_proxy http://{$HOST}:3000\n",
                     "  reverse_proxy\n",
                     "  reverse_proxy {\n    to {$GRAFANA_UP}\n  }\n",
                     "  reverse_proxy {\n    dynamic srv grafana.internal\n  }\n",
                     "  reverse_proxy unix//run/grafana.sock\n"):
            self.assertFlagged(caddy(site(body)))
            # Another inline route in the same file does not hide it.
            self.assertFlagged(caddy(site("  reverse_proxy 127.0.0.1:8080\n", "w.example") + site(body)))

    def test_block_form_route_is_not_fixed(self):
        # f2 G4: the route moved to block form, still no auth -> still open, recheck exits 1.
        res, code = self.recheck(caddy(site("  reverse_proxy {\n    to 127.0.0.1:3000\n  }\n")))
        self.assertEqual(res["fixed"], [])
        self.assertEqual(code, 1)
        res, code = self.recheck(caddy(site("  reverse_proxy {$GRAFANA_UP}\n")))
        self.assertEqual(res["fixed"], [])
        self.assertIn("reverse proxy could not be judged", res["still_open"][0]["now"])
        self.assertEqual(code, 1)


# --- findings 2+3: one structural rule per Traefik `# file` (f1, f3) --------------

STATIC_Y = "entryPoints:\n  websecure:\n    address: ':443'\n"
ROUTE_Y = ("http:\n  services:\n    g:\n      loadBalancer:\n        servers:\n"
           "          - url: http://127.0.0.1:3000\n")


class TraefikStructuralRule(Flags):
    def test_unfollowed_traefik_config_is_could_not_judge(self):
        for text in (
                traefik(("/etc/traefik/traefik.yml", STATIC_Y + "providers:\n  file:\n"             # f1 A
                         "    directory: /etc/traefik/dynamic\n")),
                traefik(("/etc/traefik/traefik.yml", STATIC_Y + "providers:\n  file:\n"             # f1 B
                         "    directory: /etc/traefik/conf.d\n\n  docker:\n    exposedByDefault: false\n"),
                        ("/etc/traefik/conf.d/g.yml", ROUTE_Y)),
                traefik(("/etc/traefik/traefik.yml", STATIC_Y + "providers:  # where routes come from\n"  # C
                         "  docker:\n    exposedByDefault: false\n")),
                traefik(("/etc/traefik/traefik.toml", "[entryPoints]\n  [entryPoints.websecure]\n"     # f1 D
                         "    address = \":443\"\n[providers]\n  [providers.docker]\n"
                         "    exposedByDefault = false\n")),
                traefik(("/etc/traefik/traefik.yml", STATIC_Y +                                     # f1 H
                         "providers: {docker: {exposedByDefault: false}}\n")),
                traefik(("/etc/traefik/traefik.yml", "providers:\n    # docker below\n"           # f3
                         "  docker: {}\n")),
                traefik(("/etc/traefik/traefik.toml", "providers.docker.exposedByDefault = false\n")),
                traefik(("/etc/traefik/traefik.yml", "x: &p\n  docker: {}\n  file:\n"          # YAML alias
                         "    filename: /etc/traefik/dynamic.yml\nproviders: *p\n")),
                traefik(("/etc/traefik/conf.d/r.yml", "http:\n  routers:\n    d:\n"
                         "      service: api@internal\n")),
                traefik(("/etc/traefik/traefik.yml", ""))):                                    # empty read
            self.assertFlagged(text)

    def test_go_template_is_could_not_judge(self):
        # Traefik renders Go templates in file-provider config; a route beside one does not hide it.
        self.assertFlagged(traefik(("/etc/traefik/dynamic.yml", ROUTE_Y + "    t:\n      loadBalancer:\n"
                                    "        servers:\n          - url: 'http://{{ env \"UP\" }}:3000'\n")))

    def test_running_proxy_with_no_config_read_is_could_not_judge(self):
        # Audit: Caddy/Traefik listening, configured outside the read paths or by flags only.
        from tests.test_coverage_175 import Remote
        empty = "#--nginx--\n#--caddyfile--\n#--traefik--\n"
        for tool in ("caddy", "traefik"):
            ss = 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("%s",pid=1,fd=3))\n' % tool
            notes = inside.read(Remote({"listeners": (0, ss), "revproxy": (0, empty)}))["notes"]
            self.assertTrue(any(n.startswith(HOST_NOTE) and tool in n for n in notes), notes)
            self.assertFalse(any(n.startswith(NONE_READ) for n in notes), notes)

    def test_toml_dynamic_route_is_read(self):
        # f1 E: `url = "..."` in TOML is a route; the static file pointing at it is plain.
        text = traefik(("/etc/traefik/traefik.toml",
                        "[providers.file]\n  filename = \"/etc/traefik/dynamic.toml\"\n"),
                       ("/etc/traefik/dynamic.toml", "[http.services.g.loadBalancer]\n"
                        "  [[http.services.g.loadBalancer.servers]]\n    url = \"http://127.0.0.1:3000\"\n"))
        self.assertEqual([e["upstream"] for e in inside.parse_revproxy(text)], ["127.0.0.1:3000"])
        notes = host_notes(text)
        self.assertFalse(any(n.startswith((HOST_NOTE, NONE_READ)) for n in notes), notes)

    def test_plain_config_is_not_flagged(self):
        # f1 control moved: a `directory` provider is never covered (review #7, TraefikForms).
        for text in (
                traefik(("/etc/traefik/traefik.yml", "providers:\n  providersThrottleDuration: 2s\n"
                         "  file:\n    filename: /etc/traefik/conf.d/g.yml\n"),
                        ("/etc/traefik/conf.d/g.yml", ROUTE_Y),
                        ("/etc/traefik/conf.d/x.yml", "# placeholder\n"),             # comment-only
                        ("/etc/traefik/conf.d/mw.yml", "http:\n  middlewares:\n    auth:\n"
                         "      basicAuth:\n        users: ['u:hash']\n")),
                caddy(site("  root * /srv\n  file_server\n", "static.example"))):      # plain Caddy site
            self.assertNotFlagged(text)


# --- note 4: a same-file Caddy snippet import is followed (f2 G3) ------------------

SNIP = "(hdrs) {\n  header X-Frame-Options DENY\n}\n"


class CaddySnippetImport(Flags):
    def test_site_auth_fix_with_snippet_import_is_fixed(self):
        text = caddy(SNIP + site("  import hdrs\n  basic_auth {\n    u $2a$x\n  }\n"
                                 "  reverse_proxy 127.0.0.1:3000\n"))
        self.assertNotFlagged(text)
        res, code = self.recheck(text)
        self.assertEqual(len(res["fixed"]), 1)
        self.assertEqual(code, 0)

    def test_other_imports_are_could_not_judge(self):
        for text in (caddy(site("  import /etc/caddy/sites/*.caddy\n")),
                     caddy(site("  import hdrs\n  reverse_proxy 127.0.0.1:8080\n")),     # not defined here
                     caddy("(px) {\n  reverse_proxy 127.0.0.1:3000\n}\n" + site("  import px\n"))):
            self.assertFlagged(text)
        # A snippet's route is not a site of its own named "(px)".
        self.assertEqual(inside._parse_caddyfile("(px) {\n  reverse_proxy 127.0.0.1:3000\n}\n"), [])


# --- review #7 (round 3 part 2): every Caddy reverse_proxy gives a whole entry or a problem ---

AUTH = "  basic_auth {\n    u $2a$x\n  }\n"


class CaddySiteForms(Flags):
    got = CaddyUpstreamForms.got

    def test_braceless_and_next_line_brace_sites_are_read(self):
        want = [(443, "admin.example", "127.0.0.1:3000", False)]
        for text in ('admin.example\n\nreverse_proxy "127.0.0.1:3000"\n',                    # g1 K1
                     "# quick-start\nadmin.example\nreverse_proxy {\n  to 127.0.0.1:3000\n}\n",  # K1b
                     "{\n  email a@b.c\n}\nadmin.example\n{\n  reverse_proxy 127.0.0.1:3000\n}\n"):  # K3
            self.assertEqual(self.got(text), want, text)
            self.assertNotFlagged(caddy(text))
        res, code = self.recheck(caddy("admin.example\n\nreverse_proxy :3000\n"))         # g3 Q1
        self.assertEqual((res["fixed"], code), ([], 1))

    def test_port_only_upstream_is_local(self):
        self.assertEqual(self.got(site("  reverse_proxy :3000\n")),
                         [(443, "admin.example", "localhost:3000", False)])
        res, code = self.recheck(caddy(site("  reverse_proxy :3000\n")))                    # g1 K4
        self.assertEqual((res["fixed"], code), ([], 1))

    def test_multi_address_site_gives_an_entry_per_address(self):
        text = site("  reverse_proxy 127.0.0.1:3000\n", "http://admin.example, https://admin.example")
        self.assertEqual(self.got(text), [(80, "admin.example", "127.0.0.1:3000", False),
                                          (443, "admin.example", "127.0.0.1:3000", False)])
        res, code = self.recheck(caddy(text))                                               # g1 K8
        self.assertEqual((res["fixed"], code), ([], 1))

    def test_brace_in_quote_or_heredoc_does_not_shift_blocks(self):
        for body in ('  respond "{" 200\n', "  respond <<EOF\n    {\n    EOF 200\n"):            # K5, K10
            text = site(AUTH + body, "www.example") + site("  reverse_proxy 127.0.0.1:3000\n")
            self.assertEqual(self.got(text), [(443, "admin.example", "127.0.0.1:3000", False)])
            self.assertNotFlagged(caddy(text))
            res, code = self.recheck(caddy(text))
            self.assertEqual((res["fixed"], code), ([], 1))

    def test_route_with_no_whole_entry_is_could_not_judge(self):
        for text in (site("  reverse_proxy localhost:3000-3001\n"),                           # g3 Q2
                     "admin.example { reverse_proxy 127.0.0.1:3000 }\n",                       # K2
                     "{\n  reverse_proxy 127.0.0.1:3000\n}\n",                                 # no site
                     site('  respond "{ 200\n  reverse_proxy 127.0.0.1:3000\n'),              # open quote
                     site("  respond <<EOF\n  reverse_proxy 127.0.0.1:3000\n"),               # open heredoc
                     site("  reverse_proxy 127.0.0.1:3000\n") + "}\n"):                        # stray }
            self.assertFlagged(caddy(text))


# --- review #7: a file with no trailing newline glues the next marker or header (g2 T5, g4) --

class GluedMarkers(Flags):
    def test_marker_and_header_are_found_mid_line(self):
        caddy_no_nl = "w.example {\n" + AUTH + "  reverse_proxy 127.0.0.1:8081\n}"
        docker = ("/etc/traefik/traefik.yml", STATIC_Y + "providers:\n  docker: {}\n")
        self.assertFlagged(traefik(docker).replace("#--traefik--", "# file /etc/caddy/Caddyfile\n"
                                                   + caddy_no_nl + "#--traefik--"))         # g2 T5
        text = traefik(("/etc/traefik/traefik.yml", "providers:\n  file:\n    filename: /etc/traefik/dynamic.yml\n"),
                       ("/etc/traefik/dynamic.yml", ROUTE_Y))
        text = text.replace("#--traefik--", "# file /etc/caddy/Caddyfile\n" + caddy_no_nl + "#--traefik--")
        self.assertEqual([e["upstream"] for e in inside.parse_revproxy(text)],               # g2 T5b
                         ["127.0.0.1:8081", "127.0.0.1:3000"])
        self.assertFlagged(traefik(("/etc/traefik/traefik.yml", "providers:\n  docker: {}"),    # g4
                                   ("/etc/traefik/conf.d/g.yml", ROUTE_Y)))


# --- review #7: Traefik directory providers, header spacing, flow continuation, comments ----

class TraefikForms(Flags):
    def test_unfollowed_forms_are_could_not_judge(self):
        for text in (
                traefik(("/etc/traefik/traefik.yml", STATIC_Y + "providers:\n  file:\n"      # g2 T1
                         "    directory: /etc/traefik/conf.d\n"), ("/etc/traefik/conf.d/g.yml", ROUTE_Y)),
                traefik(("/etc/traefik/traefik.yml", "providers:\n  file:\n"                 # T3 dotfile
                         "    filename: /etc/traefik/conf.d/.routes.yml\n")),
                traefik(("/etc/traefik/traefik.yml", "providers: {file: {filename: "         # T4b
                         "/etc/traefik/dynamic.yml},\ndocker: {}}\n")),
                traefik(("/etc/traefik/traefik.toml", "[providers.file]\n  filename = "      # T10
                         "\"/etc/traefik/dynamic.toml\"\n[ providers . docker ]\n")),
                traefik(("/etc/traefik/traefik.toml", "[providers.file]\n  filename = "      # T10b
                         "\"/etc/traefik/dynamic.toml\"\n[providers. docker]\n[api]\n  dashboard = true\n")),
                traefik(("/etc/traefik/traefik.yml", STATIC_Y + "# dashboard url: http://127.0.0.1:8080/\n"
                         "providers:\n  docker: {}\n"))):                                    # T14
            self.assertFlagged(text)

    def test_filename_provider_read_is_plain(self):
        f = "/etc/traefik/dynamic.yml"                                                          # guard
        self.assertNotFlagged(traefik(("/etc/traefik/traefik.yml", STATIC_Y + "providers:\n  file:\n"
                                       "    filename: %s\n" % f), (f, ROUTE_Y)))


# --- review #8 (round 3 part 3): Caddy read token by token; every `reverse_proxy` accounted ---

GRAF_JSON = ('{\n  "apps": {"http": {"servers": {"s": {"listen": [":443"], "routes": [{\n'
             '    "match": [{"host": ["admin.example"]}],\n'
             '    "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:3000"}]}]\n'
             '  }]}}}}\n}\n')


class CaddyStructure(Flags):
    got = CaddyUpstreamForms.got

    def test_address_list_continued_over_lines(self):
        rp = " {\n  reverse_proxy 127.0.0.1:3000\n}\n"
        self.assertEqual(self.got("localhost,\nadmin.example" + rp),                           # h1 H1
                         [(443, "localhost", "127.0.0.1:3000", False),
                          (443, "admin.example", "127.0.0.1:3000", False)])
        self.assertEqual(self.got("http://admin.example,\nhttps://admin.example" + rp),         # H1c
                         [(80, "admin.example", "127.0.0.1:3000", False),
                          (443, "admin.example", "127.0.0.1:3000", False)])
        res, code = self.recheck(caddy("localhost,\nadmin.example" + rp))
        self.assertEqual((res["fixed"], code), ([], 1))

    def test_braceless_site_beside_another_site_is_could_not_judge(self):
        for text in ("w.example\nreverse_proxy 127.0.0.1:8080\nadmin.example {\n"
                     "  reverse_proxy 127.0.0.1:3000\n}\n",
                     "w.example {\n}\nadmin.example\nreverse_proxy 127.0.0.1:3000\n"):
            self.assertFlagged(caddy(text))

    def test_reverse_proxy_not_followed_is_could_not_judge(self):
        self.assertFlagged(caddy(GRAF_JSON))                                                   # h1 H2
        self.assertFlagged(caddy('{"apps": {}}\n'))                                            # JSON, no route
        # A snippet whose directive is an argument: `import p reverse_proxy` is a route.
        self.assertFlagged(caddy("(p) {\n  {args[0]} 127.0.0.1:3000\n}\n" + site("  import p reverse_proxy\n")))
        res, code = self.recheck(caddy(GRAF_JSON))
        self.assertEqual((res["fixed"], code), ([], 1))

    def test_only_whole_brace_tokens_are_blocks(self):
        text = site(AUTH + "  respond x{ 200\n", "w.example") + site("  respond }y 200\n"     # h1 H4
                                                                     "  reverse_proxy 127.0.0.1:3000\n")
        self.assertEqual(self.got(text), [(443, "admin.example", "127.0.0.1:3000", False)])
        res, code = self.recheck(caddy(text))
        self.assertEqual((res["fixed"], code), ([], 1))
        self.assertEqual(self.got(site("  @a path /a#b {\n  }\n  reverse_proxy 127.0.0.1:3000\n")),  # H5
                         [(443, "admin.example", "127.0.0.1:3000", False)])

    def test_other_upstream_scheme_is_could_not_judge(self):
        for up in ("srv+http://_grafana._tcp.example", "srv+https://_g._tcp.example", "fastcgi://127.0.0.1:9000"):
            self.assertFlagged(caddy(site("  reverse_proxy %s\n" % up)))                        # h3 u14
        self.assertEqual(self.got(site("  reverse_proxy h2c://127.0.0.1:3000\n")),
                         [(443, "admin.example", "127.0.0.1:3000", False)])


class TraefikV1(Flags):
    def test_v1_top_level_provider_is_could_not_judge(self):
        for text in (
                traefik(("/etc/traefik/traefik.toml", "[entryPoints]\n  [entryPoints.http]\n"        # h2 V1
                         "  address = \":80\"\n[docker]\nexposedByDefault = true\n")),
                traefik(("/etc/traefik/traefik.toml", "[file]\n  filename = \"/etc/traefik/dynamic.toml\"\n"
                         "[docker]\n  exposedByDefault = true\n"), ("/etc/traefik/dynamic.toml",      # V1b
                                                                 "[http.middlewares.a.basicAuth]\n  users = ['u:x']\n")),
                traefik(("/etc/traefik/traefik.toml", "[file]\n  directory = \"/etc/traefik/rules\"\n"))):
            self.assertFlagged(text)


# --- review #9 (round 3 part 4): Caddy global ports, quoted matchers, line splits; v1 kubernetes ---

RP = "  reverse_proxy 127.0.0.1:3000\n"


class CaddyReview9(Flags):
    got = CaddyUpstreamForms.got

    def test_global_ports_are_the_default_listen(self):
        glob = "{\n  http_port 8080\n  https_port 8443\n}\n"
        self.assertEqual(self.got(glob + site(RP) + site(RP, "http://w.example") + site(RP, "localhost")),
                         [(8443, "admin.example", "127.0.0.1:3000", False),                  # i2 J4
                          (8080, "w.example", "127.0.0.1:3000", False),
                          (8443, "localhost", "127.0.0.1:3000", False)])
        res, code = self.recheck(caddy(glob + site(RP)), 8443)
        self.assertEqual((res["fixed"], code), ([], 1))

    def test_global_port_not_a_number_is_could_not_judge(self):
        self.assertFlagged(caddy("{\n  https_port {$PORT}\n}\n" + site(RP)))

    def test_quoted_auth_matcher_is_scoped(self):
        for head in ('basic_auth "/admin/*"', "basic_auth `/admin/*`",                         # i2 J1 J2
                     'forward_auth "/admin*" authelia:9091'):                                  # i1 u26
            text = caddy(site("  %s {\n    u $2a$x\n  }\n" % head + RP))
            self.assertEqual([e["auth"] for e in inside.parse_revproxy(text)], [None], head)
            res, code = self.recheck(text)
            self.assertEqual((res["fixed"], code), ([], 1), head)

    def test_only_a_newline_ends_a_line(self):
        for sep in ("\x0c", "\u2028"):                                                         # i4 K2, i3 v2
            text = caddy(site("  basic_auth%s/admin/* {\n    u $2a$x\n  }\n" % sep + RP))
            self.assertEqual([e["auth"] for e in inside.parse_revproxy(text)], [None], repr(sep))
            res, code = self.recheck(text)
            self.assertEqual((res["fixed"], code), ([], 1), repr(sep))

    def test_line_ending_backslash_is_could_not_judge(self):
        for text in (site("  basic_auth \\\n    /admin/* {\n    u $2a$x\n  }\n" + RP),        # i2 J3
                     "admin.example \\\n  localhost {\n" + RP + "}\n"):                      # i1 u7
            self.assertFlagged(caddy(text))

    def test_site_port_placeholder_is_could_not_judge(self):
        self.assertFlagged(caddy(site(RP, "admin.example:{$PORT}")))                           # i3 v3

    def test_localhost_is_that_host_only(self):
        self.assertEqual(self.got(site(RP, "localhost.example.com")),                          # i3 v4
                         [(443, "localhost.example.com", "127.0.0.1:3000", False)])

    def test_dynamic_upstreams_beside_a_static_one_are_could_not_judge(self):
        self.assertFlagged(caddy(site("  reverse_proxy 127.0.0.1:9999 {\n"                    # i5 w1
                                      "    dynamic a grafana 3000\n  }\n")))

    def test_v1_kubernetes_is_could_not_judge(self):
        self.assertFlagged(traefik(("/etc/traefik/traefik.toml", "[entryPoints]\n  [entryPoints.http]\n"  # i4 K1
                                    "  address = \":80\"\n[kubernetes]\nendpoint = \"https://10.0.0.1:6443\"\n")))


# --- review #10 (round 4): a site's directive names checked against Caddy v2's own list ---

class CaddyReview10(Flags):
    def test_v1_proxy_is_could_not_judge(self):
        for text in (site("  gzip\n  proxy / localhost:3000 {\n    transparent\n  }\n"),     # j1 C1
                     "admin.example\ntls admin@example.com\nproxy / localhost:3000 {\n"       # C2
                     "  transparent\n}\n",
                     site("  basicauth /other admin s3cret\n  proxy /grafana localhost:3000 {\n"  # C3
                          "    without /grafana\n  }\n"),
                     site("  root * /var/www/html\n  php_fastcgi 127.0.0.1:9000\n"             # C5
                          "  file_server\n"),
                     site("  handle /g/* {\n    proxy / localhost:3000\n  }\n")):
            self.assertFlagged(caddy(text))
            res, code = self.recheck(caddy(text))
            self.assertEqual((res["fixed"], code), ([], 1), text)

    def test_v2_directives_and_their_blocks_are_read(self):
        text = ("{\n  email a@example.com\n  servers {\n    protocols h1 h2\n  }\n}\n"
                "(sec) {\n  header {\n    -Server\n  }\n}\n" +
                site("  import sec\n  encode zstd gzip\n  log {\n    output file /var/log/a.log\n  }\n"
                     "  @ws {\n    header Connection *Upgrade*\n  }\n  handle_path /api/* {\n"
                     "    rewrite * /v1{uri}\n  }\n" + AUTH +
                     "  reverse_proxy 127.0.0.1:3000 {\n    header_up Host {host}\n  }\n"
                     "  handle_errors {\n    respond \"{err.status_code}\"\n  }\n"))
        self.assertNotFlagged(caddy(text))



# --- fix round 5 (2026-10-29): handle_errors routes do not inherit the site's login
# ([cyber] #11 finding 1); a no-auth admin route with no hostname is could-not-judge ---

IP = "203.0.113.9"
ERR = "  handle_errors {\n    reverse_proxy 127.0.0.1:3000\n  }\n"
AUTH4 = "    basic_auth {\n      u $2a$x\n    }\n"


def run_caddy(text, port=443):
    """A REAL inside.read + run.run (proof, vantage and snapshots stubbed; nothing sent) of
    a box whose host Caddy serves `text` on 0.0.0.0:`port` (an int or a tuple of ports; UFW
    allows them, the probe finds them open) and whose Grafana container is published on
    127.0.0.1:3000 only."""
    from tests.test_coverage_175 import Remote
    ports = port if isinstance(port, tuple) else (port,)
    ss = "".join('LISTEN 0 511 %s:%d 0.0.0.0:* users:(("%s",pid=1,fd=3))\n' % r for r in (
        ("0.0.0.0", 22, "sshd"), *[("0.0.0.0", p, "caddy") for p in ports],
        ("127.0.0.1", 3000, "docker-proxy")))
    ufw = ("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled "
           "(routed)\nNew profiles: skip\n\nTo                         Action      From\n"
           "--                         ------      ----\n"
           + "".join("%d/tcp                     ALLOW IN    Anywhere\n" % p for p in (22,) + ports))
    graf = {"Id": "a" * 64, "Name": "/grafana",
            "Config": {"Image": "grafana/grafana:11.2.0", "Cmd": [], "Labels": {
                "com.docker.compose.project": "p", "com.docker.compose.service": "grafana"}},
            "HostConfig": {"Privileged": False, "CapAdd": None, "SecurityOpt": None, "PidMode": "",
                           "NetworkMode": "bridge"},
            "Mounts": [], "NetworkSettings": {"Ports": {"3000/tcp": [{"HostIp": "127.0.0.1",
                                                                      "HostPort": "3000"}]}}}
    outs = {"listeners": (0, ss), "ufw": (0, ufw), "nft": (1, ""), "firewalld": (127, ""),
            "iptables": (0, "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n*nat\n:DOCKER - [0:0]\nCOMMIT\n"
                            "#--v6--\n"),
            "docker": (0, json.dumps([graf])), "sshd_files": (0, "#--ok--\n"),
            "sshd": (0, "port 22\npasswordauthentication no\npermitrootlogin prohibit-password\n"
                        "pubkeyauthentication yes\nkbdinteractiveauthentication no\n"),
            "revproxy": (0, caddy(text)), "dns_zones": (0, ""), "webroot_names": (0, ""),
            "addrs": (0, "2: eth0    inet %s/24 brd x scope global eth0\n" % IP),
            "machine_id": (0, "remote\n"), "boot_id": (0, "b\n"), "read_mount": (1, "")}
    t = scope.new_target("lab", "lab", IP, None, scope.ATTEST_PHRASE, by="x", all_ports=True)
    proof = [{"ip": IP, "proven": True, "method": "http-token", "port": 80, "detail": "", "tried": []}]
    with mock.patch.object(run.gate, "prove", return_value=proof), \
            mock.patch.object(run.vantage, "remote_checks", return_value=[]), \
            mock.patch.object(run.inside, "snapshot", return_value={}), \
            mock.patch.object(run.inside, "compare_snapshots", return_value={}):
        return run.run(t, remote=Remote(outs), head_fn=lambda res, proven: {},
                       prober=lambda ips, probe: {"results": {IP: {
                           p: "open" if p in (22,) + ports else "closed" for p in probe}},
                           "started": "", "seconds": 0, "retested": 0},
                       local_checks=lambda ip: [{"check": "local-interface", "same_host": False,
                                                 "detail": "x"}])


def as_prior(rep):
    return json.loads(json.dumps(report._jsonable(rep)))


class HandleErrorsAuth(Flags):
    def got(self, text):
        return [e["auth"] for e in inside._parse_caddyfile(text)]

    def test_error_routes_do_not_inherit_the_site_login(self):
        # Caddy runs handle_errors for basic_auth's own 401, so the site login is not in front.
        self.assertEqual(self.got(site(AUTH + RP + ERR)), [True, None])                    # k1 K1
        self.assertEqual(self.got(site(AUTH + '  respond "ok"\n  handle_errors 401 {\n'     # K1b
                                       "    reverse_proxy 127.0.0.1:3000\n  }\n")), [None])
        self.assertEqual(self.got(site(AUTH + "  handle_errors 4xx {\n    handle /x* {\n"
                                       "      reverse_proxy 127.0.0.1:3000\n    }\n  }\n")), [None])
        # A login inside a nested handle guards that handle only.
        self.assertEqual(self.got(site(AUTH + "  handle_errors {\n    handle /a* {\n  " +
                                       AUTH4.replace("\n    ", "\n      ") + "    }\n" +
                                       "    reverse_proxy 127.0.0.1:3000\n  }\n")), [None])
        # The handle_errors block's own login (no matcher, at its top) keeps the site's auth.
        self.assertEqual(self.got(site(AUTH + "  handle_errors {\n" + AUTH4 +
                                       "    reverse_proxy 127.0.0.1:3000\n  }\n")), [True])
        self.assertEqual(self.got(site(AUTH + RP)), [True])
        self.assertEqual(self.got(site("  file_server\n" + ERR)), [False])  # no login anywhere: a finding

    def test_error_route_is_not_a_proven_all_clear_or_fixed(self):
        prior = as_prior(run_caddy(site(RP)))
        self.assertEqual([f["kind"] for f in prior["findings"]], ["admin-route"])
        self.assertTrue(run.proven_all_clear(run_caddy(site(AUTH + RP))))   # the harness is clean
        for text in (site(AUTH + RP + ERR),
                     site(AUTH + '  respond "ok"\n  handle_errors 401 {\n'
                                 "    reverse_proxy 127.0.0.1:3000\n  }\n")):
            rep = run_caddy(text)
            self.assertEqual(run.exit_code(rep), 0)                          # note 6: exit unchanged
            self.assertIn("caddy route to 127.0.0.1:3000: auth could not be judged", run.unjudged(rep))
            self.assertFalse(run.proven_all_clear(rep))
            self.assertEqual(recheck.compare(prior, rep)["findings"]["fixed"], [], text)
            self.assertEqual(run_cli(prior, rep)[0], 1, text)


class NamelessAdminRoute(unittest.TestCase):
    def test_nameless_route_to_an_admin_app_is_could_not_judge(self):
        for text, port, line in ((":8080 {\n" + RP + "}\n", 8080, 2),                 # k1 C8
                                 ("http:// {\n" + RP + "}\n", 80, 2),
                                 ("localhost:8080 {\n  encode gzip\n" + RP + "}\n", 8080, 3)):
            rep = run_caddy(text, port)
            self.assertEqual(run.exit_code(rep), 0, text)                    # note 6: exit unchanged
            self.assertEqual(rep["findings"], [], text)
            self.assertFalse(run.proven_all_clear(rep), text)
            [u] = run.unjudged(rep)
            self.assertTrue(u.startswith("admin route could not judge: Grafana"), u)
            for want in ("port %d" % port, "/etc/caddy/Caddyfile:%d" % line, "no login",
                         "any hostname or by IP"):
                self.assertIn(want, u)
        self.assertTrue(run.proven_all_clear(run_caddy(":8080 {\n  reverse_proxy 127.0.0.1:3001\n}\n",
                                                       8080)))                # not an admin app

    def test_only_that_case_moves(self):
        from tests.test_coverage_175 import CONF_SRC, NET, containers
        e = {"tool": "nginx", "listen": 8088, "server_name": "_", "upstream": "dash:3000",
             "auth": False, "project": "lab", "where": {"file": CONF_SRC, "line": 3, "text": "x"}}
        for name in ("_", "localhost", None, ""):
            got, [u] = riders.admin_routes([dict(e, server_name=name)], containers(), {8088: NET})
            self.assertEqual(got, [])
            self.assertIn("Grafana", u)
            self.assertIn("%s:3" % CONF_SRC, u)
        for other in (dict(e, upstream="api:8000"), dict(e, auth=None), dict(e, auth=True)):
            self.assertEqual(riders.admin_routes([other], containers(), {8088: NET}), ([], []))
        self.assertEqual(riders.admin_routes([e], containers(), {}), ([], []))  # loopback-only port
        got, unjudged = riders.admin_routes([dict(e, server_name="admin.lab")], containers(), {8088: NET})
        self.assertEqual(([f["kind"] for f in got], unjudged), (["admin-route"], []))


# --- fix round 6 (2026-10-29: "fix both"; [cyber] #12 should-fix 1-2) ---
# Caddy serves `localhost`, an IP and a nameless `https://` site over HTTPS, on the https_port
# when no port is given (caddyserver.com/docs/caddyfile/concepts#addresses); recheck holds an
# admin-route FIXED while the new run could not judge a route to the same admin app.

class CaddyHttpsDefault(Flags):
    got = CaddyUpstreamForms.got

    def listen(self, head, glob=""):
        return [e[0] for e in self.got(glob + site(RP, head))]

    def test_sites_with_no_port_and_no_http_scheme_are_the_https_port(self):
        for head, want in (("localhost", 443), ("https://", 443), ("https://localhost", 443),  # M2 M13
                           ("127.0.0.1", 443), ("g.example [::1]", 443), ("localhost, g.example", 443),
                           ("http://localhost", 80), ("http://", 80), ("localhost:8080", 8080),
                           ("https://:8443", 8443), (":8080", 8080), ("localhost:443", 443),
                           ("HTTP://localhost", 80)):
            self.assertEqual(set(self.listen(head)), {want}, head)
        glob = "{\n  http_port 8080\n  https_port 8443\n}\n"
        for head, want in (("localhost", 8443), ("https://", 8443), ("127.0.0.1", 8443),
                           ("http://localhost", 8080), ("http://", 8080)):
            self.assertEqual(self.listen(head, glob), [want], head)

    def test_localhost_or_https_site_on_the_https_port_is_not_all_clear_or_fixed(self):
        prior = as_prior(run_caddy(site(RP, "g.example.com")))
        self.assertEqual([(f["kind"], f["port"]) for f in prior["findings"]], [("admin-route", 443)])
        glob = "{\n  auto_https disable_redirects\n}\n"
        for text, port in ((glob + site(RP, "localhost"), 443),                          # M2 / RC3
                           (site(RP, "localhost"), (80, 443)),                            # RC2
                           (site(RP, "https://"), 443)):                                  # M13
            rep = run_caddy(text, port)
            self.assertEqual(run.exit_code(rep), 0, text)                    # note 6: exit unchanged
            self.assertFalse(run.proven_all_clear(rep), text)
            [u] = run.unjudged(rep)
            self.assertIn("Grafana via caddy port 443", u)
            self.assertEqual(recheck.compare(prior, rep)["findings"]["fixed"], [], text)
            self.assertEqual(run_cli(prior, rep)[0], 1, text)


class AdminRouteRecheckHold(unittest.TestCase):
    def test_could_not_judge_route_to_the_same_app_holds_fixed(self):
        prior = as_prior(run_caddy(site(RP, "g.example.com"), (80, 443)))
        self.assertEqual([(f["kind"], f["port"]) for f in prior["findings"]], [("admin-route", 443)])
        for port in ((80, 443), 80):                                     # j1 C6 / RC1; 443 now closed
            rep = run_caddy(":80 {\n" + RP + "}\n", port)
            self.assertEqual(run.exit_code(rep), 0)                          # note 6: run exit unchanged
            res = recheck.compare(prior, rep)["findings"]
            self.assertEqual(res["fixed"], [], port)
            [row] = res["still_open"]
            self.assertTrue(row["now"].startswith(
                "could not re-judge (admin route could not judge: Grafana via caddy port 80 "), row)
            code, out = run_cli(prior, rep)
            self.assertEqual(code, 1, port)
            self.assertNotIn("FIXED", out)
        # The route moved to a non-admin app: no could-not-judge line, so it is fixed.
        rep = run_caddy(":80 {\n  reverse_proxy 127.0.0.1:3001\n}\n", (80, 443))
        self.assertEqual(len(recheck.compare(prior, rep)["findings"]["fixed"]), 1)
        self.assertEqual(run_cli(prior, rep)[0], 0)


if __name__ == "__main__":
    unittest.main()
