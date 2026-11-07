"""The only door to the target: the user's own ssh, running a FIXED list of
read-only commands. Nothing outside READ_ONLY is ever sent, and every command
sent is logged so the report can list it. Nothing is installed or left running.
"""
import shlex
import subprocess

# On-box ALLOW-LIST for container Cmd tokens (see "docker"). Each Cmd token arrives
# as one JSON string per line; only token shapes the riders read and that cannot
# carry a credential survive: a flag NAME, yes/no/true/false/on/off, an empty string,
# an absolute path, a config filename, a few known program names, `--flag=` with one
# of those values, and the `"#END"` sentinel. `--flag=X` keeps the name
# (`--flag=REDACTED`); a token with whitespace (an `sh -c` command line) becomes
# REDACTED-SHELL; anything else becomes REDACTED. A deny-list of secret-looking flag
# names missed `--masterauth`, `sh -c "... --requirepass X"`, URLs with a password,
# `PGPASSWORD=X` (phase-16 [cyber] review), so nothing is kept unless listed.
# The blank line `docker inspect -f` appends is dropped, not sent as a token.
# Residual: a credential shaped exactly like a flag name or a path is kept.
_CMD_VAL = r'(yes|no|true|false|on|off|/[A-Za-z0-9._/-]*|[A-Za-z0-9._-]+\.(conf|cnf|yml|yaml|toml|json))'
_CMD_KEEP = ('^"(-[A-Za-z]|--[A-Za-z][A-Za-z0-9._-]*|' + _CMD_VAL + '|'
             '--[A-Za-z][A-Za-z0-9._-]*=' + _CMD_VAL + '?|'
             'redis-server|mongod|postgres|traefik|grafana-server|nginx|portainer|'
             r'docker-entrypoint\.sh|#END)?"$')
CMD_ALLOW_SED = ("-e '/^$/d' -e '\\%" + _CMD_KEEP + "%b' "
                 "-e 's/^\"(--[A-Za-z][A-Za-z0-9._-]*=).*$/\"\\1REDACTED\"/' -e t "
                 "-e 's/^\".*[[:space:]].*$/\"REDACTED-SHELL\"/' -e t "
                 "-e 's/.*/\"REDACTED\"/'")

# name -> command. Every entry only reads. Adding one needs a read-only review.
READ_ONLY = {
    "noop": "true",
    "addrs": "ip -o addr show",
    "machine_id": "cat /etc/machine-id",
    "boot_id": "cat /proc/sys/kernel/random/boot_id",
    "listeners": "sudo -n ss -H -tlnp 2>/dev/null || ss -H -tln",
    "ufw": "sudo -n ufw status verbose 2>/dev/null",
    # firewalld: read-only queries. --state exits 0 only when firewalld is running;
    # the rest describe the default zone. No sudo: firewall-cmd reads over D-Bus and
    # a non-root user may be allowed or denied by polkit (denied -> empty/non-zero).
    "firewalld": "command -v firewall-cmd >/dev/null 2>&1 || exit 127; "
                 "firewall-cmd --state >/dev/null 2>&1 || sudo -n firewall-cmd --state >/dev/null 2>&1 || exit 1; "
                 "fc() { firewall-cmd \"$@\" 2>/dev/null || sudo -n firewall-cmd \"$@\" 2>/dev/null; }; "
                 "echo '#--zone--'; fc --get-default-zone; "
                 "echo '#--list-all--'; fc --list-all",
    "iptables": "sudo -n iptables-save 2>/dev/null; echo '#--v6--'; sudo -n ip6tables-save 2>/dev/null",
    "nft": "sudo -n nft list ruleset 2>/dev/null",
    # Only the fields the engine uses. Config.Env is NEVER dumped (it can hold
    # secrets). Of Config.Labels only the four compose labels the engine reads are
    # sent (`index` gives "" for a missing one): a label can carry a Traefik basicauth
    # hash or a header token, so the rest never leave the box.
    # The structured JSON carries the image, Cmd, the blast-radius fields
    # (Privileged, CapAdd, SecurityOpt, PidMode, NetworkMode, Mounts) and ports. A
    # SEPARATE `auth_env` block, built in shell on the box, prints only an allow-list
    # of non-secret auth-signal env keys as `KEY=value`, and for the password-bearing
    # keys prints the KEY alone (presence, no value) - so no credential leaves the box.
    # Cmd can carry a secret too (`redis-server --requirepass X`), so it is NOT in the
    # JSON: a `#--cmd--` trailer prints each Cmd token as `#cmd <id> <json-string>`
    # after CMD_ALLOW_SED ran ON THE BOX, ending with `#cmd <id> "#END"`. Only sed
    # emits that sentinel, so a sed that fails leaves no #END and the engine treats
    # that container's Cmd as unread (fail closed); a failed inspect prints no #END
    # either. LC_ALL=C keeps [A-Za-z] ASCII. Found by the phase-16 run.
    # One JSON object per container, then one `#auth <id>` line per matched env key.
    "docker": "if docker ps -q >/dev/null 2>&1; then d() { docker \"$@\"; }; "
              "elif sudo -n docker ps -q >/dev/null 2>&1; then d() { sudo -n docker \"$@\"; }; "
              "else command -v docker >/dev/null 2>&1 || exit 127; exit 1; fi; "
              "ids=$(d ps -q); if [ -z \"$ids\" ]; then echo '[]'; exit 0; fi; "
              "d inspect -f '{\"Id\":{{json .Id}},\"Name\":{{json .Name}},"
              "\"Config\":{\"Labels\":{"
              "\"com.docker.compose.project\":{{json (index .Config.Labels \"com.docker.compose.project\")}},"
              "\"com.docker.compose.service\":{{json (index .Config.Labels \"com.docker.compose.service\")}},"
              "\"com.docker.compose.project.config_files\":"
              "{{json (index .Config.Labels \"com.docker.compose.project.config_files\")}},"
              "\"com.docker.compose.project.working_dir\":"
              "{{json (index .Config.Labels \"com.docker.compose.project.working_dir\")}}},"
              "\"Image\":{{json .Config.Image}}},"
              "\"HostConfig\":{\"Privileged\":{{json .HostConfig.Privileged}},"
              "\"CapAdd\":{{json .HostConfig.CapAdd}},\"SecurityOpt\":{{json .HostConfig.SecurityOpt}},"
              "\"PidMode\":{{json .HostConfig.PidMode}},\"NetworkMode\":{{json .HostConfig.NetworkMode}}},"
              "\"Mounts\":{{json .Mounts}},"
              "\"NetworkSettings\":{\"Ports\":{{json .NetworkSettings.Ports}}}}' $ids; "
              # auth-signal env: non-secret keys with value; password keys KEY-only.
              "echo '#--auth_env--'; "
              "for c in $ids; do "
              "for kv in $(d inspect -f '{{range .Config.Env}}{{println .}}{{end}}' \"$c\"); do "
              "k=${kv%%=*}; "
              "case \"$k\" in "
              "POSTGRES_HOST_AUTH_METHOD|GF_AUTH_ANONYMOUS_ENABLED|GF_AUTH_ANONYMOUS_ORG_ROLE|"
              "MONGO_INITDB_ROOT_USERNAME) echo \"#auth $c $kv\" ;; "
              "POSTGRES_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|GF_SECURITY_ADMIN_PASSWORD|REDIS_PASSWORD|"
              "POSTGRES_PASSWORD_FILE|MONGO_INITDB_ROOT_PASSWORD_FILE|REDIS_PASSWORD_FILE|"
              "GF_SECURITY_ADMIN_PASSWORD__FILE) "
              "echo \"#auth $c $k\" ;; "
              "esac; done; done; "
              # Cmd, token by token, through the on-box allow-list (see CMD_ALLOW_SED).
              "echo '#--cmd--'; "
              "for c in $ids; do "
              "{ d inspect -f '{{range .Config.Cmd}}{{json .}}{{println}}{{end}}' \"$c\" && "
              "echo '\"#END\"'; } | LC_ALL=C sed -E " + CMD_ALLOW_SED + " | sed \"s/^/#cmd $c /\"; done",
    "read_compose": "cat -- {arg}",
    # sshd effective config. `sshd -T` prints the fully-resolved config (all includes
    # and defaults applied) one `keyword value` per line; it is the only authoritative
    # source and needs root, so sudo -n first, then a plain try. Exit 127 if sshd is
    # absent. Read-only (-T only validates and dumps; it never starts a daemon).
    "sshd": "command -v sshd >/dev/null 2>&1 || exit 127; "
            "sudo -n sshd -T 2>/dev/null || sshd -T 2>/dev/null",
    # Phase 17.5 fix 3: WHERE the password settings live, so the fix can name the file.
    # grep prints only `file:line:text` hits for Include / Match / the password
    # keywords (sshd_config holds no secrets); 50-cloud-init.conf is root-only 0600,
    # hence sudo -n first. `#--ok--` only when grep read every file (exit 0 or 1).
    "sshd_files": "f=$(ls -d /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null); "
                  "[ -n \"$f\" ] || exit 1; "
                  "re='^[[:space:]]*(include|match|passwordauthentication|kbdinteractiveauthentication)([[:space:]]|$)'; "
                  "if sudo -n true 2>/dev/null; then sudo -n grep -HniE \"$re\" $f; else grep -HniE \"$re\" $f; fi; "
                  "[ $? -le 1 ] && echo '#--ok--'",
    # Phase 17.5 fix 2: nginx config bind-mounted into a container, read on the HOST
    # at the mount's Source path (from the docker inspect already done) - never
    # `docker exec`. {arg} is that path, shell-quoted. A directory yields its *.conf,
    # *.template (rendered into conf.d by the official image) and sites-enabled files,
    # each behind `# file <path>`; a file over 256 KiB is not read but marked
    # `#--unread-- <path> is over 256 KiB` (a cut can fall between blocks, where no
    # parse would notice), and head -c still caps the read. find -H follows the Source
    # itself if it is a symlink (Docker does too); EVERY symlink INSIDE (file or
    # directory, any name) resolves differently in the container, so it is marked
    # `#--unread--`, as is a directory with no config file, a find that failed
    # partway (an unreadable subdir) and one with more than 100 entries (the cap).
    # A name not under {arg} (a newline) is skipped.
    # Only parsed in memory for listen/server_name/proxy_pass/auth/root; the raw text
    # is never stored in the report (same as the host `nginx -T` read below).
    "read_mount": "s() {{ \"$@\" 2>/dev/null || sudo -n \"$@\" 2>/dev/null; }}; p={arg}; "
                  "if s test -d \"$p\"; then fs=$(s find -H \"$p\" -maxdepth 3 \\( -type l -o \\( -type f "
                  "\\( -name '*.conf' -o -name '*.template' -o -path '*/sites-enabled/*' \\) \\) \\) -print) "
                  "|| echo '#--unread-- find failed'; fs=$(printf '%s\\n' \"$fs\" | sort -u | head -n 101); "
                  "[ $(printf '%s\\n' \"$fs\" | wc -l) -le 100 ] || echo '#--unread-- more than 100 files'; "
                  "[ -n \"$fs\" ] || echo '#--unread-- no config file'; "
                  "elif s test -f \"$p\"; then fs=$p; else exit 1; fi; "
                  "printf '%s\\n' \"$fs\" | while IFS= read -r f; do "
                  "case \"$f\" in \"$p\"|\"$p\"/*) ;; *) continue ;; esac; "
                  "if [ \"$f\" != \"$p\" ] && s test -L \"$f\"; then echo \"#--unread-- $f\"; continue; fi; "
                  "if [ -n \"$(s find -H \"$f\" -size +262144c)\" ]; then "
                  "echo \"#--unread-- $f is over 256 KiB\"; continue; fi; "
                  "echo \"# file $f\"; s head -c 262144 -- \"$f\" || echo \"#--unread-- $f\"; echo; done",
    # Phase 17.5 fix 5: secret-looking file NAMES in a served web root (a host path
    # from nginx config / the nginx container's mounts). find prints paths only; no
    # file is opened. A find that fails (unreadable root or subdir, a symlink loop)
    # exits non-zero -> 'could not judge'. .git is pruned (its presence is the
    # finding, not its contents). find -L follows symlinks inside the root, as nginx
    # does when serving (.env -> ../shared/.env, uploads -> /data); names only, the
    # existing depth cap bounds it. Name patterns match any case (.ENV, DB.SQL).
    # Both caps are marked, never silent: `#--deeper--` when anything (outside .git)
    # sits below the depth-4 cap, and a 201st line means the 200-name cap cut the list.
    "webroot_names": "s() {{ \"$@\" 2>/dev/null || sudo -n \"$@\" 2>/dev/null; }}; p={arg}; "
                     "s test -d \"$p\" || exit 1; "
                     "out=$(s find -L \"$p\" -maxdepth 4 \\( -name .git -prune -print \\) -o \\( -type f "
                     "\\( -iname .env -o -iname '.env.*' -o -iname '*.sql' -o -iname '*.sql.gz' "
                     "-o -iname '*.dump' -o -iname '*.bak' -o -iname '*.backup' -o -iname 'backup.*' "
                     "-o -iname 'dump.*' \\) -print \\)) || exit 1; "
                     "[ -z \"$(s find -L \"$p\" -mindepth 5 -maxdepth 5 ! -path '*/.git/*' -print -quit)\" ] "
                     "|| echo '#--deeper--'; "
                     "printf '%s\\n' \"$out\" | sort -u | head -n 201",
    # Reverse-proxy config, host-installed only, each behind a marker so one parser
    # can tell them apart. nginx -T dumps every config file it loads, verbatim, each
    # behind `# configuration file X:` (read-only test mode); it does not canonicalize
    # them to one directive per line. Caddy and Traefik have no safe universal dump,
    # so their config files are read where they conventionally live. Every verb only
    # reads; nothing is started. No sudo for nginx -T: as root its test mode can create
    # missing log files and temp dirs, which is a write. Without root it usually fails
    # (log, pid and key files), so nginx present (on PATH, or /usr/sbin, which a
    # non-root ssh PATH can lack) but no dump prints `#--nginx-unread--`, so a failed
    # read is never mistaken for "no host nginx".
    "revproxy": "echo '#--nginx--'; if command -v nginx >/dev/null 2>&1 || [ -x /usr/sbin/nginx ]; then "
                "nginx -T 2>/dev/null || echo '#--nginx-unread--'; fi; "
                "echo '#--caddyfile--'; "
                "for f in /etc/caddy/Caddyfile /etc/caddy/caddy.conf; do "
                "[ -f \"$f\" ] && { echo \"# file $f\"; cat -- \"$f\"; }; done; "
                "echo '#--traefik--'; "
                "for f in /etc/traefik/traefik.yml /etc/traefik/traefik.yaml "
                "/etc/traefik/traefik.toml /etc/traefik/dynamic.yml /etc/traefik/dynamic.yaml "
                "/etc/traefik/dynamic.toml /etc/traefik/conf.d/*.yml /etc/traefik/conf.d/*.yaml; do "
                "[ -f \"$f\" ] && { echo \"# file $f\"; cat -- \"$f\"; }; done; "
                "exit 0",  # an aggregating read: finding nothing is exit 0 (empty), not a failure
    # The user's OWN authoritative DNS zone files, read only where a local DNS server
    # keeps them. Never a lookup against a third-party resolver: only zone files the
    # box itself serves. Each file is preceded by `# zonefile <path>` so the parser can
    # attribute records. bind/named on Debian+RHEL layouts; nothing is resolved.
    "dns_zones": "for d in /etc/bind /var/named /etc/named /var/lib/knot/zones; do "
                 "[ -d \"$d\" ] || continue; "
                 "find \"$d\" -maxdepth 2 -type f \\( -name 'db.*' -o -name '*.zone' "
                 "-o -name '*.db' \\) 2>/dev/null | while read -r f; do "
                 "echo \"# zonefile $f\"; cat -- \"$f\"; done; done; "
                 "exit 0",  # an aggregating read: finding no zone file is exit 0 (empty), not a failure
    "snap_packages": "(dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null || rpm -qa 2>/dev/null)"
                     " | sort | sha256sum",
    "snap_services": "[ -d /run/systemd/system ] || exit 1; "
                     "systemctl list-units --type=service --state=running --no-legend --plain"
                     " | awk '{print $1}' | xargs -r systemctl show -p Id -p InvocationID",
    "snap_containers": "if docker ps -q >/dev/null 2>&1; then d() { docker \"$@\"; }; "
                       "elif sudo -n docker ps -q >/dev/null 2>&1; then d() { sudo -n docker \"$@\"; }; "
                       "else exit 1; fi; "
                       "if [ -n \"$(d ps -q)\" ]; then "
                       "d inspect -f '{{.Id}} {{.State.StartedAt}}' $(d ps -q --no-trunc); fi",
}


class RemoteError(Exception):
    pass


class Remote:
    def __init__(self, ssh_dest, timeout=30, pin=None):
        """pin=(ip, port, known_hosts_file, user_ignoreunknown): connect straight to that IP and port
        instead of the address's host, and accept ONLY the host keys in that file
        (the ownership handshake)."""
        if ssh_dest.startswith("-"):
            raise RemoteError("ssh address may not start with '-'")
        self.dest = ssh_dest
        self.timeout = timeout
        self.pin = pin
        self.log = []  # (name, command, exit code)

    def _ssh(self, command):
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "RemoteCommand=none",
                # nothing forwarded either way, no local command, no tunnel
                "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                "-o", "PermitLocalCommand=no", "-o", "Tunnel=no"]
        if self.pin:
            # Command-line -o wins over ~/.ssh/config. Pin everything that could
            # route the login, or vouch for a host key, somewhere other than the IP.
            # IgnoreUnknown keeps the user's own list (first value wins) and adds
            # KnownHostsCommand, so OpenSSH < 8.5 still runs.
            ip, port, known_hosts, ignore = self.pin
            ignore = ",".join(x for x in ("KnownHostsCommand", ignore) if x)
            argv += ["-o", "HostName=%s" % ip, "-o", "Port=%d" % port,
                     "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
                     "-o", "IgnoreUnknown=%s" % ignore, "-o", "KnownHostsCommand=none",
                     "-o", "VerifyHostKeyDNS=no", "-o", "HostKeyAlias=eyeline-proof",
                     "-o", "UserKnownHostsFile=%s" % known_hosts,
                     "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes"]
        argv += [self.dest, command]
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return 124, "", "timed out"
        return p.returncode, p.stdout, p.stderr

    def run(self, name, arg=None):
        """Run READ_ONLY[name]. `arg`, if the command takes one, is shell-quoted."""
        if name not in READ_ONLY:
            raise RemoteError("refused: %r is not in the read-only command list" % name)
        command = READ_ONLY[name]
        if arg is not None:
            command = command.format(arg=shlex.quote(arg))
        code, out, err = self._ssh(command)
        if code == 255:
            raise RemoteError("ssh to %s failed: %s (connect once by hand first, so "
                              "your key and host key are set up)" % (self.dest, err.strip()))
        self.log.append((name, command, code))
        return code, out
