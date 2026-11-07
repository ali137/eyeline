# eyeline slice lab

One box you own, set up with the textbook gap: UFW denies 5432, but Docker
publishes postgres on 5432 anyway, and the internet can reach it. eyeline runs
from a DIFFERENT machine and should report exactly one gap (5432), no gap for
the loopback-only redis decoy, and port 80 as intended-open.

You deploy this yourself, on the lab box. eyeline installs nothing on it.

## Set up the lab box (Ubuntu 22.04 or 24.04, as root or with sudo)

    apt-get update && apt-get install -y docker.io docker-compose-v2 ufw
    # if docker-compose-v2 is not found (older 22.04 mirrors), install Docker from
    # Docker's own apt repo instead: docker-ce + docker-compose-plugin
    ufw default deny incoming && ufw allow 22/tcp && ufw allow 80/tcp && ufw deny 5432
    ufw --force enable
    # copy this folder to the box, then in it:
    mkdir -p www/.well-known
    LAB_DB_PASSWORD="$(openssl rand -hex 24)" sudo -E docker compose up -d
    # (drop sudo -E if your user is in the docker group)

Then from your own machine (not the lab box): `./eyeline init`, put the token
line it prints into `www/.well-known/eyeline.txt` on the lab box, check it with
`./eyeline prove <name>`, then run the diff with `./eyeline run <name>`.
Expected: one GAP (5432, with its `docker-compose.yml` line, fix, undo and
lockout warning), the redis decoy as `loopback only`, and 80 as `intended`.

Give `init` the flag `--all-ports` (or answer yes when it asks) if every port of
the IP reaches the lab box: the IP is on the box itself (a normal VPS), or a
router forwards all ports to it (1:1 NAT or DMZ). Without it, eyeline probes
only the port the ownership proof went through, and 5432 is listed as not
checked.

Warning: if a router sits in front of the lab box, it must actually forward
5432 and 80 to the box. If it does not, the router drops 5432 before the box
sees it, and eyeline will rightly report 5432 as blocked, not as a gap.

The postgres container is really reachable from the internet while the lab is
up. That is the point, so use a long random password (above), keep it up only
for the test, and tear it down after:

    sudo docker compose down

## The SSH user eyeline reads with

eyeline reads the firewall with `sudo -n` (no password prompt), so the SSH
user needs passwordless sudo, or use root. Without it, eyeline still runs and
reports the firewall as "not readable" instead of guessing.
