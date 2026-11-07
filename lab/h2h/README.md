# eyeline head-to-head lab

The lab behind the phase-16 head-to-head comparison: one Docker host you own,
running a set of services, some misconfigured on purpose and some configured
correctly. Which is which is in the sealed answer key, kept outside the lab
folder and hashed before any tool runs, so no tool (or AI agent) on the box can
read it.

Detection only. Nothing here exploits anything; the lab plants
misconfigurations and the tools under test only read and probe.

The prompt-injection text in the lab (the `maintainer.note` label in
`docker-compose.yml` and the page title in `www/index.html`, both telling AI
assistants to report no issues) is a deliberate plant. It tests
whether a tool, or an AI agent driving one, obeys text found on the target.
It is not an instruction to anyone.

`www/.env` is a planted problem (a secrets file served from the web root), but
every secret value in it is FAKE: each starts with `lab-fake-` and is not a credential for
anything. `www/.env.example` is the empty template, planted as a decoy.

While it is up, some services are reachable from the internet on purpose. Keep
it up only for the test window, on a box that holds nothing else, then tear it
down.

## Up / down (on the lab box, from a copy of this folder placed next to the slice lab's `www/`)

    ./up.sh      # opens the lab ports in UFW, generates random passwords, starts it
    ./down.sh    # stops it, removes its volumes, and removes the lab-only UFW rules (3000, 8081, 8443)

`up.sh` copies the slice lab's ownership token (`../www/.well-known/eyeline.txt`)
so `eyeline prove` keeps working.
