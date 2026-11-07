#!/bin/sh
# Tear the head-to-head lab down and remove the rules up.sh added.
# The slice lab's baseline rules (22, 80 allow; 5432 deny) are left as they were.
set -eu
cd "$(dirname "$0")"
LAB_DB_PASSWORD=x LAB_GF_PASSWORD=x LAB_SESSION_PASSWORD=x LAB_APPDB_PASSWORD=x \
  sudo -E docker compose -p h2h down -v --remove-orphans
sudo ufw delete allow 3000/tcp
sudo ufw delete allow 8081/tcp
sudo ufw delete deny 8443
