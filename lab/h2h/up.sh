#!/bin/sh
# Stand up the head-to-head lab on a box you own (OWN LABS ONLY). Needs sudo.
# Copies the token from the slice lab so `eyeline prove` keeps working.
set -eu
cd "$(dirname "$0")"
cp ../www/.well-known/eyeline.txt www/.well-known/eyeline.txt
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw deny 5432
sudo ufw allow 3000/tcp
sudo ufw allow 8081/tcp
sudo ufw deny 8443
sudo ufw default deny incoming
sudo ufw --force enable
umask 077
r() { openssl rand -hex 24; }
LAB_DB_PASSWORD=$(r) LAB_GF_PASSWORD=$(r) LAB_SESSION_PASSWORD=$(r) LAB_APPDB_PASSWORD=$(r) \
  sudo -E docker compose -p h2h up -d
sudo docker compose -p h2h ps
