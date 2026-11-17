#!/bin/bash
# Instala a partir do pacote gerado por tools/bundle.sh (sem internet).
set -euo pipefail
cd "$(dirname "$0")/.."
IMG=../images.tar.gz
[ -f "$IMG" ] && { echo "== carregando imagens"; gunzip -c "$IMG" | docker load; }
cd deploy
[ -f .env ] || { cp .env.example .env; echo "Edite deploy/.env (interfaces, senhas, DATA_DIR) e rode de novo."; exit 0; }
./setup.sh
docker compose up -d
docker compose ps
