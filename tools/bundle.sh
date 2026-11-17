#!/bin/bash
# Gera um pacote autocontido para instalar numa VM sem internet:
#   dist/dnp3mon-bundle-<data>.tar.gz  (projeto + imagens docker salvas)
# Na VM:  tar xzf ... && cd dnp3mon && ./tools/install-offline.sh
set -euo pipefail
cd "$(dirname "$0")/.."
VER=$(date +%Y%m%d-%H%M)
OUT=dist/dnp3mon-bundle-$VER
mkdir -p "$OUT"
echo "== build da imagem dnp3mon"
docker build ${DOCKER_BUILD_ARGS:-} -t dnp3mon:latest .
echo "== salvando imagens"
docker pull clickhouse/clickhouse-server:24.8 >/dev/null 2>&1 || true
docker pull grafana/grafana:11.3.0 >/dev/null 2>&1 || true
docker save dnp3mon:latest clickhouse/clickhouse-server:24.8 grafana/grafana:11.3.0 | gzip -1 > "$OUT/images.tar.gz"
echo "== copiando projeto"
git archive --format=tar --prefix=dnp3mon/ HEAD | tar -x -C "$OUT"
cp -r deploy/grafana/plugins "$OUT/dnp3mon/deploy/grafana/" 2>/dev/null || true
tar -C dist -czf "$OUT.tar.gz" "$(basename "$OUT")"
rm -rf "$OUT"
ls -lh "$OUT.tar.gz"
