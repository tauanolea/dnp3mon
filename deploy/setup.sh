#!/bin/bash
# Prepara os diretórios de dados conforme o .env (rodar uma vez, como root).
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script cria diretórios no sistema e ajusta permissões: rode com sudo:"
  echo "  sudo ./setup.sh"
  exit 1
fi
cd "$(dirname "$0")"
[ -f .env ] || { echo "crie o .env a partir do .env.example"; exit 1; }
set -a; . ./.env; set +a
D=${DATA_DIR:-./data}
mkdir -p "$D/clickhouse" "$D/grafana" "$D/dnp3mon/pcap" "$D/dnp3mon/spool"
chown -R 472:0 "$D/grafana"        # usuário do Grafana
chmod +x grafana/plugins/*/gpx_* 2>/dev/null || true
chmod 750 "$D/dnp3mon"
echo "diretórios prontos em $D"
# A(s) interface(s) de captura não devem ter IP; o dnp3mon as coloca em modo promíscuo.
for i in ${CAPTURE_IFACES//,/ }; do
  if ip -4 addr show "$i" 2>/dev/null | grep -q inet; then
    echo "ATENÇÃO: a interface $i tem IP configurado; para captura passiva recomenda-se removê-lo."
  fi
  [ -e "/sys/class/net/$i" ] || echo "ATENÇÃO: interface $i não encontrada"
done
