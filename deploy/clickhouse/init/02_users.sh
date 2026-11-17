#!/bin/bash
# Cria o usuário somente leitura usado pelo Grafana.
set -e
clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -n <<SQL
CREATE USER IF NOT EXISTS grafana IDENTIFIED WITH sha256_password BY '${GRAFANA_CH_PASSWORD:-grafana}' SETTINGS readonly = 2;
GRANT SELECT ON dnp3.* TO grafana;
SQL
