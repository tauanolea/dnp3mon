#!/usr/bin/env python3
"""Gera deploy/grafana/provisioning/alerting/dnp3_rules.yaml (regras de alerta do Grafana)."""
import json, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RULES = [
    ("dnp3-coleta-parada", "Coleta DNP3 parada", "critical", "0s", "Alerting",
     "SELECT toFloat64(count()) AS n FROM dnp3.rtu_stats_1m WHERE minute > now() - INTERVAL 4 MINUTE",
     "lt", 1, "O dnp3mon não grava indicadores há mais de 3 minutos (captura, decodificador ou banco parado)."),
    ("dnp3-rtu-offline", "RTU sem comunicação", "critical", "2m", "OK",
     "SELECT rtu, toFloat64(1) AS offline FROM dnp3.rtu_stats_1m WHERE minute > now() - INTERVAL 4 MINUTE GROUP BY rtu HAVING argMax(online, minute) = 0",
     "gt", 0, "RTU {{ $labels.rtu }} sem quadros DNP3 válidos (timeouts consecutivos ou silêncio)."),
    ("dnp3-queda-massiva", "Queda em massa de RTUs", "critical", "0s", "OK",
     "SELECT toFloat64(uniqExact(rtu)) AS n FROM dnp3.events WHERE ts > now() - INTERVAL 5 MINUTE AND event = 'comm_lost'",
     "gt", 20, "Mais de 20 RTUs perderam comunicação em 5 minutos: provável problema de telecom, FEP ou rede."),
    ("dnp3-comando-falhou", "Comando DNP3 falhou", "critical", "0s", "OK",
     "SELECT rtu, toFloat64(count()) AS falhas FROM dnp3.commands WHERE ts > now() - INTERVAL 2 MINUTE AND result NOT IN ('success', 'sent_no_ack', 'select_only') GROUP BY rtu",
     "gt", 0, "Comando falhou na RTU {{ $labels.rtu }}. Veja o dashboard DNP3 · Comandos."),
    ("dnp3-iin-critico", "Indicação IIN crítica", "warning", "0s", "OK",
     "SELECT rtu, detail AS iin, toFloat64(count()) AS n FROM dnp3.events WHERE ts > now() - INTERVAL 5 MINUTE AND event = 'iin_set' "
     "AND detail IN ('DEVICE_RESTART', 'DEVICE_TROUBLE', 'CONFIG_CORRUPT', 'EVENT_BUFFER_OVERFLOW') GROUP BY rtu, iin",
     "gt", 0, "RTU {{ $labels.rtu }} sinalizou {{ $labels.iin }}."),
    ("dnp3-seguranca", "Alerta de segurança DNP3", "critical", "0s", "OK",
     "SELECT rtu, event AS tipo, any(master) AS origem, toFloat64(count()) AS n FROM dnp3.events WHERE ts > now() - INTERVAL 5 MINUTE AND category = 'security' GROUP BY rtu, tipo",
     "gt", 0, "{{ $labels.tipo }} na RTU {{ $labels.rtu }} vindo de {{ $labels.origem }}."),
    ("dnp3-perda-captura", "Perda de pacotes no espelhamento", "warning", "5m", "OK",
     "SELECT toFloat64(sum(tcp_gaps)) AS lacunas FROM dnp3.rtu_stats_1m WHERE minute > now() - INTERVAL 5 MINUTE",
     "gt", 50, "Lacunas de sequência TCP indicam que o SPAN/TAP está perdendo pacotes."),
    ("dnp3-chattering", "Ponto em chattering", "warning", "0s", "OK",
     "SELECT rtu, toFloat64(count()) AS n FROM dnp3.events WHERE ts > now() - INTERVAL 10 MINUTE AND event = 'chatter' GROUP BY rtu",
     "gt", 0, "Chattering na RTU {{ $labels.rtu }}."),
]

out = ["apiVersion: 1", "groups:", "  - orgId: 1", "    name: dnp3", "    folder: DNP3", "    interval: 1m", "    rules:"]
for uid, title, sev, for_, nodata, sql, op, thr, summary in RULES:
    model_a = {"refId": "A", "datasource": {"type": "grafana-clickhouse-datasource", "uid": "clickhouse"},
               "editorType": "sql", "format": 1, "queryType": "table", "rawSql": sql}
    model_b = {"refId": "B", "type": "reduce", "expression": "A", "reducer": "last", "datasource": {"type": "__expr__", "uid": "__expr__"}}
    model_c = {"refId": "C", "type": "threshold", "expression": "B", "datasource": {"type": "__expr__", "uid": "__expr__"},
               "conditions": [{"evaluator": {"type": op, "params": [thr]}}]}
    out += [f"      - uid: {uid}", f"        title: {json.dumps(title, ensure_ascii=False)}", "        condition: C", "        data:",
            "          - refId: A", "            relativeTimeRange: {from: 600, to: 0}", "            datasourceUid: clickhouse",
            f"            model: {json.dumps(model_a, ensure_ascii=False)}",
            "          - refId: B", "            datasourceUid: __expr__", f"            model: {json.dumps(model_b)}",
            "          - refId: C", "            datasourceUid: __expr__", f"            model: {json.dumps(model_c)}",
            f"        noDataState: {nodata}", "        execErrState: Error", f"        for: {for_}",
            f"        labels: {{severity: {sev}, origem: dnp3mon}}",
            f"        annotations: {{summary: {json.dumps(summary, ensure_ascii=False)}}}", "        isPaused: false"]
path = os.path.join(ROOT, "deploy/grafana/provisioning/alerting/dnp3_rules.yaml")
open(path, "w").write("\n".join(out) + "\n")
print("ok:", path, len(RULES), "regras")
