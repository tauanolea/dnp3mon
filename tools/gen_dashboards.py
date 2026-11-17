#!/usr/bin/env python3
"""Gera os dashboards do Grafana (deploy/grafana/dashboards/*.json).

Edite as consultas aqui e rode:  python3 tools/gen_dashboards.py
O script tools/check_queries.py executa todas as consultas no ClickHouse para validar.
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "deploy/grafana/dashboards")
DS = {"type": "grafana-clickhouse-datasource", "uid": "clickhouse"}

INV = "LEFT JOIN (SELECT rtu, name, medium, region FROM dnp3.rtu_inventory FINAL) AS inv ON inv.rtu = toString(s.rtu)"
RTU_LINK = [{"title": "Detalhe da RTU ${__value.raw}", "url": "/d/dnp3-rtu/dnp3-detalhe-da-rtu?var-rtu=${__value.raw}&${__url_time_range}"}]

IIN_NAMES = """arrayFilter(x -> x != '', [
  if(bitTest(iin, 15), 'RESTART', ''), if(bitTest(iin, 14), 'TROUBLE', ''),
  if(bitTest(iin, 13), 'LOCAL', ''), if(bitTest(iin, 12), 'NEED_TIME', ''),
  if(bitTest(iin, 5), 'CONFIG_CORRUPT', ''), if(bitTest(iin, 3), 'EVENT_OVERFLOW', '')])"""


class Dash:
    def __init__(self, uid, title, desc, variables=None, links=None):
        self.uid, self.title, self.desc = uid, title, desc
        self.panels, self.y, self.x, self.rowh = [], 0, 0, 0
        self.vars = variables or []
        self.links = links or []
        self.id = 1

    def _place(self, w, h):
        if self.x + w > 24:
            self.y += self.rowh
            self.x, self.rowh = 0, 0
        pos = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.x += w
        self.rowh = max(self.rowh, h)
        return pos

    def row(self, title):
        if self.x:
            self.y += self.rowh
            self.x, self.rowh = 0, 0
        self.panels.append({"type": "row", "title": title, "id": self.id, "collapsed": False,
                            "gridPos": {"x": 0, "y": self.y, "w": 24, "h": 1}, "panels": []})
        self.id += 1
        self.y += 1

    def add(self, typ, title, sql, w, h, fmt="table", desc="", unit=None, extra=None, field=None, overrides=None, opts=None, links=None):
        q = {"datasource": DS, "editorType": "sql", "format": 0 if fmt == "timeseries" else 1,
             "queryType": "timeseries" if fmt == "timeseries" else "table", "rawSql": sql.strip(), "refId": "A"}
        defaults = {"unit": unit} if unit else {}
        if field:
            defaults.update(field)
        if links:
            defaults["links"] = links
        p = {"type": typ, "title": title, "description": desc, "id": self.id, "datasource": DS,
             "gridPos": self._place(w, h), "targets": [q],
             "fieldConfig": {"defaults": defaults, "overrides": overrides or []}, "options": opts or {}}
        if extra:
            p.update(extra)
        self.id += 1
        self.panels.append(p)
        return p

    def stat(self, title, sql, w=3, h=4, unit=None, color="blue", thresholds=None, desc="", decimals=None):
        field = {"color": {"mode": "thresholds" if thresholds else "fixed", "fixedColor": color}}
        if thresholds:
            field["thresholds"] = {"mode": "absolute", "steps": thresholds}
        if decimals is not None:
            field["decimals"] = decimals
        return self.add("stat", title, sql, w, h, unit=unit, field=field, desc=desc,
                        opts={"reduceOptions": {"calcs": ["lastNotNull"], "fields": "/.*/", "values": False},
                              "colorMode": "value", "graphMode": "none", "textMode": "value", "justifyMode": "center"})

    def ts(self, title, sql, w=12, h=8, unit=None, stack=False, bars=False, desc="", overrides=None):
        custom = {"drawStyle": "bars" if bars else "line", "lineWidth": 1, "fillOpacity": 60 if bars else 12,
                  "showPoints": "never", "spanNulls": False, "stacking": {"mode": "normal" if stack else "none"}}
        return self.add("timeseries", title, sql, w, h, fmt="timeseries", unit=unit, desc=desc,
                        field={"custom": custom, "color": {"mode": "palette-classic"}}, overrides=overrides,
                        opts={"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi", "sort": "desc"}})

    def table(self, title, sql, w=24, h=9, desc="", overrides=None, sort=None):
        opts = {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}}
        if sort:
            opts["sortBy"] = [{"displayName": sort[0], "desc": sort[1]}]
        return self.add("table", title, sql, w, h, desc=desc, overrides=overrides, opts=opts,
                        field={"custom": {"align": "auto", "filterable": True}})

    def text(self, title, content, w=24, h=3):
        self.panels.append({"type": "text", "title": title, "id": self.id, "gridPos": self._place(w, h),
                            "options": {"mode": "markdown", "content": content}})
        self.id += 1

    def json(self):
        return {"uid": self.uid, "title": self.title, "description": self.desc, "tags": ["dnp3"],
                "timezone": "browser", "schemaVersion": 39, "version": 1, "editable": True,
                "refresh": "30s", "time": {"from": "now-6h", "to": "now"}, "graphTooltip": 1,
                "templating": {"list": self.vars}, "links": self.links, "panels": self.panels,
                "annotations": {"list": []}}


def link_col(name, links):
    return {"matcher": {"id": "byName", "options": name}, "properties": [{"id": "links", "value": links}]}


def color_col(name, mapping):
    steps = []
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "custom.cellOptions", "value": {"type": "color-text"}},
                           {"id": "mappings", "value": [{"type": "value", "options": {k: {"color": v, "index": i} for i, (k, v) in enumerate(mapping.items())}}]}]}


def unit_col(name, unit, decimals=None):
    props = [{"id": "unit", "value": unit}]
    if decimals is not None:
        props.append({"id": "decimals", "value": decimals})
    return {"matcher": {"id": "byName", "options": name}, "properties": props}


def gauge_col(name, thresholds):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
                           {"id": "thresholds", "value": {"mode": "absolute", "steps": thresholds}}]}


RED_GREEN = [{"color": "red", "value": None}, {"color": "orange", "value": 95}, {"color": "green", "value": 99}]
GOOD_LOW = [{"color": "green", "value": None}, {"color": "orange", "value": 1}, {"color": "red", "value": 10}]

common_links = [{"title": "DNP3", "type": "dashboards", "tags": ["dnp3"], "asDropdown": True, "includeVars": False, "keepTime": True}]
api_var = {"name": "api", "label": "API dnp3mon", "type": "textbox", "query": "http://localhost:8080",
           "current": {"text": "http://localhost:8080", "value": "http://localhost:8080"}, "hide": 0}

# Atualidade relativa ao fim do intervalo selecionado (permite olhar o passado)
NOW_WIN = "minute <= $__toTime AND minute >= (SELECT max(minute) FROM dnp3.rtu_stats_1m WHERE minute <= $__toTime AND minute > $__toTime - INTERVAL 1 DAY) - INTERVAL 2 MINUTE"

# =========================================================================
# 1. Visão geral da frota
# =========================================================================
d = Dash("dnp3-overview", "DNP3 · Visão geral da frota",
         "Saúde da comunicação DNP3 entre os FEPs do ADMS e as RTUs", [api_var], common_links)
d.row("Agora (último minuto disponível do intervalo)")
d.stat("RTUs online", f"SELECT countIf(o = 1) FROM (SELECT rtu, argMax(online, minute) o FROM dnp3.rtu_stats_1m WHERE {NOW_WIN} GROUP BY rtu)", color="green")
d.stat("RTUs offline", f"SELECT countIf(o = 0) FROM (SELECT rtu, argMax(online, minute) o FROM dnp3.rtu_stats_1m WHERE {NOW_WIN} GROUP BY rtu)",
       thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}, {"color": "red", "value": 50}])
d.stat("Disponibilidade no período", "SELECT 100 * sum(online) / count() FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)",
       unit="percent", thresholds=RED_GREEN, decimals=2, desc="Minutos-RTU online / minutos-RTU monitorados")
d.stat("Tráfego DNP3", "SELECT 8 * sum(bytes_m2o + bytes_o2m) / greatest(1, dateDiff('second', min(minute), max(minute)) + 60) / 1000 FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)",
       unit="Kbits", decimals=0, desc="Média no período (kbit/s), incluindo cabeçalhos")
d.stat("Tempo de resposta médio", "SELECT sum(resp_sum_ms) / sum(resp_cnt) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)", unit="ms", decimals=0)
d.stat("Timeouts", "SELECT sum(app_timeouts) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)", color="orange")
d.stat("Comandos", "SELECT count() FROM dnp3.commands WHERE $__timeFilter(ts)", color="purple")
d.stat("Sucesso dos comandos", "SELECT 100 * countIf(result IN ('success','sent_no_ack')) / count() FROM dnp3.commands WHERE $__timeFilter(ts)",
       unit="percent", thresholds=RED_GREEN, decimals=1)

d.row("Tendências")
d.ts("RTUs online × offline", """
SELECT minute AS time, sum(s.online) AS rtus_online, count() - sum(s.online) AS rtus_offline
FROM dnp3.rtu_stats_1m AS s WHERE $__timeFilter(s.minute) GROUP BY minute ORDER BY minute""", stack=True,
     overrides=[{"matcher": {"id": "byName", "options": "rtus_offline"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}]},
                {"matcher": {"id": "byName", "options": "rtus_online"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}]}])
d.ts("Mensagens por tipo (por minuto)", """
SELECT $__timeInterval(minute) AS time,
  sum(integrity_req) / (greatest($__interval_s, 60) / 60) AS integridade, sum(event_poll_req) / (greatest($__interval_s, 60) / 60) AS varredura_eventos,
  sum(app_unsol) / (greatest($__interval_s, 60) / 60) AS nao_solicitadas, sum(app_confirm) / (greatest($__interval_s, 60) / 60) AS confirmacoes,
  sum(link_status_req) / (greatest($__interval_s, 60) / 60) AS link_status, sum(cmd_total) / (greatest($__interval_s, 60) / 60) AS comandos
FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute) GROUP BY time ORDER BY time""", stack=True)
d.ts("Falhas de comunicação (por minuto)", """
SELECT $__timeInterval(minute) AS time,
  sum(app_timeouts) / (greatest($__interval_s, 60) / 60) AS timeouts, sum(app_retries) / (greatest($__interval_s, 60) / 60) AS retentativas,
  sum(unsol_retries) / (greatest($__interval_s, 60) / 60) AS nao_solic_repetidas, sum(link_status_timeout) / (greatest($__interval_s, 60) / 60) AS link_status_sem_resposta,
  sum(link_crc_err) / (greatest($__interval_s, 60) / 60) AS erros_crc, sum(tcp_retrans) / (greatest($__interval_s, 60) / 60) AS retrans_tcp,
  sum(tcp_connect_fail) / (greatest($__interval_s, 60) / 60) AS conexoes_falhas
FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute) GROUP BY time ORDER BY time""")
d.ts("Tempo de resposta da aplicação (ms)", """
SELECT $__timeInterval(ts) AS time, quantile(0.5)(resp_ms) AS p50, quantile(0.95)(resp_ms) AS p95, quantile(0.99)(resp_ms) AS p99
FROM dnp3.messages WHERE $__timeFilter(ts) AND layer = 'app' AND dir = 'O2M' AND resp_ms IS NOT NULL
GROUP BY time ORDER BY time""", unit="ms")
d.ts("Tráfego (kbit/s)", """
SELECT $__timeInterval(minute) AS time, 8 * sum(bytes_m2o) / greatest($__interval_s, 60) / 1000 AS master_para_rtu, 8 * sum(bytes_o2m) / greatest($__interval_s, 60) / 1000 AS rtu_para_master
FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute) GROUP BY time ORDER BY time""", unit="Kbits", stack=True)
d.ts("Indicadores de qualidade (por minuto)", """
SELECT $__timeInterval(minute) AS time, sum(pt_events) / (greatest($__interval_s, 60) / 60) AS eventos_pontos,
  sum(pt_bin_changes) / (greatest($__interval_s, 60) / 60) AS mudancas_binarias, sum(iin_restart) / (greatest($__interval_s, 60) / 60) AS respostas_com_restart,
  sum(iin_need_time) / (greatest($__interval_s, 60) / 60) AS respostas_need_time, sum(iin_overflow) / (greatest($__interval_s, 60) / 60) AS respostas_overflow
FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute) GROUP BY time ORDER BY time""")

d.row("RTUs que precisam de atenção")
d.table("RTUs offline agora", f"""
SELECT s.rtu AS rtu, inv.name AS nome, inv.medium AS meio,
  maxIf(s.minute, s.online = 1) AS ultimo_online,
  if(ultimo_online < toDateTime('2000-01-01'), NULL, dateDiff('minute', ultimo_online, $__toTime)) AS minutos_offline,
  argMax(s.active_master, s.minute) AS master
FROM dnp3.rtu_stats_1m AS s {INV}
WHERE s.minute > $__toTime - INTERVAL 7 DAY AND s.minute <= $__toTime
GROUP BY s.rtu, inv.name, inv.medium
HAVING argMax(s.online, s.minute) = 0
ORDER BY minutos_offline DESC""", w=10, h=10, overrides=[link_col("rtu", RTU_LINK)])
d.table("Piores RTUs no período", f"""
SELECT s.rtu AS rtu, inv.name AS nome, inv.medium AS meio,
  round(100 * sum(s.online) / count(), 2) AS disponib_pct,
  sum(s.app_timeouts) AS timeouts, sum(s.app_retries) AS retentativas,
  round(sum(s.resp_sum_ms) / nullIf(sum(s.resp_cnt), 0)) AS resp_ms,
  round(sum(s.tcp_rtt_sum_ms) / nullIf(sum(s.tcp_rtt_cnt), 0)) AS rtt_tcp_ms,
  sum(s.tcp_retrans) AS retrans_tcp, sum(s.link_crc_err) AS crc,
  sum(s.link_status_timeout) AS link_sem_resp, sum(s.cmd_fail) AS cmd_falhos
FROM dnp3.rtu_stats_1m AS s {INV}
WHERE $__timeFilter(s.minute)
GROUP BY s.rtu, inv.name, inv.medium
ORDER BY disponib_pct ASC, timeouts DESC
LIMIT 50""", w=14, h=10, overrides=[link_col("rtu", RTU_LINK), gauge_col("disponib_pct", RED_GREEN), unit_col("resp_ms", "ms"), unit_col("rtt_tcp_ms", "ms")])
d.table("Indicações IIN ativas", f"""
SELECT rtu, {IIN_NAMES.replace('iin', 'i')} AS iin_ativos, m AS ultimo_minuto
FROM (SELECT rtu, argMax(iin, minute) AS i, max(minute) AS m FROM dnp3.rtu_stats_1m WHERE {NOW_WIN} GROUP BY rtu)
WHERE i != 0 ORDER BY rtu""", w=10, h=9, overrides=[link_col("rtu", RTU_LINK)],
        desc="Bits de IIN de estado na última resposta: reinício, problema no equipamento, modo LOCAL, sem hora, configuração corrompida, estouro de buffer de eventos")
d.table("Eventos críticos e alertas", """
SELECT ts, rtu, severity AS sev, category AS cat, event AS evento, detail AS detalhe
FROM dnp3.events WHERE $__timeFilter(ts) AND severity IN ('crit', 'warn') AND event NOT IN ('tcp_connect_fail')
ORDER BY ts DESC LIMIT 300""", w=14, h=9, overrides=[link_col("rtu", RTU_LINK), color_col("sev", {"crit": "red", "warn": "orange"})])
d.table("Distribuição por master (FEP) ativo", f"""
SELECT a AS master, count() AS rtus, countIf(o = 1) AS online
FROM (SELECT rtu, argMax(active_master, minute) AS a, argMax(online, minute) AS o FROM dnp3.rtu_stats_1m WHERE {NOW_WIN} GROUP BY rtu)
GROUP BY master ORDER BY rtus DESC""", w=8, h=7)
d.table("Por meio de comunicação (requer inventário)", f"""
SELECT ifNull(nullIf(inv.medium, ''), '(sem inventário)') AS meio, uniqExact(s.rtu) AS rtus,
  round(100 * sum(s.online) / count(), 2) AS disponib_pct,
  round(sum(s.resp_sum_ms) / nullIf(sum(s.resp_cnt), 0)) AS resp_ms,
  sum(s.app_timeouts) AS timeouts, round(1000 * sum(s.app_timeouts) / nullIf(sum(s.app_req), 0), 2) AS timeouts_por_mil
FROM dnp3.rtu_stats_1m AS s {INV}
WHERE $__timeFilter(s.minute) GROUP BY meio ORDER BY rtus DESC""", w=16, h=7, overrides=[unit_col("resp_ms", "ms")])
dashboards = [("01_visao_geral.json", d)]

# =========================================================================
# 2. Detalhe da RTU
# =========================================================================
rtu_var = {"name": "rtu", "label": "RTU (ip:porta)", "type": "query", "datasource": DS,
           "query": "SELECT DISTINCT rtu FROM dnp3.rtu_stats_1m WHERE minute > now() - INTERVAL 2 DAY ORDER BY rtu",
           "refresh": 2, "sort": 1, "includeAll": False, "multi": False, "hide": 0}
pt_var = {"name": "ponto", "label": "Pontos", "type": "query", "datasource": DS,
          "query": "SELECT concat(type, ':', toString(idx)) FROM dnp3.point_last FINAL WHERE rtu = '${rtu}' ORDER BY type, idx",
          "refresh": 1, "includeAll": False, "multi": True, "hide": 0}
d = Dash("dnp3-rtu", "DNP3 · Detalhe da RTU", "Tudo sobre uma RTU: comunicação, mensagens, pontos e comandos",
         [rtu_var, pt_var, api_var], common_links + [
             {"title": "Tráfego ao vivo desta RTU", "type": "link", "url": "${api}/?rtu=${rtu}", "targetBlank": True, "icon": "bolt"},
             {"title": "Baixar PCAP do intervalo", "type": "link", "url": "${api}/api/pcap?rtu=${rtu}&from=${__from}&to=${__to}", "targetBlank": True, "icon": "download-alt"}])
R = "rtu = '${rtu}'"
d.stat("Estado", f"SELECT if(argMax(online, minute) = 1, 'ONLINE', 'OFFLINE') FROM dnp3.rtu_stats_1m WHERE {R} AND minute <= $__toTime AND minute > $__toTime - INTERVAL 1 DAY",
       thresholds=None)
d.panels[-1]["fieldConfig"]["defaults"]["mappings"] = [{"type": "value", "options": {"ONLINE": {"color": "green"}, "OFFLINE": {"color": "red"}}}]
d.panels[-1]["fieldConfig"]["defaults"]["color"] = {"mode": "thresholds"}
d.stat("Disponibilidade", f"SELECT 100 * sum(online) / count() FROM dnp3.rtu_stats_1m WHERE {R} AND $__timeFilter(minute)", unit="percent", thresholds=RED_GREEN, decimals=2)
d.stat("Resposta média", f"SELECT sum(resp_sum_ms) / sum(resp_cnt) FROM dnp3.rtu_stats_1m WHERE {R} AND $__timeFilter(minute)", unit="ms", decimals=0)
d.stat("RTT TCP médio", f"SELECT sum(tcp_rtt_sum_ms) / sum(tcp_rtt_cnt) FROM dnp3.rtu_stats_1m WHERE {R} AND $__timeFilter(minute)", unit="ms", decimals=0)
d.stat("Timeouts", f"SELECT sum(app_timeouts) FROM dnp3.rtu_stats_1m WHERE {R} AND $__timeFilter(minute)", thresholds=GOOD_LOW, w=2)
d.stat("Quedas", f"SELECT count() FROM dnp3.events WHERE {R} AND $__timeFilter(ts) AND event = 'comm_lost'", thresholds=GOOD_LOW, w=2)
d.stat("Tempo offline", f"SELECT sum(value) FROM dnp3.events WHERE {R} AND $__timeFilter(ts) AND event = 'comm_restored'", unit="s", w=2,
       desc="Soma das quedas encerradas no intervalo (do último quadro válido até a volta)")
d.stat("Master ativo", f"SELECT argMax(active_master, minute) FROM dnp3.rtu_stats_1m WHERE {R} AND minute <= $__toTime AND minute > $__toTime - INTERVAL 1 DAY", color="text")
d.stat("IIN", f"SELECT if(empty(x), 'normal', arrayStringConcat(x, ' ')) FROM (SELECT {IIN_NAMES.replace('iin', 'argMax(iin, minute)')} AS x FROM dnp3.rtu_stats_1m WHERE {R} AND minute <= $__toTime AND minute > $__toTime - INTERVAL 1 DAY)", color="text")
d.ts("Online (1) / offline (0)", f"SELECT minute AS time, online FROM dnp3.rtu_stats_1m WHERE {R} AND $__timeFilter(minute) ORDER BY minute", w=12, h=6)
d.ts("Tempo de resposta por requisição (ms)", f"""
SELECT ts AS time, req_kind, resp_ms FROM dnp3.messages
WHERE {R} AND $__timeFilter(ts) AND dir = 'O2M' AND resp_ms IS NOT NULL ORDER BY ts""", w=12, h=6, unit="ms")
d.panels[-1]["fieldConfig"]["defaults"]["custom"].update({"drawStyle": "points", "pointSize": 4})
d.panels[-1]["fieldConfig"]["defaults"]["displayName"] = "${__field.labels.req_kind}"
d.ts("Mensagens por minuto", f"""
SELECT minute AS time, app_req AS requisicoes, app_resp AS respostas, app_unsol AS nao_solicitadas, app_confirm AS confirmacoes,
  link_status_req AS link_status, app_timeouts AS timeouts, app_retries AS retentativas
FROM dnp3.rtu_stats_1m WHERE {R} AND $__timeFilter(minute) ORDER BY minute""", w=12, h=7, bars=True)
d.ts("Rede: RTT, retransmissões e erros", f"""
SELECT minute AS time, tcp_rtt_sum_ms / nullIf(tcp_rtt_cnt, 0) AS rtt_tcp_ms, link_rtt_sum_ms / nullIf(link_rtt_cnt, 0) AS link_status_ms,
  tcp_retrans AS retrans_tcp, link_crc_err AS crc, tcp_connect_fail AS conexoes_falhas
FROM dnp3.rtu_stats_1m WHERE {R} AND $__timeFilter(minute) ORDER BY minute""", w=12, h=7,
     overrides=[{"matcher": {"id": "byRegexp", "options": ".*_ms"}, "properties": [{"id": "unit", "value": "ms"}]},
                {"matcher": {"id": "byRegexp", "options": "^(retrans_tcp|crc|conexoes_falhas)$"}, "properties": [{"id": "custom.axisPlacement", "value": "right"}, {"id": "custom.drawStyle", "value": "bars"}]}])
d.ts("Valores dos pontos selecionados", f"""
SELECT ts AS time, concat(type, ':', toString(idx)) AS ponto, value FROM dnp3.points
WHERE {R} AND $__timeFilter(ts) AND concat(type, ':', toString(idx)) IN (${{ponto:singlequote}}) ORDER BY ts""", w=12, h=8,
     desc="Escolha os pontos na variável 'Pontos'. Eventos e mudanças de estático.")
d.panels[-1]["fieldConfig"]["defaults"]["custom"].update({"lineInterpolation": "stepAfter", "showPoints": "always", "pointSize": 3, "fillOpacity": 0})
d.panels[-1]["fieldConfig"]["defaults"]["displayName"] = "${__field.labels.ponto}"
d.ts("Atraso dos eventos (relógio da RTU)", f"""
SELECT minute AS time, ev_delay_min_ms AS atraso_min_ms, ev_delay_sum_ms / ev_delay_cnt AS atraso_medio_ms
FROM dnp3.rtu_stats_1m WHERE {R} AND $__timeFilter(minute) AND ev_delay_cnt > 0 ORDER BY minute""", w=12, h=8, unit="ms",
     desc="Hora da captura menos o carimbo de tempo do evento. Mínimo negativo = relógio da RTU adiantado; mínimo muito alto = relógio atrasado ou eventos retidos.")
d.table("Comandos", f"""
SELECT ts, mode AS modo, concat(type, ':', toString(idx)) AS ponto, op AS operacao, select_status, status, result AS resultado,
  round(duration_ms) AS duracao_ms, feedback_point AS retorno, round(feedback_ms) AS retorno_ms, retries AS retent
FROM dnp3.commands WHERE {R} AND $__timeFilter(ts) ORDER BY ts DESC LIMIT 200""", w=12, h=8,
        overrides=[color_col("resultado", {"success": "green", "sent_no_ack": "green", "failed": "red", "timeout": "red", "select_failed": "red", "select_timeout": "red", "echo_mismatch": "orange", "select_only": "orange"})])
d.table("Eventos", f"""
SELECT ts, severity AS sev, category AS cat, event AS evento, detail AS detalhe, value AS valor
FROM dnp3.events WHERE {R} AND $__timeFilter(ts) ORDER BY ts DESC LIMIT 500""", w=12, h=8,
        overrides=[color_col("sev", {"crit": "red", "warn": "orange", "info": "text"})])
d.table("Últimos valores dos pontos", f"""
SELECT type AS tipo, idx AS indice, value AS valor, flags, if(bitAnd(flags, 1) = 1 OR type IN ('BOC','AOC'), 'ok', 'OFFLINE/RUIM') AS qualidade, ts AS atualizado, src AS origem
FROM dnp3.point_last FINAL WHERE {R} ORDER BY tipo, indice""", w=12, h=10,
        overrides=[color_col("qualidade", {"ok": "green", "OFFLINE/RUIM": "red"})])
d.table("Mensagens (decodificadas)", f"""
SELECT ts, dir AS sentido, kind AS tipo, seq, round(resp_ms) AS resp_ms, if(retry = 1, 'sim', '') AS retry, err AS erro, summary AS resumo, pcap_file
FROM dnp3.messages WHERE {R} AND $__timeFilter(ts) ORDER BY ts DESC LIMIT 1000""", w=24, h=12,
        overrides=[unit_col("resp_ms", "ms"), color_col("sentido", {"M2O": "blue", "O2M": "green"}),
                   {"matcher": {"id": "byName", "options": "resumo"}, "properties": [{"id": "custom.width", "value": 900}]}])
d.ts("Período entre integridades (s)", f"""
SELECT time, periodo_s FROM (
  SELECT ts AS time, dateDiff('millisecond', lagInFrame(ts) OVER (ORDER BY ts ROWS BETWEEN 1 PRECEDING AND CURRENT ROW), ts) / 1000 AS periodo_s
  FROM dnp3.messages WHERE {R} AND $__timeFilter(ts) AND dir = 'M2O' AND kind = 'integrity' AND retry = 0)
WHERE periodo_s < 86400 ORDER BY time""", w=24, h=6, unit="s",
     desc="Intervalo entre pedidos de integridade (classe 0) do master. Esperado: 300 s.")
dashboards.append(("02_detalhe_rtu.json", d))

# =========================================================================
# 3. Comandos
# =========================================================================
d = Dash("dnp3-cmds", "DNP3 · Comandos", "Comandos (CROB e saídas analógicas): resultado, tempos e retorno de estado", [api_var], common_links)
d.stat("Comandos", "SELECT count() FROM dnp3.commands WHERE $__timeFilter(ts)", color="purple")
d.stat("Sucesso", "SELECT 100 * countIf(result IN ('success','sent_no_ack')) / count() FROM dnp3.commands WHERE $__timeFilter(ts)", unit="percent", thresholds=RED_GREEN, decimals=1)
d.stat("Falharam", "SELECT countIf(result NOT IN ('success','sent_no_ack','select_only')) FROM dnp3.commands WHERE $__timeFilter(ts)", thresholds=GOOD_LOW)
d.stat("Sem resposta (timeout)", "SELECT countIf(result IN ('timeout','select_timeout')) FROM dnp3.commands WHERE $__timeFilter(ts)", thresholds=GOOD_LOW)
d.stat("Sucesso sem mudança de estado", "SELECT countIf(result = 'success' AND type = 'CROB' AND feedback_ms IS NULL) FROM dnp3.commands WHERE $__timeFilter(ts)",
       thresholds=GOOD_LOW, desc="RTU aceitou o comando, mas nenhum ponto binário mudou na janela de retorno (padrão 30 s)")
d.stat("Resposta média", "SELECT avg(duration_ms) FROM dnp3.commands WHERE $__timeFilter(ts) AND duration_ms IS NOT NULL", unit="ms", decimals=0)
d.stat("Select→Operate médio", "SELECT avg(select_to_operate_ms) FROM dnp3.commands WHERE $__timeFilter(ts)", unit="ms", decimals=0)
d.stat("Retorno de estado médio", "SELECT avg(feedback_ms) FROM dnp3.commands WHERE $__timeFilter(ts)", unit="ms", decimals=0)
d.ts("Comandos por resultado", """
SELECT $__timeInterval(ts) AS time, result, count() AS n FROM dnp3.commands WHERE $__timeFilter(ts) GROUP BY time, result ORDER BY time""", bars=True, stack=True, w=16)
d.panels[-1]["fieldConfig"]["defaults"]["displayName"] = "${__field.labels.result}"
d.table("Falhas por status", """
SELECT result AS resultado, if(status = '', select_status, status) AS status, count() AS n FROM dnp3.commands
WHERE $__timeFilter(ts) AND result NOT IN ('success','sent_no_ack') GROUP BY resultado, status ORDER BY n DESC""", w=8, h=8)
d.table("RTUs com mais falhas de comando", f"""
SELECT c.rtu AS rtu, count() AS comandos, countIf(c.result NOT IN ('success','sent_no_ack')) AS falhas,
  round(100 * falhas / comandos, 1) AS falha_pct, groupUniqArrayIf(concat(c.result, if(c.status = '' AND c.select_status = '', '', concat(':', if(c.status = '', c.select_status, c.status)))), c.result NOT IN ('success','sent_no_ack')) AS tipos_falha
FROM dnp3.commands AS c WHERE $__timeFilter(c.ts) GROUP BY c.rtu HAVING falhas > 0 ORDER BY falhas DESC LIMIT 50""", w=10, h=9,
        overrides=[link_col("rtu", RTU_LINK)])
d.add("histogram", "Tempo até a mudança de estado (ms)", "SELECT feedback_ms FROM dnp3.commands WHERE $__timeFilter(ts) AND feedback_ms IS NOT NULL", 14, 9,
      opts={"bucketCount": 30, "legend": {"showLegend": False}}, unit="ms")
d.table("Todos os comandos", """
SELECT ts, rtu, mode AS modo, concat(type, ':', toString(idx)) AS ponto, op AS operacao, select_status, status, result AS resultado,
  round(duration_ms) AS duracao_ms, round(select_to_operate_ms) AS sel_op_ms, feedback_point AS retorno, round(feedback_ms) AS retorno_ms,
  retries AS retent, master, detail AS detalhe
FROM dnp3.commands WHERE $__timeFilter(ts) ORDER BY ts DESC LIMIT 2000""", h=14,
        overrides=[link_col("rtu", RTU_LINK), color_col("resultado", {"success": "green", "sent_no_ack": "green", "failed": "red", "timeout": "red", "select_failed": "red", "select_timeout": "red", "echo_mismatch": "orange", "select_only": "orange"})])
dashboards.append(("03_comandos.json", d))

# =========================================================================
# 4. Qualidade de dados
# =========================================================================
d = Dash("dnp3-quality", "DNP3 · Qualidade de dados", "Eventos, chattering, eventos perdidos, qualidade dos pontos e relógio das RTUs", [api_var], common_links)
d.stat("Eventos de pontos", "SELECT sum(pt_events) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)")
d.stat("Mudanças binárias", "SELECT sum(pt_bin_changes) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)")
d.stat("Chattering", "SELECT count() FROM dnp3.events WHERE $__timeFilter(ts) AND event = 'chatter'", thresholds=GOOD_LOW)
d.stat("Eventos perdidos (suspeita)", "SELECT count() FROM dnp3.events WHERE $__timeFilter(ts) AND event = 'lost_event_suspect'", thresholds=GOOD_LOW,
       desc="Binário mudou na integridade sem que um evento tivesse sido reportado")
d.stat("Estouro de buffer", "SELECT uniqExactIf(rtu, iin_overflow > 0) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)", thresholds=GOOD_LOW, desc="RTUs com IIN2.3 EVENT_BUFFER_OVERFLOW")
d.stat("RTUs pedindo hora", "SELECT uniqExactIf(rtu, iin_need_time > 0) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)", thresholds=GOOD_LOW)
d.stat("Reinícios", "SELECT count() FROM dnp3.events WHERE $__timeFilter(ts) AND event = 'iin_set' AND detail = 'DEVICE_RESTART'", thresholds=GOOD_LOW)
d.stat("Carimbo de tempo inválido", "SELECT sum(ev_bad_time) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)", thresholds=GOOD_LOW)
d.table("Pontos mais ativos (candidatos a chattering)", """
SELECT rtu, type AS tipo, idx AS indice, count() AS mudancas, countIf(is_event = 1) AS eventos, min(ts) AS primeira, max(ts) AS ultima
FROM dnp3.points WHERE $__timeFilter(ts) AND type IN ('BI', 'DBI')
GROUP BY rtu, type, idx ORDER BY mudancas DESC LIMIT 50""", w=12, h=10, overrides=[link_col("rtu", RTU_LINK)])
d.table("Relógio das RTUs (atraso dos eventos)", f"""
SELECT s.rtu AS rtu, inv.medium AS meio, sum(s.ev_delay_cnt) AS eventos,
  round(minIf(s.ev_delay_min_ms, s.ev_delay_cnt > 0)) AS atraso_min_ms,
  round(sum(s.ev_delay_sum_ms) / sum(s.ev_delay_cnt)) AS atraso_medio_ms,
  multiIf(atraso_min_ms < -1000, 'RELÓGIO ADIANTADO', atraso_min_ms > 60000, 'RELÓGIO ATRASADO / EVENTOS RETIDOS', atraso_min_ms > 5000, 'atenção', 'ok') AS avaliacao
FROM dnp3.rtu_stats_1m AS s {INV}
WHERE $__timeFilter(s.minute) GROUP BY s.rtu, inv.medium HAVING eventos > 0
ORDER BY abs(atraso_min_ms) DESC LIMIT 100""", w=12, h=10,
        desc="O atraso mínimo aproxima o erro do relógio da RTU somado à latência da rede.",
        overrides=[link_col("rtu", RTU_LINK), unit_col("atraso_min_ms", "ms"), unit_col("atraso_medio_ms", "ms"),
                   color_col("avaliacao", {"RELÓGIO ADIANTADO": "red", "RELÓGIO ATRASADO / EVENTOS RETIDOS": "red", "atenção": "orange", "ok": "green"})])
d.table("Pontos com qualidade ruim agora", """
SELECT rtu, type AS tipo, idx AS indice, value AS valor, flags,
  arrayFilter(x -> x != '', [if(bitAnd(flags, 1) = 0, 'OFFLINE', ''), if(bitAnd(flags, 2) != 0, 'RESTART', ''), if(bitAnd(flags, 4) != 0, 'COMM_LOST', ''),
    if(bitAnd(flags, 8) != 0, 'REMOTE_FORCED', ''), if(bitAnd(flags, 16) != 0, 'LOCAL_FORCED', '')]) AS qualidade, ts AS atualizado
FROM dnp3.point_last FINAL WHERE type NOT IN ('BOC', 'AOC') AND (bitAnd(flags, 1) = 0 OR bitAnd(flags, 28) != 0)
ORDER BY rtu, tipo, indice LIMIT 1000""", w=12, h=10, overrides=[link_col("rtu", RTU_LINK)])
d.table("Eventos de qualidade", """
SELECT ts, rtu, event AS evento, detail AS detalhe FROM dnp3.events
WHERE $__timeFilter(ts) AND event IN ('chatter', 'lost_event_suspect', 'iin_set', 'iin_clear', 'parse_error', 'request_rejected')
ORDER BY ts DESC LIMIT 500""", w=12, h=10, overrides=[link_col("rtu", RTU_LINK)])
d.ts("Eventos e mudanças por minuto", """
SELECT $__timeInterval(minute) AS time, sum(pt_events) / (greatest($__interval_s, 60) / 60) AS eventos, sum(pt_static_changes) / (greatest($__interval_s, 60) / 60) AS mudancas_estaticos,
  sum(pt_bad_quality) / (greatest($__interval_s, 60) / 60) AS pontos_qualidade_ruim
FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute) GROUP BY time ORDER BY time""", w=24, h=7)
dashboards.append(("04_qualidade.json", d))

# =========================================================================
# 5. Rede, enlace e segurança
# =========================================================================
d = Dash("dnp3-net", "DNP3 · Rede, enlace e segurança", "TCP, camada de enlace DNP3, FEPs e segurança", [api_var], common_links)
d.stat("Retransmissões TCP", "SELECT sum(tcp_retrans) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)", color="orange")
d.stat("Lacunas na captura", "SELECT sum(tcp_gaps) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)", thresholds=GOOD_LOW,
       desc="Saltos de sequência TCP: pacotes que não chegaram ao monitor (SPAN sobrecarregado ou espelhamento incompleto)")
d.stat("Conexões abertas", "SELECT sum(tcp_connects) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)")
d.stat("Conexões falhas", "SELECT sum(tcp_connect_fail) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)", thresholds=GOOD_LOW)
d.stat("Resets TCP", "SELECT sum(tcp_resets) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)", thresholds=GOOD_LOW)
d.stat("Erros de CRC", "SELECT sum(link_crc_err) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)", thresholds=GOOD_LOW)
d.stat("Link status sem resposta", "SELECT sum(link_status_timeout) FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute)", thresholds=GOOD_LOW)
d.stat("Alertas de segurança", "SELECT count() FROM dnp3.events WHERE $__timeFilter(ts) AND category = 'security'", thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}])
d.ts("TCP (por minuto)", """
SELECT $__timeInterval(minute) AS time, sum(tcp_retrans) AS retransmissoes, sum(tcp_gaps) AS lacunas_captura, sum(tcp_resets) AS resets,
  sum(tcp_connect_fail) AS conexoes_falhas, sum(tcp_syn_retry) AS syn_repetidos, sum(tcp_connects) AS conexoes
FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute) GROUP BY time ORDER BY time""")
d.ts("Latências médias", """
SELECT $__timeInterval(minute) AS time, sum(tcp_rtt_sum_ms) / sum(tcp_rtt_cnt) AS rtt_tcp, sum(link_rtt_sum_ms) / sum(link_rtt_cnt) AS link_status,
  sum(resp_sum_ms) / sum(resp_cnt) AS resposta_aplicacao
FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute) GROUP BY time ORDER BY time""", unit="ms")
d.ts("Tráfego por master (FEP)", """
SELECT $__timeInterval(minute) AS time, active_master, 8 * sum(bytes_m2o + bytes_o2m) / greatest($__interval_s, 60) / 1000 AS kbps
FROM dnp3.rtu_stats_1m WHERE $__timeFilter(minute) AND active_master != '' GROUP BY time, active_master ORDER BY time""", unit="Kbits", stack=True)
d.panels[-1]["fieldConfig"]["defaults"]["displayName"] = "${__field.labels.active_master}"
d.table("Latência e erros por RTU", f"""
SELECT s.rtu AS rtu, inv.medium AS meio,
  round(sum(s.tcp_rtt_sum_ms) / nullIf(sum(s.tcp_rtt_cnt), 0)) AS rtt_medio_ms, round(max(s.tcp_rtt_max_ms)) AS rtt_max_ms,
  round(sum(s.link_rtt_sum_ms) / nullIf(sum(s.link_rtt_cnt), 0)) AS link_status_ms,
  sum(s.tcp_retrans) AS retrans, round(100 * sum(s.tcp_retrans) / nullIf(sum(s.pkts_m2o + s.pkts_o2m), 0), 2) AS retrans_pct,
  sum(s.link_crc_err) AS crc, sum(s.tcp_resets) AS resets, sum(s.tcp_connect_fail) AS conexoes_falhas
FROM dnp3.rtu_stats_1m AS s {INV}
WHERE $__timeFilter(s.minute) GROUP BY s.rtu, inv.medium ORDER BY rtt_medio_ms DESC LIMIT 100""", w=12, h=10,
        overrides=[link_col("rtu", RTU_LINK), unit_col("rtt_medio_ms", "ms"), unit_col("rtt_max_ms", "ms"), unit_col("link_status_ms", "ms")])
d.table("Trocas de master ativo (failover de FEP)", """
SELECT ts, rtu, detail AS detalhe FROM dnp3.events WHERE $__timeFilter(ts) AND event = 'master_change' ORDER BY ts DESC LIMIT 500""", w=12, h=10,
        overrides=[link_col("rtu", RTU_LINK)])
d.table("Segurança: masters não autorizados e funções sensíveis", """
SELECT ts, rtu, master, event AS evento, detail AS detalhe FROM dnp3.events
WHERE $__timeFilter(ts) AND category = 'security' ORDER BY ts DESC LIMIT 500""", w=12, h=8, overrides=[link_col("rtu", RTU_LINK)])
d.table("Eventos TCP", """
SELECT ts, rtu, master, event AS evento, detail AS detalhe, round(value) AS valor FROM dnp3.events
WHERE $__timeFilter(ts) AND category = 'tcp' AND event != 'tcp_connect' ORDER BY ts DESC LIMIT 1000""", w=12, h=8, overrides=[link_col("rtu", RTU_LINK)])
dashboards.append(("05_rede_seguranca.json", d))

os.makedirs(OUT, exist_ok=True)
for name, dash in dashboards:
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(dash.json(), f, ensure_ascii=False, indent=1)
    print("ok:", name, len(dash.panels), "painéis")
