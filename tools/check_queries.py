#!/usr/bin/env python3
"""Executa todas as consultas dos dashboards no ClickHouse (substituindo as macros
do Grafana) para garantir que estão corretas.  Uso:
  python3 tools/check_queries.py http://usuario:senha@127.0.0.1:8123 [rtu]
"""
import base64, glob, json, os, re, sys, urllib.request

url = sys.argv[1] if len(sys.argv) > 1 else "http://dnp3mon:dnp3mon@127.0.0.1:8123"
m = re.match(r"(https?://)(?:([^:@]+):([^@]*)@)?(.*)", url)
base, user, pw = m.group(1) + m.group(4), m.group(2), m.group(3)

def q(sql):
    req = urllib.request.Request(base.rstrip("/") + "/?default_format=JSONCompact", data=sql.encode())
    if user:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode())
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or b"{}")

rng = q("SELECT toUnixTimestamp(min(minute)), toUnixTimestamp(max(minute)) + 60 FROM dnp3.rtu_stats_1m")["data"][0]
rtu = sys.argv[2] if len(sys.argv) > 2 else q("SELECT rtu FROM dnp3.commands GROUP BY rtu ORDER BY count() DESC LIMIT 1")["data"][0][0]
pts = q(f"SELECT concat(type, ':', toString(idx)) FROM dnp3.point_last FINAL WHERE rtu = '{rtu}' LIMIT 3")["data"]
ptlist = ",".join(f"'{p[0]}'" for p in pts) or "''"
f, t = f"toDateTime({rng[0]})", f"toDateTime({rng[1]})"

def sub(sql):
    sql = re.sub(r"\$__timeFilter\(([^)]+)\)", lambda m: f"({m.group(1)} >= {f} AND {m.group(1)} <= {t})", sql)
    sql = re.sub(r"\$__timeInterval\(([^)]+)\)", lambda m: f"toStartOfInterval(toDateTime({m.group(1)}), INTERVAL 60 second)", sql)
    return (sql.replace("$__interval_s", "60").replace("$__fromTime", f).replace("$__toTime", t)
               .replace("${ponto:singlequote}", ptlist).replace("${rtu}", rtu))

bad = 0
for path in sorted(glob.glob(os.path.join(os.path.dirname(__file__), "../deploy/grafana/dashboards/*.json"))):
    d = json.load(open(path))
    for v in d["templating"]["list"]:
        if v.get("type") == "query":
            try:
                n = len(q(sub(v["query"]))["data"])
                print(f"   var {v['name']}: {n} valores")
            except Exception as e:
                bad += 1
                print(f"ERRO var {v['name']}: {getattr(e, 'read', lambda: str(e).encode())()[:300]}")
    for p in d["panels"]:
        for tg in p.get("targets", []):
            try:
                r = q(sub(tg["rawSql"]))
                n = r.get("rows", 0)
                first = r["data"][0] if r.get("data") else None
                print(f"ok  {os.path.basename(path)[:14]} | {p['title'][:48]:48} | {n:5} linhas | {str(first)[:70]}")
            except Exception as e:
                bad += 1
                msg = e.read().decode()[:400] if hasattr(e, "read") else str(e)
                print(f"ERRO {os.path.basename(path)} | {p['title']}: {msg}")
print("rtu de teste:", rtu, "| erros:", bad)
sys.exit(1 if bad else 0)
