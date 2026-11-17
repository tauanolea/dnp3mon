#!/usr/bin/env python3
"""Gera deploy/clickhouse/init/01_schema.sql a partir de internal/model/model.go
(as colunas de rtu_stats_1m acompanham a struct Stats)."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = open(os.path.join(ROOT, "internal/model/model.go")).read()
stats = src[src.index("type Stats struct"):]
stats = stats[: stats.index("\n}\n")]
cols = re.findall(r"^\s+\w+\s+(\w+)\s+`json:\"(\w+)\"`", stats, re.M)

GO2CH = {"uint8": "UInt8", "uint16": "UInt16", "uint32": "UInt32", "uint64": "UInt64",
         "float32": "Float32", "float64": "Float64", "string": "String"}
KEYS = {"minute", "rtu", "online", "iin", "active_master"}

stat_cols, hour_cols, hour_sel = [], [], []
for gotype, name in cols:
    if name in KEYS:
        continue
    ch = GO2CH[gotype]
    stat_cols.append(f"    {name} {ch}")
    if name.endswith("_max_ms"):
        fn = "max"
    elif name.endswith("_min_ms"):
        fn = "min"
    else:
        fn = "sum"
    agg_t = ch
    if fn == "sum":
        agg_t = "Float64" if ch.startswith("Float") else "UInt64"
    hour_cols.append(f"    {name} SimpleAggregateFunction({fn}, {agg_t})")
    if fn == "min":
        hour_sel.append(f"    min(if(s.ev_delay_cnt > 0, s.{name}, inf)) AS {name}" if name == "ev_delay_min_ms" else f"    min(s.{name}) AS {name}")
    elif fn == "sum":
        hour_sel.append(f"    toFloat64(sum(s.{name})) AS {name}" if agg_t == "Float64" else f"    toUInt64(sum(s.{name})) AS {name}")
    else:
        hour_sel.append(f"    {fn}(s.{name}) AS {name}")

sql = f"""-- GERADO por tools/gen_schema.py (não edite à mão as tabelas de estatística)
CREATE DATABASE IF NOT EXISTS dnp3;

-- Mensagens DNP3 (um APDU completo ou frame de enlace por linha)
CREATE TABLE IF NOT EXISTS dnp3.messages
(
    ts DateTime64(6, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    rtu LowCardinality(String),
    rtu_ip LowCardinality(String),
    rtu_port UInt16,
    master LowCardinality(String),
    dir Enum8('M2O' = 1, 'O2M' = 2),
    layer Enum8('app' = 1, 'link' = 2),
    link_src UInt16,
    link_dst UInt16,
    link_fc LowCardinality(String),
    fc UInt8,
    fc_name LowCardinality(String),
    kind LowCardinality(String),
    req_kind LowCardinality(String),
    seq UInt8,
    fir UInt8,
    fin UInt8,
    con UInt8,
    uns UInt8,
    iin UInt16,
    iin_flags Array(LowCardinality(String)),
    objects Array(LowCardinality(String)),
    n_points UInt16,
    size UInt16,
    frags UInt8,
    resp_ms Nullable(Float32),
    retry UInt8,
    dup UInt8,
    late UInt8,
    err LowCardinality(String),
    summary String CODEC(ZSTD(3)),
    pcap_file LowCardinality(String),
    INDEX idx_kind kind TYPE set(64) GRANULARITY 4,
    INDEX idx_fc fc TYPE set(64) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (rtu, ts)
TTL toDateTime(ts) + INTERVAL 90 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;

-- Valores de pontos: eventos e mudanças de estáticos
CREATE TABLE IF NOT EXISTS dnp3.points
(
    ts DateTime64(6, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    rtu LowCardinality(String),
    type LowCardinality(String),
    idx UInt32,
    value Float64 CODEC(Gorilla, ZSTD(1)),
    flags UInt8,
    online UInt8,
    is_event UInt8,
    src LowCardinality(String),
    event_ts Nullable(DateTime64(3, 'UTC')),
    gv LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (rtu, type, idx, ts)
TTL toDateTime(ts) + INTERVAL 90 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;

-- Último valor de cada ponto (consultar com FINAL)
CREATE TABLE IF NOT EXISTS dnp3.point_last
(
    rtu LowCardinality(String),
    type LowCardinality(String),
    idx UInt32,
    ts DateTime64(6, 'UTC'),
    value Float64,
    flags UInt8,
    src LowCardinality(String)
)
ENGINE = ReplacingMergeTree(ts)
ORDER BY (rtu, type, idx);

CREATE MATERIALIZED VIEW IF NOT EXISTS dnp3.point_last_mv TO dnp3.point_last AS
SELECT rtu, type, idx, ts, value, flags, src FROM dnp3.points;

-- Ciclo de vida dos comandos
CREATE TABLE IF NOT EXISTS dnp3.commands
(
    ts DateTime64(6, 'UTC'),
    rtu LowCardinality(String),
    master LowCardinality(String),
    type LowCardinality(String),
    idx UInt32,
    op LowCardinality(String),
    value Float64,
    mode LowCardinality(String),
    select_ts Nullable(DateTime64(6, 'UTC')),
    select_status LowCardinality(String),
    operate_ts Nullable(DateTime64(6, 'UTC')),
    resp_ts Nullable(DateTime64(6, 'UTC')),
    status LowCardinality(String),
    result LowCardinality(String),
    duration_ms Nullable(Float32),
    select_to_operate_ms Nullable(Float32),
    echo_ok UInt8,
    feedback_point LowCardinality(String),
    feedback_ms Nullable(Float32),
    retries UInt8,
    detail String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (rtu, ts)
TTL toDateTime(ts) + INTERVAL 730 DAY DELETE;

-- Eventos (transições, falhas, segurança)
CREATE TABLE IF NOT EXISTS dnp3.events
(
    ts DateTime64(6, 'UTC'),
    rtu LowCardinality(String),
    master LowCardinality(String),
    category LowCardinality(String),
    event LowCardinality(String),
    severity LowCardinality(String),
    value Float64,
    detail String,
    INDEX idx_event event TYPE set(128) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (rtu, ts)
TTL toDateTime(ts) + INTERVAL 365 DAY DELETE;

-- Indicadores por RTU por minuto (emitidos pelo dnp3mon)
CREATE TABLE IF NOT EXISTS dnp3.rtu_stats_1m
(
    minute DateTime('UTC'),
    rtu LowCardinality(String),
    online UInt8,
    iin UInt16,
    active_master LowCardinality(String),
{",\n".join(stat_cols)}
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (rtu, minute)
TTL minute + INTERVAL 90 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;

-- Agregado por hora (histórico longo, 2 anos)
CREATE TABLE IF NOT EXISTS dnp3.rtu_stats_1h
(
    hour DateTime('UTC'),
    rtu LowCardinality(String),
    minutes SimpleAggregateFunction(sum, UInt64),
    online_minutes SimpleAggregateFunction(sum, UInt64),
    iin_or SimpleAggregateFunction(groupBitOr, UInt16),
{",\n".join(hour_cols)}
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (rtu, hour)
TTL hour + INTERVAL 730 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS dnp3.rtu_stats_1h_mv TO dnp3.rtu_stats_1h AS
SELECT
    toStartOfHour(s.minute) AS hour,
    s.rtu AS rtu,
    toUInt64(count()) AS minutes,
    toUInt64(sum(s.online)) AS online_minutes,
    groupBitOr(s.iin) AS iin_or,
{",\n".join(hour_sel)}
FROM dnp3.rtu_stats_1m AS s
GROUP BY hour, rtu;

-- Inventário (opcional): preencha com nome, subestação, região, meio etc.
-- A chave é a mesma usada pelo dnp3mon: "ip:porta" (ou só "ip" quando a RTU é cliente TCP).
CREATE TABLE IF NOT EXISTS dnp3.rtu_inventory
(
    rtu String,
    name String,
    substation String,
    region String,
    medium LowCardinality(String),
    vendor String,
    model String,
    notes String,
    updated DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated)
ORDER BY rtu;

-- Estado mais recente de cada RTU (última linha de minuto)
CREATE VIEW IF NOT EXISTS dnp3.rtu_current AS
SELECT
    s.rtu AS rtu,
    argMax(s.online, s.minute) AS online,
    argMax(s.iin, s.minute) AS iin,
    argMax(s.active_master, s.minute) AS active_master,
    max(s.minute) AS last_minute,
    maxIf(s.minute, s.pkts_o2m > 0) AS last_rx_minute
FROM dnp3.rtu_stats_1m AS s
WHERE s.minute > now() - INTERVAL 2 DAY
GROUP BY s.rtu;
"""
out = os.path.join(ROOT, "deploy/clickhouse/init/01_schema.sql")
os.makedirs(os.path.dirname(out), exist_ok=True)
open(out, "w").write(sql)
print("ok:", out, len(stat_cols), "colunas de estatística")
