-- GERADO por tools/gen_schema.py (não edite à mão as tabelas de estatística)
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
    pkts_m2o UInt32,
    pkts_o2m UInt32,
    bytes_m2o UInt64,
    bytes_o2m UInt64,
    tcp_syn UInt32,
    tcp_syn_retry UInt32,
    tcp_connects UInt32,
    tcp_connect_fail UInt32,
    tcp_resets UInt32,
    tcp_closes UInt32,
    tcp_retrans UInt32,
    tcp_gaps UInt32,
    tcp_keepalive UInt32,
    tcp_zero_win UInt32,
    tcp_rtt_sum_ms Float64,
    tcp_rtt_cnt UInt32,
    tcp_rtt_max_ms Float32,
    link_frames UInt32,
    link_crc_err UInt32,
    link_garbage_bytes UInt32,
    link_status_req UInt32,
    link_status_resp UInt32,
    link_status_timeout UInt32,
    link_rtt_sum_ms Float64,
    link_rtt_cnt UInt32,
    link_resets UInt32,
    link_nack UInt32,
    link_retries UInt32,
    transport_err UInt32,
    app_req UInt32,
    app_resp UInt32,
    app_unsol UInt32,
    app_unsol_null UInt32,
    app_confirm UInt32,
    app_timeouts UInt32,
    app_retries UInt32,
    app_late_resp UInt32,
    app_unexpected_resp UInt32,
    app_parse_err UInt32,
    app_rejected UInt32,
    unsol_retries UInt32,
    unsol_confirm_missing UInt32,
    resp_confirm_missing UInt32,
    resp_sum_ms Float64,
    resp_cnt UInt32,
    resp_max_ms Float32,
    integrity_req UInt32,
    integrity_ok UInt32,
    event_poll_req UInt32,
    time_syncs UInt32,
    sensitive_fc UInt32,
    iin_restart UInt32,
    iin_need_time UInt32,
    iin_local UInt32,
    iin_trouble UInt32,
    iin_overflow UInt32,
    iin_config_corrupt UInt32,
    cmd_total UInt32,
    cmd_ok UInt32,
    cmd_fail UInt32,
    pt_events UInt32,
    pt_static_changes UInt32,
    pt_bin_changes UInt32,
    pt_bad_quality UInt32,
    lost_event_suspect UInt32,
    chatter UInt32,
    ev_bad_time UInt32,
    ev_delay_cnt UInt32,
    ev_delay_sum_ms Float64,
    ev_delay_min_ms Float64,
    ev_delay_max_ms Float64
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
    pkts_m2o SimpleAggregateFunction(sum, UInt64),
    pkts_o2m SimpleAggregateFunction(sum, UInt64),
    bytes_m2o SimpleAggregateFunction(sum, UInt64),
    bytes_o2m SimpleAggregateFunction(sum, UInt64),
    tcp_syn SimpleAggregateFunction(sum, UInt64),
    tcp_syn_retry SimpleAggregateFunction(sum, UInt64),
    tcp_connects SimpleAggregateFunction(sum, UInt64),
    tcp_connect_fail SimpleAggregateFunction(sum, UInt64),
    tcp_resets SimpleAggregateFunction(sum, UInt64),
    tcp_closes SimpleAggregateFunction(sum, UInt64),
    tcp_retrans SimpleAggregateFunction(sum, UInt64),
    tcp_gaps SimpleAggregateFunction(sum, UInt64),
    tcp_keepalive SimpleAggregateFunction(sum, UInt64),
    tcp_zero_win SimpleAggregateFunction(sum, UInt64),
    tcp_rtt_sum_ms SimpleAggregateFunction(sum, Float64),
    tcp_rtt_cnt SimpleAggregateFunction(sum, UInt64),
    tcp_rtt_max_ms SimpleAggregateFunction(max, Float32),
    link_frames SimpleAggregateFunction(sum, UInt64),
    link_crc_err SimpleAggregateFunction(sum, UInt64),
    link_garbage_bytes SimpleAggregateFunction(sum, UInt64),
    link_status_req SimpleAggregateFunction(sum, UInt64),
    link_status_resp SimpleAggregateFunction(sum, UInt64),
    link_status_timeout SimpleAggregateFunction(sum, UInt64),
    link_rtt_sum_ms SimpleAggregateFunction(sum, Float64),
    link_rtt_cnt SimpleAggregateFunction(sum, UInt64),
    link_resets SimpleAggregateFunction(sum, UInt64),
    link_nack SimpleAggregateFunction(sum, UInt64),
    link_retries SimpleAggregateFunction(sum, UInt64),
    transport_err SimpleAggregateFunction(sum, UInt64),
    app_req SimpleAggregateFunction(sum, UInt64),
    app_resp SimpleAggregateFunction(sum, UInt64),
    app_unsol SimpleAggregateFunction(sum, UInt64),
    app_unsol_null SimpleAggregateFunction(sum, UInt64),
    app_confirm SimpleAggregateFunction(sum, UInt64),
    app_timeouts SimpleAggregateFunction(sum, UInt64),
    app_retries SimpleAggregateFunction(sum, UInt64),
    app_late_resp SimpleAggregateFunction(sum, UInt64),
    app_unexpected_resp SimpleAggregateFunction(sum, UInt64),
    app_parse_err SimpleAggregateFunction(sum, UInt64),
    app_rejected SimpleAggregateFunction(sum, UInt64),
    unsol_retries SimpleAggregateFunction(sum, UInt64),
    unsol_confirm_missing SimpleAggregateFunction(sum, UInt64),
    resp_confirm_missing SimpleAggregateFunction(sum, UInt64),
    resp_sum_ms SimpleAggregateFunction(sum, Float64),
    resp_cnt SimpleAggregateFunction(sum, UInt64),
    resp_max_ms SimpleAggregateFunction(max, Float32),
    integrity_req SimpleAggregateFunction(sum, UInt64),
    integrity_ok SimpleAggregateFunction(sum, UInt64),
    event_poll_req SimpleAggregateFunction(sum, UInt64),
    time_syncs SimpleAggregateFunction(sum, UInt64),
    sensitive_fc SimpleAggregateFunction(sum, UInt64),
    iin_restart SimpleAggregateFunction(sum, UInt64),
    iin_need_time SimpleAggregateFunction(sum, UInt64),
    iin_local SimpleAggregateFunction(sum, UInt64),
    iin_trouble SimpleAggregateFunction(sum, UInt64),
    iin_overflow SimpleAggregateFunction(sum, UInt64),
    iin_config_corrupt SimpleAggregateFunction(sum, UInt64),
    cmd_total SimpleAggregateFunction(sum, UInt64),
    cmd_ok SimpleAggregateFunction(sum, UInt64),
    cmd_fail SimpleAggregateFunction(sum, UInt64),
    pt_events SimpleAggregateFunction(sum, UInt64),
    pt_static_changes SimpleAggregateFunction(sum, UInt64),
    pt_bin_changes SimpleAggregateFunction(sum, UInt64),
    pt_bad_quality SimpleAggregateFunction(sum, UInt64),
    lost_event_suspect SimpleAggregateFunction(sum, UInt64),
    chatter SimpleAggregateFunction(sum, UInt64),
    ev_bad_time SimpleAggregateFunction(sum, UInt64),
    ev_delay_cnt SimpleAggregateFunction(sum, UInt64),
    ev_delay_sum_ms SimpleAggregateFunction(sum, Float64),
    ev_delay_min_ms SimpleAggregateFunction(min, Float64),
    ev_delay_max_ms SimpleAggregateFunction(max, Float64)
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
    toUInt64(sum(s.pkts_m2o)) AS pkts_m2o,
    toUInt64(sum(s.pkts_o2m)) AS pkts_o2m,
    toUInt64(sum(s.bytes_m2o)) AS bytes_m2o,
    toUInt64(sum(s.bytes_o2m)) AS bytes_o2m,
    toUInt64(sum(s.tcp_syn)) AS tcp_syn,
    toUInt64(sum(s.tcp_syn_retry)) AS tcp_syn_retry,
    toUInt64(sum(s.tcp_connects)) AS tcp_connects,
    toUInt64(sum(s.tcp_connect_fail)) AS tcp_connect_fail,
    toUInt64(sum(s.tcp_resets)) AS tcp_resets,
    toUInt64(sum(s.tcp_closes)) AS tcp_closes,
    toUInt64(sum(s.tcp_retrans)) AS tcp_retrans,
    toUInt64(sum(s.tcp_gaps)) AS tcp_gaps,
    toUInt64(sum(s.tcp_keepalive)) AS tcp_keepalive,
    toUInt64(sum(s.tcp_zero_win)) AS tcp_zero_win,
    toFloat64(sum(s.tcp_rtt_sum_ms)) AS tcp_rtt_sum_ms,
    toUInt64(sum(s.tcp_rtt_cnt)) AS tcp_rtt_cnt,
    max(s.tcp_rtt_max_ms) AS tcp_rtt_max_ms,
    toUInt64(sum(s.link_frames)) AS link_frames,
    toUInt64(sum(s.link_crc_err)) AS link_crc_err,
    toUInt64(sum(s.link_garbage_bytes)) AS link_garbage_bytes,
    toUInt64(sum(s.link_status_req)) AS link_status_req,
    toUInt64(sum(s.link_status_resp)) AS link_status_resp,
    toUInt64(sum(s.link_status_timeout)) AS link_status_timeout,
    toFloat64(sum(s.link_rtt_sum_ms)) AS link_rtt_sum_ms,
    toUInt64(sum(s.link_rtt_cnt)) AS link_rtt_cnt,
    toUInt64(sum(s.link_resets)) AS link_resets,
    toUInt64(sum(s.link_nack)) AS link_nack,
    toUInt64(sum(s.link_retries)) AS link_retries,
    toUInt64(sum(s.transport_err)) AS transport_err,
    toUInt64(sum(s.app_req)) AS app_req,
    toUInt64(sum(s.app_resp)) AS app_resp,
    toUInt64(sum(s.app_unsol)) AS app_unsol,
    toUInt64(sum(s.app_unsol_null)) AS app_unsol_null,
    toUInt64(sum(s.app_confirm)) AS app_confirm,
    toUInt64(sum(s.app_timeouts)) AS app_timeouts,
    toUInt64(sum(s.app_retries)) AS app_retries,
    toUInt64(sum(s.app_late_resp)) AS app_late_resp,
    toUInt64(sum(s.app_unexpected_resp)) AS app_unexpected_resp,
    toUInt64(sum(s.app_parse_err)) AS app_parse_err,
    toUInt64(sum(s.app_rejected)) AS app_rejected,
    toUInt64(sum(s.unsol_retries)) AS unsol_retries,
    toUInt64(sum(s.unsol_confirm_missing)) AS unsol_confirm_missing,
    toUInt64(sum(s.resp_confirm_missing)) AS resp_confirm_missing,
    toFloat64(sum(s.resp_sum_ms)) AS resp_sum_ms,
    toUInt64(sum(s.resp_cnt)) AS resp_cnt,
    max(s.resp_max_ms) AS resp_max_ms,
    toUInt64(sum(s.integrity_req)) AS integrity_req,
    toUInt64(sum(s.integrity_ok)) AS integrity_ok,
    toUInt64(sum(s.event_poll_req)) AS event_poll_req,
    toUInt64(sum(s.time_syncs)) AS time_syncs,
    toUInt64(sum(s.sensitive_fc)) AS sensitive_fc,
    toUInt64(sum(s.iin_restart)) AS iin_restart,
    toUInt64(sum(s.iin_need_time)) AS iin_need_time,
    toUInt64(sum(s.iin_local)) AS iin_local,
    toUInt64(sum(s.iin_trouble)) AS iin_trouble,
    toUInt64(sum(s.iin_overflow)) AS iin_overflow,
    toUInt64(sum(s.iin_config_corrupt)) AS iin_config_corrupt,
    toUInt64(sum(s.cmd_total)) AS cmd_total,
    toUInt64(sum(s.cmd_ok)) AS cmd_ok,
    toUInt64(sum(s.cmd_fail)) AS cmd_fail,
    toUInt64(sum(s.pt_events)) AS pt_events,
    toUInt64(sum(s.pt_static_changes)) AS pt_static_changes,
    toUInt64(sum(s.pt_bin_changes)) AS pt_bin_changes,
    toUInt64(sum(s.pt_bad_quality)) AS pt_bad_quality,
    toUInt64(sum(s.lost_event_suspect)) AS lost_event_suspect,
    toUInt64(sum(s.chatter)) AS chatter,
    toUInt64(sum(s.ev_bad_time)) AS ev_bad_time,
    toUInt64(sum(s.ev_delay_cnt)) AS ev_delay_cnt,
    toFloat64(sum(s.ev_delay_sum_ms)) AS ev_delay_sum_ms,
    min(if(s.ev_delay_cnt > 0, s.ev_delay_min_ms, inf)) AS ev_delay_min_ms,
    max(s.ev_delay_max_ms) AS ev_delay_max_ms
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
