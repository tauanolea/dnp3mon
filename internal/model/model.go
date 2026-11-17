// Package model define as linhas gravadas no ClickHouse e publicadas ao vivo.
package model

import (
	"strconv"
	"time"
)

// Time serializa no formato aceito pelo ClickHouse DateTime64(6, 'UTC').
type Time time.Time

// MarshalJSON implementa json.Marshaler.
func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Time(t).UTC().Format("2006-01-02 15:04:05.000000") + `"`), nil
}

// T converte time.Time em *Time (nil se zero).
func T(t time.Time) *Time {
	if t.IsZero() {
		return nil
	}
	x := Time(t)
	return &x
}

// Ms converte uma duração em *float32 de milissegundos.
func Ms(d time.Duration) *float32 {
	v := float32(d.Microseconds()) / 1000
	return &v
}

// Msg é uma mensagem DNP3 (APDU completo ou frame de enlace sem dados).
type Msg struct {
	TS       Time     `json:"ts"`
	RTU      string   `json:"rtu"`
	RTUIP    string   `json:"rtu_ip"`
	RTUPort  uint16   `json:"rtu_port"`
	Master   string   `json:"master"`
	Dir      string   `json:"dir"`   // M2O | O2M
	Layer    string   `json:"layer"` // app | link
	LinkSrc  uint16   `json:"link_src"`
	LinkDst  uint16   `json:"link_dst"`
	LinkFC   string   `json:"link_fc"`
	FC       uint8    `json:"fc"`
	FCName   string   `json:"fc_name"`
	Kind     string   `json:"kind"`
	ReqKind  string   `json:"req_kind"`
	Seq      uint8    `json:"seq"`
	FIR      uint8    `json:"fir"`
	FIN      uint8    `json:"fin"`
	CON      uint8    `json:"con"`
	UNS      uint8    `json:"uns"`
	IIN      uint16   `json:"iin"`
	IINFlags []string `json:"iin_flags"`
	Objects  []string `json:"objects"`
	NPoints  uint16   `json:"n_points"`
	Size     uint16   `json:"size"`
	Frags    uint8    `json:"frags"`
	RespMs   *float32 `json:"resp_ms"`
	Retry    uint8    `json:"retry"`
	Dup      uint8    `json:"dup"`
	Late     uint8    `json:"late"`
	Err      string   `json:"err"`
	Summary  string   `json:"summary"`
	PcapFile string   `json:"pcap_file"`
}

// Point é um valor de ponto (evento ou mudança de estático).
type Point struct {
	TS      Time    `json:"ts"`
	RTU     string  `json:"rtu"`
	Type    string  `json:"type"`
	Idx     uint32  `json:"idx"`
	Value   float64 `json:"value"`
	Flags   uint8   `json:"flags"`
	Online  uint8   `json:"online"`
	IsEvent uint8   `json:"is_event"`
	Src     string  `json:"src"` // event | unsol | static
	EventTS *Time   `json:"event_ts"`
	GV      string  `json:"gv"`
}

// Command é o ciclo de vida completo de um comando.
type Command struct {
	TS            Time     `json:"ts"`
	RTU           string   `json:"rtu"`
	Master        string   `json:"master"`
	Type          string   `json:"type"` // CROB | AO
	Idx           uint32   `json:"idx"`
	Op            string   `json:"op"`
	Value         float64  `json:"value"`
	Mode          string   `json:"mode"` // SBO | DO | DO_NR | OPERATE_NO_SELECT
	SelectTS      *Time    `json:"select_ts"`
	SelectStatus  string   `json:"select_status"`
	OperateTS     *Time    `json:"operate_ts"`
	RespTS        *Time    `json:"resp_ts"`
	Status        string   `json:"status"`
	Result        string   `json:"result"`
	DurationMs    *float32 `json:"duration_ms"`
	SelectToOpMs  *float32 `json:"select_to_operate_ms"`
	EchoOK        uint8    `json:"echo_ok"`
	FeedbackPoint string   `json:"feedback_point"`
	FeedbackMs    *float32 `json:"feedback_ms"`
	Retries       uint8    `json:"retries"`
	Detail        string   `json:"detail"`
}

// Event é um acontecimento relevante (transição, falha, segurança...).
type Event struct {
	TS       Time    `json:"ts"`
	RTU      string  `json:"rtu"`
	Master   string  `json:"master"`
	Category string  `json:"category"` // tcp, link, app, iin, comm, cmd, data, time, security
	Event    string  `json:"event"`
	Severity string  `json:"severity"` // info | warn | crit
	Value    float64 `json:"value"`
	Detail   string  `json:"detail"`
	LiveOnly bool    `json:"-"`
}

// Stats são contadores por RTU por minuto.
type Stats struct {
	Minute       Time   `json:"minute"`
	RTU          string `json:"rtu"`
	Online       uint8  `json:"online"`
	IIN          uint16 `json:"iin"`
	ActiveMaster string `json:"active_master"`

	PktsM2O  uint32 `json:"pkts_m2o"`
	PktsO2M  uint32 `json:"pkts_o2m"`
	BytesM2O uint64 `json:"bytes_m2o"`
	BytesO2M uint64 `json:"bytes_o2m"`

	TCPSyn         uint32  `json:"tcp_syn"`
	TCPSynRetry    uint32  `json:"tcp_syn_retry"`
	TCPConnects    uint32  `json:"tcp_connects"`
	TCPConnectFail uint32  `json:"tcp_connect_fail"`
	TCPResets      uint32  `json:"tcp_resets"`
	TCPCloses      uint32  `json:"tcp_closes"`
	TCPRetrans     uint32  `json:"tcp_retrans"`
	TCPGaps        uint32  `json:"tcp_gaps"`
	TCPKeepalive   uint32  `json:"tcp_keepalive"`
	TCPZeroWin     uint32  `json:"tcp_zero_win"`
	TCPRttSumMs    float64 `json:"tcp_rtt_sum_ms"`
	TCPRttCnt      uint32  `json:"tcp_rtt_cnt"`
	TCPRttMaxMs    float32 `json:"tcp_rtt_max_ms"`

	LinkFrames        uint32  `json:"link_frames"`
	LinkCRCErr        uint32  `json:"link_crc_err"`
	LinkGarbage       uint32  `json:"link_garbage_bytes"`
	LinkStatusReq     uint32  `json:"link_status_req"`
	LinkStatusResp    uint32  `json:"link_status_resp"`
	LinkStatusTimeout uint32  `json:"link_status_timeout"`
	LinkRttSumMs      float64 `json:"link_rtt_sum_ms"`
	LinkRttCnt        uint32  `json:"link_rtt_cnt"`
	LinkResets        uint32  `json:"link_resets"`
	LinkNack          uint32  `json:"link_nack"`
	LinkRetries       uint32  `json:"link_retries"`
	TransportErr      uint32  `json:"transport_err"`

	AppReq          uint32  `json:"app_req"`
	AppResp         uint32  `json:"app_resp"`
	AppUnsol        uint32  `json:"app_unsol"`
	AppUnsolNull    uint32  `json:"app_unsol_null"`
	AppConfirm      uint32  `json:"app_confirm"`
	AppTimeouts     uint32  `json:"app_timeouts"`
	AppRetries      uint32  `json:"app_retries"`
	AppLateResp     uint32  `json:"app_late_resp"`
	AppUnexpected   uint32  `json:"app_unexpected_resp"`
	AppParseErr     uint32  `json:"app_parse_err"`
	AppRejected     uint32  `json:"app_rejected"`
	UnsolRetries    uint32  `json:"unsol_retries"`
	UnsolConfMiss   uint32  `json:"unsol_confirm_missing"`
	RespConfMiss    uint32  `json:"resp_confirm_missing"`
	RespSumMs       float64 `json:"resp_sum_ms"`
	RespCnt         uint32  `json:"resp_cnt"`
	RespMaxMs       float32 `json:"resp_max_ms"`
	IntegrityReq    uint32  `json:"integrity_req"`
	IntegrityOK     uint32  `json:"integrity_ok"`
	EventPollReq    uint32  `json:"event_poll_req"`
	TimeSyncs       uint32  `json:"time_syncs"`
	SensitiveFC     uint32  `json:"sensitive_fc"`
	IINRestart      uint32  `json:"iin_restart"`
	IINNeedTime     uint32  `json:"iin_need_time"`
	IINLocal        uint32  `json:"iin_local"`
	IINTrouble      uint32  `json:"iin_trouble"`
	IINOverflow     uint32  `json:"iin_overflow"`
	IINCfgCorrupt   uint32  `json:"iin_config_corrupt"`
	CmdTotal        uint32  `json:"cmd_total"`
	CmdOK           uint32  `json:"cmd_ok"`
	CmdFail         uint32  `json:"cmd_fail"`
	PtEvents        uint32  `json:"pt_events"`
	PtStaticChanges uint32  `json:"pt_static_changes"`
	PtBinChanges    uint32  `json:"pt_bin_changes"`
	PtBadQuality    uint32  `json:"pt_bad_quality"`
	LostEventSusp   uint32  `json:"lost_event_suspect"`
	Chatter         uint32  `json:"chatter"`
	EvBadTime       uint32  `json:"ev_bad_time"`
	EvDelayCnt      uint32  `json:"ev_delay_cnt"`
	EvDelaySumMs    float64 `json:"ev_delay_sum_ms"`
	EvDelayMinMs    float64 `json:"ev_delay_min_ms"`
	EvDelayMaxMs    float64 `json:"ev_delay_max_ms"`
}

// Output recebe as linhas produzidas pelo motor.
type Output interface {
	Msg(m *Msg, detail any)
	Point(p *Point)
	Command(c *Command)
	Event(e *Event)
	Stats(s *Stats)
	WantDetail() bool
}

// Multi distribui para várias saídas.
type Multi []Output

func (m Multi) Msg(x *Msg, d any) {
	for _, o := range m {
		o.Msg(x, d)
	}
}
func (m Multi) Point(x *Point) {
	for _, o := range m {
		o.Point(x)
	}
}
func (m Multi) Command(x *Command) {
	for _, o := range m {
		o.Command(x)
	}
}
func (m Multi) Event(x *Event) {
	for _, o := range m {
		o.Event(x)
	}
}
func (m Multi) Stats(x *Stats) {
	for _, o := range m {
		o.Stats(x)
	}
}
func (m Multi) WantDetail() bool {
	for _, o := range m {
		if o.WantDetail() {
			return true
		}
	}
	return false
}

// Itoa utilitário.
func Itoa(i int) string { return strconv.Itoa(i) }
