// Package engine correlaciona o tráfego DNP3 por RTU: TCP, enlace,
// transporte, aplicação, comandos, pontos e indicadores por minuto.
package engine

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"sync"
	"time"

	"dnp3mon/internal/capture"
	"dnp3mon/internal/dnp3"
	"dnp3mon/internal/model"
)

// Config parametriza o motor.
type Config struct {
	Ports             map[uint16]bool // portas DNP3 (padrão 20000)
	RespTimeout       time.Duration   // sem resposta => timeout
	LinkTimeout       time.Duration   // REQUEST_LINK_STATUS sem LINK_STATUS
	OfflineAfter      time.Duration   // sem quadro válido da RTU => comm_lost
	OfflineTimeouts   int             // timeouts consecutivos => comm_lost
	RetryWindow       time.Duration
	FeedbackWindow    time.Duration // janela para ver mudança de estado após comando
	SelectTimeout     time.Duration // SELECT sem OPERATE
	StaticMode        string        // changes | all
	AuthorizedMasters []netip.Prefix
	DedupWindow       time.Duration
	ChatterCount      int
	ChatterWindow     time.Duration
	ForgetAfter       time.Duration
}

// DefaultConfig devolve valores padrão adequados ao cenário (LTE/rádio/satélite).
func DefaultConfig() Config {
	return Config{
		Ports:           map[uint16]bool{20000: true},
		RespTimeout:     30 * time.Second,
		LinkTimeout:     30 * time.Second,
		OfflineAfter:    10 * time.Minute,
		OfflineTimeouts: 3,
		RetryWindow:     3 * time.Minute,
		FeedbackWindow:  30 * time.Second,
		SelectTimeout:   60 * time.Second,
		StaticMode:      "changes",
		DedupWindow:     30 * time.Millisecond,
		ChatterCount:    10,
		ChatterWindow:   time.Minute,
		ForgetAfter:     7 * 24 * time.Hour,
	}
}

// Counters globais de saúde do motor.
type Counters struct {
	Packets, DNP3Packets, Dups, NonIP uint64
	Frames, APDUs                     uint64
	Flows, RTUs                       int
}

// Engine é o motor de correlação. É seguro para uso concorrente.
type Engine struct {
	cfg  Config
	out  model.Output
	mu   sync.Mutex
	now  time.Time
	min  time.Time // minuto corrente das estatísticas
	last time.Time // última varredura

	flows   map[flowKey]*flow
	rtus    map[string]*rtu
	masters map[netip.Addr]bool
	dedup   map[uint64]time.Time
	rlimit  map[string]time.Time
	C       Counters
}

// New cria o motor.
func New(cfg Config, out model.Output) *Engine {
	return &Engine{cfg: cfg, out: out, flows: map[flowKey]*flow{}, rtus: map[string]*rtu{},
		masters: map[netip.Addr]bool{}, dedup: map[uint64]time.Time{}, rlimit: map[string]time.Time{}}
}

type flowKey struct {
	a, b  netip.AddrPort
	proto uint8
}

type half struct {
	valid    bool
	next     uint32
	sc       dnp3.FrameScanner
	reasm    map[uint32]*dnp3.Reassembler
	rttOn    bool
	rttEnd   uint32
	rttTS    time.Time
	finSeen  bool
	lastFCB  int8 // -1 desconhecido
	lastConf uint64
}

type flow struct {
	key      flowKey
	rtuIsA   bool
	locked   bool // lado da RTU confirmado pelo bit DIR
	r        *rtu
	master   netip.AddrPort
	h        [2]*half
	synTS    time.Time
	synSeq   uint32
	estab    bool
	closed   bool
	lastTS   time.Time
	linkPend [2]time.Time
	s        session
}

type session struct {
	pending *request
	last    *request
	unsol   *pendConf
	respCon *pendConf
}

type request struct {
	ts       time.Time
	seq      uint8
	fc       uint8
	kind     string
	dig      uint64
	done     bool
	timedOut bool
	nextSeq  uint8
	frags    int
	retry    int
	cmds     []pkey
}

type pendConf struct {
	seq uint8
	ts  time.Time
	dig uint64
}

type pkey struct {
	typ string
	idx uint32
}

type pstate struct {
	value     float64
	flags     uint8
	ts        time.Time
	eventSeen bool
	changes   []time.Time
	chatterTS time.Time
}

type rtu struct {
	key       string
	ip        netip.Addr
	port      uint16
	firstSeen time.Time
	lastSeen  time.Time
	lastValid time.Time
	state     string // unknown | online | offline
	offSince  time.Time
	consecTO  int
	outAddr   int32
	iin       uint16
	iinKnown  bool
	master    netip.AddrPort
	lastMChg  time.Time
	points    map[pkey]*pstate
	cmds      map[pkey]*cmdState
	st        model.Stats
	lastResp  float32
	lastIntOK time.Time
	flows     int
	msgs      uint64
}

func (e *Engine) rlOK(key string, every time.Duration) bool {
	if t, ok := e.rlimit[key]; ok && e.now.Sub(t) < every {
		return false
	}
	e.rlimit[key] = e.now
	return true
}

func (e *Engine) isPort(p uint16) bool { return e.cfg.Ports[p] }

// Process trata um pacote.
func (e *Engine) Process(p *capture.Packet) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.C.Packets++
	e.advance(p.TS)
	if !e.isPort(p.SrcPort) && !e.isPort(p.DstPort) {
		return
	}
	e.C.DNP3Packets++
	if e.isDup(p) {
		e.C.Dups++
		return
	}
	src := netip.AddrPortFrom(p.SrcIP, p.SrcPort)
	dst := netip.AddrPortFrom(p.DstIP, p.DstPort)
	k := flowKey{src, dst, p.Proto}
	d := 0
	if dst.Addr().Less(src.Addr()) || (dst.Addr() == src.Addr() && dst.Port() < src.Port()) {
		k = flowKey{dst, src, p.Proto}
		d = 1
	}
	fl := e.flows[k]
	if fl == nil || (p.SYN && !p.ACK && fl.closed) {
		fl = e.newFlow(k, d, p)
	}
	fl.lastTS = p.TS
	r := fl.r
	r.lastSeen = p.TS
	fromRTU := fl.isRTU(d)
	if fromRTU {
		r.st.PktsO2M++
		r.st.BytesO2M += uint64(p.WireLen)
	} else {
		r.st.PktsM2O++
		r.st.BytesM2O += uint64(p.WireLen)
	}
	if p.Proto == 6 {
		e.tcp(fl, d, p)
	} else {
		h := fl.h[d]
		h.sc.Reset()
		e.feed(fl, d, p, p.Payload)
	}
}

func (e *Engine) isDup(p *capture.Packet) bool {
	if e.cfg.DedupWindow <= 0 {
		return false
	}
	h := fnv.New64a()
	b := make([]byte, 0, 64)
	b = append(b, p.SrcIP.AsSlice()...)
	b = append(b, p.DstIP.AsSlice()...)
	b = append(b, byte(p.SrcPort>>8), byte(p.SrcPort), byte(p.DstPort>>8), byte(p.DstPort),
		byte(p.Seq>>24), byte(p.Seq>>16), byte(p.Seq>>8), byte(p.Seq),
		byte(p.Ack>>24), byte(p.Ack>>16), byte(p.Ack>>8), byte(p.Ack),
		byte(p.IPID>>8), byte(p.IPID), b2u(p.SYN)|b2u(p.ACK)<<1|b2u(p.FIN)<<2|b2u(p.RST)<<3)
	h.Write(b)
	h.Write(p.Payload)
	k := h.Sum64()
	if t, ok := e.dedup[k]; ok && p.TS.Sub(t) < e.cfg.DedupWindow && p.TS.Sub(t) >= 0 {
		return true
	}
	e.dedup[k] = p.TS
	return false
}

func b2u(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func (fl *flow) isRTU(d int) bool { return (d == 0) == fl.rtuIsA }

func (fl *flow) rtuAP() netip.AddrPort {
	if fl.rtuIsA {
		return fl.key.a
	}
	return fl.key.b
}

func (fl *flow) masterAP() netip.AddrPort {
	if fl.rtuIsA {
		return fl.key.b
	}
	return fl.key.a
}

func newHalf() *half { return &half{reasm: map[uint32]*dnp3.Reassembler{}, lastFCB: -1} }

func (e *Engine) newFlow(k flowKey, d int, p *capture.Packet) *flow {
	if old := e.flows[k]; old != nil {
		e.dropFlow(old)
	}
	fl := &flow{key: k, h: [2]*half{newHalf(), newHalf()}}
	src := netip.AddrPortFrom(p.SrcIP, p.SrcPort)
	dst := netip.AddrPortFrom(p.DstIP, p.DstPort)
	rtuIsDst := true
	switch {
	case e.masters[src.Addr()] && !e.masters[dst.Addr()]:
		rtuIsDst = true
	case e.masters[dst.Addr()] && !e.masters[src.Addr()]:
		rtuIsDst = false
	case p.SYN && !p.ACK:
		rtuIsDst = true // padrão: master conecta na RTU
	case p.SYN && p.ACK:
		rtuIsDst = false
	case e.isPort(dst.Port()) && !e.isPort(src.Port()):
		rtuIsDst = true
	case e.isPort(src.Port()) && !e.isPort(dst.Port()):
		rtuIsDst = false
	}
	// d==0 => src é "a"
	fl.rtuIsA = (d == 0) != rtuIsDst
	e.flows[k] = fl
	e.attach(fl, p.TS)
	return fl
}

// attach associa o fluxo ao objeto RTU (chave ip:porta da RTU).
func (e *Engine) attach(fl *flow, ts time.Time) {
	ap := fl.rtuAP()
	key := ap.String()
	port := ap.Port()
	if !e.isPort(port) && port >= 1024 {
		// RTU é cliente TCP (porta efêmera): chave apenas pelo IP
		key = ap.Addr().String()
		port = 0
	}
	r := e.rtus[key]
	if r == nil {
		r = &rtu{key: key, ip: ap.Addr(), port: port, firstSeen: ts, state: "unknown", outAddr: -1,
			points: map[pkey]*pstate{}, cmds: map[pkey]*cmdState{}}
		r.st.RTU = key
		e.rtus[key] = r
	}
	if fl.r != r {
		if fl.r != nil {
			fl.r.flows--
		}
		r.flows++
	}
	fl.r = r
	fl.master = fl.masterAP()
}

func (e *Engine) dropFlow(fl *flow) {
	if fl.r != nil {
		fl.r.flows--
	}
	if fl.s.pending != nil && !fl.s.pending.done && !fl.s.pending.timedOut {
		e.timeout(fl, fl.s.pending, e.now)
	}
	delete(e.flows, fl.key)
}

func seqLE(a, b uint32) bool { return int32(a-b) <= 0 }

func (e *Engine) tcp(fl *flow, d int, p *capture.Packet) {
	h, o := fl.h[d], fl.h[1-d]
	r := fl.r
	fromRTU := fl.isRTU(d)
	if p.RST {
		r.st.TCPResets++
		who := "master"
		if fromRTU {
			who = "rtu"
		}
		ev := "tcp_reset"
		if !fl.estab && !fl.synTS.IsZero() {
			ev = "tcp_connect_refused"
			r.st.TCPConnectFail++
			fl.synTS = time.Time{}
		}
		e.event(r, fl, "tcp", ev, "warn", 0, "reset enviado por "+who)
		fl.closed = true
		return
	}
	if p.SYN && !p.ACK {
		if !fl.synTS.IsZero() && !fl.estab && p.Seq == fl.synSeq {
			r.st.TCPSynRetry++
		} else {
			r.st.TCPSyn++
			fl.synTS, fl.synSeq, fl.estab, fl.closed = p.TS, p.Seq, false, false
			fl.h = [2]*half{newHalf(), newHalf()}
			h = fl.h[d]
		}
		h.valid, h.next = true, p.Seq+1
		return
	}
	if p.SYN && p.ACK {
		if !fl.estab {
			fl.estab = true
			var rtt float64
			if !fl.synTS.IsZero() {
				rtt = float64(p.TS.Sub(fl.synTS).Microseconds()) / 1000
			}
			r.st.TCPConnects++
			e.event(r, fl, "tcp", "tcp_connect", "info", rtt, "conexão estabelecida (rtt handshake ms)")
			fl.synTS = time.Time{}
		}
		h.valid, h.next = true, p.Seq+1
		return
	}
	if p.Window == 0 {
		r.st.TCPZeroWin++
	}
	// amostra de RTT: dado do master reconhecido pela RTU
	if p.ACK && fromRTU && o.rttOn && seqLE(o.rttEnd, p.Ack) {
		rtt := float32(p.TS.Sub(o.rttTS).Microseconds()) / 1000
		// ACKs muito tardios (ACK pegando carona dados posteriores) não são RTT
		if rtt <= 15000 {
			r.st.TCPRttSumMs += float64(rtt)
			r.st.TCPRttCnt++
			if rtt > r.st.TCPRttMaxMs {
				r.st.TCPRttMaxMs = rtt
			}
		}
		o.rttOn = false
	}
	n := uint32(len(p.Payload))
	if n > 0 {
		if !h.valid {
			h.valid, h.next = true, p.Seq
		}
		diff := int32(p.Seq - h.next)
		switch {
		case diff == 0:
			e.feed(fl, d, p, p.Payload)
			h.next += n
		case diff < 0:
			end := p.Seq + n
			if int32(end-h.next) <= 0 {
				if n <= 1 && diff == -1 {
					r.st.TCPKeepalive++
				} else {
					r.st.TCPRetrans++
					if !fromRTU {
						h.rttOn = false // Karn
					}
				}
			} else {
				r.st.TCPRetrans++
				e.feed(fl, d, p, p.Payload[uint32(-diff):])
				h.next = end
			}
		default:
			r.st.TCPGaps++
			h.sc.Reset()
			for _, ra := range h.reasm {
				ra.Reset()
			}
			e.feed(fl, d, p, p.Payload)
			h.next = p.Seq + n
		}
		if !fromRTU && !h.rttOn {
			h.rttOn, h.rttEnd, h.rttTS = true, p.Seq+n, p.TS
		}
	}
	if p.FIN && !h.finSeen {
		h.finSeen = true
		h.next++
		r.st.TCPCloses++
		who := "master"
		if fromRTU {
			who = "rtu"
		}
		e.event(r, fl, "tcp", "tcp_close", "info", 0, "FIN enviado por "+who)
		if o.finSeen {
			fl.closed = true
		}
	}
}

func (e *Engine) event(r *rtu, fl *flow, cat, ev, sev string, val float64, detail string) {
	m := ""
	if fl != nil {
		m = fl.master.String()
	}
	key := ""
	if r != nil {
		key = r.key
	}
	e.out.Event(&model.Event{TS: model.Time(e.now), RTU: key, Master: m, Category: cat, Event: ev,
		Severity: sev, Value: val, Detail: detail})
}

func (e *Engine) liveEvent(r *rtu, fl *flow, cat, ev, sev string, val float64, detail string) {
	m := ""
	if fl != nil {
		m = fl.master.String()
	}
	e.out.Event(&model.Event{TS: model.Time(e.now), RTU: r.key, Master: m, Category: cat, Event: ev,
		Severity: sev, Value: val, Detail: detail, LiveOnly: true})
}

// advance move o relógio do motor (tempo dos pacotes) e dispara varreduras.
func (e *Engine) advance(ts time.Time) {
	if ts.Before(e.now) {
		return
	}
	if e.now.IsZero() {
		e.now = ts
		e.min = ts.Truncate(time.Minute)
		e.last = ts
		return
	}
	e.now = ts
	if ts.Sub(e.last) >= time.Second {
		e.sweep()
		e.last = ts
	}
	m := ts.Truncate(time.Minute)
	if m.After(e.min) {
		e.flushMinute()
		e.min = m
	}
}

// Tick avança o relógio sem pacotes (modo ao vivo, link ocioso).
func (e *Engine) Tick(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.advance(now)
}

// Flush encerra (fim de arquivo): emite estatísticas pendentes.
func (e *Engine) Flush() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sweep()
	for _, r := range e.rtus {
		for k, c := range r.cmds {
			e.finishCmd(r, k, c, "")
		}
	}
	e.flushMinute()
}

func (e *Engine) flushMinute() {
	for k, r := range e.rtus {
		if e.now.Sub(r.lastSeen) > e.cfg.ForgetAfter {
			delete(e.rtus, k)
			continue
		}
		if r.state == "unknown" {
			continue // acumula até saber se a RTU responde
		}
		st := r.st
		st.Minute = model.Time(e.min)
		st.RTU = r.key
		if r.state == "online" {
			st.Online = 1
		}
		st.IIN = r.iin
		if r.master.IsValid() {
			st.ActiveMaster = r.master.Addr().String()
		}
		e.out.Stats(&st)
		r.st = model.Stats{RTU: r.key}
	}
}

func (e *Engine) sweep() {
	now := e.now
	for k, t := range e.dedup {
		if now.Sub(t) > time.Second {
			delete(e.dedup, k)
		}
	}
	for _, fl := range e.flows {
		r := fl.r
		if q := fl.s.pending; q != nil && !q.done && !q.timedOut && now.Sub(q.ts) > e.cfg.RespTimeout {
			e.timeout(fl, q, now)
		}
		for i := 0; i < 2; i++ {
			if t := fl.linkPend[i]; !t.IsZero() && now.Sub(t) > e.cfg.LinkTimeout {
				r.st.LinkStatusTimeout++
				fl.linkPend[i] = time.Time{}
				e.liveEvent(r, fl, "link", "link_status_timeout", "warn", 0, "REQUEST_LINK_STATUS sem resposta")
			}
		}
		if !fl.synTS.IsZero() && !fl.estab && now.Sub(fl.synTS) > 10*time.Second {
			r.st.TCPConnectFail++
			e.event(r, fl, "tcp", "tcp_connect_fail", "warn", 0, "SYN sem resposta")
			fl.synTS = time.Time{}
		}
		idle := now.Sub(fl.lastTS)
		if (fl.closed && idle > time.Minute) || idle > 30*time.Minute {
			e.dropFlow(fl)
		}
	}
	for _, r := range e.rtus {
		if r.state == "unknown" && now.Sub(r.firstSeen) > e.cfg.OfflineAfter {
			e.commLost(r, nil, "nenhum quadro válido da RTU desde o início da monitoração")
		}
		if r.state == "online" && now.Sub(r.lastValid) > e.cfg.OfflineAfter {
			e.commLost(r, nil, fmt.Sprintf("sem quadros válidos há %s", now.Sub(r.lastValid).Round(time.Second)))
		}
		for k, c := range r.cmds {
			switch {
			case c.stage == stageFeedback && now.Sub(c.opTS) > e.cfg.FeedbackWindow:
				e.finishCmd(r, k, c, "")
			case c.stage == stageSelected && now.Sub(c.selRespTS) > e.cfg.SelectTimeout:
				e.finishCmd(r, k, c, "select_only")
			case now.Sub(c.start) > 10*time.Minute:
				e.finishCmd(r, k, c, "unknown")
			}
		}
	}
}

func (e *Engine) commLost(r *rtu, fl *flow, why string) {
	r.state = "offline"
	r.offSince = r.lastValid
	if r.offSince.IsZero() {
		r.offSince = r.firstSeen
	}
	e.event(r, fl, "comm", "comm_lost", "crit", 0, why)
}

func (e *Engine) markOnline(r *rtu, fl *flow) {
	r.consecTO = 0
	if r.state != "online" {
		if r.state == "offline" {
			d := e.now.Sub(r.offSince)
			e.event(r, fl, "comm", "comm_restored", "info", d.Seconds(),
				fmt.Sprintf("comunicação restabelecida após %s", d.Round(time.Second)))
		}
		r.state = "online"
	}
	r.lastValid = e.now
}

// --- consultas para a API -----------------------------------------------

// RTUInfo é o estado atual resumido de uma RTU.
type RTUInfo struct {
	Key        string    `json:"rtu"`
	State      string    `json:"state"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	LastValid  time.Time `json:"last_valid"`
	OffSince   time.Time `json:"offline_since,omitempty"`
	Master     string    `json:"master"`
	LinkAddr   int32     `json:"link_addr"`
	IIN        []string  `json:"iin"`
	Flows      int       `json:"tcp_flows"`
	Points     int       `json:"points"`
	PendingCmd int       `json:"pending_cmds"`
	LastRespMs float32   `json:"last_resp_ms"`
	LastIntOK  time.Time `json:"last_integrity_ok"`
	Msgs       uint64    `json:"msgs"`
}

func (r *rtu) info() RTUInfo {
	i := RTUInfo{Key: r.key, State: r.state, FirstSeen: r.firstSeen, LastSeen: r.lastSeen, LastValid: r.lastValid,
		LinkAddr: r.outAddr, IIN: dnp3.IINNames(r.iin), Flows: r.flows, Points: len(r.points),
		PendingCmd: len(r.cmds), LastRespMs: r.lastResp, LastIntOK: r.lastIntOK, Msgs: r.msgs}
	if r.state == "offline" {
		i.OffSince = r.offSince
	}
	if r.master.IsValid() {
		i.Master = r.master.String()
	}
	return i
}

// RTUs devolve o estado de todas as RTUs.
func (e *Engine) RTUs() []RTUInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RTUInfo, 0, len(e.rtus))
	for _, r := range e.rtus {
		out = append(out, r.info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// PointInfo é o último valor conhecido de um ponto.
type PointInfo struct {
	Type    string    `json:"type"`
	Index   uint32    `json:"idx"`
	Value   float64   `json:"value"`
	Flags   []string  `json:"flags"`
	TS      time.Time `json:"ts"`
	Changes int       `json:"recent_changes"`
}

// RTUDetail devolve estado e pontos de uma RTU.
func (e *Engine) RTUDetail(key string) (RTUInfo, []PointInfo, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.rtus[key]
	if r == nil {
		return RTUInfo{}, nil, false
	}
	pts := make([]PointInfo, 0, len(r.points))
	for k, p := range r.points {
		pts = append(pts, PointInfo{Type: k.typ, Index: k.idx, Value: p.value, Flags: dnp3.FlagNames(k.typ, p.flags), TS: p.ts, Changes: len(p.changes)})
	}
	sort.Slice(pts, func(i, j int) bool {
		if pts[i].Type != pts[j].Type {
			return pts[i].Type < pts[j].Type
		}
		return pts[i].Index < pts[j].Index
	})
	return r.info(), pts, true
}

// Snapshot devolve contadores globais.
func (e *Engine) Snapshot() Counters {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.C
	c.Flows = len(e.flows)
	c.RTUs = len(e.rtus)
	return c
}

// StateCounts devolve quantas RTUs em cada estado.
func (e *Engine) StateCounts() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := map[string]int{"online": 0, "offline": 0, "unknown": 0}
	for _, r := range e.rtus {
		m[r.state]++
	}
	return m
}
