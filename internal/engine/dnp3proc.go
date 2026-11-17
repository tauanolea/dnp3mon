package engine

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net/netip"
	"time"

	"dnp3mon/internal/capture"
	"dnp3mon/internal/dnp3"
	"dnp3mon/internal/model"
)

func (e *Engine) feed(fl *flow, d int, p *capture.Packet, data []byte) {
	fl.h[d].sc.Feed(data, func(ev dnp3.ScanEvent) { e.onScan(fl, d, p, ev) })
}

func (e *Engine) onScan(fl *flow, d int, p *capture.Packet, ev dnp3.ScanEvent) {
	r := fl.r
	switch ev.Kind {
	case dnp3.ScanGarbage:
		r.st.LinkGarbage += uint32(ev.Skipped)
	case dnp3.ScanHeaderCRCError, dnp3.ScanDataCRCError:
		r.st.LinkCRCErr++
		if e.rlOK("crc|"+r.key, time.Minute) {
			what := "cabeçalho"
			if ev.Kind == dnp3.ScanDataCRCError {
				what = "bloco de dados"
			}
			e.event(r, fl, "link", "crc_error", "warn", 0, "CRC inválido no "+what)
		}
	case dnp3.ScanFrame:
		e.C.Frames++
		e.onFrame(fl, d, p, ev.Frame)
	}
}

func (e *Engine) authorized(a netip.Addr) bool {
	if len(e.cfg.AuthorizedMasters) == 0 {
		return true
	}
	for _, p := range e.cfg.AuthorizedMasters {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (e *Engine) baseMsg(fl *flow, d int, p *capture.Packet, f *dnp3.LinkFrame) *model.Msg {
	r := fl.r
	m := &model.Msg{TS: model.Time(p.TS), RTU: r.key, RTUIP: r.ip.String(), RTUPort: fl.rtuAP().Port(),
		Master: fl.master.String(), Dir: "M2O", LinkSrc: f.Src, LinkDst: f.Dst,
		LinkFC: dnp3.LinkFCName(f.Prm, f.FC), PcapFile: p.File, IINFlags: []string{}, Objects: []string{}}
	if !f.Dir {
		m.Dir = "O2M"
	}
	return m
}

func (e *Engine) onFrame(fl *flow, d int, p *capture.Packet, f *dnp3.LinkFrame) {
	sender := netip.AddrPortFrom(p.SrcIP, p.SrcPort)
	// confirma/corrige o lado da RTU pelo bit DIR
	if f.Dir == fl.isRTU(d) && !fl.locked {
		fl.rtuIsA = !fl.rtuIsA
		e.attach(fl, p.TS)
	}
	fl.locked = true
	r := fl.r
	r.st.LinkFrames++
	if f.Dir {
		if !e.masters[sender.Addr()] {
			e.masters[sender.Addr()] = true
		}
		if !e.authorized(sender.Addr()) && e.rlOK("unauth|"+sender.Addr().String(), time.Hour) {
			e.event(r, fl, "security", "unauthorized_master", "crit", 0,
				"quadro DNP3 de master não autorizado: "+sender.String())
		}
	} else {
		if r.outAddr >= 0 && uint16(r.outAddr) != f.Src {
			e.event(r, fl, "link", "link_addr_change", "warn", float64(f.Src),
				fmt.Sprintf("endereço DNP3 da outstation mudou de %d para %d", r.outAddr, f.Src))
		}
		r.outAddr = int32(f.Src)
		e.markOnline(r, fl)
	}
	h := fl.h[d]
	if !f.IsUserData() {
		e.linkService(fl, d, p, f)
		return
	}
	if f.FC == dnp3.LinkConfirmedUserData && f.FCV {
		hs := fnv.New64a()
		hs.Write(f.Data)
		dg := hs.Sum64()
		fcb := int8(0)
		if f.FCB {
			fcb = 1
		}
		if h.lastFCB == fcb && h.lastConf == dg {
			r.st.LinkRetries++
			return // retransmissão de enlace: já processado
		}
		h.lastFCB, h.lastConf = fcb, dg
	}
	rk := uint32(f.Src)<<16 | uint32(f.Dst)
	ra := h.reasm[rk]
	if ra == nil {
		ra = &dnp3.Reassembler{}
		h.reasm[rk] = ra
	}
	apdu, segs, err := ra.Push(f.Data)
	if err != nil {
		r.st.TransportErr++
		if e.rlOK("tp|"+r.key, time.Minute) {
			e.event(r, fl, "link", "transport_error", "warn", 0, err.Error())
		}
	}
	if apdu == nil {
		return
	}
	e.C.APDUs++
	a := dnp3.ParseAPDU(apdu)
	e.onAPDU(fl, d, p, f, a, segs)
}

func (e *Engine) linkService(fl *flow, d int, p *capture.Packet, f *dnp3.LinkFrame) {
	r := fl.r
	m := e.baseMsg(fl, d, p, f)
	m.Layer = "link"
	m.Kind = "link"
	m.FCName = "LINK:" + m.LinkFC
	m.Summary = m.FCName + fmt.Sprintf(" %d->%d", f.Src, f.Dst)
	switch {
	case f.Prm && f.FC == dnp3.LinkRequestLinkStatus:
		r.st.LinkStatusReq++
		if !fl.linkPend[d].IsZero() {
			r.st.LinkStatusTimeout++
		}
		fl.linkPend[d] = p.TS
		m.Kind = "link_status"
	case !f.Prm && f.FC == dnp3.LinkStatus:
		if t := fl.linkPend[1-d]; !t.IsZero() {
			r.st.LinkStatusResp++
			lat := p.TS.Sub(t)
			r.st.LinkRttSumMs += float64(lat.Microseconds()) / 1000
			r.st.LinkRttCnt++
			m.RespMs = model.Ms(lat)
			fl.linkPend[1-d] = time.Time{}
		}
		m.Kind = "link_status"
	case f.Prm && f.FC == dnp3.LinkResetLinkStates:
		r.st.LinkResets++
		e.event(r, fl, "link", "link_reset", "info", 0, "RESET_LINK_STATES")
	case !f.Prm && (f.FC == dnp3.LinkNack || f.FC == dnp3.LinkNotSupported):
		r.st.LinkNack++
	}
	r.msgs++
	e.out.Msg(m, nil)
}

func digest(fc uint8, b []byte) uint64 {
	h := fnv.New64a()
	h.Write([]byte{fc})
	h.Write(b)
	return h.Sum64()
}

func (e *Engine) onAPDU(fl *flow, d int, p *capture.Packet, f *dnp3.LinkFrame, a *dnp3.APDU, segs int) {
	r := fl.r
	s := &fl.s
	m := e.baseMsg(fl, d, p, f)
	m.Layer = "app"
	m.FC, m.FCName, m.Seq = a.FC, dnp3.FCName(a.FC), a.Seq
	m.FIR, m.FIN, m.CON, m.UNS = b2u(a.FIR), b2u(a.FIN), b2u(a.CON), b2u(a.UNS)
	m.Objects = a.ObjectSummaries()
	m.Size = uint16(len(a.Raw))
	m.Frags = uint8(segs)
	m.Kind = a.Kind()
	m.Err = a.ParseErr
	if a.ParseErr != "" {
		r.st.AppParseErr++
		if e.rlOK("parse|"+r.key, time.Minute) {
			e.event(r, fl, "app", "parse_error", "warn", 0, a.ParseErr+" em "+dnp3.FCName(a.FC))
		}
	}
	var pts []dnp3.Point
	if f.Dir {
		e.masterAPDU(fl, p, a, m)
	} else {
		if a.HasIIN {
			m.IIN = a.IIN
			m.IINFlags = dnp3.IINNames(a.IIN)
			e.iin(r, fl, a)
		}
		switch a.FC {
		case dnp3.FCUnsolResponse:
			r.st.AppUnsol++
			if len(a.Objects) == 0 {
				r.st.AppUnsolNull++
			}
			dg := digest(a.FC, a.Raw[2:])
			if s.unsol != nil && s.unsol.seq == a.Seq && s.unsol.dig == dg {
				r.st.UnsolRetries++
				m.Retry = 1
			} else {
				if s.unsol != nil {
					r.st.UnsolConfMiss++
				}
				if a.CON {
					s.unsol = &pendConf{seq: a.Seq, ts: p.TS, dig: dg}
				} else {
					s.unsol = nil
				}
				pts = a.Points()
				e.points(r, fl, pts, "unsol")
			}
		case dnp3.FCResponse:
			r.st.AppResp++
			src := "static"
			q := s.pending
			if q != nil && !q.done && ((a.FIR && a.Seq == q.seq) || (!a.FIR && q.frags > 0 && a.Seq == q.nextSeq)) {
				m.ReqKind = q.kind
				if a.FIR {
					rt := p.TS.Sub(q.ts)
					m.RespMs = model.Ms(rt)
					ms := float32(rt.Microseconds()) / 1000
					r.st.RespSumMs += float64(ms)
					r.st.RespCnt++
					if ms > r.st.RespMaxMs {
						r.st.RespMaxMs = ms
					}
					r.lastResp = ms
					if q.timedOut {
						r.st.AppLateResp++
						m.Late = 1
					}
				}
				q.frags++
				q.nextSeq = (a.Seq + 1) & 0x0F
				if q.kind == "event_poll" {
					src = "event"
				}
				if a.FIN {
					q.done = true
					if q.kind == "integrity" && a.IIN&dnp3.IINRequestErrorMask == 0 {
						r.st.IntegrityOK++
						r.lastIntOK = p.TS
					}
					if a.IIN&dnp3.IINRequestErrorMask != 0 {
						r.st.AppRejected++
						e.event(r, fl, "app", "request_rejected", "warn", float64(q.fc),
							fmt.Sprintf("%s rejeitado: %v", dnp3.FCName(q.fc), dnp3.IINNames(a.IIN&dnp3.IINRequestErrorMask)))
					}
					if len(q.cmds) > 0 {
						e.cmdResponse(r, fl, q, a, p.TS)
					}
				}
			} else {
				r.st.AppUnexpected++
				m.Err = "unexpected_response"
			}
			if a.CON {
				s.respCon = &pendConf{seq: a.Seq, ts: p.TS}
			}
			pts = a.Points()
			e.points(r, fl, pts, src)
		}
	}
	m.NPoints = uint16(len(pts))
	m.Summary = a.Summary()
	r.msgs++
	var detail any
	if e.out.WantDetail() {
		detail = buildDetail(a, pts)
	}
	e.out.Msg(m, detail)
}

func (e *Engine) masterAPDU(fl *flow, p *capture.Packet, a *dnp3.APDU, m *model.Msg) {
	r := fl.r
	s := &fl.s
	if a.FC == dnp3.FCConfirm {
		r.st.AppConfirm++
		if a.UNS {
			if s.unsol != nil && s.unsol.seq == a.Seq {
				m.RespMs = model.Ms(p.TS.Sub(s.unsol.ts))
				s.unsol = nil
			}
		} else if s.respCon != nil && s.respCon.seq == a.Seq {
			s.respCon = nil
		}
		return
	}
	r.st.AppReq++
	if q := s.pending; q != nil && !q.done && !q.timedOut {
		e.timeout(fl, q, p.TS)
	}
	if s.respCon != nil {
		r.st.RespConfMiss++
		s.respCon = nil
	}
	q := &request{ts: p.TS, seq: a.Seq, fc: a.FC, kind: m.Kind, dig: digest(a.FC, a.Raw[2:])}
	if l := s.last; l != nil && l.dig == q.dig && (l.timedOut || !l.done) && p.TS.Sub(l.ts) < e.cfg.RetryWindow {
		q.retry = l.retry + 1
		r.st.AppRetries++
		m.Retry = 1
		if l.seq == a.Seq {
			m.Dup = 1
		}
	}
	s.pending, s.last = q, q
	switch q.kind {
	case "integrity":
		r.st.IntegrityReq++
	case "event_poll":
		r.st.EventPollReq++
	case "time_sync":
		r.st.TimeSyncs++
		for _, o := range a.Objects {
			if o.Group == 50 && (o.Var == 1 || o.Var == 3) && len(o.Items) > 0 && len(o.Items[0].Data) >= 6 {
				off := dnp3.DNPTime(o.Items[0].Data).Sub(p.TS)
				e.event(r, fl, "time", "time_write", "info", float64(off.Milliseconds()),
					"hora escrita pelo master menos hora da captura (ms)")
			}
		}
	}
	// master ativo (redundância de FEPs)
	if q.kind == "integrity" || q.kind == "event_poll" || q.kind == "command" {
		if r.master != fl.master {
			if r.master.IsValid() && r.master.Addr() != fl.master.Addr() {
				e.event(r, fl, "session", "master_change", "info", 0,
					fmt.Sprintf("master ativo mudou de %s para %s", r.master, fl.master))
			}
			r.master = fl.master
		}
	}
	if dnp3.SensitiveFC(a.FC) {
		r.st.SensitiveFC++
		e.event(r, fl, "security", "sensitive_fc", "warn", float64(a.FC), dnp3.FCName(a.FC)+" enviado por "+fl.master.String())
	}
	if q.kind == "command" {
		e.cmdRequest(r, fl, q, a, p.TS)
	}
	if a.FC == dnp3.FCDirectOperateNR {
		q.done = true
	}
}

func (e *Engine) timeout(fl *flow, q *request, ts time.Time) {
	r := fl.r
	q.timedOut = true
	r.st.AppTimeouts++
	r.consecTO++
	e.liveEvent(r, fl, "app", "app_timeout", "warn", float64(ts.Sub(q.ts).Milliseconds()),
		fmt.Sprintf("%s (%s) seq=%d sem resposta", dnp3.FCName(q.fc), q.kind, q.seq))
	for _, k := range q.cmds {
		if c := r.cmds[k]; c != nil {
			res := "timeout"
			if q.fc == dnp3.FCSelect {
				res = "select_timeout"
			}
			e.finishCmd(r, k, c, res)
		}
	}
	if r.state != "offline" && r.consecTO >= e.cfg.OfflineTimeouts {
		e.commLost(r, fl, fmt.Sprintf("%d timeouts consecutivos", r.consecTO))
	}
}

func (e *Engine) iin(r *rtu, fl *flow, a *dnp3.APDU) {
	v := a.IIN
	cnt := func(mask uint16, c *uint32) {
		if v&mask != 0 {
			*c++
		}
	}
	cnt(dnp3.IINDeviceRestart, &r.st.IINRestart)
	cnt(dnp3.IINNeedTime, &r.st.IINNeedTime)
	cnt(dnp3.IINLocalControl, &r.st.IINLocal)
	cnt(dnp3.IINDeviceTrouble, &r.st.IINTrouble)
	cnt(dnp3.IINEventOverflow, &r.st.IINOverflow)
	cnt(dnp3.IINConfigCorrupt, &r.st.IINCfgCorrupt)
	const stateMask = dnp3.IINDeviceRestart | dnp3.IINDeviceTrouble | dnp3.IINLocalControl |
		dnp3.IINNeedTime | dnp3.IINEventOverflow | dnp3.IINConfigCorrupt
	sv := v & stateMask
	prev := r.iin
	if !r.iinKnown {
		prev = 0
		r.iinKnown = true
	}
	if ch := prev ^ sv; ch != 0 {
		for _, b := range dnp3.IINBits {
			if ch&b.Mask == 0 {
				continue
			}
			if sv&b.Mask != 0 {
				e.event(r, fl, "iin", "iin_set", b.Severity, 0, b.Name)
			} else {
				e.event(r, fl, "iin", "iin_clear", "info", 0, b.Name)
			}
		}
	}
	r.iin = sv
}

// detail para a visualização ao vivo.
type liveObj struct {
	Header string `json:"header"`
	Items  int    `json:"items"`
}

type liveDetail struct {
	Objects  []liveObj      `json:"objects"`
	Points   []dnp3.Point   `json:"points,omitempty"`
	Commands []liveCmd      `json:"commands,omitempty"`
	IIN      []string       `json:"iin,omitempty"`
	Hex      string         `json:"hex"`
	Extra    map[string]any `json:"extra,omitempty"`
}

type liveCmd struct {
	Type   string  `json:"type"`
	Index  uint32  `json:"idx"`
	Op     string  `json:"op"`
	Status string  `json:"status"`
	Value  float64 `json:"value"`
	OnMs   uint32  `json:"on_ms"`
	Count  uint8   `json:"count"`
}

func buildDetail(a *dnp3.APDU, pts []dnp3.Point) *liveDetail {
	d := &liveDetail{Hex: hex.EncodeToString(a.Raw)}
	for i := range a.Objects {
		d.Objects = append(d.Objects, liveObj{a.Objects[i].Summary(), len(a.Objects[i].Items)})
	}
	if len(pts) > 200 {
		pts = pts[:200]
	}
	d.Points = pts
	for _, c := range a.Commands() {
		d.Commands = append(d.Commands, liveCmd{c.Type, c.Index, c.Op(), dnp3.CmdStatusName(c.Status), c.Value, c.OnMs, c.Count})
	}
	if a.HasIIN {
		d.IIN = dnp3.IINNames(a.IIN)
	}
	return d
}

var _ = bytes.Equal
