package engine

import (
	"net/netip"
	"testing"
	"time"

	"dnp3mon/internal/capture"
	"dnp3mon/internal/dnp3"
	"dnp3mon/internal/model"
)

type collect struct {
	msgs   []*model.Msg
	cmds   []*model.Command
	events []*model.Event
	points []*model.Point
	stats  []*model.Stats
}

func (c *collect) Msg(m *model.Msg, _ any)  { c.msgs = append(c.msgs, m) }
func (c *collect) Point(p *model.Point)     { c.points = append(c.points, p) }
func (c *collect) Command(x *model.Command) { c.cmds = append(c.cmds, x) }
func (c *collect) Event(e *model.Event)     { c.events = append(c.events, e) }
func (c *collect) Stats(s *model.Stats)     { c.stats = append(c.stats, s) }
func (c *collect) WantDetail() bool         { return true }
func (c *collect) has(ev string) bool {
	for _, e := range c.events {
		if e.Event == ev {
			return true
		}
	}
	return false
}

// conversa TCP sintética entre um FEP e uma RTU
type talk struct {
	t      *testing.T
	e      *Engine
	now    time.Time
	m, r   netip.AddrPort
	sm, sr uint32
	tm, tr uint8
	seq    uint8
}

func (k *talk) pkt(fromM bool, syn, ack bool, payload []byte) {
	p := &capture.Packet{TS: k.now, Proto: 6, SYN: syn, ACK: ack, Payload: payload, WireLen: 54 + len(payload), Window: 8192}
	if fromM {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Seq, p.Ack = k.m.Addr(), k.m.Port(), k.r.Addr(), k.r.Port(), k.sm, k.sr
		k.sm += uint32(len(payload))
	} else {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Seq, p.Ack = k.r.Addr(), k.r.Port(), k.m.Addr(), k.m.Port(), k.sr, k.sm
		k.sr += uint32(len(payload))
	}
	k.e.Process(p)
}

func (k *talk) adv(d time.Duration) { k.now = k.now.Add(d) }

func (k *talk) req(fc uint8, objs []byte) uint8 {
	k.seq = (k.seq + 1) & 15
	apdu := append(dnp3.AppHeader(true, true, false, false, k.seq, fc), objs...)
	fr, nt := dnp3.EncodeAPDUFrames(true, 10, 1, apdu, k.tm)
	k.tm = nt
	for _, f := range fr {
		k.pkt(true, false, true, f)
	}
	return k.seq
}

func (k *talk) resp(seq uint8, iin1, iin2 byte, objs []byte) {
	apdu := append(dnp3.AppHeader(true, true, false, false, seq, dnp3.FCResponse), iin1, iin2)
	apdu = append(apdu, objs...)
	fr, nt := dnp3.EncodeAPDUFrames(false, 1, 10, apdu, k.tr)
	k.tr = nt
	for _, f := range fr {
		k.pkt(false, false, true, f)
	}
}

func TestEngineScenario(t *testing.T) {
	out := &collect{}
	cfg := DefaultConfig()
	cfg.AuthorizedMasters = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	e := New(cfg, out)
	k := &talk{t: t, e: e, now: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC),
		m: netip.MustParseAddrPort("10.0.0.11:40000"), r: netip.MustParseAddrPort("10.20.0.5:20000"), sm: 1000, sr: 5000}

	// conexão
	k.pkt(true, true, false, nil)
	k.sm++
	k.adv(300 * time.Millisecond)
	k.pkt(false, true, true, nil)
	k.sr++
	k.pkt(true, false, true, nil)

	// integridade com resposta (2 binários, 1 analógico)
	static := (&dnp3.ObjBuilder{}).Header(1, 2, 0x00).U8(0).U8(1).U8(0x81).U8(0x01).Header(30, 1, 0x00).U8(0).U8(0).U8(0x01).U32(123).B
	s := k.req(dnp3.FCRead, (&dnp3.ObjBuilder{}).Header(60, 1, 0x06).B)
	k.adv(500 * time.Millisecond)
	k.resp(s, 0x80|0x10, 0, static) // RESTART + NEED_TIME

	// SELECT/OPERATE com sucesso e mudança de estado do BI:1
	crob := (&dnp3.ObjBuilder{}).Header(12, 1, 0x28).U16(1).U16(1).U8(0x41).U8(1).U32(1000).U32(0).B
	k.adv(time.Second)
	s = k.req(dnp3.FCSelect, append(append([]byte{}, crob...), 0))
	k.adv(400 * time.Millisecond)
	k.resp(s, 0, 0, append(append([]byte{}, crob...), 0))
	k.adv(time.Second)
	s = k.req(dnp3.FCOperate, append(append([]byte{}, crob...), 0))
	k.adv(400 * time.Millisecond)
	k.resp(s, 0, 0, append(append([]byte{}, crob...), 0))
	k.adv(1500 * time.Millisecond)
	s = k.req(dnp3.FCRead, (&dnp3.ObjBuilder{}).Header(60, 2, 0x06).B)
	k.adv(400 * time.Millisecond)
	k.resp(s, 0, 0, (&dnp3.ObjBuilder{}).Header(2, 2, 0x28).U16(1).U16(1).U8(0x81).Time48(k.now.Add(-time.Second)).B)

	// SELECT recusado (LOCAL)
	k.adv(5 * time.Second)
	s = k.req(dnp3.FCSelect, append(append([]byte{}, crob...), 0))
	k.adv(400 * time.Millisecond)
	k.resp(s, 0x20, 0, append(append([]byte{}, crob...), 7))

	// três varreduras sem resposta -> timeouts, retentativas e comm_lost
	for i := 0; i < 3; i++ {
		k.adv(40 * time.Second)
		k.req(dnp3.FCRead, (&dnp3.ObjBuilder{}).Header(60, 2, 0x06).B)
	}
	k.adv(40 * time.Second)
	e.Tick(k.now)
	// volta
	s = k.req(dnp3.FCRead, (&dnp3.ObjBuilder{}).Header(60, 2, 0x06).B)
	k.adv(300 * time.Millisecond)
	k.resp(s, 0, 0, nil)
	e.Flush()

	if len(out.cmds) != 2 {
		t.Fatalf("esperava 2 comandos, veio %d", len(out.cmds))
	}
	ok, local := out.cmds[0], out.cmds[1]
	if ok.Result != "success" || ok.FeedbackPoint != "BI:1" || ok.FeedbackMs == nil {
		t.Fatalf("comando 1 errado: %+v", ok)
	}
	if local.Result != "select_failed" || local.SelectStatus != "LOCAL" {
		t.Fatalf("comando 2 errado: %+v", local)
	}
	for _, ev := range []string{"tcp_connect", "iin_set", "comm_lost", "comm_restored", "command_failed"} {
		if !out.has(ev) {
			t.Errorf("faltou evento %s", ev)
		}
	}
	var to, rt, resp uint32
	for _, st := range out.stats {
		to += st.AppTimeouts
		rt += st.AppRetries
		resp += st.RespCnt
	}
	if to < 3 || rt < 2 || resp != 6 {
		t.Fatalf("estatísticas: timeouts=%d retentativas=%d respostas=%d", to, rt, resp)
	}
	if len(out.points) < 4 {
		t.Fatalf("pontos: %d", len(out.points))
	}
}
