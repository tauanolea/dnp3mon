// dnp3sim gera um pcap sintético e realista de tráfego DNP3/TCP entre FEPs de
// um ADMS e milhares de RTUs, com falhas injetadas, para testar o dnp3mon.
package main

import (
	"container/heap"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"sort"
	"time"

	"dnp3mon/internal/dnp3"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type item struct {
	t   time.Time
	n   int
	f   func()
	idx int
}
type pq []*item

func (q pq) Len() int { return len(q) }
func (q pq) Less(i, j int) bool {
	if q[i].t.Equal(q[j].t) {
		return q[i].n < q[j].n
	}
	return q[i].t.Before(q[j].t)
}
func (q pq) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *pq) Push(x any)   { *q = append(*q, x.(*item)) }
func (q *pq) Pop() any     { o := *q; n := len(o); it := o[n-1]; *q = o[:n-1]; return it }

type pkt struct {
	ts   time.Time
	data []byte
}

type conn struct {
	m, r   netip.AddrPort
	sm, sr uint32
	open   bool
	id     uint16
}

type ev struct {
	typ string // BI DBI AI
	idx int
	val float64
	t   time.Time
}

type rtuSim struct {
	id                int
	ip                netip.Addr
	port              uint16
	addr              uint16
	medium            string
	fep               int
	c                 *conn
	bi                []bool
	dbi               []uint8
	ai                []float64
	ctr               []uint32
	aiFloat, useCTO   bool
	events            []ev
	unsol             bool
	mseq, useq        uint8
	tseqM, tseqR      uint8
	busy              bool
	queue             []func()
	downUntil         time.Time
	rebootAt          time.Time
	restart, needTime bool
	local, overflow   bool
	clockOff          time.Duration
	flaky             float64
	chatter, lostEvt  bool
	failedCycles      int
	reconnecting      bool
	cmdFailHW         bool
}

type sim struct {
	h     pq
	n     int
	now   time.Time
	rng   *rand.Rand
	pk    []pkt
	feps  []netip.Addr
	rtus  []*rtuSim
	end   time.Time
	stats map[string]int
}

func (s *sim) at(t time.Time, f func()) {
	s.n++
	heap.Push(&s.h, &item{t: t, n: s.n, f: f})
}

func (s *sim) dur(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(s.rng.Int63n(int64(max-min)+1))
}

func (s *sim) owd(r *rtuSim) time.Duration {
	switch r.medium {
	case "fibra":
		return s.dur(2*time.Millisecond, 8*time.Millisecond)
	case "lte":
		d := s.dur(40*time.Millisecond, 250*time.Millisecond)
		if s.rng.Float64() < 0.03 {
			d += s.dur(500*time.Millisecond, 2500*time.Millisecond)
		}
		return d
	case "radio":
		return s.dur(150*time.Millisecond, 500*time.Millisecond)
	default: // satelite
		return s.dur(280*time.Millisecond, 650*time.Millisecond)
	}
}

var macM = net.HardwareAddr{0x00, 0x1b, 0x21, 0x01, 0x02, 0x03}
var macR = net.HardwareAddr{0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc}

func (s *sim) raw(ts time.Time, c *conn, fromM bool, seq, ack uint32, syn, ackf, fin, rst bool, payload []byte) {
	src, dst := c.m, c.r
	if !fromM {
		src, dst = c.r, c.m
	}
	c.id++
	eth := &layers.Ethernet{SrcMAC: macM, DstMAC: macR, EthernetType: layers.EthernetTypeIPv4}
	if !fromM {
		eth.SrcMAC, eth.DstMAC = macR, macM
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, Id: c.id, Flags: layers.IPv4DontFragment,
		SrcIP: src.Addr().AsSlice(), DstIP: dst.Addr().AsSlice()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(src.Port()), DstPort: layers.TCPPort(dst.Port()), Seq: seq, Ack: ack,
		SYN: syn, ACK: ackf, FIN: fin, RST: rst, PSH: len(payload) > 0, Window: 16384}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload))
	s.pk = append(s.pk, pkt{ts, append([]byte{}, buf.Bytes()...)})
}

// send envia dados (segmentando em 1460) e devolve o seq inicial.
func (s *sim) send(c *conn, ts time.Time, fromM bool, data []byte) []func(time.Time) {
	var resend []func(time.Time)
	for len(data) > 0 {
		n := len(data)
		if n > 1460 {
			n = 1460
		}
		chunk := append([]byte{}, data[:n]...)
		data = data[n:]
		if fromM {
			seq, ack := c.sm, c.sr
			s.raw(ts, c, true, seq, ack, false, true, false, false, chunk)
			c.sm += uint32(n)
			resend = append(resend, func(t time.Time) { s.raw(t, c, true, seq, ack, false, true, false, false, chunk) })
		} else {
			seq, ack := c.sr, c.sm
			s.raw(ts, c, false, seq, ack, false, true, false, false, chunk)
			c.sr += uint32(n)
			resend = append(resend, func(t time.Time) { s.raw(t, c, false, seq, ack, false, true, false, false, chunk) })
		}
		ts = ts.Add(200 * time.Microsecond)
	}
	return resend
}

func (s *sim) ack(c *conn, ts time.Time, fromM bool) {
	if fromM {
		s.raw(ts, c, true, c.sm, c.sr, false, true, false, false, nil)
	} else {
		s.raw(ts, c, false, c.sr, c.sm, false, true, false, false, nil)
	}
}

func join(fr [][]byte) []byte {
	var b []byte
	for _, f := range fr {
		b = append(b, f...)
	}
	return b
}

func (r *rtuSim) up(t time.Time) bool { return !t.Before(r.downUntil) }

// --- conexão --------------------------------------------------------------

func (s *sim) connect(r *rtuSim, t time.Time, fep int, then func(time.Time)) {
	r.fep = fep
	c := &conn{m: netip.AddrPortFrom(s.feps[fep], uint16(30000+s.rng.Intn(30000))), r: netip.AddrPortFrom(r.ip, r.port),
		sm: s.rng.Uint32(), sr: s.rng.Uint32()}
	r.c = c
	r.reconnecting = true
	var try func(n int, t time.Time)
	try = func(n int, t time.Time) {
		if r.c != c {
			return
		}
		s.raw(t, c, true, c.sm, 0, true, false, false, false, nil)
		if !r.up(t) {
			s.stats["syn_sem_resposta"]++
			delay := []time.Duration{time.Second, 3 * time.Second}
			if n < len(delay) {
				s.at(t.Add(delay[n]), func() { try(n+1, s.now) })
			} else {
				s.at(t.Add(60*time.Second), func() { try(0, s.now) })
			}
			return
		}
		rtt := 2 * s.owd(r)
		s.at(t.Add(rtt), func() {
			c.sm++
			s.raw(s.now, c, false, c.sr, c.sm, true, true, false, false, nil)
			c.sr++
			s.raw(s.now.Add(100*time.Microsecond), c, true, c.sm, c.sr, false, true, false, false, nil)
			c.open = true
			r.reconnecting = false
			r.failedCycles = 0
			r.busy = false
			r.queue = nil
			then(s.now.Add(time.Millisecond))
		})
	}
	try(0, t)
}

func (s *sim) closeConn(r *rtuSim, t time.Time) {
	c := r.c
	if c == nil || !c.open {
		return
	}
	s.raw(t, c, true, c.sm, c.sr, false, true, true, false, nil)
	c.sm++
	c.open = false
}

// --- tarefas do master (uma requisição por vez por RTU) -------------------

func (s *sim) enqueue(r *rtuSim, f func()) {
	if r.busy || r.c == nil || !r.c.open {
		if len(r.queue) < 10 && r.c != nil && r.c.open {
			r.queue = append(r.queue, f)
		}
		return
	}
	r.busy = true
	f()
}

func (s *sim) done(r *rtuSim) {
	r.busy = false
	if len(r.queue) > 0 && r.c != nil && r.c.open {
		f := r.queue[0]
		r.queue = r.queue[1:]
		r.busy = true
		s.at(s.now.Add(5*time.Millisecond), f)
	}
}

// request envia requisição com retentativas; respond monta e envia a resposta.
func (s *sim) request(r *rtuSim, fc uint8, objs []byte, respond func(seq uint8), after func(ok bool)) {
	r.mseq = (r.mseq + 1) & 15
	seq := r.mseq
	c := r.c
	var attempt func(n int)
	attempt = func(n int) {
		if r.c != c || !c.open {
			r.busy = false
			return
		}
		t := s.now
		apdu := append(dnp3.AppHeader(true, true, false, false, seq, fc), objs...)
		var fr [][]byte
		fr, r.tseqM = dnp3.EncodeAPDUFrames(true, r.addr, 1, apdu, r.tseqM)
		rs := s.send(c, t, true, join(fr))
		if !r.up(t) {
			// sem ACK: retransmissões TCP do master
			for _, d := range []time.Duration{1200 * time.Millisecond, 3600 * time.Millisecond} {
				d := d
				s.at(t.Add(d), func() {
					if r.c == c && c.open {
						for _, f := range rs {
							f(s.now)
						}
					}
				})
			}
		} else {
			s.at(t.Add(2*s.owd(r)), func() { s.ack(c, s.now, false) })
		}
		answered := r.up(t) && s.rng.Float64() >= r.flaky
		if answered {
			proc := s.dur(20*time.Millisecond, 150*time.Millisecond)
			s.at(t.Add(2*s.owd(r)+proc), func() {
				if r.c != c || !c.open {
					return
				}
				respond(seq)
				r.failedCycles = 0
				after(true)
			})
			return
		}
		s.stats["requisicao_sem_resposta"]++
		s.at(t.Add(20*time.Second), func() {
			if n < 2 {
				if s.rng.Float64() < 0.5 {
					r.mseq = (r.mseq + 1) & 15
					seq = r.mseq
				}
				attempt(n + 1)
				return
			}
			r.failedCycles++
			after(false)
		})
	}
	attempt(0)
}

func (s *sim) iin(r *rtuSim) (byte, byte) {
	var i1, i2 byte
	if r.restart {
		i1 |= 0x80
	}
	if r.needTime {
		i1 |= 0x10
	}
	if r.local {
		i1 |= 0x20
	}
	if len(r.events) > 0 {
		i1 |= 0x02
	}
	if r.overflow {
		i2 |= 0x08
	}
	return i1, i2
}

// sendResp envia um APDU de resposta (fragmenta em 2048 com confirmações).
func (s *sim) sendResp(r *rtuSim, seq uint8, fc uint8, objs []byte, con bool) {
	c := r.c
	const maxFrag = 2048 - 4
	var frags [][]byte
	for len(objs) > maxFrag {
		frags = append(frags, objs[:maxFrag])
		objs = objs[maxFrag:]
	}
	frags = append(frags, objs)
	var sendFrag func(i int, sq uint8)
	sendFrag = func(i int, sq uint8) {
		if r.c != c || !c.open {
			return
		}
		fin := i == len(frags)-1
		cn := con || !fin
		uns := fc == dnp3.FCUnsolResponse
		i1, i2 := s.iin(r)
		apdu := append(dnp3.AppHeader(i == 0, fin, cn, uns, sq, fc), i1, i2)
		apdu = append(apdu, frags[i]...)
		var fr [][]byte
		fr, r.tseqR = dnp3.EncodeAPDUFrames(false, 1, r.addr, apdu, r.tseqR)
		data := join(fr)
		corrupt := r.medium == "radio" && s.rng.Float64() < 0.004
		if corrupt && len(data) > 14 {
			data = append([]byte{}, data...)
			data[12] ^= 0x5A
			s.stats["crc_injetado"]++
		}
		rs := s.send(c, s.now, false, data)
		s.ack(c, s.now.Add(300*time.Microsecond), true)
		if r.medium == "lte" && s.rng.Float64() < 0.01 {
			s.stats["retrans_tcp_injetada"]++
			s.at(s.now.Add(s.dur(250*time.Millisecond, 600*time.Millisecond)), func() {
				for _, f := range rs {
					f(s.now)
				}
			})
		}
		if cn && !corrupt {
			s.at(s.now.Add(2*time.Millisecond), func() {
				if uns && s.rng.Float64() < r.flaky*3 {
					s.stats["unsol_sem_confirm"]++
					s.at(s.now.Add(5*time.Second), func() { // RTU retransmite a não solicitada
						if r.c == c && c.open {
							i1, i2 := s.iin(r)
							_ = i1
							_ = i2
							s.send(c, s.now, false, data)
						}
					})
					return
				}
				conf := dnp3.AppHeader(true, true, false, uns, sq, dnp3.FCConfirm)
				var cf [][]byte
				cf, r.tseqM = dnp3.EncodeAPDUFrames(true, r.addr, 1, conf, r.tseqM)
				s.send(c, s.now, true, join(cf))
				if r.up(s.now) {
					s.at(s.now.Add(2*s.owd(r)+40*time.Millisecond), func() {
						if r.c == c && c.open {
							s.ack(c, s.now, false)
						}
					})
				}
				if !fin {
					s.at(s.now.Add(2*s.owd(r)+5*time.Millisecond), func() { sendFrag(i+1, (sq+1)&15) })
				}
			})
		}
	}
	sendFrag(0, seq)
}

// --- objetos ---------------------------------------------------------------

func (s *sim) staticObjs(r *rtuSim) []byte {
	ob := &dnp3.ObjBuilder{}
	if len(r.bi) > 0 {
		ob.Header(1, 2, 0x01).U16(0).U16(uint16(len(r.bi) - 1))
		for i, v := range r.bi {
			f := byte(0x01)
			if v {
				f |= 0x80
			}
			if i == len(r.bi)-1 && r.id%37 == 0 {
				f = 0x04 // COMM_LOST
			}
			ob.U8(f)
		}
	}
	if len(r.dbi) > 0 {
		ob.Header(3, 2, 0x00).U8(0).U8(uint8(len(r.dbi) - 1))
		for _, v := range r.dbi {
			ob.U8(0x01 | v<<6)
		}
	}
	if len(r.ai) > 0 {
		if r.aiFloat {
			ob.Header(30, 5, 0x00).U8(0).U8(uint8(len(r.ai) - 1))
			for _, v := range r.ai {
				ob.U8(0x01).F32(float32(v))
			}
		} else {
			ob.Header(30, 1, 0x00).U8(0).U8(uint8(len(r.ai) - 1))
			for _, v := range r.ai {
				ob.U8(0x01).U32(uint32(int32(v)))
			}
		}
	}
	if len(r.ctr) > 0 {
		ob.Header(20, 1, 0x00).U8(0).U8(uint8(len(r.ctr) - 1))
		for _, v := range r.ctr {
			ob.U8(0x01).U32(v)
		}
	}
	return ob.B
}

func (s *sim) eventObjs(r *rtuSim) []byte {
	ob := &dnp3.ObjBuilder{}
	var bi, dbi, ai []ev
	for _, e := range r.events {
		switch e.typ {
		case "BI":
			bi = append(bi, e)
		case "DBI":
			dbi = append(dbi, e)
		case "AI":
			ai = append(ai, e)
		}
	}
	if len(bi) > 0 {
		if r.useCTO {
			base := bi[0].t
			ob.Header(51, 1, 0x07).U8(1).Time48(base)
			ob.Header(2, 3, 0x28).U16(uint16(len(bi)))
			for _, e := range bi {
				ob.U16(uint16(e.idx)).U8(0x01 | byte(e.val)<<7).U16(uint16(e.t.Sub(base).Milliseconds()))
			}
		} else {
			ob.Header(2, 2, 0x28).U16(uint16(len(bi)))
			for _, e := range bi {
				ob.U16(uint16(e.idx)).U8(0x01 | byte(e.val)<<7).Time48(e.t)
			}
		}
	}
	if len(dbi) > 0 {
		ob.Header(4, 2, 0x28).U16(uint16(len(dbi)))
		for _, e := range dbi {
			ob.U16(uint16(e.idx)).U8(0x01 | byte(e.val)<<6).Time48(e.t)
		}
	}
	if len(ai) > 0 {
		if r.aiFloat {
			ob.Header(32, 7, 0x28).U16(uint16(len(ai)))
			for _, e := range ai {
				ob.U16(uint16(e.idx)).U8(0x01).F32(float32(e.val)).Time48(e.t)
			}
		} else {
			ob.Header(32, 3, 0x28).U16(uint16(len(ai)))
			for _, e := range ai {
				ob.U16(uint16(e.idx)).U8(0x01).U32(uint32(int32(e.val))).Time48(e.t)
			}
		}
	}
	return ob.B
}

func classObjs(c0 bool) []byte {
	ob := &dnp3.ObjBuilder{}
	ob.Header(60, 2, 0x06).Header(60, 3, 0x06).Header(60, 4, 0x06)
	if c0 {
		ob.Header(60, 1, 0x06)
	}
	return ob.B
}

// --- comportamento --------------------------------------------------------

func (s *sim) integrity(r *rtuSim) {
	s.enqueue(r, func() {
		s.request(r, dnp3.FCRead, classObjs(true), func(seq uint8) {
			objs := append(s.eventObjs(r), s.staticObjs(r)...)
			con := len(r.events) > 0
			r.events = nil
			s.sendResp(r, seq, dnp3.FCResponse, objs, con)
			r.overflow = false
		}, func(ok bool) {
			if ok && (r.restart || r.needTime) {
				s.postRestart(r)
			}
			s.done(r)
			s.checkDead(r)
		})
	})
}

func (s *sim) eventPoll(r *rtuSim) {
	s.enqueue(r, func() {
		s.request(r, dnp3.FCRead, classObjs(false), func(seq uint8) {
			objs := s.eventObjs(r)
			con := len(r.events) > 0
			r.events = nil
			s.sendResp(r, seq, dnp3.FCResponse, objs, con)
		}, func(ok bool) { s.done(r); s.checkDead(r) })
	})
}

func (s *sim) simpleReq(r *rtuSim, fc uint8, objs []byte, apply func()) {
	s.enqueue(r, func() {
		s.request(r, fc, objs, func(seq uint8) {
			apply()
			s.sendResp(r, seq, dnp3.FCResponse, nil, false)
		}, func(ok bool) { s.done(r) })
	})
}

func (s *sim) postRestart(r *rtuSim) {
	if r.restart {
		ob := &dnp3.ObjBuilder{}
		ob.Header(80, 1, 0x00).U8(7).U8(7).U8(0)
		s.simpleReq(r, dnp3.FCWrite, ob.B, func() { r.restart = false })
	}
	if r.needTime {
		s.enqueue(r, func() {
			s.request(r, dnp3.FCWrite, (&dnp3.ObjBuilder{}).Header(50, 1, 0x07).U8(1).Time48(s.now).B, func(seq uint8) {
				r.needTime = false
				s.sendResp(r, seq, dnp3.FCResponse, nil, false)
			}, func(bool) { s.done(r) })
		})
	}
	if r.unsol {
		s.simpleReq(r, dnp3.FCEnableUnsol, (&dnp3.ObjBuilder{}).Header(60, 2, 0x06).Header(60, 3, 0x06).Header(60, 4, 0x06).B, func() {})
	}
}

func (s *sim) checkDead(r *rtuSim) {
	if r.failedCycles >= 3 && r.c != nil && r.c.open {
		s.stats["conexao_fechada_por_falhas"]++
		s.closeConn(r, s.now)
		s.at(s.now.Add(30*time.Second), func() { s.connect(r, s.now, r.fep, func(t time.Time) { s.integrity(r) }) })
	}
}

func (s *sim) linkStatus(r *rtuSim) {
	c := r.c
	if c == nil || !c.open {
		return
	}
	s.send(c, s.now, true, dnp3.EncodeLinkFrame(true, true, false, false, dnp3.LinkRequestLinkStatus, r.addr, 1, nil))
	if r.up(s.now) {
		s.at(s.now.Add(2*s.owd(r)+2*time.Millisecond), func() {
			if r.c == c && c.open {
				s.send(c, s.now, false, dnp3.EncodeLinkFrame(false, false, false, false, dnp3.LinkStatus, 1, r.addr, nil))
				s.ack(c, s.now.Add(200*time.Microsecond), true)
			}
		})
	}
}

// change gera mudança de ponto (evento) no campo.
func (s *sim) change(r *rtuSim, typ string, idx int, val float64, report bool) {
	switch typ {
	case "BI":
		r.bi[idx] = val != 0
	case "DBI":
		r.dbi[idx] = uint8(val)
	case "AI":
		r.ai[idx] = val
	}
	if !report || !r.up(s.now) {
		return
	}
	e := ev{typ, idx, val, s.now.Add(r.clockOff)}
	if r.unsol && r.c != nil && r.c.open {
		r.events = append(r.events, e)
		delay := s.owd(r)
		c := r.c
		s.at(s.now.Add(delay), func() {
			if r.c != c || !c.open || len(r.events) == 0 {
				return
			}
			objs := s.eventObjs(r)
			r.events = nil
			r.useq = (r.useq + 1) & 15
			s.sendResp(r, r.useq, dnp3.FCUnsolResponse, objs, true)
		})
		return
	}
	if len(r.events) > 200 {
		r.overflow = true
		return
	}
	r.events = append(r.events, e)
}

func (s *sim) command(r *rtuSim) {
	if r.c == nil || !r.c.open || len(r.bi) == 0 {
		return
	}
	idx := s.rng.Intn(int(math.Min(4, float64(len(r.bi)))))
	// operação coerente com o estado atual (abrir o que está fechado e vice-versa)
	code, target := []byte{0x03, 0x41}[s.rng.Intn(2)], 1.0
	if r.bi[idx] {
		code, target = []byte{0x04, 0x81}[s.rng.Intn(2)], 0
	}
	crob := (&dnp3.ObjBuilder{}).Header(12, 1, 0x28).U16(1).U16(uint16(idx)).U8(code).U8(1).U32(1000).U32(0)
	req := append([]byte{}, crob.B...)
	req = append(req, 0)
	echo := func(st byte) []byte { b := append([]byte{}, crob.B...); return append(b, st) }
	s.stats["comandos"]++
	s.enqueue(r, func() {
		s.request(r, dnp3.FCSelect, req, func(seq uint8) {
			st := byte(0)
			if r.local {
				st = 7
			}
			s.sendResp(r, seq, dnp3.FCResponse, echo(st), false)
			if st != 0 {
				s.stats["comando_falha_local"]++
				return
			}
			s.at(s.now.Add(s.dur(300*time.Millisecond, 1500*time.Millisecond)), func() {
				s.request(r, dnp3.FCOperate, req, func(seq uint8) {
					st := byte(0)
					x := s.rng.Float64()
					switch {
					case r.cmdFailHW || x < 0.015:
						st = 6
					case x < 0.025:
						st = 2
					}
					s.sendResp(r, seq, dnp3.FCResponse, echo(st), false)
					if st != 0 {
						s.stats["comando_falha_status"]++
						return
					}
					if s.rng.Float64() < 0.92 {
						s.at(s.now.Add(s.dur(400*time.Millisecond, 2500*time.Millisecond)), func() { s.change(r, "BI", idx, target, true) })
					} else {
						s.stats["comando_sem_retorno"]++
					}
					if !r.unsol {
						s.at(s.now.Add(3*time.Second), func() { s.eventPoll(r) })
					}
				}, func(bool) { s.done(r) })
			})
		}, func(ok bool) {
			if !ok {
				s.done(r)
			}
		})
	})
}

func (s *sim) aoCommand(r *rtuSim) {
	if r.c == nil || !r.c.open {
		return
	}
	v := float32(13.8 + s.rng.Float64())
	obj := (&dnp3.ObjBuilder{}).Header(41, 3, 0x28).U16(1).U16(0).F32(v)
	req := append(append([]byte{}, obj.B...), 0)
	s.stats["comandos_ao"]++
	s.enqueue(r, func() {
		s.request(r, dnp3.FCDirectOperate, req, func(seq uint8) {
			s.sendResp(r, seq, dnp3.FCResponse, req, false)
		}, func(bool) { s.done(r) })
	})
}

func (s *sim) every(start time.Time, period time.Duration, jitter time.Duration, f func()) {
	var tick func()
	tick = func() {
		f()
		next := s.now.Add(period)
		if jitter > 0 {
			next = next.Add(s.dur(0, jitter))
		}
		if next.Before(s.end) {
			s.at(next, tick)
		}
	}
	s.at(start, tick)
}

func (s *sim) poisson(mean time.Duration, f func()) {
	var next func()
	next = func() {
		d := time.Duration(s.rng.ExpFloat64() * float64(mean))
		t := s.now.Add(d)
		if t.After(s.end) {
			return
		}
		s.at(t, func() { f(); next() })
	}
	next()
}

func main() {
	nRTU := flag.Int("rtus", 300, "número de RTUs")
	nFEP := flag.Int("feps", 4, "número de FEPs")
	dur := flag.Duration("dur", time.Hour, "duração simulada")
	out := flag.String("o", "sim.pcap", "arquivo pcap de saída")
	seed := flag.Int64("seed", 1, "semente")
	startS := flag.String("start", "", "início (RFC3339); padrão: agora - dur")
	class0 := flag.Duration("class0", 5*time.Minute, "período de integridade")
	evPoll := flag.Duration("event-poll", time.Minute, "período de varredura de eventos (RTUs sem não solicitadas)")
	link := flag.Duration("link", 3*time.Minute, "período do REQUEST_LINK_STATUS")
	flag.Parse()

	start := time.Now().UTC().Add(-*dur).Truncate(time.Second)
	if *startS != "" {
		t, err := time.Parse(time.RFC3339, *startS)
		if err != nil {
			log.Fatal(err)
		}
		start = t
	}
	s := &sim{rng: rand.New(rand.NewSource(*seed)), end: start.Add(*dur), stats: map[string]int{}}
	s.now = start
	for i := 0; i < *nFEP; i++ {
		s.feps = append(s.feps, netip.AddrFrom4([4]byte{10, 0, 0, byte(11 + i)}))
	}
	media := []string{"lte", "lte", "lte", "lte", "lte", "radio", "radio", "satelite", "fibra", "fibra"}
	for i := 0; i < *nRTU; i++ {
		r := &rtuSim{id: i, ip: netip.AddrFrom4([4]byte{10, byte(20 + i/250), byte(i % 250), 10}), port: 20000,
			addr: uint16(100 + i%3000), medium: media[s.rng.Intn(len(media))]}
		if i%50 == 7 {
			r.port = 20001 // algumas RTUs em outra porta
		}
		r.bi = make([]bool, 8+s.rng.Intn(56))
		r.dbi = make([]uint8, 2+s.rng.Intn(6))
		for j := range r.dbi {
			r.dbi[j] = 1
		}
		r.ai = make([]float64, 4+s.rng.Intn(28))
		for j := range r.ai {
			r.ai[j] = 100 + s.rng.Float64()*400
		}
		r.ctr = make([]uint32, s.rng.Intn(4))
		r.aiFloat = s.rng.Float64() < 0.5
		r.useCTO = s.rng.Float64() < 0.1
		r.unsol = s.rng.Float64() < 0.5
		x := s.rng.Float64()
		switch {
		case x < 0.85:
			r.clockOff = s.dur(0, 600*time.Millisecond) - 300*time.Millisecond
		case x < 0.95:
			r.clockOff = s.dur(2*time.Second, 10*time.Second)
		default:
			r.clockOff = -s.dur(2*time.Minute, 30*time.Minute)
		}
		if s.rng.Float64() < 0.06 {
			r.flaky = 0.05 + s.rng.Float64()*0.15
		}
		r.local = s.rng.Float64() < 0.02
		r.cmdFailHW = s.rng.Float64() < 0.01
		r.chatter = s.rng.Float64() < 0.01
		r.lostEvt = s.rng.Float64() < 0.01
		r.fep = i % 2 // FEPs 0 e 1 ativos; 2 e 3 reserva
		s.rtus = append(s.rtus, r)
	}

	for _, r := range s.rtus {
		r := r
		s.connect(r, start.Add(s.dur(0, 20*time.Second)), r.fep, func(t time.Time) {})
		phase := s.dur(20*time.Second, *class0)
		s.every(start.Add(phase), *class0, 2*time.Second, func() {
			if r.c != nil && r.c.open {
				s.integrity(r)
			}
		})
		if !r.unsol {
			s.every(start.Add(s.dur(25*time.Second, *evPoll+25*time.Second)), *evPoll, time.Second, func() {
				if r.c != nil && r.c.open {
					s.eventPoll(r)
				}
			})
		}
		s.every(start.Add(s.dur(30*time.Second, *link)), *link, time.Second, func() { s.linkStatus(r) })
		s.poisson(30*time.Minute, func() {
			i := s.rng.Intn(len(r.bi))
			s.change(r, "BI", i, float64(b2f(!r.bi[i])), !(r.lostEvt && s.rng.Float64() < 0.3))
		})
		s.poisson(2*time.Hour, func() {
			i := s.rng.Intn(len(r.dbi))
			s.change(r, "DBI", i, float64(3-r.dbi[i]), true)
		})
		s.poisson(3*time.Minute, func() {
			i := s.rng.Intn(len(r.ai))
			s.change(r, "AI", i, r.ai[i]*(0.9+s.rng.Float64()*0.2), true)
		})
		s.poisson(3*time.Hour, func() { s.command(r) })
		s.poisson(30*time.Hour, func() { s.aoCommand(r) })
		if r.chatter {
			s.every(start.Add(s.dur(time.Minute, 20*time.Minute)), 20*time.Minute, 0, func() {
				for k := 0; k < 60; k++ {
					s.at(s.now.Add(time.Duration(k)*3*time.Second), func() {
						if len(r.bi) > 1 {
							s.change(r, "BI", 1, float64(b2f(!r.bi[1])), true)
						}
					})
				}
			})
		}
		// quedas de comunicação
		if s.rng.Float64() < 0.05 {
			t := start.Add(s.dur(5*time.Minute, *dur*2/3))
			s.at(t, func() {
				r.downUntil = s.now.Add(s.dur(15*time.Minute, 40*time.Minute))
				s.stats["rtus_derrubadas"]++
			})
		}
		// reinício
		if s.rng.Float64() < 0.015 {
			t := start.Add(s.dur(5*time.Minute, *dur*3/4))
			s.at(t, func() {
				s.stats["rtus_reiniciadas"]++
				r.downUntil = s.now.Add(90 * time.Second)
				s.at(r.downUntil.Add(time.Second), func() {
					r.restart, r.needTime = true, true
					if r.c != nil && r.c.open {
						c := r.c
						c.open = false
						s.raw(s.now, c, false, c.sr, c.sm, false, false, false, true, nil) // RST
					}
					s.connect(r, s.now.Add(2*time.Second), r.fep, func(t time.Time) {
						if r.unsol {
							r.useq = 0
							s.sendResp(r, 0, dnp3.FCUnsolResponse, nil, true)
						}
						s.integrity(r)
					})
				})
			})
		}
		if s.rng.Float64() < 0.005 {
			s.at(start.Add(s.dur(5*time.Minute, *dur/2)), func() { r.overflow = true })
		}
	}
	// failover do FEP 0 para o FEP 2
	s.at(start.Add(*dur*2/5), func() {
		for _, r := range s.rtus {
			if r.fep == 0 && r.c != nil {
				r.c.open = false
				r := r
				s.connect(r, s.now.Add(s.dur(time.Second, 20*time.Second)), 2, func(t time.Time) { s.integrity(r) })
			}
		}
		s.stats["failover_fep"]++
	})
	// master não autorizado e FC sensível
	if len(s.rtus) > 5 {
		s.at(start.Add(*dur*3/10), func() {
			r := s.rtus[5]
			bad := &rtuSim{id: -1, ip: r.ip, port: r.port, addr: r.addr, medium: r.medium, bi: r.bi, dbi: r.dbi, ai: r.ai, ctr: r.ctr, aiFloat: r.aiFloat}
			old := s.feps
			s.feps = append(append([]netip.Addr{}, old...), netip.MustParseAddr("10.99.0.50"))
			s.connect(bad, s.now, len(s.feps)-1, func(t time.Time) {
				s.integrity(bad)
				s.simpleReq(bad, dnp3.FCColdRestart, nil, func() {})
			})
		})
	}

	heap.Init(&s.h)
	for s.h.Len() > 0 {
		it := heap.Pop(&s.h).(*item)
		if it.t.After(s.end) {
			break
		}
		s.now = it.t
		it.f()
	}
	sort.SliceStable(s.pk, func(i, j int) bool { return s.pk[i].ts.Before(s.pk[j].ts) })
	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	w := pcapgo.NewWriterNanos(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	var bytes int
	for _, p := range s.pk {
		w.WritePacket(gopacket.CaptureInfo{Timestamp: p.ts, CaptureLength: len(p.data), Length: len(p.data)}, p.data)
		bytes += len(p.data)
	}
	f.Close()
	fmt.Printf("%s: %d pacotes, %.1f MB, %d RTUs, %s (%.0f kbps médios)\n", *out, len(s.pk), float64(bytes)/1e6, *nRTU, *dur,
		float64(bytes)*8/dur.Seconds()/1000)
	keys := make([]string, 0, len(s.stats))
	for k := range s.stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-28s %d\n", k, s.stats[k])
	}
}

func b2f(b bool) int {
	if b {
		return 1
	}
	return 0
}
