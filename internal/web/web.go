// Package web expõe a API HTTP, o tail ao vivo (SSE) e o recorte de PCAP.
package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dnp3mon/internal/capture"
	"dnp3mon/internal/engine"
	"dnp3mon/internal/model"
	"dnp3mon/internal/pcapring"
)

//go:embed static/*
var static embed.FS

// Hub distribui eventos aos assinantes do tail ao vivo.
type Hub struct {
	mu   sync.RWMutex
	subs map[*sub]struct{}
	n    atomic.Int32
}

type sub struct {
	ch    chan []byte
	rtu   string
	types map[string]bool
	q     string
	drops atomic.Int64
}

// NewHub cria o hub.
func NewHub() *Hub { return &Hub{subs: map[*sub]struct{}{}} }

func (h *Hub) publish(typ, rtu, text string, v any) {
	if h.n.Load() == 0 {
		return
	}
	var data []byte
	h.mu.RLock()
	defer h.mu.RUnlock()
	for s := range h.subs {
		if len(s.types) > 0 && !s.types[typ] {
			continue
		}
		if s.rtu != "" && !strings.HasPrefix(rtu, s.rtu) {
			continue
		}
		if s.q != "" && !strings.Contains(strings.ToLower(text), s.q) {
			continue
		}
		if data == nil {
			data, _ = json.Marshal(map[string]any{"type": typ, "data": v})
		}
		select {
		case s.ch <- data:
		default:
			s.drops.Add(1)
		}
	}
}

type msgWithDetail struct {
	*model.Msg
	Detail any `json:"detail,omitempty"`
}

func (h *Hub) Msg(m *model.Msg, d any) {
	h.publish("msg", m.RTU, m.Summary+" "+m.Kind+" "+m.FCName, msgWithDetail{m, d})
}
func (h *Hub) Point(p *model.Point) {
	h.publish("point", p.RTU, fmt.Sprintf("%s:%d", p.Type, p.Idx), p)
}
func (h *Hub) Command(c *model.Command) {
	h.publish("cmd", c.RTU, c.Op+" "+c.Result+" "+c.Status, c)
}
func (h *Hub) Event(e *model.Event) { h.publish("event", e.RTU, e.Event+" "+e.Detail, e) }
func (h *Hub) Stats(s *model.Stats) { h.publish("stats", s.RTU, "", s) }
func (h *Hub) WantDetail() bool     { return h.n.Load() > 0 }

// Server é o servidor HTTP.
type Server struct {
	Hub    *Hub
	Eng    *engine.Engine
	Ring   *pcapring.Ring
	Health func() map[string]any
}

// Handler devolve o mux HTTP.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, _ := static.ReadFile("static/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
	mux.HandleFunc("/api/live", s.live)
	mux.HandleFunc("/api/rtus", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Eng.RTUs())
	})
	mux.HandleFunc("/api/rtu", func(w http.ResponseWriter, r *http.Request) {
		info, pts, ok := s.Eng.RTUDetail(r.URL.Query().Get("key"))
		if !ok {
			http.Error(w, "rtu não encontrada", 404)
			return
		}
		writeJSON(w, map[string]any{"rtu": info, "points": pts})
	})
	mux.HandleFunc("/api/pcap", s.pcap)
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Health())
	})
	mux.HandleFunc("/metrics", s.metrics)
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming não suportado", 500)
		return
	}
	q := r.URL.Query()
	sb := &sub{ch: make(chan []byte, 4096), rtu: q.Get("rtu"), q: strings.ToLower(q.Get("q"))}
	if t := q.Get("types"); t != "" {
		sb.types = map[string]bool{}
		for _, x := range strings.Split(t, ",") {
			sb.types[strings.TrimSpace(x)] = true
		}
	}
	s.Hub.mu.Lock()
	s.Hub.subs[sb] = struct{}{}
	s.Hub.mu.Unlock()
	s.Hub.n.Add(1)
	defer func() {
		s.Hub.mu.Lock()
		delete(s.Hub.subs, sb)
		s.Hub.mu.Unlock()
		s.Hub.n.Add(-1)
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, ": ok\n\n")
	fl.Flush()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-sb.ch:
			fmt.Fprintf(w, "data: %s\n\n", b)
			// esvazia o que estiver pendente antes do flush
			for i := 0; i < 200; i++ {
				select {
				case b := <-sb.ch:
					fmt.Fprintf(w, "data: %s\n\n", b)
					continue
				default:
				}
				break
			}
			if d := sb.drops.Swap(0); d > 0 {
				fmt.Fprintf(w, "data: {\"type\":\"drops\",\"data\":%d}\n\n", d)
			}
			fl.Flush()
		case <-tick.C:
			fmt.Fprintf(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

func parseTime(s string, def time.Time) time.Time {
	if s == "" || s == "now" {
		return def
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n > 1e12 {
			return time.UnixMilli(n)
		}
		return time.Unix(n, 0)
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t
	}
	return def
}

func (s *Server) pcap(w http.ResponseWriter, r *http.Request) {
	if s.Ring == nil {
		http.Error(w, "ring de pcap desabilitado (modo arquivo)", 400)
		return
	}
	q := r.URL.Query()
	now := time.Now()
	to := parseTime(q.Get("to"), now)
	from := parseTime(q.Get("from"), to.Add(-15*time.Minute))
	if to.Sub(from) > 24*time.Hour {
		http.Error(w, "intervalo máximo 24h", 400)
		return
	}
	var filt func(*capture.Packet) bool
	if rk := q.Get("rtu"); rk != "" {
		if ap, err := netip.ParseAddrPort(rk); err == nil {
			filt = func(p *capture.Packet) bool {
				return (p.SrcIP == ap.Addr() && (ap.Port() == 0 || p.SrcPort == ap.Port())) ||
					(p.DstIP == ap.Addr() && (ap.Port() == 0 || p.DstPort == ap.Port()))
			}
		} else if a, err := netip.ParseAddr(rk); err == nil {
			filt = func(p *capture.Packet) bool { return p.SrcIP == a || p.DstIP == a }
		} else {
			http.Error(w, "rtu inválida (use ip:porta ou ip)", 400)
			return
		}
	}
	name := fmt.Sprintf("dnp3_%s_%s.pcap", strings.NewReplacer(":", "_", ".", "-").Replace(q.Get("rtu")), from.UTC().Format("20060102T150405"))
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	s.Ring.Slice(w, from, to, filt, 2_000_000)
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	for k, v := range s.Health() {
		switch x := v.(type) {
		case int, int64, uint64, float64, uint32, int32:
			fmt.Fprintf(w, "dnp3mon_%s %v\n", k, x)
		}
	}
	for st, n := range s.Eng.StateCounts() {
		fmt.Fprintf(w, "dnp3mon_rtus{state=%q} %d\n", st, n)
	}
}
