// Package sink grava as linhas no ClickHouse (HTTP, JSONEachRow) em lotes,
// com spool em disco quando o banco está indisponível.
package sink

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dnp3mon/internal/model"
)

// ClickHouse é uma saída model.Output.
type ClickHouse struct {
	URL      string // http://clickhouse:8123
	DB       string
	User     string
	Password string
	SpoolDir string
	MaxBatch int
	Interval time.Duration

	mu      sync.Mutex
	bufs    map[string]*bytes.Buffer
	rows    map[string]int
	client  *http.Client
	Written atomic.Uint64
	Failed  atomic.Uint64
	Spooled atomic.Uint64
	LastErr atomic.Value
}

// Start inicia o flush periódico.
func (c *ClickHouse) Start() {
	c.bufs = map[string]*bytes.Buffer{}
	c.rows = map[string]int{}
	c.client = &http.Client{Timeout: 60 * time.Second}
	if c.MaxBatch == 0 {
		c.MaxBatch = 20000
	}
	if c.Interval == 0 {
		c.Interval = time.Second
	}
	os.MkdirAll(c.SpoolDir, 0o755)
	go func() {
		for range time.Tick(c.Interval) {
			c.FlushAll()
		}
	}()
	go func() {
		for range time.Tick(30 * time.Second) {
			c.replaySpool()
		}
	}()
}

func (c *ClickHouse) add(table string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	c.mu.Lock()
	buf := c.bufs[table]
	if buf == nil {
		buf = &bytes.Buffer{}
		c.bufs[table] = buf
	}
	buf.Write(b)
	buf.WriteByte('\n')
	c.rows[table]++
	full := c.rows[table] >= c.MaxBatch
	c.mu.Unlock()
	if full {
		c.flush(table)
	}
}

func (c *ClickHouse) Msg(m *model.Msg, _ any)  { c.add("messages", m) }
func (c *ClickHouse) Point(p *model.Point)     { c.add("points", p) }
func (c *ClickHouse) Command(x *model.Command) { c.add("commands", x) }
func (c *ClickHouse) Stats(s *model.Stats)     { c.add("rtu_stats_1m", s) }
func (c *ClickHouse) WantDetail() bool         { return false }
func (c *ClickHouse) Event(ev *model.Event) {
	if !ev.LiveOnly {
		c.add("events", ev)
	}
}

// FlushAll envia todos os buffers.
func (c *ClickHouse) FlushAll() {
	c.mu.Lock()
	tables := make([]string, 0, len(c.bufs))
	for t := range c.bufs {
		tables = append(tables, t)
	}
	c.mu.Unlock()
	for _, t := range tables {
		c.flush(t)
	}
}

func (c *ClickHouse) flush(table string) {
	c.mu.Lock()
	buf := c.bufs[table]
	n := c.rows[table]
	if buf == nil || buf.Len() == 0 {
		c.mu.Unlock()
		return
	}
	data := append([]byte{}, buf.Bytes()...)
	buf.Reset()
	c.rows[table] = 0
	c.mu.Unlock()
	if err := c.insert(table, data); err != nil {
		c.Failed.Add(uint64(n))
		c.LastErr.Store(err.Error())
		log.Printf("clickhouse: %s: %v (spool)", table, err)
		c.spool(table, data)
		return
	}
	c.Written.Add(uint64(n))
}

func (c *ClickHouse) insert(table string, data []byte) error {
	q := url.Values{}
	q.Set("query", fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", c.DB, table))
	q.Set("input_format_skip_unknown_fields", "1")
	q.Set("date_time_input_format", "best_effort")
	q.Set("async_insert", "0")
	req, err := http.NewRequest("POST", strings.TrimRight(c.URL, "/")+"/?"+q.Encode(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	if c.User != "" {
		req.SetBasicAuth(c.User, c.Password)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *ClickHouse) spool(table string, data []byte) {
	if c.SpoolDir == "" {
		return
	}
	name := filepath.Join(c.SpoolDir, fmt.Sprintf("%d__%s.jsonl", time.Now().UnixNano(), table))
	if err := os.WriteFile(name, data, 0o644); err == nil {
		c.Spooled.Add(1)
	}
}

func (c *ClickHouse) replaySpool() {
	files, _ := filepath.Glob(filepath.Join(c.SpoolDir, "*.jsonl"))
	sort.Strings(files)
	for _, f := range files {
		parts := strings.SplitN(strings.TrimSuffix(filepath.Base(f), ".jsonl"), "__", 2)
		if len(parts) != 2 {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if err := c.insert(parts[1], data); err != nil {
			return // banco ainda indisponível
		}
		os.Remove(f)
		log.Printf("clickhouse: spool reenviado %s", filepath.Base(f))
	}
}

// Ping testa a conexão.
func (c *ClickHouse) Ping() error {
	resp, err := http.Get(strings.TrimRight(c.URL, "/") + "/ping")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Stdout grava JSON lines na saída padrão (depuração).
type Stdout struct {
	mu  sync.Mutex
	W   io.Writer
	Inc map[string]bool
}

func (s *Stdout) put(kind string, v any) {
	if s.Inc != nil && !s.Inc[kind] {
		return
	}
	b, _ := json.Marshal(map[string]any{"type": kind, "data": v})
	s.mu.Lock()
	s.W.Write(append(b, '\n'))
	s.mu.Unlock()
}
func (s *Stdout) Msg(m *model.Msg, _ any)  { s.put("msg", m) }
func (s *Stdout) Point(p *model.Point)     { s.put("point", p) }
func (s *Stdout) Command(c *model.Command) { s.put("cmd", c) }
func (s *Stdout) Event(e *model.Event)     { s.put("event", e) }
func (s *Stdout) Stats(x *model.Stats)     { s.put("stats", x) }
func (s *Stdout) WantDetail() bool         { return false }
