// Package pcapring grava a captura bruta em arquivos pcap rotativos
// (fonte da verdade) e permite recortar trechos por RTU/período.
package pcapring

import (
	"bufio"
	"compress/gzip"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"dnp3mon/internal/capture"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const nameLayout = "20060102T150405Z"

// Ring grava pacotes em arquivos rotacionados por tempo.
type Ring struct {
	Dir        string
	Rotate     time.Duration
	RetainDays int
	MaxGB      float64
	Gzip       bool

	mu      sync.Mutex
	f       *os.File
	bw      *bufio.Writer
	w       *pcapgo.Writer
	cur     string
	curEnd  time.Time
	Bytes   uint64
	Packets uint64
}

// Open prepara o diretório e inicia rotinas de manutenção.
func (r *Ring) Open() error {
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		return err
	}
	// comprime sobras de execuções anteriores
	if r.Gzip {
		files, _ := filepath.Glob(filepath.Join(r.Dir, "cap-*.pcap"))
		for _, f := range files {
			go compress(f)
		}
	}
	go func() {
		for {
			r.enforceRetention()
			time.Sleep(5 * time.Minute)
		}
	}()
	go func() {
		for range time.Tick(time.Second) {
			r.mu.Lock()
			if r.bw != nil {
				r.bw.Flush()
			}
			r.mu.Unlock()
		}
	}()
	return nil
}

// Write grava o pacote e devolve o nome do arquivo em que ficou.
func (r *Ring) Write(raw *capture.Raw) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ts := raw.CI.Timestamp
	if r.w == nil || !ts.Before(r.curEnd) {
		r.rotate(ts)
	}
	if r.w == nil {
		return ""
	}
	ci := raw.CI
	ci.CaptureLength = len(raw.Data)
	if err := r.w.WritePacket(ci, raw.Data); err == nil {
		r.Bytes += uint64(len(raw.Data))
		r.Packets++
	}
	return r.cur
}

func (r *Ring) rotate(ts time.Time) {
	r.closeLocked()
	start := ts.UTC().Truncate(r.Rotate)
	name := "cap-" + start.Format(nameLayout) + ".pcap"
	path := filepath.Join(r.Dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("pcapring: %v", err)
		return
	}
	st, _ := f.Stat()
	r.f = f
	r.bw = bufio.NewWriterSize(f, 1<<20)
	r.w = pcapgo.NewWriterNanos(r.bw)
	if st.Size() == 0 {
		r.w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	}
	r.cur = name
	r.curEnd = start.Add(r.Rotate)
}

func (r *Ring) closeLocked() {
	if r.f == nil {
		return
	}
	r.bw.Flush()
	r.f.Close()
	if r.Gzip {
		go compress(r.f.Name())
	}
	r.f, r.w, r.bw = nil, nil, nil
}

// Close fecha o arquivo atual.
func (r *Ring) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeLocked()
}

func compress(path string) {
	in, err := os.Open(path)
	if err != nil {
		return
	}
	defer in.Close()
	tmp := path + ".gz.tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return
	}
	gz, _ := gzip.NewWriterLevel(out, gzip.BestSpeed)
	if _, err := io.Copy(gz, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return
	}
	gz.Close()
	out.Close()
	if err := os.Rename(tmp, path+".gz"); err == nil {
		os.Remove(path)
	}
}

type fileInfo struct {
	path  string
	start time.Time
	size  int64
}

func (r *Ring) list() []fileInfo {
	ents, _ := os.ReadDir(r.Dir)
	var out []fileInfo
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, "cap-") || strings.HasSuffix(n, ".tmp") {
			continue
		}
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(n, "cap-"), ".gz"), ".pcap")
		t, err := time.Parse(nameLayout, base)
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, fileInfo{filepath.Join(r.Dir, n), t, info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start.Before(out[j].start) })
	return out
}

func (r *Ring) enforceRetention() {
	files := r.list()
	cut := time.Now().Add(-time.Duration(r.RetainDays) * 24 * time.Hour)
	var total int64
	for _, f := range files {
		total += f.size
	}
	maxBytes := int64(r.MaxGB * (1 << 30))
	for _, f := range files {
		r.mu.Lock()
		isCur := r.f != nil && filepath.Base(f.path) == r.cur
		r.mu.Unlock()
		if isCur {
			continue
		}
		if (r.RetainDays > 0 && f.start.Before(cut)) || (maxBytes > 0 && total > maxBytes) {
			if os.Remove(f.path) == nil {
				total -= f.size
				log.Printf("pcapring: removido %s", filepath.Base(f.path))
			}
		}
	}
}

// Usage devolve (arquivos, bytes, início mais antigo).
func (r *Ring) Usage() (int, int64, time.Time) {
	files := r.list()
	var total int64
	for _, f := range files {
		total += f.size
	}
	if len(files) == 0 {
		return 0, 0, time.Time{}
	}
	return len(files), total, files[0].start
}

// Slice escreve em w um pcap com os pacotes no intervalo que passam no filtro.
func (r *Ring) Slice(w io.Writer, from, to time.Time, filter func(*capture.Packet) bool, maxPackets int) (int, error) {
	r.mu.Lock()
	if r.bw != nil {
		r.bw.Flush()
	}
	r.mu.Unlock()
	pw := pcapgo.NewWriterNanos(w)
	if err := pw.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return 0, err
	}
	files := r.list()
	n := 0
	for i, f := range files {
		end := time.Now().Add(time.Hour)
		if i+1 < len(files) {
			end = files[i+1].start
		}
		if !end.After(from) || f.start.After(to) {
			continue
		}
		src, err := capture.OpenFile(f.path)
		if err != nil {
			continue
		}
		for {
			raw, err := src.Next()
			if err != nil {
				break
			}
			ts := raw.CI.Timestamp
			if ts.Before(from) {
				continue
			}
			if ts.After(to) {
				break
			}
			p, ok := capture.Decode(raw)
			if !ok || (filter != nil && !filter(p)) {
				continue
			}
			ci := gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(raw.Data), Length: raw.CI.Length}
			if err := pw.WritePacket(ci, raw.Data); err != nil {
				src.Close()
				return n, err
			}
			n++
			if maxPackets > 0 && n >= maxPackets {
				src.Close()
				return n, nil
			}
		}
		src.Close()
	}
	return n, nil
}
