// dnp3mon: monitor passivo de DNP3 (captura ao vivo ou reprocessamento de pcap).
//
//	dnp3mon live -i eth1[,eth2]   captura ao vivo, grava ring de pcap, ClickHouse e API
//	dnp3mon pcap arq1.pcap ...    reprocessa arquivos (backfill / testes)
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"dnp3mon/internal/capture"
	"dnp3mon/internal/engine"
	"dnp3mon/internal/model"
	"dnp3mon/internal/pcapring"
	"dnp3mon/internal/sink"
	"dnp3mon/internal/web"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "live" && os.Args[1] != "pcap") {
		fmt.Fprintln(os.Stderr, "uso: dnp3mon live -i eth1[,eth2] [opções] | dnp3mon pcap arquivo... [opções]")
		os.Exit(2)
	}
	mode := os.Args[1]
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	ifaces := fs.String("i", env("DNP3MON_IFACES", ""), "interfaces de captura (separadas por vírgula)")
	ports := fs.String("ports", env("DNP3MON_PORTS", "20000"), "portas TCP/UDP DNP3")
	chURL := fs.String("ch-url", env("DNP3MON_CH_URL", "http://127.0.0.1:8123"), "URL HTTP do ClickHouse")
	chDB := fs.String("ch-db", env("DNP3MON_CH_DB", "dnp3"), "banco no ClickHouse")
	chUser := fs.String("ch-user", env("DNP3MON_CH_USER", "default"), "usuário ClickHouse")
	chPass := fs.String("ch-pass", env("DNP3MON_CH_PASS", ""), "senha ClickHouse")
	noDB := fs.Bool("no-db", os.Getenv("DNP3MON_NO_DB") == "1", "não gravar no ClickHouse")
	stdout := fs.String("stdout", "", "imprimir linhas JSON (msg,event,cmd,point,stats ou all)")
	spool := fs.String("spool", env("DNP3MON_SPOOL", "/data/spool"), "diretório de spool quando o banco cai")
	pcapDir := fs.String("pcap-dir", env("DNP3MON_PCAP_DIR", "/data/pcap"), "diretório do ring de pcap (vazio desabilita)")
	pcapRot := fs.Duration("pcap-rotate", envDur("DNP3MON_PCAP_ROTATE", 5*time.Minute), "rotação dos arquivos pcap")
	pcapDays := fs.Int("pcap-days", envInt("DNP3MON_PCAP_DAYS", 30), "retenção do pcap em dias")
	pcapGB := fs.Float64("pcap-max-gb", float64(envInt("DNP3MON_PCAP_MAX_GB", 0)), "limite de disco do pcap em GB (0 = sem limite)")
	pcapGz := fs.Bool("pcap-gzip", env("DNP3MON_PCAP_GZIP", "1") == "1", "comprimir arquivos rotacionados")
	pcapPorts := fs.String("pcap-ports", env("DNP3MON_PCAP_PORTS", "2404"), "portas extras gravadas no pcap além das DNP3 (ex.: 2404 do IEC 104); 'all' grava tudo")
	httpAddr := fs.String("http", env("DNP3MON_HTTP", ":8080"), "endereço HTTP (API/tail ao vivo)")
	bufMB := fs.Int("buf-mb", envInt("DNP3MON_BUF_MB", 64), "buffer AF_PACKET por interface (MB)")
	masters := fs.String("masters", env("DNP3MON_MASTERS", ""), "IPs/CIDRs dos FEPs autorizados (alerta para outros)")
	serve := fs.Bool("serve", false, "no modo pcap, manter a API no ar ao terminar")
	cfg := engine.DefaultConfig()
	fs.DurationVar(&cfg.RespTimeout, "resp-timeout", envDur("DNP3MON_RESP_TIMEOUT", cfg.RespTimeout), "tempo sem resposta para contar timeout")
	fs.DurationVar(&cfg.OfflineAfter, "offline-after", envDur("DNP3MON_OFFLINE_AFTER", cfg.OfflineAfter), "sem quadros válidos => RTU offline")
	fs.IntVar(&cfg.OfflineTimeouts, "offline-timeouts", envInt("DNP3MON_OFFLINE_TIMEOUTS", cfg.OfflineTimeouts), "timeouts consecutivos => RTU offline")
	fs.DurationVar(&cfg.FeedbackWindow, "feedback-window", envDur("DNP3MON_FEEDBACK_WINDOW", cfg.FeedbackWindow), "janela para mudança de estado após comando")
	fs.StringVar(&cfg.StaticMode, "static-mode", env("DNP3MON_STATIC_MODE", cfg.StaticMode), "pontos estáticos: changes | all")
	// permite flags antes ou depois dos arquivos
	var files []string
	args := os.Args[2:]
	for {
		fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		files = append(files, fs.Arg(0))
		args = fs.Args()[1:]
	}

	cfg.Ports = map[uint16]bool{}
	for _, p := range strings.Split(*ports, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			cfg.Ports[uint16(n)] = true
		}
	}
	for _, m := range strings.Split(*masters, ",") {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		var pfx netip.Prefix
		var err error
		if strings.Contains(m, "/") {
			pfx, err = netip.ParsePrefix(m)
		} else {
			var a netip.Addr
			if a, err = netip.ParseAddr(m); err == nil {
				pfx = netip.PrefixFrom(a, a.BitLen()) // IP único (/32 ou /128)
			}
		}
		if err != nil {
			log.Fatalf("master inválido %q: %v", m, err)
		}
		cfg.AuthorizedMasters = append(cfg.AuthorizedMasters, pfx)
	}

	hub := web.NewHub()
	outs := model.Multi{hub}
	var ch *sink.ClickHouse
	if !*noDB {
		ch = &sink.ClickHouse{URL: *chURL, DB: *chDB, User: *chUser, Password: *chPass, SpoolDir: *spool}
		ch.Start()
		outs = append(outs, ch)
	}
	if *stdout != "" {
		so := &sink.Stdout{W: os.Stdout}
		if *stdout != "all" {
			so.Inc = map[string]bool{}
			for _, k := range strings.Split(*stdout, ",") {
				so.Inc[k] = true
			}
		}
		outs = append(outs, so)
	}
	eng := engine.New(cfg, outs)

	var ring *pcapring.Ring
	if mode == "live" && *pcapDir != "" {
		ring = &pcapring.Ring{Dir: *pcapDir, Rotate: *pcapRot, RetainDays: *pcapDays, MaxGB: *pcapGB, Gzip: *pcapGz}
		if err := ring.Open(); err != nil {
			log.Fatalf("pcap ring: %v", err)
		}
	}

	var lives []*capture.LiveSource
	var qlen atomic.Int64
	var rawPkts, nonIP atomic.Uint64
	start := time.Now()
	health := func() map[string]any {
		c := eng.Snapshot()
		h := map[string]any{
			"uptime_seconds": int64(time.Since(start).Seconds()), "packets": c.Packets, "dnp3_packets": c.DNP3Packets,
			"dup_packets": c.Dups, "frames": c.Frames, "apdus": c.APDUs, "flows": int64(c.Flows), "rtus": int64(c.RTUs),
			"queue_len": qlen.Load(), "raw_packets": rawPkts.Load(), "non_ip_packets": nonIP.Load(),
		}
		var kp, kd uint64
		for _, l := range lives {
			p, d := l.Stats()
			kp += p
			kd += d
		}
		h["kernel_packets"], h["kernel_drops"] = kp, kd
		if ring != nil {
			n, b, oldest := ring.Usage()
			h["pcap_files"], h["pcap_bytes"] = int64(n), b
			if !oldest.IsZero() {
				h["pcap_oldest_age_seconds"] = int64(time.Since(oldest).Seconds())
			}
		}
		if ch != nil {
			h["db_rows_written"], h["db_rows_failed"], h["db_spool_files"] = ch.Written.Load(), ch.Failed.Load(), ch.Spooled.Load()
			if e, ok := ch.LastErr.Load().(string); ok {
				h["db_last_error"] = e
			}
		}
		return h
	}
	srv := &web.Server{Hub: hub, Eng: eng, Ring: ring, Health: health}
	if *httpAddr != "" {
		go func() {
			log.Printf("API/tail ao vivo em %s", *httpAddr)
			if err := http.ListenAndServe(*httpAddr, srv.Handler()); err != nil {
				log.Fatalf("http: %v", err)
			}
		}()
	}

	if mode == "pcap" {
		sort.Strings(files)
		t0 := time.Now()
		for _, f := range files {
			src, err := capture.OpenFile(f)
			if err != nil {
				log.Printf("%s: %v", f, err)
				continue
			}
			base := filepath.Base(f)
			for {
				raw, err := src.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Printf("%s: %v", f, err)
					break
				}
				rawPkts.Add(1)
				p, ok := capture.Decode(raw)
				if !ok {
					nonIP.Add(1)
					continue
				}
				p.File = base
				eng.Process(p)
			}
			src.Close()
			log.Printf("processado %s", base)
		}
		eng.Flush()
		if ch != nil {
			ch.FlushAll()
		}
		c := eng.Snapshot()
		log.Printf("fim: %d pacotes (%d DNP3, %d duplicados), %d frames, %d APDUs, %d RTUs em %s",
			c.Packets, c.DNP3Packets, c.Dups, c.Frames, c.APDUs, c.RTUs, time.Since(t0).Round(time.Millisecond))
		if *serve {
			select {}
		}
		return
	}

	// modo ao vivo
	pcapAll := *pcapPorts == "all"
	keep := map[uint16]bool{}
	for p := range cfg.Ports {
		keep[p] = true
	}
	for _, p := range strings.Split(*pcapPorts, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			keep[uint16(n)] = true
		}
	}
	if *ifaces == "" {
		log.Fatal("informe as interfaces com -i ou DNP3MON_IFACES")
	}
	rawCh := make(chan *capture.Raw, 200000)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for _, ifc := range strings.Split(*ifaces, ",") {
		ifc = strings.TrimSpace(ifc)
		ls, err := capture.OpenLive(ifc, *bufMB)
		if err != nil {
			log.Fatalf("captura %s: %v", ifc, err)
		}
		lives = append(lives, ls)
		log.Printf("capturando em %s", ifc)
		wg.Add(1)
		go func(ls *capture.LiveSource) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				raw, err := ls.Next()
				if err != nil {
					log.Printf("captura: %v", err)
					time.Sleep(time.Second)
					continue
				}
				if raw == nil {
					continue
				}
				qlen.Add(1)
				rawCh <- raw
			}
		}(ls)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	tick := time.NewTicker(time.Second)
	for {
		select {
		case raw := <-rawCh:
			qlen.Add(-1)
			rawPkts.Add(1)
			p, ok := capture.Decode(raw)
			file := ""
			if ring != nil && (pcapAll || (ok && (keep[p.SrcPort] || keep[p.DstPort]))) {
				file = ring.Write(raw)
			}
			if !ok {
				nonIP.Add(1)
				continue
			}
			p.File = file
			eng.Process(p)
		case now := <-tick.C:
			eng.Tick(now)
		case <-sig:
			log.Printf("encerrando…")
			close(stop)
			eng.Flush()
			if ch != nil {
				ch.FlushAll()
			}
			if ring != nil {
				ring.Close()
			}
			return
		}
	}
}
