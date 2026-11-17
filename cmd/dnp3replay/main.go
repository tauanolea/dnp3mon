// dnp3replay injeta um pcap numa interface (AF_PACKET), respeitando o tempo
// entre pacotes. Útil para testar o dnp3mon numa interface de laboratório.
//
//	dnp3replay -i veth0 [-speed 1] arquivo.pcap
package main

import (
	"flag"
	"io"
	"log"
	"time"

	"dnp3mon/internal/capture"

	"github.com/gopacket/gopacket/afpacket"
)

func main() {
	iface := flag.String("i", "", "interface de saída")
	speed := flag.Float64("speed", 1, "fator de velocidade (2 = duas vezes mais rápido)")
	flag.Parse()
	if *iface == "" || flag.NArg() != 1 {
		log.Fatal("uso: dnp3replay -i iface [-speed 1] arquivo.pcap")
	}
	src, err := capture.OpenFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	h, err := afpacket.NewTPacket(afpacket.OptInterface(*iface))
	if err != nil {
		log.Fatal(err)
	}
	var first time.Time
	start := time.Now()
	n := 0
	for {
		raw, err := src.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if first.IsZero() {
			first = raw.CI.Timestamp
		}
		due := start.Add(time.Duration(float64(raw.CI.Timestamp.Sub(first)) / *speed))
		if d := time.Until(due); d > 0 {
			time.Sleep(d)
		}
		if err := h.WritePacketData(raw.Data); err != nil {
			log.Printf("envio: %v", err)
		}
		n++
		if n%20000 == 0 {
			log.Printf("%d pacotes enviados", n)
		}
	}
	log.Printf("fim: %d pacotes em %s", n, time.Since(start).Round(time.Second))
}
