// Package capture lê pacotes ao vivo (AF_PACKET) ou de arquivos pcap/pcapng
// e os converte em Packet (somente IPv4/IPv6 + TCP/UDP).
package capture

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Packet é a visão simplificada de um pacote IP.
type Packet struct {
	TS               time.Time
	SrcIP, DstIP     netip.Addr
	SrcPort, DstPort uint16
	Proto            uint8 // 6 TCP, 17 UDP
	SYN, ACK, FIN    bool
	RST, PSH         bool
	Seq, Ack         uint32
	Window           uint16
	IPID             uint16
	Payload          []byte
	WireLen          int
	Iface            string
	File             string // arquivo pcap onde o pacote está gravado
}

// Raw é um pacote cru com metadados (para gravar em pcap).
type Raw struct {
	CI    gopacket.CaptureInfo
	Data  []byte
	LT    layers.LinkType
	Iface string
}

// Decode converte bytes crus em Packet. Devolve false se não for TCP/UDP sobre IP.
func Decode(r *Raw) (*Packet, bool) {
	pk := gopacket.NewPacket(r.Data, r.LT, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	p := &Packet{TS: r.CI.Timestamp, WireLen: r.CI.Length, Iface: r.Iface}
	if l := pk.Layer(layers.LayerTypeIPv4); l != nil {
		ip := l.(*layers.IPv4)
		p.SrcIP, _ = netip.AddrFromSlice(ip.SrcIP.To4())
		p.DstIP, _ = netip.AddrFromSlice(ip.DstIP.To4())
		p.IPID = ip.Id
	} else if l := pk.Layer(layers.LayerTypeIPv6); l != nil {
		ip := l.(*layers.IPv6)
		p.SrcIP, _ = netip.AddrFromSlice(ip.SrcIP)
		p.DstIP, _ = netip.AddrFromSlice(ip.DstIP)
	} else {
		return nil, false
	}
	if l := pk.Layer(layers.LayerTypeTCP); l != nil {
		t := l.(*layers.TCP)
		p.Proto = 6
		p.SrcPort, p.DstPort = uint16(t.SrcPort), uint16(t.DstPort)
		p.SYN, p.ACK, p.FIN, p.RST, p.PSH = t.SYN, t.ACK, t.FIN, t.RST, t.PSH
		p.Seq, p.Ack, p.Window = t.Seq, t.Ack, t.Window
		p.Payload = t.Payload
	} else if l := pk.Layer(layers.LayerTypeUDP); l != nil {
		u := l.(*layers.UDP)
		p.Proto = 17
		p.SrcPort, p.DstPort = uint16(u.SrcPort), uint16(u.DstPort)
		p.Payload = u.Payload
	} else {
		return nil, false
	}
	return p, true
}

// Source produz pacotes crus.
type Source interface {
	Next() (*Raw, error) // io.EOF ao terminar
	LinkType() layers.LinkType
	Close()
}

// fileSource lê pcap ou pcapng (opcionalmente .gz).
type fileSource struct {
	f *os.File
	r interface {
		ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	}
	lt   layers.LinkType
	name string
}

// OpenFile abre um arquivo de captura.
func OpenFile(path string) (Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var rd io.Reader = bufio.NewReaderSize(f, 1<<20)
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(rd)
		if err != nil {
			f.Close()
			return nil, err
		}
		rd = gz
	}
	br := bufio.NewReader(rd)
	magic, err := br.Peek(4)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s := &fileSource{f: f, name: path}
	if magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A {
		ng, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, err
		}
		s.r, s.lt = ng, ng.LinkType()
	} else {
		pr, err := pcapgo.NewReader(br)
		if err != nil {
			f.Close()
			return nil, err
		}
		s.r, s.lt = pr, pr.LinkType()
	}
	return s, nil
}

func (s *fileSource) Next() (*Raw, error) {
	d, ci, err := s.r.ReadPacketData()
	if err != nil {
		return nil, err
	}
	return &Raw{CI: ci, Data: d, LT: s.lt, Iface: "file"}, nil
}
func (s *fileSource) LinkType() layers.LinkType { return s.lt }
func (s *fileSource) Close()                    { s.f.Close() }
