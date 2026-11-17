//go:build linux

package capture

import (
	"fmt"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"
)

// LiveSource captura de uma interface via AF_PACKET (TPACKET_V3).
type LiveSource struct {
	h     *afpacket.TPacket
	iface string
}

// OpenLive abre a interface em modo promíscuo. bufMB é o tamanho do ring do kernel.
func OpenLive(iface string, bufMB int) (*LiveSource, error) {
	if err := setPromisc(iface); err != nil {
		return nil, fmt.Errorf("promisc %s: %w", iface, err)
	}
	const frame = 1 << 16
	block := frame * 32
	nblocks := bufMB * (1 << 20) / block
	if nblocks < 4 {
		nblocks = 4
	}
	h, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptFrameSize(frame),
		afpacket.OptBlockSize(block),
		afpacket.OptNumBlocks(nblocks),
		afpacket.OptPollTimeout(500*time.Millisecond),
		afpacket.OptBlockTimeout(100*time.Millisecond),
		afpacket.TPacketVersion3,
	)
	if err != nil {
		return nil, err
	}
	return &LiveSource{h: h, iface: iface}, nil
}

// Next devolve o próximo pacote; em timeout devolve (nil, nil).
func (s *LiveSource) Next() (*Raw, error) {
	d, ci, err := s.h.ReadPacketData()
	if err == afpacket.ErrTimeout {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Raw{CI: ci, Data: d, LT: layers.LinkTypeEthernet, Iface: s.iface}, nil
}

// LinkType da captura ao vivo.
func (s *LiveSource) LinkType() layers.LinkType { return layers.LinkTypeEthernet }

// Close encerra a captura.
func (s *LiveSource) Close() { s.h.Close() }

// Stats devolve pacotes recebidos e descartados pelo kernel desde o início.
func (s *LiveSource) Stats() (pkts, drops uint64) {
	_, st, err := s.h.SocketStats()
	if err != nil {
		return 0, 0
	}
	return uint64(st.Packets()), uint64(st.Drops())
}

func setPromisc(iface string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(iface)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_PROMISC)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
