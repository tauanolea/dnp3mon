// Package dnp3 implementa a decodificação passiva do DNP3 (IEEE 1815):
// camada de enlace (com CRC), transporte (remontagem) e aplicação (objetos).
package dnp3

import "encoding/binary"

var crcTable [256]uint16

func init() {
	for i := 0; i < 256; i++ {
		crc := uint16(i)
		for j := 0; j < 8; j++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
		crcTable[i] = crc
	}
}

// CRC calcula o CRC-16 DNP (polinômio 0x3D65, refletido, complementado).
func CRC(b []byte) uint16 {
	var crc uint16
	for _, x := range b {
		crc = (crc >> 8) ^ crcTable[(crc^uint16(x))&0xFF]
	}
	return ^crc
}

// Códigos de função da camada de enlace.
const (
	LinkResetLinkStates     = 0
	LinkTestLinkStates      = 2
	LinkConfirmedUserData   = 3
	LinkUnconfirmedUserData = 4
	LinkRequestLinkStatus   = 9

	LinkAck          = 0
	LinkNack         = 1
	LinkStatus       = 11
	LinkNotSupported = 15
)

// LinkFCName devolve o nome do código de função de enlace.
func LinkFCName(prm bool, fc uint8) string {
	if prm {
		switch fc {
		case LinkResetLinkStates:
			return "RESET_LINK_STATES"
		case LinkTestLinkStates:
			return "TEST_LINK_STATES"
		case LinkConfirmedUserData:
			return "CONFIRMED_USER_DATA"
		case LinkUnconfirmedUserData:
			return "UNCONFIRMED_USER_DATA"
		case LinkRequestLinkStatus:
			return "REQUEST_LINK_STATUS"
		}
	} else {
		switch fc {
		case LinkAck:
			return "ACK"
		case LinkNack:
			return "NACK"
		case LinkStatus:
			return "LINK_STATUS"
		case LinkNotSupported:
			return "NOT_SUPPORTED"
		}
	}
	return "LINK_FC_" + itoa(int(fc))
}

// LinkFrame é um frame de enlace validado.
type LinkFrame struct {
	Dir      bool // true = enviado pelo master
	Prm      bool // true = primário
	FCB, FCV bool // FCV também é DFC em frames secundários
	FC       uint8
	Dst, Src uint16
	Data     []byte // dados de usuário sem os CRCs
	WireLen  int
}

// IsUserData indica se o frame carrega um TPDU.
func (f *LinkFrame) IsUserData() bool {
	return f.Prm && (f.FC == LinkConfirmedUserData || f.FC == LinkUnconfirmedUserData)
}

// ScanEventKind classifica o resultado da varredura de bytes.
type ScanEventKind int

const (
	ScanFrame ScanEventKind = iota
	ScanHeaderCRCError
	ScanDataCRCError
	ScanGarbage
)

// ScanEvent é emitido pelo FrameScanner.
type ScanEvent struct {
	Kind    ScanEventKind
	Frame   *LinkFrame // em ScanFrame e ScanDataCRCError (sem Data)
	Skipped int        // bytes descartados (ScanGarbage)
}

// FrameScanner extrai frames de enlace de um fluxo de bytes (um sentido de
// uma conexão TCP ou um datagrama UDP). Sincroniza em 0x05 0x64.
type FrameScanner struct {
	buf []byte
}

// Reset descarta o buffer (usado quando há lacuna no TCP).
func (s *FrameScanner) Reset() { s.buf = s.buf[:0] }

// Pending devolve quantos bytes estão aguardando completar um frame.
func (s *FrameScanner) Pending() int { return len(s.buf) }

// Feed adiciona bytes e emite eventos para cada frame encontrado.
func (s *FrameScanner) Feed(b []byte, emit func(ScanEvent)) {
	s.buf = append(s.buf, b...)
	buf := s.buf
	for {
		i := indexStart(buf)
		if i < 0 {
			// mantém um 0x05 final que pode ser início de frame
			keep := 0
			if len(buf) > 0 && buf[len(buf)-1] == 0x05 {
				keep = 1
			}
			if len(buf)-keep > 0 {
				emit(ScanEvent{Kind: ScanGarbage, Skipped: len(buf) - keep})
			}
			buf = buf[len(buf)-keep:]
			break
		}
		if i > 0 {
			emit(ScanEvent{Kind: ScanGarbage, Skipped: i})
			buf = buf[i:]
		}
		if len(buf) < 10 {
			break
		}
		if CRC(buf[:8]) != binary.LittleEndian.Uint16(buf[8:10]) || buf[2] < 5 {
			emit(ScanEvent{Kind: ScanHeaderCRCError})
			buf = buf[1:]
			continue
		}
		dataLen := int(buf[2]) - 5
		total := 10 + dataLen + 2*((dataLen+15)/16)
		if len(buf) < total {
			break
		}
		ctrl := buf[3]
		f := &LinkFrame{
			Dir:     ctrl&0x80 != 0,
			Prm:     ctrl&0x40 != 0,
			FCB:     ctrl&0x20 != 0,
			FCV:     ctrl&0x10 != 0,
			FC:      ctrl & 0x0F,
			Dst:     binary.LittleEndian.Uint16(buf[4:6]),
			Src:     binary.LittleEndian.Uint16(buf[6:8]),
			WireLen: total,
		}
		data := make([]byte, 0, dataLen)
		ok := true
		p, rem := 10, dataLen
		for rem > 0 {
			n := rem
			if n > 16 {
				n = 16
			}
			blk := buf[p : p+n]
			if CRC(blk) != binary.LittleEndian.Uint16(buf[p+n:p+n+2]) {
				ok = false
			}
			data = append(data, blk...)
			p += n + 2
			rem -= n
		}
		buf = buf[total:]
		if !ok {
			emit(ScanEvent{Kind: ScanDataCRCError, Frame: f})
			continue
		}
		f.Data = data
		emit(ScanEvent{Kind: ScanFrame, Frame: f})
	}
	// compacta o buffer
	if len(buf) > 4096 {
		buf = buf[len(buf)-4096:]
	}
	s.buf = append(s.buf[:0], buf...)
}

func indexStart(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == 0x05 && b[i+1] == 0x64 {
			return i
		}
	}
	return -1
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}

// Transport -----------------------------------------------------------------

// TransportError descreve problemas de remontagem.
type TransportError string

func (e TransportError) Error() string { return string(e) }

const (
	ErrTransportNoFIR    TransportError = "transport_no_fir"
	ErrTransportSeq      TransportError = "transport_seq_gap"
	ErrTransportDiscard  TransportError = "transport_incomplete_discarded"
	ErrTransportTooLarge TransportError = "transport_too_large"
	ErrTransportEmpty    TransportError = "transport_empty"
)

// Reassembler remonta APDUs a partir de TPDUs (um por par de endereços/sentido).
type Reassembler struct {
	buf     []byte
	next    uint8
	active  bool
	Segment int // segmentos no APDU atual
}

// Push processa um TPDU. Devolve o APDU completo (se FIN) e um eventual erro
// (o erro pode vir junto de um APDU válido quando um anterior foi descartado).
func (r *Reassembler) Push(tpdu []byte) (apdu []byte, segs int, err error) {
	if len(tpdu) < 1 {
		return nil, 0, ErrTransportEmpty
	}
	h := tpdu[0]
	fin, fir, seq := h&0x80 != 0, h&0x40 != 0, h&0x3F
	if fir {
		if r.active {
			err = ErrTransportDiscard
		}
		r.buf = r.buf[:0]
		r.active = true
		r.Segment = 0
	} else if !r.active {
		return nil, 0, ErrTransportNoFIR
	} else if seq != r.next {
		r.active = false
		return nil, 0, ErrTransportSeq
	}
	r.buf = append(r.buf, tpdu[1:]...)
	r.Segment++
	r.next = (seq + 1) & 0x3F
	if len(r.buf) > 8192 {
		r.active = false
		return nil, 0, ErrTransportTooLarge
	}
	if fin {
		r.active = false
		out := make([]byte, len(r.buf))
		copy(out, r.buf)
		return out, r.Segment, err
	}
	return nil, 0, err
}

// Reset descarta remontagem em andamento.
func (r *Reassembler) Reset() { r.active = false; r.buf = r.buf[:0] }
