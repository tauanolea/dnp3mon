package dnp3

import (
	"encoding/binary"
	"math"
	"time"
)

// Funções de codificação (usadas pelo simulador e pelos testes).

// EncodeLinkFrame monta um frame de enlace completo com CRCs.
func EncodeLinkFrame(dir, prm, fcb, fcv bool, fc uint8, dst, src uint16, data []byte) []byte {
	ctrl := fc & 0x0F
	if dir {
		ctrl |= 0x80
	}
	if prm {
		ctrl |= 0x40
	}
	if fcb {
		ctrl |= 0x20
	}
	if fcv {
		ctrl |= 0x10
	}
	h := []byte{0x05, 0x64, byte(5 + len(data)), ctrl, byte(dst), byte(dst >> 8), byte(src), byte(src >> 8)}
	out := append([]byte{}, h...)
	out = binary.LittleEndian.AppendUint16(out, CRC(h))
	for len(data) > 0 {
		n := len(data)
		if n > 16 {
			n = 16
		}
		out = append(out, data[:n]...)
		out = binary.LittleEndian.AppendUint16(out, CRC(data[:n]))
		data = data[n:]
	}
	return out
}

// EncodeAPDUFrames segmenta um APDU em TPDUs (até 249 bytes) e frames de enlace
// UNCONFIRMED_USER_DATA. tseq é a sequência de transporte inicial; devolve a próxima.
func EncodeAPDUFrames(dir bool, dst, src uint16, apdu []byte, tseq uint8) ([][]byte, uint8) {
	var frames [][]byte
	first := true
	for {
		n := len(apdu)
		if n > 249 {
			n = 249
		}
		h := tseq & 0x3F
		if first {
			h |= 0x40
		}
		if n == len(apdu) {
			h |= 0x80
		}
		tpdu := append([]byte{h}, apdu[:n]...)
		frames = append(frames, EncodeLinkFrame(dir, true, false, false, LinkUnconfirmedUserData, dst, src, tpdu))
		tseq = (tseq + 1) & 0x3F
		apdu = apdu[n:]
		first = false
		if len(apdu) == 0 {
			break
		}
	}
	return frames, tseq
}

// AppHeader monta o cabeçalho de aplicação.
func AppHeader(fir, fin, con, uns bool, seq, fc uint8) []byte {
	ac := seq & 0x0F
	if fir {
		ac |= 0x80
	}
	if fin {
		ac |= 0x40
	}
	if con {
		ac |= 0x20
	}
	if uns {
		ac |= 0x10
	}
	return []byte{ac, fc}
}

// ObjBuilder ajuda a montar a seção de objetos.
type ObjBuilder struct{ B []byte }

// Header adiciona g/v/qualificador.
func (o *ObjBuilder) Header(g, v, q uint8) *ObjBuilder { o.B = append(o.B, g, v, q); return o }

// U8 adiciona um byte.
func (o *ObjBuilder) U8(x uint8) *ObjBuilder { o.B = append(o.B, x); return o }

// U16 adiciona 2 bytes LE.
func (o *ObjBuilder) U16(x uint16) *ObjBuilder {
	o.B = binary.LittleEndian.AppendUint16(o.B, x)
	return o
}

// U32 adiciona 4 bytes LE.
func (o *ObjBuilder) U32(x uint32) *ObjBuilder {
	o.B = binary.LittleEndian.AppendUint32(o.B, x)
	return o
}

// F32 adiciona float32.
func (o *ObjBuilder) F32(x float32) *ObjBuilder { return o.U32(math.Float32bits(x)) }

// Time48 adiciona tempo DNP3.
func (o *ObjBuilder) Time48(t time.Time) *ObjBuilder {
	ms := uint64(t.UnixMilli())
	for i := 0; i < 6; i++ {
		o.B = append(o.B, byte(ms>>(8*i)))
	}
	return o
}

// Bytes adiciona bytes crus.
func (o *ObjBuilder) Bytes(b []byte) *ObjBuilder { o.B = append(o.B, b...); return o }
