package dnp3

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

// APDU decodificado.
type APDU struct {
	FIR, FIN, CON, UNS bool
	Seq                uint8
	FC                 uint8
	IIN                uint16
	HasIIN             bool
	Objects            []Object
	ParseErr           string
	Raw                []byte
}

// IsResponse indica APDU enviado pela outstation.
func (a *APDU) IsResponse() bool { return a.FC >= 129 }

// Object é um cabeçalho de objeto e seus itens.
type Object struct {
	Group, Var, Qual uint8
	Start, Stop      uint32
	Count            uint32
	HasRange         bool
	Items            []Item
}

// Item é um elemento de dado dentro de um cabeçalho.
type Item struct {
	Index uint32
	Data  []byte // bytes do objeto (vazio em leituras)
	Bits  uint8  // valor para objetos empacotados
}

// GV devolve "g1v2".
func (o *Object) GV() string { return fmt.Sprintf("g%dv%d", o.Group, o.Var) }

// Summary devolve texto curto: "g1v2 q00 [0-15]".
func (o *Object) Summary() string {
	s := fmt.Sprintf("g%dv%d q%02X", o.Group, o.Var, o.Qual)
	switch {
	case o.Qual&0x0F == 0x06:
		s += " all"
	case o.HasRange:
		s += fmt.Sprintf(" [%d-%d]", o.Start, o.Stop)
	default:
		s += fmt.Sprintf(" n=%d", o.Count)
	}
	return s
}

// layout descreve o formato binário de um grupo/variação.
type layout struct {
	typ    string
	flags  bool
	val    byte // I i32, i i16, U u32, u u16, F f32, D f64, b bit7, d bits6-7, 0 nenhum
	t      byte // 0, 6 (abs 48 bits), 2 (relativo 16 bits)
	packed int  // bits por ponto em objetos empacotados
	event  bool
	status bool // primeiro byte é status de comando (g13, g43)
	fixed  int  // tamanho fixo especial (g12, g41, g50...)
}

func gv(g, v uint8) uint16 { return uint16(g)<<8 | uint16(v) }

func (l layout) size() int {
	if l.fixed > 0 {
		return l.fixed
	}
	n := 0
	if l.flags || l.status {
		n++
	}
	switch l.val {
	case 'I', 'U', 'F':
		n += 4
	case 'i', 'u':
		n += 2
	case 'D':
		n += 8
	}
	return n + int(l.t)
}

var layouts = map[uint16]layout{}

func reg(g uint8, typ string, event bool, vars map[uint8]layout) {
	for v, l := range vars {
		l.typ = typ
		l.event = event
		layouts[gv(g, v)] = l
	}
}

func init() {
	bi := map[uint8]layout{1: {packed: 1}, 2: {flags: true, val: 'b'}}
	reg(1, "BI", false, bi)
	reg(2, "BI", true, map[uint8]layout{1: {flags: true, val: 'b'}, 2: {flags: true, val: 'b', t: 6}, 3: {flags: true, val: 'b', t: 2}})
	reg(3, "DBI", false, map[uint8]layout{1: {packed: 2}, 2: {flags: true, val: 'd'}})
	reg(4, "DBI", true, map[uint8]layout{1: {flags: true, val: 'd'}, 2: {flags: true, val: 'd', t: 6}, 3: {flags: true, val: 'd', t: 2}})
	reg(10, "BOS", false, map[uint8]layout{1: {packed: 1}, 2: {flags: true, val: 'b'}})
	reg(11, "BOS", true, map[uint8]layout{1: {flags: true, val: 'b'}, 2: {flags: true, val: 'b', t: 6}})
	reg(13, "BOC", true, map[uint8]layout{1: {flags: true, val: 'b'}, 2: {flags: true, val: 'b', t: 6}})
	ctr := map[uint8]layout{1: {flags: true, val: 'U'}, 2: {flags: true, val: 'u'}, 3: {flags: true, val: 'U'}, 4: {flags: true, val: 'u'},
		5: {val: 'U'}, 6: {val: 'u'}, 7: {val: 'U'}, 8: {val: 'u'}}
	reg(20, "CTR", false, ctr)
	reg(21, "FCTR", false, map[uint8]layout{1: {flags: true, val: 'U'}, 2: {flags: true, val: 'u'}, 3: {flags: true, val: 'U'}, 4: {flags: true, val: 'u'},
		5: {flags: true, val: 'U', t: 6}, 6: {flags: true, val: 'u', t: 6}, 7: {flags: true, val: 'U', t: 6}, 8: {flags: true, val: 'u', t: 6},
		9: {val: 'U'}, 10: {val: 'u'}, 11: {val: 'U'}, 12: {val: 'u'}})
	ctrEv := map[uint8]layout{1: {flags: true, val: 'U'}, 2: {flags: true, val: 'u'}, 3: {flags: true, val: 'U'}, 4: {flags: true, val: 'u'},
		5: {flags: true, val: 'U', t: 6}, 6: {flags: true, val: 'u', t: 6}, 7: {flags: true, val: 'U', t: 6}, 8: {flags: true, val: 'u', t: 6}}
	reg(22, "CTR", true, ctrEv)
	reg(23, "FCTR", true, ctrEv)
	reg(30, "AI", false, map[uint8]layout{1: {flags: true, val: 'I'}, 2: {flags: true, val: 'i'}, 3: {val: 'I'}, 4: {val: 'i'}, 5: {flags: true, val: 'F'}, 6: {flags: true, val: 'D'}})
	reg(31, "FAI", false, map[uint8]layout{1: {flags: true, val: 'I'}, 2: {flags: true, val: 'i'}, 3: {flags: true, val: 'I', t: 6}, 4: {flags: true, val: 'i', t: 6},
		5: {val: 'I'}, 6: {val: 'i'}, 7: {flags: true, val: 'F'}, 8: {flags: true, val: 'D'}})
	aiEv := map[uint8]layout{1: {flags: true, val: 'I'}, 2: {flags: true, val: 'i'}, 3: {flags: true, val: 'I', t: 6}, 4: {flags: true, val: 'i', t: 6},
		5: {flags: true, val: 'F'}, 6: {flags: true, val: 'D'}, 7: {flags: true, val: 'F', t: 6}, 8: {flags: true, val: 'D', t: 6}}
	reg(32, "AI", true, aiEv)
	reg(33, "FAI", true, aiEv)
	reg(40, "AOS", false, map[uint8]layout{1: {flags: true, val: 'I'}, 2: {flags: true, val: 'i'}, 3: {flags: true, val: 'F'}, 4: {flags: true, val: 'D'}})
	reg(42, "AOS", true, aiEv)
	reg(43, "AOC", true, map[uint8]layout{1: {status: true, val: 'I'}, 2: {status: true, val: 'i'}, 3: {status: true, val: 'I', t: 6}, 4: {status: true, val: 'i', t: 6},
		5: {status: true, val: 'F'}, 6: {status: true, val: 'D'}, 7: {status: true, val: 'F', t: 6}, 8: {status: true, val: 'D', t: 6}})
	// Comandos
	layouts[gv(12, 1)] = layout{typ: "CROB", fixed: 11}
	layouts[gv(12, 2)] = layout{typ: "PCB", fixed: 11}
	layouts[gv(12, 3)] = layout{typ: "PCM", packed: 1}
	reg(41, "AOCMD", false, map[uint8]layout{1: {fixed: 5}, 2: {fixed: 3}, 3: {fixed: 5}, 4: {fixed: 9}})
	// Tempo, deadbands, IIN
	layouts[gv(50, 1)] = layout{typ: "TIME", fixed: 6}
	layouts[gv(50, 2)] = layout{typ: "TIME", fixed: 10}
	layouts[gv(50, 3)] = layout{typ: "TIME", fixed: 6}
	layouts[gv(50, 4)] = layout{typ: "TIME", fixed: 11}
	layouts[gv(51, 1)] = layout{typ: "CTO", fixed: 6}
	layouts[gv(51, 2)] = layout{typ: "CTO", fixed: 6}
	layouts[gv(52, 1)] = layout{typ: "DELAY", fixed: 2}
	layouts[gv(52, 2)] = layout{typ: "DELAY", fixed: 2}
	layouts[gv(34, 1)] = layout{typ: "DEADBAND", fixed: 2}
	layouts[gv(34, 2)] = layout{typ: "DEADBAND", fixed: 4}
	layouts[gv(34, 3)] = layout{typ: "DEADBAND", fixed: 4}
	layouts[gv(80, 1)] = layout{typ: "IIN", packed: 1}
}

// requestHasNoData: FCs cujos objetos de requisição não carregam dados.
func requestHasNoData(fc uint8) bool {
	switch fc {
	case FCRead, FCImmedFreeze, FCImmedFreezeNR, FCFreezeClear, FCFreezeClearNR,
		FCEnableUnsol, FCDisableUnsol, FCAssignClass:
		return true
	}
	return false
}

// ParseAPDU decodifica um APDU. Em caso de erro nos objetos, devolve o que
// conseguiu e preenche ParseErr.
func ParseAPDU(b []byte) *APDU {
	a := &APDU{Raw: b}
	if len(b) < 2 {
		a.ParseErr = "apdu_too_short"
		return a
	}
	ac := b[0]
	a.FIR, a.FIN, a.CON, a.UNS = ac&0x80 != 0, ac&0x40 != 0, ac&0x20 != 0, ac&0x10 != 0
	a.Seq = ac & 0x0F
	a.FC = b[1]
	p := 2
	if a.IsResponse() {
		if len(b) < 4 {
			a.ParseErr = "response_too_short"
			return a
		}
		a.IIN = uint16(b[2])<<8 | uint16(b[3])
		a.HasIIN = true
		p = 4
	}
	noData := !a.IsResponse() && requestHasNoData(a.FC)
	objs, err := parseObjects(b[p:], noData, a.IsResponse())
	a.Objects = objs
	if err != nil {
		a.ParseErr = err.Error()
	}
	return a
}

func parseObjects(b []byte, noData, isResp bool) ([]Object, error) {
	var out []Object
	p := 0
	rd := func(n int) (uint32, bool) {
		if p+n > len(b) {
			return 0, false
		}
		var v uint32
		switch n {
		case 1:
			v = uint32(b[p])
		case 2:
			v = uint32(binary.LittleEndian.Uint16(b[p:]))
		case 4:
			v = binary.LittleEndian.Uint32(b[p:])
		}
		p += n
		return v, true
	}
	for p < len(b) {
		if p+3 > len(b) {
			return out, fmt.Errorf("truncated_object_header")
		}
		o := Object{Group: b[p], Var: b[p+1], Qual: b[p+2]}
		p += 3
		prefix := (o.Qual >> 4) & 0x07
		rcode := o.Qual & 0x0F
		var n uint32
		var ok bool
		switch rcode {
		case 0, 1, 2, 3, 4, 5:
			sz := []int{1, 2, 4, 1, 2, 4}[rcode]
			if o.Start, ok = rd(sz); !ok {
				return out, fmt.Errorf("truncated_range")
			}
			if o.Stop, ok = rd(sz); !ok {
				return out, fmt.Errorf("truncated_range")
			}
			if o.Stop < o.Start || o.Stop-o.Start > 65535 {
				return out, fmt.Errorf("invalid_range")
			}
			o.HasRange = true
			n = o.Stop - o.Start + 1
		case 6:
			n = 0
		case 7, 8, 9, 0x0B:
			sz := map[uint8]int{7: 1, 8: 2, 9: 4, 0x0B: 1}[rcode]
			if n, ok = rd(sz); !ok {
				return out, fmt.Errorf("truncated_count")
			}
			if n > 65535 {
				return out, fmt.Errorf("invalid_count")
			}
		default:
			return out, fmt.Errorf("unsupported_qualifier_%02X", o.Qual)
		}
		o.Count = n
		l, known := layouts[gv(o.Group, o.Var)]
		dataPresent := !noData && o.Group != 60 && rcode != 6
		// objetos empacotados com faixa (sem prefixo)
		if known && l.packed > 0 && prefix == 0 && o.HasRange && dataPresent {
			nb := (int(n)*l.packed + 7) / 8
			if p+nb > len(b) {
				return out, fmt.Errorf("truncated_packed_data")
			}
			for i := 0; i < int(n); i++ {
				bit := i * l.packed
				v := (b[p+bit/8] >> (bit % 8)) & byte((1<<l.packed)-1)
				o.Items = append(o.Items, Item{Index: o.Start + uint32(i), Bits: v})
			}
			p += nb
			out = append(out, o)
			continue
		}
		size := 0
		if known {
			size = l.size()
		}
		switch o.Group {
		case 110, 111, 112, 113:
			size, known = int(o.Var), true
		}
		for i := uint32(0); i < n; i++ {
			it := Item{Index: o.Start + i}
			if !o.HasRange {
				it.Index = i
			}
			switch prefix {
			case 1, 2, 3:
				v, ok := rd([]int{0, 1, 2, 4}[prefix])
				if !ok {
					return append(out, o), fmt.Errorf("truncated_prefix")
				}
				it.Index = v
			}
			if dataPresent {
				sz := size
				switch {
				case prefix >= 4 && prefix <= 6:
					v, ok := rd([]int{0, 0, 0, 0, 1, 2, 4}[prefix])
					if !ok {
						return append(out, o), fmt.Errorf("truncated_size_prefix")
					}
					sz = int(v)
				case o.Group == 0 && isResp:
					// atributos de dispositivo: tipo(1) + tamanho(1) + valor
					if p+2 > len(b) {
						return append(out, o), fmt.Errorf("truncated_attr")
					}
					sz = 2 + int(b[p+1])
				case !known:
					return append(out, o), fmt.Errorf("unknown_object_g%dv%d", o.Group, o.Var)
				}
				if p+sz > len(b) {
					return append(out, o), fmt.Errorf("truncated_object_data_g%dv%d", o.Group, o.Var)
				}
				it.Data = b[p : p+sz]
				p += sz
			}
			o.Items = append(o.Items, it)
		}
		out = append(out, o)
	}
	return out, nil
}

// Point é um valor de ponto extraído de um objeto.
type Point struct {
	Type     string
	Index    uint32
	Value    float64
	Flags    uint8
	HasFlags bool
	Time     time.Time
	Event    bool
	Group    uint8
	Var      uint8
}

// DNPTime converte 48 bits em ms desde a época (UTC).
func DNPTime(b []byte) time.Time {
	var ms uint64
	for i := 5; i >= 0; i-- {
		ms = ms<<8 | uint64(b[i])
	}
	return time.UnixMilli(int64(ms)).UTC()
}

// Points extrai todos os pontos de medição/estado de um APDU de resposta.
func (a *APDU) Points() []Point {
	var out []Point
	var cto time.Time
	for oi := range a.Objects {
		o := &a.Objects[oi]
		if o.Group == 51 && len(o.Items) > 0 && len(o.Items[0].Data) >= 6 {
			cto = DNPTime(o.Items[0].Data)
			continue
		}
		l, ok := layouts[gv(o.Group, o.Var)]
		if !ok || l.fixed > 0 || l.typ == "IIN" || l.typ == "PCM" {
			continue
		}
		for _, it := range o.Items {
			pt := Point{Type: l.typ, Index: it.Index, Event: l.event, Group: o.Group, Var: o.Var}
			if l.packed > 0 {
				if len(it.Data) > 0 {
					continue
				}
				pt.Value = float64(it.Bits)
				pt.Flags = 0x01
				out = append(out, pt)
				continue
			}
			d := it.Data
			if len(d) < l.size() {
				continue
			}
			p := 0
			if l.flags || l.status {
				pt.Flags = d[0]
				pt.HasFlags = true
				p = 1
			}
			switch l.val {
			case 'b':
				pt.Value = float64(d[0] >> 7)
			case 'd':
				pt.Value = float64((d[0] >> 6) & 0x03)
			case 'I':
				pt.Value = float64(int32(binary.LittleEndian.Uint32(d[p:])))
				p += 4
			case 'U':
				pt.Value = float64(binary.LittleEndian.Uint32(d[p:]))
				p += 4
			case 'i':
				pt.Value = float64(int16(binary.LittleEndian.Uint16(d[p:])))
				p += 2
			case 'u':
				pt.Value = float64(binary.LittleEndian.Uint16(d[p:]))
				p += 2
			case 'F':
				pt.Value = float64(math.Float32frombits(binary.LittleEndian.Uint32(d[p:])))
				p += 4
			case 'D':
				pt.Value = math.Float64frombits(binary.LittleEndian.Uint64(d[p:]))
				p += 8
			}
			switch l.t {
			case 6:
				pt.Time = DNPTime(d[p:])
			case 2:
				if !cto.IsZero() {
					pt.Time = cto.Add(time.Duration(binary.LittleEndian.Uint16(d[p:])) * time.Millisecond)
				}
			}
			out = append(out, pt)
		}
	}
	return out
}

// Command representa um item de controle (CROB ou saída analógica).
type Command struct {
	Type   string // CROB | AO
	Index  uint32
	Code   uint8 // CROB: código de controle
	Count  uint8
	OnMs   uint32
	OffMs  uint32
	Value  float64 // AO
	Status uint8
	Body   []byte // bytes do objeto sem o status (para comparar eco)
	Group  uint8
	Var    uint8
}

// Op devolve a operação em texto.
func (c *Command) Op() string {
	if c.Type == "CROB" {
		return CROBOpName(c.Code)
	}
	return fmt.Sprintf("SET %g", c.Value)
}

// Commands extrai os comandos de um APDU (requisição ou eco na resposta).
func (a *APDU) Commands() []Command {
	var out []Command
	for oi := range a.Objects {
		o := &a.Objects[oi]
		for _, it := range o.Items {
			d := it.Data
			switch {
			case o.Group == 12 && (o.Var == 1 || o.Var == 2) && len(d) >= 11:
				out = append(out, Command{Type: "CROB", Index: it.Index, Code: d[0], Count: d[1],
					OnMs: binary.LittleEndian.Uint32(d[2:]), OffMs: binary.LittleEndian.Uint32(d[6:]),
					Status: d[10] & 0x7F, Body: d[:10], Group: 12, Var: o.Var})
			case o.Group == 41 && len(d) > 0:
				c := Command{Type: "AO", Index: it.Index, Group: 41, Var: o.Var}
				switch o.Var {
				case 1:
					c.Value = float64(int32(binary.LittleEndian.Uint32(d)))
				case 2:
					c.Value = float64(int16(binary.LittleEndian.Uint16(d)))
				case 3:
					c.Value = float64(math.Float32frombits(binary.LittleEndian.Uint32(d)))
				case 4:
					c.Value = math.Float64frombits(binary.LittleEndian.Uint64(d))
				}
				c.Status = d[len(d)-1] & 0x7F
				c.Body = d[:len(d)-1]
				out = append(out, c)
			}
		}
	}
	return out
}

// HasGV indica se o APDU contém o grupo/variação (v=0 qualquer variação).
func (a *APDU) HasGV(g, v uint8) bool {
	for i := range a.Objects {
		if a.Objects[i].Group == g && (v == 0 || a.Objects[i].Var == v) {
			return true
		}
	}
	return false
}

// ObjectSummaries devolve a lista de resumos de objetos.
func (a *APDU) ObjectSummaries() []string {
	out := make([]string, 0, len(a.Objects))
	for i := range a.Objects {
		out = append(out, a.Objects[i].Summary())
	}
	return out
}

// Kind classifica a finalidade de uma requisição do master.
func (a *APDU) Kind() string {
	switch a.FC {
	case FCRead:
		c0, cev, other := false, false, false
		for _, o := range a.Objects {
			switch {
			case o.Group == 60 && o.Var == 1:
				c0 = true
			case o.Group == 60:
				cev = true
			default:
				other = true
			}
		}
		switch {
		case c0:
			return "integrity"
		case cev && !other:
			return "event_poll"
		default:
			return "read"
		}
	case FCWrite:
		if a.HasGV(80, 1) {
			return "clear_restart"
		}
		if a.HasGV(50, 0) {
			return "time_sync"
		}
		return "write"
	case FCDelayMeasure, FCRecordCurrTime:
		return "time_sync"
	case FCSelect, FCOperate, FCDirectOperate, FCDirectOperateNR:
		return "command"
	case FCEnableUnsol, FCDisableUnsol:
		return "unsol_config"
	case FCConfirm:
		if a.UNS {
			return "confirm_unsol"
		}
		return "confirm"
	case FCColdRestart, FCWarmRestart:
		return "restart"
	case FCResponse:
		return "response"
	case FCUnsolResponse:
		if len(a.Objects) == 0 {
			return "unsol_null"
		}
		return "unsolicited"
	}
	return strings.ToLower(FCName(a.FC))
}

// Summary monta uma linha de texto estilo Wireshark.
func (a *APDU) Summary() string {
	var sb strings.Builder
	sb.WriteString(FCName(a.FC))
	fmt.Fprintf(&sb, " seq=%d", a.Seq)
	if a.FIR {
		sb.WriteString(" FIR")
	}
	if a.FIN {
		sb.WriteString(" FIN")
	}
	if a.CON {
		sb.WriteString(" CON")
	}
	if a.UNS {
		sb.WriteString(" UNS")
	}
	if a.HasIIN {
		if n := IINNames(a.IIN &^ IINEventClassMask); len(n) > 0 {
			sb.WriteString(" IIN[" + strings.Join(n, ",") + "]")
		}
	}
	for i := range a.Objects {
		o := &a.Objects[i]
		sb.WriteString(" ")
		sb.WriteString(o.Summary())
		if (o.Group == 12 || o.Group == 41) && len(o.Items) > 0 {
			for _, c := range a.Commands() {
				fmt.Fprintf(&sb, " idx=%d %s", c.Index, c.Op())
				if a.IsResponse() {
					sb.WriteString(" st=" + CmdStatusName(c.Status))
				}
			}
			break
		}
	}
	if a.ParseErr != "" {
		sb.WriteString(" ERR=" + a.ParseErr)
	}
	return sb.String()
}
