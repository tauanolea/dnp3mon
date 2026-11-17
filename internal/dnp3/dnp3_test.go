package dnp3

import (
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	ob := &ObjBuilder{}
	ob.Header(1, 2, 0x00).U8(0).U8(39)
	for i := 0; i < 40; i++ {
		ob.U8(0x01 | byte(i%2)<<7)
	}
	ob.Header(51, 1, 0x07).U8(1).Time48(time.UnixMilli(1700000000000))
	ob.Header(2, 3, 0x17).U8(1).U8(5).U8(0x81).U16(250)
	ob.Header(32, 3, 0x28).U16(1).U16(7).U8(0x01).U32(1234).Time48(time.UnixMilli(1700000001000))
	ob.Header(12, 1, 0x28).U16(1).U16(3).U8(0x43).U8(1).U32(100).U32(0).U8(7)
	apdu := append(AppHeader(true, true, false, false, 5, FCResponse), 0x80|0x02, 0x08)
	apdu = append(apdu, ob.B...)
	// força fragmentação de transporte com um APDU grande
	frames, _ := EncodeAPDUFrames(false, 1, 1024, apdu, 10)
	var sc FrameScanner
	var r Reassembler
	var got *APDU
	for _, f := range frames {
		// entrega byte a byte para testar o scanner
		for i := range f {
			sc.Feed(f[i:i+1], func(ev ScanEvent) {
				if ev.Kind != ScanFrame {
					t.Fatalf("evento inesperado %v", ev.Kind)
				}
				a, _, err := r.Push(ev.Frame.Data)
				if err != nil {
					t.Fatal(err)
				}
				if a != nil {
					got = ParseAPDU(a)
				}
			})
		}
	}
	if got == nil || got.ParseErr != "" {
		t.Fatalf("parse falhou: %+v", got)
	}
	if got.IIN&IINDeviceRestart == 0 || got.IIN&IINEventOverflow == 0 {
		t.Fatalf("IIN errado %04x", got.IIN)
	}
	pts := got.Points()
	if len(pts) != 42 {
		t.Fatalf("esperava 42 pontos, veio %d", len(pts))
	}
	ev := pts[40]
	if !ev.Event || ev.Index != 5 || ev.Value != 1 || ev.Time.UnixMilli() != 1700000000250 {
		t.Fatalf("evento g2v3 errado %+v", ev)
	}
	if pts[41].Value != 1234 || pts[41].Index != 7 {
		t.Fatalf("g32v3 errado %+v", pts[41])
	}
	cmds := got.Commands()
	if len(cmds) != 1 || cmds[0].Status != 7 || cmds[0].Op() != "LATCH_ON/CLOSE" {
		t.Fatalf("crob errado %+v", cmds)
	}
	t.Log(got.Summary())
}

func TestCRCError(t *testing.T) {
	f := EncodeLinkFrame(true, true, false, false, LinkRequestLinkStatus, 1024, 1, nil)
	var sc FrameScanner
	ok := 0
	sc.Feed(f, func(ev ScanEvent) {
		if ev.Kind == ScanFrame && ev.Frame.FC == LinkRequestLinkStatus && ev.Frame.Dir {
			ok++
		}
	})
	f2 := append([]byte{}, f...)
	f2[5] ^= 0xFF
	errs := 0
	sc.Feed(append(f2, f...), func(ev ScanEvent) {
		if ev.Kind == ScanHeaderCRCError {
			errs++
		}
		if ev.Kind == ScanFrame {
			ok++
		}
	})
	if ok != 2 || errs != 1 {
		t.Fatalf("ok=%d errs=%d", ok, errs)
	}
}
