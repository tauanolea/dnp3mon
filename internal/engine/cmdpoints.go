package engine

import (
	"bytes"
	"fmt"
	"time"

	"dnp3mon/internal/dnp3"
	"dnp3mon/internal/model"
)

const (
	stageSelecting = iota
	stageSelected
	stageOperating
	stageFeedback
)

type cmdState struct {
	row       model.Command
	stage     int
	body      []byte
	start     time.Time
	selTS     time.Time
	selRespTS time.Time
	opTS      time.Time
	respTS    time.Time
	echoBad   bool
	opBad     bool
	retries   int
}

func (e *Engine) cmdRequest(r *rtu, fl *flow, q *request, a *dnp3.APDU, ts time.Time) {
	for _, c := range a.Commands() {
		k := pkey{c.Type, c.Index}
		cur := r.cmds[k]
		newCmd := func(mode string) *cmdState {
			if cur != nil {
				res := ""
				if cur.stage == stageSelected {
					res = "select_only"
				}
				// retentativa do mesmo comando após timeout: mantém o contador
				if cur.stage == stageSelecting || cur.stage == stageOperating {
					res = "superseded"
				}
				e.finishCmd(r, k, cur, res)
			}
			st := &cmdState{start: ts, body: append([]byte{}, c.Body...)}
			st.row = model.Command{RTU: r.key, Master: fl.master.String(), Type: c.Type, Idx: c.Index,
				Op: c.Op(), Value: c.Value, Mode: mode, EchoOK: 1}
			if c.Type == "CROB" {
				st.row.Detail = fmt.Sprintf("count=%d on=%dms off=%dms", c.Count, c.OnMs, c.OffMs)
			}
			st.retries = q.retry
			r.cmds[k] = st
			return st
		}
		switch a.FC {
		case dnp3.FCSelect:
			st := newCmd("SBO")
			st.selTS = ts
			st.stage = stageSelecting
		case dnp3.FCOperate:
			if cur != nil && cur.stage == stageSelected {
				cur.opTS = ts
				cur.stage = stageOperating
				if !bytes.Equal(cur.body, c.Body) {
					cur.opBad = true
				}
			} else if cur != nil && cur.stage == stageOperating && q.retry > 0 {
				cur.retries = q.retry
			} else {
				st := newCmd("OPERATE_NO_SELECT")
				st.opTS = ts
				st.stage = stageOperating
			}
		case dnp3.FCDirectOperate:
			if cur != nil && cur.stage == stageOperating && q.retry > 0 && bytes.Equal(cur.body, c.Body) {
				cur.retries = q.retry
			} else {
				st := newCmd("DO")
				st.opTS = ts
				st.stage = stageOperating
			}
		case dnp3.FCDirectOperateNR:
			st := newCmd("DO_NR")
			st.opTS = ts
			st.stage = stageFeedback
			st.row.Status = "NO_ACK"
		}
		q.cmds = append(q.cmds, k)
	}
}

func (e *Engine) cmdResponse(r *rtu, fl *flow, q *request, a *dnp3.APDU, ts time.Time) {
	echo := map[pkey]dnp3.Command{}
	for _, c := range a.Commands() {
		echo[pkey{c.Type, c.Index}] = c
	}
	for _, k := range q.cmds {
		st := r.cmds[k]
		if st == nil {
			continue
		}
		c, ok := echo[k]
		status := "NO_ECHO"
		if ok {
			status = dnp3.CmdStatusName(c.Status)
			if !bytes.Equal(c.Body, st.body) {
				st.echoBad = true
			}
		} else if n := dnp3.IINNames(a.IIN & dnp3.IINRequestErrorMask); len(n) > 0 {
			status = "IIN:" + n[0]
		}
		if q.fc == dnp3.FCSelect {
			st.row.SelectStatus = status
			st.selRespTS = ts
			if !ok || c.Status != 0 {
				e.finishCmd(r, k, st, "select_failed")
			} else {
				st.stage = stageSelected
			}
			continue
		}
		st.respTS = ts
		st.row.Status = status
		if !ok || c.Status != 0 {
			e.finishCmd(r, k, st, "failed")
		} else {
			st.stage = stageFeedback
		}
	}
}

// feedback: primeira mudança de estado binário após um comando bem-sucedido.
func (e *Engine) feedback(r *rtu, pt *dnp3.Point, ts time.Time) {
	for k, st := range r.cmds {
		if st.stage != stageFeedback || st.row.FeedbackPoint != "" {
			continue
		}
		if ts.Sub(st.opTS) > e.cfg.FeedbackWindow {
			continue
		}
		st.row.FeedbackPoint = fmt.Sprintf("%s:%d", pt.Type, pt.Index)
		st.row.FeedbackMs = model.Ms(ts.Sub(st.opTS))
		e.finishCmd(r, k, st, "")
	}
}

func (e *Engine) finishCmd(r *rtu, k pkey, st *cmdState, result string) {
	delete(r.cmds, k)
	row := st.row
	if result == "" {
		switch {
		case st.stage == stageFeedback:
			result = "success"
			if row.Mode == "DO_NR" {
				result = "sent_no_ack"
			}
		default:
			result = "unknown"
		}
	}
	if result == "success" && (st.echoBad || st.opBad) {
		result = "echo_mismatch"
	}
	if st.echoBad || st.opBad {
		row.EchoOK = 0
	}
	row.Result = result
	ts := st.opTS
	if ts.IsZero() {
		ts = st.selTS
	}
	if ts.IsZero() {
		ts = st.start
	}
	row.TS = model.Time(ts)
	row.SelectTS = model.T(st.selTS)
	row.OperateTS = model.T(st.opTS)
	row.RespTS = model.T(st.respTS)
	if !st.respTS.IsZero() {
		row.DurationMs = model.Ms(st.respTS.Sub(st.start))
	}
	if !st.selTS.IsZero() && !st.opTS.IsZero() {
		row.SelectToOpMs = model.Ms(st.opTS.Sub(st.selTS))
	}
	row.Retries = uint8(st.retries)
	r.st.CmdTotal++
	switch result {
	case "success", "sent_no_ack":
		r.st.CmdOK++
	case "superseded":
		r.st.CmdTotal--
		return
	default:
		r.st.CmdFail++
		e.event(r, nil, "cmd", "command_failed", "crit", float64(k.idx),
			fmt.Sprintf("%s %s idx=%d %s: %s (select=%s status=%s)", row.Mode, k.typ, k.idx, row.Op, result, row.SelectStatus, row.Status))
	}
	e.out.Command(&row)
}

func (e *Engine) points(r *rtu, fl *flow, pts []dnp3.Point, ctx string) {
	now := e.now
	for i := range pts {
		pt := &pts[i]
		k := pkey{pt.Type, pt.Index}
		st := r.points[k]
		bin := pt.Type == "BI" || pt.Type == "DBI"
		if pt.HasFlags && (pt.Flags&0x01 == 0 || pt.Flags&0x1C != 0) && pt.Type != "BOC" && pt.Type != "AOC" {
			r.st.PtBadQuality++
		}
		if !pt.Time.IsZero() {
			dl := float64(now.Sub(pt.Time).Microseconds()) / 1000
			if pt.Time.Year() < 2000 || pt.Time.After(now.Add(24*time.Hour)) {
				r.st.EvBadTime++
			} else {
				if r.st.EvDelayCnt == 0 || dl < r.st.EvDelayMinMs {
					r.st.EvDelayMinMs = dl
				}
				if r.st.EvDelayCnt == 0 || dl > r.st.EvDelayMaxMs {
					r.st.EvDelayMaxMs = dl
				}
				r.st.EvDelaySumMs += dl
				r.st.EvDelayCnt++
			}
		}
		changed := st == nil || st.value != pt.Value || st.flags != pt.Flags
		valueChanged := st != nil && st.value != pt.Value
		emit := false
		src := "static"
		if pt.Event {
			r.st.PtEvents++
			emit = true
			src = "event"
			if ctx == "unsol" {
				src = "unsol"
			}
		} else {
			if changed {
				r.st.PtStaticChanges++
				emit = true
				if bin && valueChanged && st.eventSeen {
					r.st.LostEventSusp++
					e.event(r, fl, "data", "lost_event_suspect", "warn", float64(pt.Index),
						fmt.Sprintf("%s:%d mudou de %g para %g sem evento", pt.Type, pt.Index, st.value, pt.Value))
				}
			} else if e.cfg.StaticMode == "all" {
				emit = true
			}
		}
		if st == nil {
			st = &pstate{}
			r.points[k] = st
		}
		if bin && valueChanged {
			r.st.PtBinChanges++
			e.feedback(r, pt, now)
			st.changes = append(st.changes, now)
			cut := now.Add(-e.cfg.ChatterWindow)
			j := 0
			for j < len(st.changes) && st.changes[j].Before(cut) {
				j++
			}
			st.changes = st.changes[j:]
			if len(st.changes) >= e.cfg.ChatterCount && now.Sub(st.chatterTS) > 10*time.Minute {
				st.chatterTS = now
				r.st.Chatter++
				e.event(r, fl, "data", "chatter", "warn", float64(pt.Index),
					fmt.Sprintf("%s:%d com %d mudanças em %s", pt.Type, pt.Index, len(st.changes), e.cfg.ChatterWindow))
			}
		}
		st.value, st.flags, st.ts = pt.Value, pt.Flags, now
		if pt.Event {
			st.eventSeen = true
		}
		if emit {
			row := &model.Point{TS: model.Time(now), RTU: r.key, Type: pt.Type, Idx: pt.Index, Value: pt.Value,
				Flags: pt.Flags, IsEvent: b2u(pt.Event), Src: src, EventTS: model.T(pt.Time),
				GV: fmt.Sprintf("g%dv%d", pt.Group, pt.Var)}
			if pt.Flags&0x01 != 0 || !pt.HasFlags {
				row.Online = 1
			}
			e.out.Point(row)
		}
	}
}
