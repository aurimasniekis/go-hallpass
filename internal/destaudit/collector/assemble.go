package collector

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/destaudit/wire"
)

// Filter selects which destination logins are shipped. A login is shipped when its certificate key ID was issued by
// Hallpass ("hallpass:" prefix), or its key fingerprint or account is listed. Everything else (other users' activity)
// stays on the destination.
type Filter struct {
	Fingerprints map[string]bool
	Accounts     map[string]bool
}

func (f Filter) ships(a *SSHDAuth) bool {
	if strings.HasPrefix(a.CertKeyID, wire.CertKeyIDPrefix) {
		return true
	}
	if a.CertKeyID == "" && f.Fingerprints[a.Fingerprint] {
		return true
	}
	return f.Accounts[a.User]
}

// Stats counts what the assembler did.
type Stats struct {
	Lines      int
	Ignored    int // lines that are neither audit nor sshd records
	Execs      int // complete exec events seen
	Shipped    int
	NotShipped int // exec events of logins outside the filter, without a login session, or never resolved
}

type execEvent struct {
	stamp   string
	t       time.Time
	syscall *AuditLine
	execve  []*AuditLine
	cwd     string
	done    bool
	seenAt  time.Time
}

type loginSession struct {
	stamp string
	pid   int64
	t     time.Time
}

type pendingExec struct {
	rec    wire.Record
	ses    int64
	seenAt time.Time
}

// Assembler turns interleaved audit and sshd lines into wire records. It is not safe for concurrent use.
type Assembler struct {
	Filter Filter
	// PendingTimeout is how long an exec waits for its login information (lines from different sources can arrive
	// out of order). Default 30s.
	PendingTimeout time.Duration
	// MaxTracked bounds every internal map (logins, sshd authentications, partial events). Default 10000.
	MaxTracked int
	Stats      Stats

	events  map[string]*execEvent
	logins  map[int64]loginSession // audit ses → login
	auths   map[int64]*SSHDAuth    // sshd pid → authentication
	pending []pendingExec
	ready   []wire.Record
}

// NewAssembler returns an assembler with defaults.
func NewAssembler(f Filter) *Assembler {
	return &Assembler{Filter: f, PendingTimeout: 30 * time.Second, MaxTracked: 10000,
		events: map[string]*execEvent{}, logins: map[int64]loginSession{}, auths: map[int64]*SSHDAuth{}}
}

// Add consumes one input line. now is the wall clock used for pending timeouts.
func (a *Assembler) Add(line string, now time.Time) {
	a.Stats.Lines++
	if auth, ok := ParseSSHDLine(line); ok {
		if len(a.auths) >= a.MaxTracked {
			clear(a.auths)
		}
		a.auths[auth.PID] = auth
		return
	}
	l, err := ParseAuditLine(line)
	if err != nil {
		a.Stats.Ignored++
		return
	}
	switch l.Type {
	case "LOGIN":
		ses, ok1 := l.Int("ses")
		pid, ok2 := l.Int("pid")
		if ok1 && ok2 && ses != unsetID {
			if len(a.logins) >= a.MaxTracked {
				clear(a.logins)
			}
			a.logins[ses] = loginSession{stamp: l.Stamp, pid: pid, t: l.Time}
		}
	case "SYSCALL", "EXECVE", "CWD":
		ev := a.event(l, now)
		switch l.Type {
		case "SYSCALL":
			ev.syscall = l
		case "EXECVE":
			ev.execve = append(ev.execve, l)
		case "CWD":
			ev.cwd = l.Str("cwd")
		}
	case "EOE":
		if ev, ok := a.events[l.Stamp]; ok {
			ev.done = true
			a.finish(ev, now)
		}
	}
}

func (a *Assembler) event(l *AuditLine, now time.Time) *execEvent {
	ev, ok := a.events[l.Stamp]
	if !ok {
		if len(a.events) >= a.MaxTracked {
			a.flushEvents(now, true)
		}
		ev = &execEvent{stamp: l.Stamp, t: l.Time, seenAt: now}
		a.events[l.Stamp] = ev
	}
	return ev
}

// finish turns a complete event into a pending exec (if it is one).
func (a *Assembler) finish(ev *execEvent, now time.Time) {
	delete(a.events, ev.stamp)
	if ev.syscall == nil || len(ev.execve) == 0 {
		return // not an exec event (or an incomplete one)
	}
	a.Stats.Execs++
	s := ev.syscall
	ses, ok := s.Int("ses")
	if !ok || ses == unsetID {
		a.Stats.NotShipped++
		return
	}
	pid, _ := s.Int("pid")
	ppid, _ := s.Int("ppid")
	uid, _ := s.Int("uid")
	auid, _ := s.Int("auid")
	argv, truncated := wire.TruncateArgv(joinArgv(ev.execve))
	rec := wire.Record{ID: ev.stamp, Source: wire.SourceAuditd, Time: ev.t, PID: pid, PPID: ppid, UID: uid, AUID: auid,
		Success: s.Fields["success"] == "yes", Exe: clip(s.Str("exe"), wire.MaxPathLen), Argv: argv, Truncated: truncated,
		CWD: clip(ev.cwd, wire.MaxPathLen)}
	a.pending = append(a.pending, pendingExec{rec: rec, ses: ses, seenAt: now})
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// joinArgv rebuilds argv from one or more EXECVE records: aN, or aN_len with aN[0], aN[1], … chunks.
func joinArgv(recs []*AuditLine) []string {
	merged := &AuditLine{Fields: map[string]string{}, Quoted: map[string]bool{}}
	for _, r := range recs {
		for k, v := range r.Fields {
			merged.Fields[k] = v
			merged.Quoted[k] = r.Quoted[k]
		}
	}
	argc, ok := merged.Int("argc")
	if !ok || argc < 0 {
		return nil
	}
	argc = min(argc, wire.MaxArgs+1) // more than MaxArgs is truncated anyway
	argv := make([]string, 0, argc)
	for i := range argc {
		key := "a" + strconv.FormatInt(i, 10)
		if _, ok := merged.Fields[key]; ok {
			argv = append(argv, merged.Str(key))
			continue
		}
		// Split argument: aN[0]=…, aN[1]=… (always hex-encoded chunks or quoted pieces).
		var parts []int
		prefix := key + "["
		for k := range merged.Fields {
			if strings.HasPrefix(k, prefix) && strings.HasSuffix(k, "]") {
				if n, err := strconv.Atoi(k[len(prefix) : len(k)-1]); err == nil && n >= 0 {
					parts = append(parts, n)
				}
			}
		}
		if len(parts) == 0 {
			break // record missing (lost): keep what we have
		}
		sort.Ints(parts)
		var b strings.Builder
		for _, n := range parts {
			b.WriteString(merged.Str(prefix + strconv.Itoa(n) + "]"))
		}
		argv = append(argv, b.String())
	}
	return argv
}

// Drain resolves pending execs against known logins and returns records ready to ship. With final set (end of
// input) it completes partial events and drops anything still unresolved.
func (a *Assembler) Drain(now time.Time, final bool) []wire.Record {
	a.flushEvents(now, final)
	keep := a.pending[:0]
	for _, p := range a.pending {
		login, okL := a.logins[p.ses]
		var auth *SSHDAuth
		if okL {
			auth = a.auths[login.pid]
		}
		if auth == nil {
			if !final && now.Sub(p.seenAt) < a.PendingTimeout {
				keep = append(keep, p)
			} else {
				a.Stats.NotShipped++
			}
			continue
		}
		if !a.Filter.ships(auth) {
			a.Stats.NotShipped++
			continue
		}
		rec := p.rec
		rec.Login = wire.Login{Ref: login.stamp + "/" + strconv.FormatInt(p.ses, 10), User: auth.User, Time: login.t}
		if auth.CertKeyID != "" {
			rec.Login.CertKeyID = auth.CertKeyID
		} else {
			rec.Login.KeyFingerprint = auth.Fingerprint
		}
		a.ready = append(a.ready, rec)
		a.Stats.Shipped++
	}
	a.pending = keep
	out := a.ready
	a.ready = nil
	return out
}

// flushEvents completes events whose EOE never arrived (single-record events, lost lines) after the pending
// timeout, or all of them when final.
func (a *Assembler) flushEvents(now time.Time, final bool) {
	var stale []*execEvent
	for _, ev := range a.events {
		if final || now.Sub(ev.seenAt) >= a.PendingTimeout {
			stale = append(stale, ev)
		}
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].stamp < stale[j].stamp })
	for _, ev := range stale {
		a.finish(ev, now)
	}
}
