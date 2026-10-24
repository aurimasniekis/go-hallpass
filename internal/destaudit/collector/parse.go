// Package collector is the reference destination-side audit collector (WP25): it reads Linux audit (auditd) log
// lines and sshd authentication log lines, assembles exec records for logins HallPass made, and ships them as signed
// batches. It deliberately has no storage or HallPass-internal dependencies beyond the wire format.
//
// Input format (one line per record, any interleaving of the two sources):
//
//   - auditd raw lines, as written to /var/log/audit/audit.log or printed by `ausearch --raw`:
//     "[node=<host> ]type=<TYPE> msg=audit(<sec>.<ms>:<serial>): key=value …". Used types: SYSCALL, EXECVE, CWD,
//     EOE (exec events) and LOGIN (pam_loginuid assigning an audit session to the sshd process). Quoted values are
//     literal; unquoted string values are hex-encoded (auditd's encoding for values with spaces or control bytes);
//     long arguments split as aN_len/aN[i] are joined. The ENRICHED-format suffix (after 0x1d) is ignored.
//   - sshd lines from syslog or `journalctl -o short`: "… sshd[<pid>]: Accepted publickey for <user> from <addr>
//     port <port> ssh2: <KEYTYPE> SHA256:<fp>[ ID <key id> (serial <n>) CA <type> SHA256:<fp>]" (also sshd-session).
//
// Anything else is ignored.
package collector

import (
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AuditLine is one parsed auditd record line.
type AuditLine struct {
	Type   string
	Stamp  string // "<sec>.<ms>:<serial>", the event identifier shared by all records of one event
	Time   time.Time
	Fields map[string]string // raw values (quotes removed; hex left encoded)
	// Quoted records which fields were quoted (literal) rather than hex-encoded.
	Quoted map[string]bool
}

var errNotAudit = errors.New("not an audit line")

// ParseAuditLine parses one auditd line.
func ParseAuditLine(line string) (*AuditLine, error) {
	if i := strings.IndexByte(line, 0x1d); i >= 0 { // ENRICHED format: interpreted fields follow GS
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "node=") {
		_, rest, ok := strings.Cut(line, " ")
		if !ok {
			return nil, errNotAudit
		}
		line = rest
	}
	typ, rest, ok := strings.Cut(line, " ")
	if !ok || !strings.HasPrefix(typ, "type=") {
		return nil, errNotAudit
	}
	rest = strings.TrimLeft(rest, " ")
	if !strings.HasPrefix(rest, "msg=audit(") {
		return nil, errNotAudit
	}
	end := strings.Index(rest, "):")
	if end < 0 {
		return nil, errNotAudit
	}
	stamp := rest[len("msg=audit("):end]
	t, err := stampTime(stamp)
	if err != nil {
		return nil, err
	}
	l := &AuditLine{Type: strings.TrimPrefix(typ, "type="), Stamp: stamp, Time: t, Fields: map[string]string{}, Quoted: map[string]bool{}}
	parseFields(rest[end+2:], l)
	return l, nil
}

func stampTime(stamp string) (time.Time, error) {
	ts, serial, ok := strings.Cut(stamp, ":")
	if !ok {
		return time.Time{}, errNotAudit
	}
	if _, err := strconv.ParseUint(serial, 10, 64); err != nil {
		return time.Time{}, errNotAudit
	}
	secS, msS, ok := strings.Cut(ts, ".")
	if !ok {
		return time.Time{}, errNotAudit
	}
	sec, err1 := strconv.ParseInt(secS, 10, 64)
	ms, err2 := strconv.ParseInt(msS, 10, 64)
	if err1 != nil || err2 != nil || len(msS) != 3 {
		return time.Time{}, errNotAudit
	}
	return time.Unix(sec, ms*int64(time.Millisecond)).UTC(), nil
}

// parseFields splits `k=v k2="quoted v" k3='nested …'` into l.Fields. Later duplicates win.
func parseFields(s string, l *AuditLine) {
	for {
		s = strings.TrimLeft(s, " ")
		if s == "" {
			return
		}
		eq := strings.IndexByte(s, '=')
		sp := strings.IndexByte(s, ' ')
		if eq < 0 || (sp >= 0 && sp < eq) {
			// A bare token without '=': skip it.
			if sp < 0 {
				return
			}
			s = s[sp:]
			continue
		}
		key := s[:eq]
		s = s[eq+1:]
		var val string
		quoted := false
		switch {
		case strings.HasPrefix(s, `"`):
			endQ := strings.IndexByte(s[1:], '"')
			if endQ < 0 {
				val, s = s[1:], ""
			} else {
				val, s = s[1:1+endQ], s[2+endQ:]
			}
			quoted = true
		case strings.HasPrefix(s, `'`):
			endQ := strings.IndexByte(s[1:], '\'')
			if endQ < 0 {
				val, s = s[1:], ""
			} else {
				val, s = s[1:1+endQ], s[2+endQ:]
			}
			quoted = true
		default:
			if sp := strings.IndexByte(s, ' '); sp >= 0 {
				val, s = s[:sp], s[sp:]
			} else {
				val, s = s, ""
			}
		}
		l.Fields[key] = val
		l.Quoted[key] = quoted
	}
}

// Str decodes a string field: quoted values are literal, unquoted values are hex (auditd's untrusted-string
// encoding). "(null)" and missing fields return "".
func (l *AuditLine) Str(key string) string {
	v, ok := l.Fields[key]
	if !ok || v == "(null)" {
		return ""
	}
	if l.Quoted[key] {
		return v
	}
	return decodeHex(v)
}

func decodeHex(v string) string {
	b, err := hex.DecodeString(v)
	if err != nil {
		return v
	}
	return string(b)
}

// Int parses a numeric field.
func (l *AuditLine) Int(key string) (int64, bool) {
	v, ok := l.Fields[key]
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil
}

// unsetID is the kernel's "unset" auid/ses value ((uint32)-1).
const unsetID = 4294967295

// SSHDAuth is an sshd "Accepted publickey" line.
type SSHDAuth struct {
	PID         int64
	User        string
	KeyType     string
	Fingerprint string
	CertKeyID   string // set for certificate logins
}

var sshdAccepted = regexp.MustCompile(`\bsshd(?:-session)?\[(\d+)\]: Accepted publickey for (\S+) from \S+ port \d+ ssh2: (\S+) (SHA256:[A-Za-z0-9+/=]+)(?: ID (\S+) \(serial \d+\) CA \S+ SHA256:[A-Za-z0-9+/=]+)?\s*$`)

// ParseSSHDLine parses an sshd public-key acceptance line.
func ParseSSHDLine(line string) (*SSHDAuth, bool) {
	m := sshdAccepted.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
	if m == nil {
		return nil, false
	}
	pid, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || pid <= 0 {
		return nil, false
	}
	a := &SSHDAuth{PID: pid, User: m[2], KeyType: m[3], Fingerprint: m[4], CertKeyID: m[5]}
	if a.CertKeyID != "" && !strings.HasSuffix(a.KeyType, "-CERT") {
		return nil, false
	}
	return a, true
}
