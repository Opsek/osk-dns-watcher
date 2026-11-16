package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

func transportRun(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRunVersion(t *testing.T) {
	code, out, errOut := transportRun("version")
	lines := strings.Split(out, "\n")
	if code != 0 || errOut != "" || len(lines) != 4 || !strings.HasPrefix(lines[0], "osk ") ||
		!strings.HasPrefix(lines[1], "go ") || !strings.HasPrefix(lines[2], "sqlite ") || lines[3] != "" {
		t.Errorf("exit code %d, output:\n%s\nerrors:\n%s", code, out, errOut)
	}
}

func TestRunWrongUse(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"other"},
		{"version", "extra"},
		{"query"},
		{"query", "corp.test."},
		{"query", "@127.0.0.1"},
		{"query", "127.0.0.1", "corp.test."},
		{"query", "@ns1.corp.test", "corp.test."}, // no host names
		{"query", "@127.0.0.1:99999", "corp.test."},
		{"query", "@127.0.0.1", "a..b"},
		{"query", "@127.0.0.1", "corp.test.", "NOTATYPE"},
		{"query", "@127.0.0.1", "corp.test.", "AXFR"},
		{"query", "@127.0.0.1", "corp.test.", "IXFR"},
		{"query", "@127.0.0.1", "corp.test.", "OPT"},
		{"query", "@127.0.0.1", "corp.test.", "TSIG"},
		{"query", "@127.0.0.1", "corp.test.", "A", "extra"},
		{"query", "@127.0.0.1", "corp.test.", "A", "--tcp"}, // flags come first
		{"query", "--other", "@127.0.0.1", "corp.test."},
		{"query", "--timeout", "soon", "@127.0.0.1", "corp.test."},
	} {
		code, out, errOut := transportRun(args...)
		if code != 2 || out != "" || !strings.Contains(strings.ToLower(errOut), "usage") {
			t.Errorf("run(%q): exit code %d, output %q, errors %q; want 2, nothing and the usage", args, code, out, errOut)
		}
	}
}

// transportQuery is a query that the fake server received.
type transportQuery struct {
	wire []byte // without the TCP length
	tcp  bool
}

// transportServer is a fake DNS server on one port of 127.0.0.1. It answers
// each query, over UDP or TCP, with the message that answer returns, or with
// nothing for nil.
type transportServer struct {
	addr    string
	queries chan transportQuery
}

func transportStart(t *testing.T, answer func(q []byte, tcp bool) []byte) *transportServer {
	t.Helper()
	var pc net.PacketConn
	var ln net.Listener
	for range 20 {
		var err error
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		_ = pc.Close()
		ln = nil
	}
	if ln == nil {
		t.Fatal("no port of 127.0.0.1 is free for both UDP and TCP")
	}
	t.Cleanup(func() {
		_ = pc.Close()
		_ = ln.Close()
	})
	s := &transportServer{addr: pc.LocalAddr().String(), queries: make(chan transportQuery, 10)}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := bytes.Clone(buf[:n])
			s.record(q, false)
			if a := transportAnswerOf(answer, q, false); a != nil {
				_, _ = pc.WriteTo(a, from)
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var n [2]byte
			if _, err := io.ReadFull(c, n[:]); err == nil {
				q := make([]byte, binary.BigEndian.Uint16(n[:]))
				if _, err := io.ReadFull(c, q); err == nil {
					s.record(q, true)
					if a := transportAnswerOf(answer, q, true); a != nil {
						_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(a))), a...))
					}
				}
			}
			_ = c.Close()
		}
	}()
	return s
}

// transportAnswerOf calls answer only for a query with a question that it
// can copy.
func transportAnswerOf(answer func([]byte, bool) []byte, q []byte, tcp bool) []byte {
	if answer == nil || transportQuestionOf(q) == nil {
		return nil
	}
	return answer(q, tcp)
}

func (s *transportServer) record(q []byte, tcp bool) {
	select {
	case s.queries <- transportQuery{q, tcp}:
	default:
	}
}

func (s *transportServer) next(t *testing.T) transportQuery {
	t.Helper()
	select {
	case q := <-s.queries:
		return q
	case <-time.After(5 * time.Second):
		t.Fatal("the server received no query")
		return transportQuery{}
	}
}

// transportQuestionOf returns the question section of a query, whose name is
// uncompressed, or nil when it has none.
func transportQuestionOf(q []byte) []byte {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:]) != 1 {
		return nil
	}
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	if i+5 > len(q) {
		return nil
	}
	return q[12 : i+5]
}

func transportWire(name string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func transportRR(owner []byte, typ, class uint16, ttl uint32, data []byte) []byte {
	b := bytes.Clone(owner)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, class)
	b = binary.BigEndian.AppendUint32(b, ttl)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// transportAnswer returns an answer to q with its ID and question, the flags
// with the rcode in the lowest four bits, and the records of each section.
func transportAnswer(q []byte, flags uint16, answer, authority, additional [][]byte) []byte {
	b := slices.Clone(q[:2])
	b = binary.BigEndian.AppendUint16(b, flags)
	for _, n := range []int{1, len(answer), len(authority), len(additional)} {
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	}
	b = append(b, transportQuestionOf(q)...)
	for _, r := range slices.Concat(answer, authority, additional) {
		b = append(b, r...)
	}
	return b
}

const (
	transportQR = 0x8000
	transportAA = 0x0400
	// Every flag that the flags line names: qr aa tc rd ra ad cd.
	transportAllFlags = 0x8000 | 0x0400 | 0x0200 | 0x0100 | 0x0080 | 0x0020 | 0x0010
)

// transportA is the record corp.test. 300 IN A 192.0.2.1, its owner a pointer
// to the question name.
var transportA = transportRR([]byte{0xC0, 12}, 1, 1, 300, []byte{192, 0, 2, 1})

// transportOPT holds a cookie and an extended error whose text tries to start
// lines of its own, which the output must not show as lines.
func transportOPT() []byte {
	text := "x\n;; ANSWER SECTION:\nforged\x00"
	var opts []byte
	opts = binary.BigEndian.AppendUint16(opts, 10)
	opts = binary.BigEndian.AppendUint16(opts, 16)
	opts = append(opts, "clientcoserverco"...)
	opts = binary.BigEndian.AppendUint16(opts, 15)
	opts = binary.BigEndian.AppendUint16(opts, uint16(2+len(text)))
	opts = binary.BigEndian.AppendUint16(opts, 0)
	opts = append(opts, text...)
	return transportRR([]byte{0}, 41, 1232, 0, opts)
}

// transportShape returns the lines of the output that are not free lines:
// all but the empty ones and those that start with "; ".
func transportShape(out string) []string {
	var lines []string
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if l != "" && !strings.HasPrefix(l, "; ") {
			lines = append(lines, l)
		}
	}
	return lines
}

func TestRunQuery(t *testing.T) {
	s := transportStart(t, func(q []byte, tcp bool) []byte {
		if tcp {
			return transportAnswer(q, transportAllFlags, [][]byte{transportA}, nil, [][]byte{transportOPT()})
		}
		return transportAnswer(q, transportQR|transportAA, [][]byte{transportA}, nil, [][]byte{transportOPT()})
	})
	cases := []struct {
		name            string
		args            []string
		rd, do, cd, tcp bool
		flags           string
	}{
		{name: "defaults", args: []string{"@" + s.addr, "corp.test."}, flags: "qr aa"},
		{name: "rd do cd", args: []string{"--rd", "--do", "--cd", "@" + s.addr, "corp.test.", "A"}, rd: true, do: true, cd: true, flags: "qr aa"},
		{name: "tcp", args: []string{"--tcp", "--timeout", "3s", "@" + s.addr, "corp.test.", "a"}, tcp: true, flags: "qr aa tc rd ra ad cd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errOut := transportRun(append([]string{"query"}, c.args...)...)
			if code != 0 || errOut != "" {
				t.Fatalf("exit code %d, errors %q; want 0 and none", code, errOut)
			}
			q := s.next(t)
			m, err := dnswire.Parse(q.wire)
			if err != nil {
				t.Fatal(err)
			}
			if q.tcp != c.tcp || m.RecursionDesired != c.rd || m.CheckingDisabled != c.cd || m.EDNS == nil || m.EDNS.DO != c.do {
				t.Errorf("query: TCP %v, RD %v, CD %v, EDNS %+v; want TCP %v, RD %v, CD %v, DO %v",
					q.tcp, m.RecursionDesired, m.CheckingDisabled, m.EDNS, c.tcp, c.rd, c.cd, c.do)
			}
			if len(m.Question) != 1 || m.Question[0].Name.String() != "corp.test." || m.Question[0].Type != dnswire.TypeA {
				t.Errorf("question %v, want corp.test. A", m.Question)
			}
			if m.EDNS != nil {
				client, server, ok := m.EDNS.Cookie()
				if !ok || len(client) != 8 || len(server) != 0 {
					t.Errorf("cookie %x %x %v, want a client cookie of 8 octets only", client, server, ok)
				}
			}
			want := []string{
				fmt.Sprintf(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: %d", m.ID),
				";; flags: " + c.flags + "; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1",
				";; ANSWER SECTION:",
				"corp.test.\t300\tIN\tA\t192.0.2.1",
			}
			if got := transportShape(out); !slices.Equal(got, want) {
				t.Errorf("output:\n%s\nwant these lines besides free ones:\n%s", out, strings.Join(want, "\n"))
			}
		})
	}
}

// transportTSIG is a TSIG record for the answer to q. Nothing checks its MAC:
// osk query has no key.
func transportTSIG(q []byte) []byte {
	data := transportWire("hmac-sha256.")
	data = append(data, 0, 0, 0, 0, 0, 0) // time signed
	data = binary.BigEndian.AppendUint16(data, 300)
	data = binary.BigEndian.AppendUint16(data, 32)
	data = append(data, make([]byte, 32)...)
	data = append(data, q[0], q[1], 0, 0, 0, 0) // original ID, error, other length
	return transportRR(transportWire("xfr-key."), 250, 255, 0, data)
}

// The additional count is the one on the wire, as dig prints it: the OPT and
// the TSIG record count, although neither prints as a record.
func TestRunQueryCountsOPTAndTSIG(t *testing.T) {
	s := transportStart(t, func(q []byte, _ bool) []byte {
		return transportAnswer(q, transportQR|transportAA, [][]byte{transportA}, nil,
			[][]byte{transportOPT(), transportTSIG(q)})
	})
	code, out, errOut := transportRun("query", "@"+s.addr, "corp.test.")
	if code != 0 || errOut != "" {
		t.Fatalf("exit code %d, errors %q; want 0 and none", code, errOut)
	}
	q := s.next(t)
	want := []string{
		fmt.Sprintf(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: %d", binary.BigEndian.Uint16(q.wire)),
		";; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2",
		";; ANSWER SECTION:",
		"corp.test.\t300\tIN\tA\t192.0.2.1",
	}
	if got := transportShape(out); !slices.Equal(got, want) {
		t.Errorf("output:\n%s\nwant these lines besides free ones:\n%s", out, strings.Join(want, "\n"))
	}
}

// Any rcode is an answer; a section without records has no header.
func TestRunQueryNXDOMAIN(t *testing.T) {
	var soa []byte
	soa = append(soa, transportWire("ns1.corp.test.")...)
	soa = append(soa, transportWire("hostmaster.corp.test.")...)
	for _, v := range []uint32{1, 3600, 600, 604800, 300} {
		soa = binary.BigEndian.AppendUint32(soa, v)
	}
	soaRR := transportRR(transportWire("corp.test."), 6, 1, 300, soa)
	s := transportStart(t, func(q []byte, _ bool) []byte {
		return transportAnswer(q, transportQR|transportAA|3, nil, [][]byte{soaRR}, nil)
	})
	code, out, errOut := transportRun("query", "@"+s.addr, "nx.corp.test.", "TXT")
	if code != 0 || errOut != "" {
		t.Fatalf("exit code %d, errors %q; want 0 and none", code, errOut)
	}
	q := s.next(t)
	want := []string{
		fmt.Sprintf(";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: %d", binary.BigEndian.Uint16(q.wire)),
		";; flags: qr aa; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0",
		";; AUTHORITY SECTION:",
		"corp.test.\t300\tIN\tSOA\tns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300",
	}
	if got := transportShape(out); !slices.Equal(got, want) {
		t.Errorf("output:\n%s\nwant these lines besides free ones:\n%s", out, strings.Join(want, "\n"))
	}
}

// Each case reaches no usable answer. The addresses of the documentation
// ranges show that each form of address is accepted.
func TestRunQueryNoAnswer(t *testing.T) {
	silent := transportStart(t, nil)
	empty := transportStart(t, func(q []byte, _ bool) []byte { return []byte{} })
	mismatch := transportStart(t, func(q []byte, _ bool) []byte {
		b := transportAnswer(q, transportQR, [][]byte{transportA}, nil, nil)
		b[0] ^= 0x80
		return b
	})
	for _, args := range [][]string{
		{"--timeout", "300ms", "@" + silent.addr, "corp.test."},
		{"--tcp", "@" + empty.addr, "corp.test."},
		{"--tcp", "@" + mismatch.addr, "corp.test."},
		{"--timeout", "300ms", "@192.0.2.1", "corp.test."},
		{"--timeout", "300ms", "@192.0.2.1:5353", "corp.test."},
		{"--timeout", "300ms", "@2001:db8::1", "corp.test."},
		{"--timeout", "300ms", "@[2001:db8::1]:53", "corp.test."},
	} {
		start := time.Now()
		code, out, errOut := transportRun(append([]string{"query"}, args...)...)
		if code != 1 || out != "" || !strings.HasPrefix(errOut, "osk: ") || strings.Count(errOut, "\n") != 1 ||
			!strings.HasSuffix(errOut, "\n") {
			t.Errorf("query %q: exit code %d, output %q, errors %q; want 1, nothing and one line \"osk: ...\"",
				args, code, out, errOut)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("query %q took %v", args, d)
		}
	}
}

// svcAsUser makes the check for root see the user id uid until the test
// ends. The tests may run as root, so the real id proves nothing either way.
func svcAsUser(t *testing.T, uid int) {
	t.Helper()
	old := geteuid
	geteuid = func() int { return uid }
	t.Cleanup(func() { geteuid = old })
}

func svcStart(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = start(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// As root, every command but version is refused before it reads, opens or
// asks anything.
func TestStartRefusesRootForEveryCommandButVersion(t *testing.T) {
	svcAsUser(t, 0)
	s := transportStart(t, expWorld)
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	cfg := filepath.Join(dir, "osk.json")
	// The expectations file is missing, so a command that is not refused ends
	// at once with another error instead of running.
	text := `{"state": "` + state + `", "domains": [{"name": "corp.test.", "expect": "` + filepath.Join(dir, "missing.expect") +
		`"}], "slack": {"url": {"env": "OSK_SLACK_URL"}}, "network": {"root_servers": ["` + s.addr + `"], "extra_ranges": ["127.0.0.0/8"]}}`
	if err := os.WriteFile(cfg, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OSK_SLACK_URL", "https://127.0.0.1:1/x/"+runMarker)
	for _, args := range [][]string{
		{},
		{"run", "--config", cfg},
		{"run"},
		{"check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test."},
		{"snapshot", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test."},
		{"query", "@" + s.addr, "corp.test."},
		{"validate", "--config", cfg},
		{"status", "--config", cfg},
		{"watch", "--config", cfg},
		{"accept", "--config", cfg, "1"},
		{"test-alert", "--config", cfg},
		{"version", "extra"},
		{"other"},
	} {
		code, out, errOut := expWithin(t, 5*time.Second, func() (int, string, string) { return svcStart(args...) })
		if want := "osk: osk does not run as root; start it as an ordinary user\n"; code != 1 || out != "" || errOut != want {
			t.Errorf("osk %q as root: exit code %d, output %q, errors %q; want 1, nothing and %q", args, code, out, errOut, want)
		}
	}
	for _, args := range [][]string{{"version"}, {"version", "--json"}} {
		if code, out, errOut := svcStart(args...); code != 0 || out == "" || errOut != "" {
			t.Errorf("osk %q as root: exit code %d, output %q, errors %q; want 0, the version and none", args, code, out, errOut)
		}
	}
	slkNotThere(t, state)
	expNoQueries(t, s)
}

// For an ordinary user, start runs the command.
func TestStartRunsTheCommandForAnOrdinaryUser(t *testing.T) {
	svcAsUser(t, 1000)
	if code, out, errOut := svcStart("version"); code != 0 || !strings.HasPrefix(out, "osk ") || errOut != "" {
		t.Errorf("osk version: exit code %d, output %q, errors %q; want 0, the version and none", code, out, errOut)
	}
	if code, out, errOut := svcStart("run"); code != 2 || out != "" || !strings.HasPrefix(errOut, "osk run: --config is required\n") {
		t.Errorf("osk run: exit code %d, output %q, errors %q; want 2, nothing and the wrong use", code, out, errOut)
	}
	if code, out, errOut := svcStart("other"); code != 2 || out != "" || errOut != usage {
		t.Errorf("osk other: exit code %d, output %q, errors %q; want 2, nothing and the usage", code, out, errOut)
	}
}

// The reading commands are reached from the command line, and the usage
// names each of them.
func TestRunDispatchesTheReadingCommands(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	for _, c := range []struct {
		args  []string
		usage string
	}{
		{[]string{"validate", "--config", missing}, "osk validate --config <file> [--json]"},
		{[]string{"status", "--config", missing}, "osk status --config <file> [--json]"},
		{[]string{"watch", "--config", missing}, "osk watch --config <file> [--json]"},
		{[]string{"accept", "--config", missing, "1"}, "osk accept --config <file> [--write <code>] [--json] <alert id>"},
		{[]string{"test-alert", "--config", missing}, "osk test-alert --config <file> [--json]"},
	} {
		code, out, errOut := expWithin(t, 5*time.Second, func() (int, string, string) { return transportRun(c.args...) })
		if c.args[0] == "validate" {
			// validate prints the problems of the config as its output.
			if code != 1 || errOut != "" || !strings.HasPrefix(out, missing+": cannot be read: ") || !strings.HasSuffix(out, "\n1 problems\n") ||
				strings.Count(out, "\n") != 2 {
				t.Errorf("osk validate: exit code %d, output %q, errors %q; want 1, the problem of the config and 1 problems, and none", code, out, errOut)
			}
		} else if code != 1 || out != "" || !strings.HasPrefix(errOut, "osk: "+missing+": cannot be read: ") || strings.Count(errOut, "\n") != 1 {
			t.Errorf("osk %s: exit code %d, output %q, errors %q; want 1, nothing and the problem of the config", c.args[0], code, out, errOut)
		}
		code, out, errOut = expWithin(t, 5*time.Second, func() (int, string, string) { return transportRun(c.args[0]) })
		if code != 2 || out != "" || !strings.HasPrefix(errOut, "osk "+c.args[0]+": --config is required\n") {
			t.Errorf("osk %s without --config: exit code %d, output %q, errors %q; want 2, nothing and the wrong use", c.args[0], code, out, errOut)
		}
		if !slices.ContainsFunc(strings.Split(usage, "\n"), func(l string) bool { return strings.TrimLeft(strings.TrimPrefix(l, "usage:"), " ") == c.usage }) {
			t.Errorf("the usage lacks the line %q:\n%s", c.usage, usage)
		}
	}
}

// svcJSONKinds are the keys of each type of JSON line of the older
// commands, in order, each with the kind of its value: s string, n number,
// l list.
var svcJSONKinds = map[string][]string{
	"version":  {"type s", "osk s", "go s", "sqlite s"},
	"header":   {"type s", "opcode s", "status s", "id n", "flags l"},
	"counts":   {"type s", "query n", "answer n", "authority n", "additional n"},
	"edns":     {"type s", "version n", "flags l", "udp n", "cookie s"},
	"ede":      {"type s", "code n", "text s"},
	"record":   {"type s", "section s", "text s"},
	"walk":     svcAnswerKinds,
	"answer":   svcAnswerKinds,
	"unknown":  svcAnswerKinds,
	"finding":  {"type s", "severity s", "rule s", "kind s", "name s", "rtype s", "expected s", "seen l"},
	"checked":  {"type s", "domain s", "sets n", "findings n", "unknown n"},
	"alert":    {"type s", "label s"},
	"delivery": {"type s", "channel s", "state s", "label s", "reason s", "next s"},
	"line":     {"type s", "text s"},
	"skip":     {"type s", "name s", "rtype s", "why s"},
}

var svcAnswerKinds = []string{"type s", "kind s", "qname s", "qtype s", "address s", "host s", "received s", "transport s", "case s", "data s"}

// svcObject reads one JSON object and gives its keys in order and its
// values.
func svcObject(data []byte) ([]string, map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, nil, errors.New("not a JSON object")
	}
	var keys []string
	values := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		key, _ := tok.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, err
		}
		keys = append(keys, key)
		values[key] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, nil, errors.New("not one JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, errors.New("more than one JSON value")
	}
	return keys, values, nil
}

func svcKind(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return "?"
	}
	switch v.(type) {
	case string:
		return "s"
	case float64:
		return "n"
	case []any:
		return "l"
	}
	return "?"
}

// svcJSON checks that every line of out is one JSON object of a type of
// types, with exactly the keys of its type in order, and gives the values of
// the lines by type.
func svcJSON(t *testing.T, what, out string, types ...string) map[string][]map[string]json.RawMessage {
	t.Helper()
	byType := map[string][]map[string]json.RawMessage{}
	if out == "" || !strings.HasSuffix(out, "\n") {
		t.Errorf("%s printed %q, want JSON lines", what, out)
		return byType
	}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		keys, values, err := svcObject([]byte(line))
		var typ string
		if err == nil {
			err = json.Unmarshal(values["type"], &typ)
		}
		if err != nil || !slices.Contains(types, typ) {
			t.Errorf("%s printed %s: %v; want an object whose type is one of %q", what, line, err, types)
			continue
		}
		want := svcJSONKinds[typ]
		var got []string
		for _, k := range keys {
			got = append(got, k+" "+svcKind(values[k]))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s printed %s: keys and kinds %q, want %q", what, line, got, want)
		}
		if typ == "finding" {
			var seen []json.RawMessage
			_ = json.Unmarshal(values["seen"], &seen)
			for _, s := range seen {
				if keys, values, err := svcObject(s); err != nil || !slices.Equal(keys, []string{"address", "host", "text"}) ||
					svcKind(values["address"])+svcKind(values["host"])+svcKind(values["text"]) != "sss" {
					t.Errorf("%s printed the seen item %s, want the strings address, host and text", what, s)
				}
			}
		}
		byType[typ] = append(byType[typ], values)
	}
	return byType
}

func svcString(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

func svcNumber(raw json.RawMessage) float64 {
	var n float64
	_ = json.Unmarshal(raw, &n)
	return n
}

// With --json, version, query, check and snapshot print JSON Lines: each
// line one object, its type first, then the keys of its type in order.
func TestOlderCommandsPrintJSON(t *testing.T) {
	code, out, errOut := transportRun("version", "--json")
	v := svcJSON(t, "version --json", out, "version")["version"]
	if code != 0 || errOut != "" || len(v) != 1 || svcString(v[0]["osk"]) != version ||
		svcString(v[0]["go"]) != strings.TrimPrefix(runtime.Version(), "go") || svcString(v[0]["sqlite"]) == "" {
		t.Errorf("version --json: exit code %d, errors %q, output %s; want 0, none and one line with osk %s", code, errOut, out, version)
	}

	s := transportStart(t, func(q []byte, tcp bool) []byte {
		return transportAnswer(q, transportQR|transportAA, [][]byte{transportA}, nil, [][]byte{transportOPT()})
	})
	code, out, errOut = transportRun("query", "--json", "@"+s.addr, "corp.test.")
	q := s.next(t)
	byType := svcJSON(t, "query --json", out, "header", "counts", "edns", "ede", "record")
	h, c, r := byType["header"], byType["counts"], byType["record"]
	if code != 0 || errOut != "" || len(h) != 1 || len(c) != 1 || len(byType["edns"]) != 1 || len(byType["ede"]) != 1 || len(r) != 1 {
		t.Fatalf("query --json: exit code %d, errors %q, output:\n%s\nwant 0, none, and one line of each type", code, errOut, out)
	}
	if svcString(h[0]["opcode"]) != "QUERY" || svcString(h[0]["status"]) != "NOERROR" || svcNumber(h[0]["id"]) != float64(binary.BigEndian.Uint16(q.wire)) ||
		string(h[0]["flags"]) != `["qr","aa"]` {
		t.Errorf("query --json: the header is %s, want QUERY, NOERROR, the id of the query and the flags qr and aa", out)
	}
	if svcNumber(c[0]["query"]) != 1 || svcNumber(c[0]["answer"]) != 1 || svcNumber(c[0]["authority"]) != 0 || svcNumber(c[0]["additional"]) != 1 {
		t.Errorf("query --json: the counts are %s, want 1, 1, 0 and 1", out)
	}
	if svcString(r[0]["section"]) != "answer" || !strings.Contains(svcString(r[0]["text"]), "192.0.2.1") {
		t.Errorf("query --json: the record is %s, want the A record in the answer section", out)
	}

	world := transportStart(t, expWorld)
	root := []string{"--root-server", world.addr, "--extra-range", "127.0.0.0/8"}
	code, out, errOut = transportRun(slices.Concat([]string{"check", "--json"}, root, []string{"corp.test.", "www.corp.test.", "A"})...)
	byType = svcJSON(t, "check --json", out, "walk", "answer")
	if code != 0 || errOut != "" || len(byType["walk"]) == 0 || !slices.ContainsFunc(byType["answer"], func(a map[string]json.RawMessage) bool {
		return svcString(a["qname"]) == "www.corp.test." && svcString(a["qtype"]) == "A" && svcString(a["address"]) == world.addr
	}) {
		t.Errorf("check --json: exit code %d, errors %q, output:\n%s\nwant 0, none, walk lines and the answer of www.corp.test. A", code, errOut, out)
	}

	file := expFile(t, runFile)
	code, out, errOut = transportRun(slices.Concat([]string{"check", "--json"}, root, []string{"--expect", file})...)
	byType = svcJSON(t, "check --expect --json", out, "finding", "unknown", "checked")
	f, ch := byType["finding"], byType["checked"]
	if code != 1 || errOut != "" || len(f) != 1 || len(ch) != 1 || svcString(f[0]["rule"]) != "not-covered" ||
		svcString(f[0]["kind"]) != "delegation" || svcString(ch[0]["domain"]) != "corp.test." || svcNumber(ch[0]["findings"]) != 1 {
		t.Errorf("check --expect --json: exit code %d, errors %q, output:\n%s\nwant 1, none, the not-covered finding and the checked line", code, errOut, out)
	}

	t.Setenv("OSK_SLACK_URL", "https://127.0.0.1:1/x/"+runMarker)
	state := filepath.Join(t.TempDir(), "state")
	code, out, errOut = transportRun(slices.Concat([]string{"check", "--json"}, root, []string{"--expect", file, "--state", state})...)
	byType = svcJSON(t, "check --expect --state --json", out, "finding", "unknown", "checked", "alert", "delivery")
	a, d := byType["alert"], byType["delivery"]
	if code != 1 || errOut != "" || len(a) != 1 || svcString(a[0]["label"]) != runNotCovered || len(d) != 1 ||
		svcString(d[0]["channel"]) != "slack" || svcString(d[0]["state"]) != "failed" || svcString(d[0]["label"]) != runNotCovered || strings.Contains(out, runMarker) {
		t.Errorf("check --state --json: exit code %d, errors %q, output:\n%s\nwant 1, none, the alert and its delivery to slack", code, errOut, runShow(out))
	}

	code, out, errOut = transportRun(slices.Concat([]string{"snapshot", "--json"}, root, []string{"corp.test.", "www.example.", "A"})...)
	byType = svcJSON(t, "snapshot --json", out, "line", "skip")
	var texts []string
	for _, l := range byType["line"] {
		texts = append(texts, svcString(l["text"]))
	}
	// The fake world serves the NS set of corp.test. from the root zone, so
	// the snapshot leaves it out and exits 1.
	if code != 1 || errOut != "" || len(byType["skip"]) == 0 || !slices.Contains(texts, "domain corp.test.") ||
		!slices.Contains(texts, "www.example. A 192.0.2.80") {
		t.Errorf("snapshot --json: exit code %d, errors %q, output:\n%s\nwant 1, none, the lines of the file and the sets left out", code, errOut, out)
	}
}
