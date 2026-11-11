package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
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
