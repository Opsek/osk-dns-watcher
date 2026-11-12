package observe

import (
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

func askName(t *testing.T, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatalf("name %q: %v", s, err)
	}
	return n
}

// askRR reads one record of class IN from "owner ttl [IN] type data", the
// form that Record.String prints.
func askRR(t *testing.T, text string) dnswire.Record {
	t.Helper()
	f := strings.Fields(text)
	if len(f) > 2 && f[2] == "IN" {
		f = slices.Delete(f, 2, 3)
	}
	if len(f) < 4 {
		t.Fatalf("record %q: want owner, ttl, type and data", text)
	}
	ttl, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		t.Fatalf("record %q: %v", text, err)
	}
	typ, err := dnswire.ParseType(f[2])
	if err != nil {
		t.Fatalf("record %q: %v", text, err)
	}
	data, err := dnswire.ParseRData(typ, strings.Join(f[3:], " "))
	if err != nil {
		t.Fatalf("record %q: %v", text, err)
	}
	return dnswire.Record{Name: askName(t, f[0]), Class: dnswire.ClassINET, TTL: uint32(ttl), Data: data}
}

// askChaos is askRR with class CH, which classify must not read as data.
func askChaos(t *testing.T, text string) dnswire.Record {
	t.Helper()
	r := askRR(t, text)
	r.Class = dnswire.ClassCHAOS
	return r
}

func askRRs(t *testing.T, texts ...string) []dnswire.Record {
	t.Helper()
	var rs []dnswire.Record
	for _, s := range texts {
		rs = append(rs, askRR(t, s))
	}
	return rs
}

func askQuestion(t *testing.T, name string, typ dnswire.Type) dnswire.Question {
	t.Helper()
	return dnswire.Question{Name: askName(t, name), Type: typ, Class: dnswire.ClassINET}
}

// askReply describes an answer to one question.
type askReply struct {
	rcode                         dnswire.Rcode
	noAA, tc, ra                  bool
	answer, authority, additional []dnswire.Record
	options                       []dnswire.Option // EDNS options; the answer has an OPT record in any case
}

func askMessage(q dnswire.Question, r askReply) *dnswire.Message {
	return &dnswire.Message{
		Header: dnswire.Header{
			Response:           true,
			Authoritative:      !r.noAA,
			Truncated:          r.tc,
			RecursionAvailable: r.ra,
			Rcode:              r.rcode,
		},
		Question:   []dnswire.Question{q},
		Answer:     r.answer,
		Authority:  r.authority,
		Additional: r.additional,
		EDNS:       &dnswire.EDNS{UDPSize: 1232, DO: true, Flags: 0x8000, Options: r.options},
	}
}

func askExtendedError(code uint16, text string) dnswire.Option {
	return dnswire.Option{Code: 15, Data: append(binary.BigEndian.AppendUint16(nil, code), text...)}
}

// askWant is the expected result. kind is "records", "nodata", "noname",
// "noname-compact" or "failure".
type askWant struct {
	kind   string
	reason obs.Reason // failure only
	detail []string   // failure only: texts Detail must hold
	set    []string   // records: Set, in message order
	glue   []string   // records: Glue, in any order
	soa    string     // nodata and noname: the SOA record
}

func askLines(rs []dnswire.Record) []string {
	lines := []string{}
	for _, r := range rs {
		lines = append(lines, r.String())
	}
	return lines
}

func askLinesOf(t *testing.T, texts []string) []string {
	t.Helper()
	return askLines(askRRs(t, texts...))
}

func askSorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

// askCheck compares a result with the expectation; what names the case.
func askCheck(t *testing.T, what string, got obs.Result, want askWant) {
	t.Helper()
	var soa string
	if want.soa != "" {
		soa = askRR(t, want.soa).String()
	}
	wanted := want.kind + " " + soa
	switch want.kind {
	case "failure":
		wanted = "failure " + want.reason.String()
	case "records":
		wanted = fmt.Sprintf("records %q", askLinesOf(t, want.set))
	}
	obs.Match(got,
		func(r obs.Records) any {
			switch {
			case want.kind != "records":
				t.Errorf("%s: got records %q, want %s", what, askLines(r.Set), wanted)
			case !slices.Equal(askLines(r.Set), askLinesOf(t, want.set)):
				t.Errorf("%s: Set\n%q\nwant\n%q", what, askLines(r.Set), askLinesOf(t, want.set))
			case !slices.Equal(askSorted(askLines(r.Glue)), askSorted(askLinesOf(t, want.glue))):
				t.Errorf("%s: Glue\n%q\nwant\n%q", what, askLines(r.Glue), askLinesOf(t, want.glue))
			}
			return nil
		},
		func(n obs.NoData) any {
			if want.kind != "nodata" || n.SOA.String() != soa {
				t.Errorf("%s: got nodata %q, want %s", what, n.SOA.String(), wanted)
			}
			return nil
		},
		func(n obs.NoName) any {
			kind := "noname"
			if n.Compact {
				kind = "noname-compact"
			}
			if want.kind != kind || n.SOA.String() != soa {
				t.Errorf("%s: got %s %q, want %s", what, kind, n.SOA.String(), wanted)
			}
			return nil
		},
		func(f obs.Failure) any {
			if want.kind != "failure" || f.Reason != want.reason {
				t.Errorf("%s: got failure %v (%q), want %s", what, f.Reason, f.Detail, wanted)
				return nil
			}
			for _, d := range want.detail {
				if !strings.Contains(f.Detail, d) {
					t.Errorf("%s: Detail %q does not hold %q", what, f.Detail, d)
				}
			}
			return nil
		})
}

const (
	askSOA     = "corp.test. 300 SOA ns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300"
	askTestSOA = "test. 300 SOA ns.test. hostmaster.test. 1 3600 600 604800 300"
)

// TestAskClassify has cases for each reading of an answer, in the order
// in which classify tries them, then cases where two fit and the first wins.
func TestAskClassify(t *testing.T) {
	rr := func(texts ...string) []dnswire.Record { return askRRs(t, texts...) }
	www := askQuestion(t, "www.corp.test.", dnswire.TypeA)
	corpNS := rr("corp.test. 3600 NS ns1.corp.test.", "corp.test. 3600 NS ns2.corp.test.")
	corpGlue := rr("ns1.corp.test. 3600 A 10.53.7.11", "ns2.corp.test. 3600 A 10.53.7.12")
	soa := rr(askSOA)
	nxname := "www.corp.test. 300 NSEC \\000.www.corp.test. RRSIG NSEC TYPE128"
	failure := func(r obs.Reason, detail ...string) askWant {
		return askWant{kind: "failure", reason: r, detail: detail}
	}

	cases := []struct {
		name  string
		kind  obs.Kind
		zone  string
		q     dnswire.Question
		reply askReply
		want  askWant
	}{
		// A truncated answer, also one that came over TCP.
		{"truncated", obs.KindRecords, "corp.test.", www,
			askReply{tc: true, answer: rr("www.corp.test. 300 A 10.53.7.81")},
			failure(obs.ReasonTruncated)},

		// An rcode other than NOERROR and NXDOMAIN.
		{"refused", obs.KindRecords, "corp.test.", www, askReply{rcode: 5, noAA: true}, failure(obs.ReasonRefused)},
		{"servfail with extended errors", obs.KindRecords, "corp.test.", www,
			askReply{rcode: 2, noAA: true, options: []dnswire.Option{
				askExtendedError(22, `no "reachable" authority`), askExtendedError(1027, "x\x01y")}},
			failure(obs.ReasonServFail, "22", strconv.Quote(`no "reachable" authority`), "1027", strconv.Quote("x\x01y"))},
		{"formerr", obs.KindRecords, "corp.test.", www, askReply{rcode: 1}, failure(obs.ReasonRcode, "FORMERR")},
		{"notimp", obs.KindRecords, "corp.test.", www, askReply{rcode: 4}, failure(obs.ReasonRcode, "NOTIMP")},
		{"badcookie", obs.KindRecords, "corp.test.", www, askReply{rcode: 23}, failure(obs.ReasonRcode, "BADCOOKIE")},

		// The parent refers the delegation check to the asked name.
		{"delegation from a referral", obs.KindDelegation, "test.", askQuestion(t, "corp.test.", dnswire.TypeNS),
			askReply{noAA: true, authority: corpNS, additional: rr(
				"ns1.corp.test. 3600 A 10.53.7.11",
				"ns2.corp.test. 3600 A 10.53.7.12",
				"ns2.corp.test. 3600 AAAA fd53:0:0:7::12",
				"www.corp.test. 3600 A 10.53.7.81",
				"ns1.corp.test. 3600 TXT \"not an address\"")},
			askWant{kind: "records",
				set:  []string{"corp.test. 3600 NS ns1.corp.test.", "corp.test. 3600 NS ns2.corp.test."},
				glue: []string{"ns1.corp.test. 3600 A 10.53.7.11", "ns2.corp.test. 3600 A 10.53.7.12", "ns2.corp.test. 3600 AAAA fd53:0:0:7::12"}}},
		{"delegation from a signed referral, sibling and outside glue", obs.KindDelegation, "test.", askQuestion(t, "shop.test.", dnswire.TypeNS),
			askReply{noAA: true, authority: rr(
				"shop.test. 3600 NS ns1.dnshost.test.",
				"shop.test. 3600 NS ns.elsewhere.example.",
				"shop.test. 3600 DS 12345 13 2 0011223344556677889900112233445566778899001122334455667788990011",
				"shop.test. 3600 RRSIG DS 13 2 3600 20261201000000 20261101000000 4711 test. AAAA"),
				additional: rr("ns1.dnshost.test. 3600 A 10.53.7.11", "ns.elsewhere.example. 3600 A 192.0.2.53")},
			askWant{kind: "records",
				set:  []string{"shop.test. 3600 NS ns1.dnshost.test.", "shop.test. 3600 NS ns.elsewhere.example."},
				glue: []string{"ns1.dnshost.test. 3600 A 10.53.7.11"}}},

		// AA clear.
		{"referral for a records check", obs.KindRecords, "test.", www,
			askReply{noAA: true, authority: corpNS, additional: corpGlue}, failure(obs.ReasonLame)},
		{"recursive answer", obs.KindRecords, "corp.test.", www,
			askReply{noAA: true, ra: true, answer: rr("www.corp.test. 300 A 10.53.7.81")}, failure(obs.ReasonLame)},
		{"non-authoritative nxdomain", obs.KindRecords, "corp.test.", www,
			askReply{rcode: 3, noAA: true, authority: soa}, failure(obs.ReasonLame)},
		{"delegation check referred to a cut above the asked name", obs.KindDelegation, "test.", askQuestion(t, "sub.corp.test.", dnswire.TypeNS),
			askReply{noAA: true, authority: corpNS, additional: corpGlue}, failure(obs.ReasonLame)},
		{"delegation check with a cached answer", obs.KindDelegation, "test.", askQuestion(t, "corp.test.", dnswire.TypeNS),
			askReply{noAA: true, answer: corpNS, additional: corpGlue}, failure(obs.ReasonLame)},

		// Records of the asked name and type.
		{"records", obs.KindRecords, "corp.test.", www,
			askReply{
				answer: append(rr(
					"www.corp.test. 300 A 10.53.7.81",
					"www.corp.test. 300 RRSIG A 13 3 300 20261201000000 20261101000000 4711 corp.test. AAAA",
					"mail.corp.test. 300 A 10.53.7.82",
					"WWW.Corp.Test. 60 A 10.53.7.85"),
					askChaos(t, "www.corp.test. 300 A 10.53.7.86")),
				authority:  corpNS,
				additional: corpGlue},
			askWant{kind: "records", set: []string{"www.corp.test. 300 A 10.53.7.81", "WWW.Corp.Test. 60 A 10.53.7.85"}}},
		{"records whatever the rcode", obs.KindRecords, "corp.test.", www,
			askReply{rcode: 3, answer: rr("www.corp.test. 300 A 10.53.7.81"), authority: soa},
			askWant{kind: "records", set: []string{"www.corp.test. 300 A 10.53.7.81"}}},
		{"delegation answered with AA", obs.KindDelegation, "test.", askQuestion(t, "corp.test.", dnswire.TypeNS),
			askReply{answer: corpNS, additional: append(rr("ns.elsewhere.example. 3600 A 192.0.2.53"), corpGlue...)},
			askWant{kind: "records",
				set:  []string{"corp.test. 3600 NS ns1.corp.test.", "corp.test. 3600 NS ns2.corp.test."},
				glue: []string{"ns1.corp.test. 3600 A 10.53.7.11", "ns2.corp.test. 3600 A 10.53.7.12"}}},
		{"ds", obs.KindDS, "test.", askQuestion(t, "corp.test.", dnswire.TypeDS),
			askReply{answer: rr(
				"corp.test. 3600 DS 12345 13 2 0011223344556677889900112233445566778899001122334455667788990011",
				"corp.test. 3600 RRSIG DS 13 2 3600 20261201000000 20261101000000 4711 test. AAAA")},
			askWant{kind: "records", set: []string{"corp.test. 3600 DS 12345 13 2 0011223344556677889900112233445566778899001122334455667788990011"}}},
		{"serial", obs.KindSerial, "corp.test.", askQuestion(t, "corp.test.", dnswire.TypeSOA),
			askReply{answer: soa, authority: corpNS},
			askWant{kind: "records", set: []string{askSOA}}},
		{"signatures when asked for", obs.KindRecords, "corp.test.", askQuestion(t, "www.corp.test.", dnswire.TypeRRSIG),
			askReply{answer: rr("www.corp.test. 300 RRSIG A 13 3 300 20261201000000 20261101000000 4711 corp.test. AAAA")},
			askWant{kind: "records", set: []string{"www.corp.test. 300 RRSIG A 13 3 300 20261201000000 20261101000000 4711 corp.test. AAAA"}}},

		// A CNAME at the asked name.
		{"cname", obs.KindRecords, "corp.test.", askQuestion(t, "cdn.corp.test.", dnswire.TypeA),
			askReply{answer: rr(
				"cdn.corp.test. 300 CNAME edge.dnshost.test.",
				"cdn.corp.test. 300 RRSIG CNAME 13 3 300 20261201000000 20261101000000 4711 corp.test. AAAA",
				"edge.dnshost.test. 300 A 10.53.7.83")},
			askWant{kind: "records", set: []string{"cdn.corp.test. 300 CNAME edge.dnshost.test."}}},
		{"cname with nxdomain", obs.KindRecords, "corp.test.", askQuestion(t, "alias.corp.test.", dnswire.TypeA),
			askReply{rcode: 3, answer: rr("alias.corp.test. 300 CNAME gone.corp.test."), authority: soa},
			askWant{kind: "records", set: []string{"alias.corp.test. 300 CNAME gone.corp.test."}}},
		// With the SOA, the answer would read as nodata if the two were not refused.
		{"two cnames", obs.KindRecords, "corp.test.", askQuestion(t, "cdn.corp.test.", dnswire.TypeA),
			askReply{answer: rr("cdn.corp.test. 300 CNAME edge.dnshost.test.", "cdn.corp.test. 300 CNAME www.corp.test."), authority: soa},
			failure(obs.ReasonBadAnswer)},

		// Not exactly one SOA between the zone and the name: nothing says what is missing.
		{"no soa", obs.KindRecords, "corp.test.", www, askReply{authority: corpNS}, failure(obs.ReasonBadAnswer)},
		{"no soa with nxdomain", obs.KindRecords, "corp.test.", www,
			askReply{rcode: 3, authority: rr("corp.test. 300 NSEC ns1.corp.test. NS SOA RRSIG NSEC DNSKEY")}, failure(obs.ReasonBadAnswer)},
		{"two soas", obs.KindRecords, "corp.test.", www,
			askReply{authority: rr(askSOA, "corp.test. 300 SOA ns2.corp.test. hostmaster.corp.test. 2 3600 600 604800 300")},
			failure(obs.ReasonBadAnswer)},
		{"soa of class CH only", obs.KindRecords, "corp.test.", www,
			askReply{authority: []dnswire.Record{askChaos(t, askSOA)}}, failure(obs.ReasonBadAnswer)},
		{"soa outside the zone", obs.KindRecords, "corp.test.", www,
			askReply{authority: rr("shop.test. 300 SOA ns1.dnshost.test. hostmaster.shop.test. 1 3600 600 604800 300")},
			failure(obs.ReasonBadAnswer)},
		{"soa above the zone", obs.KindRecords, "corp.test.", www,
			askReply{rcode: 3, authority: rr(askTestSOA)}, failure(obs.ReasonBadAnswer)},
		{"soa not above the name", obs.KindRecords, "corp.test.", www,
			askReply{authority: rr("mail.corp.test. 300 SOA ns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300")},
			failure(obs.ReasonBadAnswer)},
		{"soa below the name", obs.KindRecords, "corp.test.", www,
			askReply{authority: rr("x.www.corp.test. 300 SOA ns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300")},
			failure(obs.ReasonBadAnswer)},

		// No such name.
		{"nxdomain", obs.KindRecords, "corp.test.", www, askReply{rcode: 3, authority: soa},
			askWant{kind: "noname", soa: askSOA}},
		{"nxdomain with the soa of a zone below", obs.KindRecords, "test.", askQuestion(t, "x.corp.test.", dnswire.TypeA),
			askReply{rcode: 3, authority: soa}, askWant{kind: "noname", soa: askSOA}},
		{"nxdomain with an nxname proof", obs.KindRecords, "corp.test.", www,
			askReply{rcode: 3, authority: rr(askSOA, nxname)}, askWant{kind: "noname", soa: askSOA}},

		// No such name in the compact form.
		{"compact", obs.KindRecords, "corp.test.", www, askReply{authority: rr(askSOA, nxname)},
			askWant{kind: "noname-compact", soa: askSOA}},
		{"compact with the nsec owner in other case", obs.KindRecords, "corp.test.", www,
			askReply{authority: rr(askSOA, "WWW.CORP.test. 300 NSEC \\000.www.corp.test. RRSIG NSEC TYPE128")},
			askWant{kind: "noname-compact", soa: askSOA}},
		{"type 128 at another owner", obs.KindRecords, "corp.test.", www,
			askReply{authority: rr(askSOA, "mail.corp.test. 300 NSEC \\000.mail.corp.test. RRSIG NSEC TYPE128")},
			askWant{kind: "nodata", soa: askSOA}},
		{"nsec at the name without type 128", obs.KindRecords, "corp.test.", www,
			askReply{authority: rr(askSOA, "www.corp.test. 300 NSEC \\000.www.corp.test. TXT RRSIG NSEC")},
			askWant{kind: "nodata", soa: askSOA}},

		// No data.
		{"nodata", obs.KindRecords, "corp.test.", www, askReply{authority: soa}, askWant{kind: "nodata", soa: askSOA}},
		{"nodata at the apex", obs.KindRecords, "corp.test.", askQuestion(t, "corp.test.", dnswire.TypePTR),
			askReply{authority: soa}, askWant{kind: "nodata", soa: askSOA}},
		{"nodata with records of another type", obs.KindRecords, "corp.test.", askQuestion(t, "www.corp.test.", dnswire.TypeAAAA),
			askReply{answer: rr("www.corp.test. 300 A 10.53.7.81"), authority: soa}, askWant{kind: "nodata", soa: askSOA}},

		// Two readings fit; the first wins.
		{"truncated before refused", obs.KindRecords, "corp.test.", www, askReply{tc: true, rcode: 5}, failure(obs.ReasonTruncated)},
		{"servfail before lame", obs.KindRecords, "corp.test.", www, askReply{rcode: 2, noAA: true}, failure(obs.ReasonServFail)},
		{"refused before records", obs.KindRecords, "corp.test.", www,
			askReply{rcode: 5, answer: rr("www.corp.test. 300 A 10.53.7.81")}, failure(obs.ReasonRefused)},
		{"servfail before the delegation referral", obs.KindDelegation, "test.", askQuestion(t, "corp.test.", dnswire.TypeNS),
			askReply{rcode: 2, noAA: true, authority: corpNS, additional: corpGlue}, failure(obs.ReasonServFail)},
		{"lame before records", obs.KindDelegation, "test.", askQuestion(t, "corp.test.", dnswire.TypeNS),
			askReply{noAA: true, answer: corpNS, authority: corpNS}, failure(obs.ReasonLame)},
		{"cname before nxdomain", obs.KindRecords, "corp.test.", askQuestion(t, "cdn.corp.test.", dnswire.TypeA),
			askReply{rcode: 3, answer: rr("cdn.corp.test. 300 CNAME edge.dnshost.test.")},
			askWant{kind: "records", set: []string{"cdn.corp.test. 300 CNAME edge.dnshost.test."}}},
		{"bad soa before nxdomain", obs.KindRecords, "corp.test.", www,
			askReply{rcode: 3, authority: rr(askSOA, askSOA)}, failure(obs.ReasonBadAnswer)},
	}
	for _, c := range cases {
		m := askMessage(c.q, c.reply)
		askCheck(t, c.name, classify(c.kind, askName(t, c.zone), c.q, m), c.want)
	}
}

func TestAskReferral(t *testing.T) {
	rr := func(texts ...string) []dnswire.Record { return askRRs(t, texts...) }
	corpNS := rr("corp.test. 3600 NS ns1.corp.test.", "corp.test. 3600 NS ns2.corp.test.")
	cases := []struct {
		name, zone, target string
		reply              askReply
		ok                 bool
		cut                string
		hosts              []string
		glue               []string
	}{
		{"glue in the zone", "test.", "www.corp.test.",
			askReply{noAA: true, authority: corpNS, additional: rr(
				"ns1.corp.test. 3600 A 10.53.7.11", "ns2.corp.test. 3600 A 10.53.7.12", "ns2.corp.test. 3600 AAAA fd53:0:0:7::12")},
			true, "corp.test.", []string{"ns1.corp.test.", "ns2.corp.test."},
			[]string{"ns1.corp.test. 3600 A 10.53.7.11", "ns2.corp.test. 3600 A 10.53.7.12", "ns2.corp.test. 3600 AAAA fd53:0:0:7::12"}},
		{"target at the cut", "test.", "corp.test.",
			askReply{noAA: true, authority: corpNS},
			true, "corp.test.", []string{"ns1.corp.test.", "ns2.corp.test."}, nil},
		{"from the root", ".", "www.corp.test.",
			askReply{noAA: true, authority: rr("test. 86400 NS ns.test."), additional: rr("ns.test. 86400 A 10.53.7.3")},
			true, "test.", []string{"ns.test."}, []string{"ns.test. 86400 A 10.53.7.3"}},
		{"sibling glue", "test.", "shop.test.",
			askReply{noAA: true, authority: rr("shop.test. 3600 NS ns1.dnshost.test.", "shop.test. 3600 NS ns2.dnshost.test."),
				additional: rr("ns1.dnshost.test. 3600 A 10.53.7.11", "ns2.dnshost.test. 3600 A 10.53.7.12")},
			true, "shop.test.", []string{"ns1.dnshost.test.", "ns2.dnshost.test."},
			[]string{"ns1.dnshost.test. 3600 A 10.53.7.11", "ns2.dnshost.test. 3600 A 10.53.7.12"}},
		{"glue outside the zone, of no host, or not an address", "test.", "shop.test.",
			askReply{noAA: true,
				authority: rr("shop.test. 3600 NS ns.elsewhere.example.", "shop.test. 3600 NS ns1.dnshost.test."),
				additional: rr(
					"ns.elsewhere.example. 3600 A 192.0.2.53",
					"www.shop.test. 3600 A 10.53.7.84",
					"ns1.dnshost.test. 3600 TXT \"text\"",
					"ns1.dnshost.test. 3600 AAAA fd53:0:0:7::11")},
			true, "shop.test.", []string{"ns.elsewhere.example.", "ns1.dnshost.test."},
			[]string{"ns1.dnshost.test. 3600 AAAA fd53:0:0:7::11"}},
		{"repeated host", "test.", "corp.test.",
			askReply{noAA: true, authority: rr("corp.test. 3600 NS ns2.corp.test.", "corp.test. 3600 NS ns1.corp.test.", "corp.test. 3600 NS ns2.corp.test.")},
			true, "corp.test.", []string{"ns2.corp.test.", "ns1.corp.test."}, nil},
		{"signed, with other records in the authority section", "test.", "corp.test.",
			askReply{noAA: true, authority: append(rr(
				"corp.test. 3600 NS ns1.corp.test.",
				"corp.test. 3600 DS 12345 13 2 0011223344556677889900112233445566778899001122334455667788990011",
				"corp.test. 3600 RRSIG DS 13 2 3600 20261201000000 20261101000000 4711 test. AAAA"),
				askChaos(t, "other.test. 3600 NS ns.other.test."))},
			true, "corp.test.", []string{"ns1.corp.test."}, nil},

		{"aa set", "test.", "corp.test.", askReply{authority: corpNS}, false, "", nil, nil},
		{"nxdomain", "test.", "corp.test.", askReply{rcode: 3, noAA: true, authority: corpNS}, false, "", nil, nil},
		{"servfail", "test.", "corp.test.", askReply{rcode: 2, noAA: true, authority: corpNS}, false, "", nil, nil},
		{"answer not empty", "test.", "corp.test.", askReply{noAA: true, answer: corpNS, authority: corpNS}, false, "", nil, nil},
		{"two owners", "test.", "corp.test.",
			askReply{noAA: true, authority: rr("corp.test. 3600 NS ns1.corp.test.", "shop.test. 3600 NS ns1.dnshost.test.")},
			false, "", nil, nil},
		{"cut equal to the zone", "corp.test.", "www.corp.test.", askReply{noAA: true, authority: corpNS}, false, "", nil, nil},
		{"cut above the zone", "corp.test.", "www.corp.test.",
			askReply{noAA: true, authority: rr("test. 3600 NS ns.test.")}, false, "", nil, nil},
		{"cut beside the zone", "corp.test.", "www.corp.test.",
			askReply{noAA: true, authority: rr("shop.test. 3600 NS ns1.dnshost.test.")}, false, "", nil, nil},
		{"target outside the cut", "test.", "www.corp.test.",
			askReply{noAA: true, authority: rr("shop.test. 3600 NS ns1.dnshost.test.")}, false, "", nil, nil},
		{"no NS", "test.", "corp.test.", askReply{noAA: true, authority: rr(askTestSOA)}, false, "", nil, nil},
	}
	for _, c := range cases {
		m := askMessage(askQuestion(t, c.target, dnswire.TypeNS), c.reply)
		cut, hosts, glue, ok := referral(askName(t, c.zone), askName(t, c.target), m)
		if ok != c.ok {
			t.Errorf("%s: ok %v, want %v", c.name, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		var hostNames []string
		for _, h := range hosts {
			hostNames = append(hostNames, h.String())
		}
		if cut.String() != c.cut || !slices.Equal(hostNames, c.hosts) {
			t.Errorf("%s: cut %s hosts %q, want %s %q", c.name, cut, hostNames, c.cut, c.hosts)
		}
		if got, want := askSorted(askLines(glue)), askSorted(askLinesOf(t, c.glue)); !slices.Equal(got, want) {
			t.Errorf("%s: glue\n%q\nwant\n%q", c.name, got, want)
		}
	}
}

// TestCompactNoName reads an answer captured from an online signer. Its
// note, testdata/compact-nxname.txt, says where it came from.
func TestCompactNoName(t *testing.T) {
	wire, err := os.ReadFile("testdata/compact-nxname.answer")
	if err != nil {
		t.Fatal(err)
	}
	parse := func() *dnswire.Message {
		m, err := dnswire.Parse(wire)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := parse()
	if len(m.Question) != 1 {
		t.Fatalf("%d questions, want 1", len(m.Question))
	}
	q := m.Question[0]
	zone := askName(t, "ietf.org.")

	// The sample must be the compact form, or the checks below mean nothing.
	var soas, nxnames []dnswire.Record
	for _, r := range m.Authority {
		if r.Type() == dnswire.TypeSOA {
			soas = append(soas, r)
		}
		if n, ok := r.Data.(dnswire.NSEC); ok && r.Name.Equal(q.Name) && slices.Contains(n.Types, dnswire.TypeNXNAME) {
			nxnames = append(nxnames, r)
		}
	}
	if m.Rcode != 0 || !m.Authoritative || len(m.Answer) != 0 || len(soas) != 1 || len(nxnames) != 1 {
		t.Fatalf("not the compact form: rcode %v, AA %v, %d answers, %d SOA, %d NSEC with type 128 at %s",
			m.Rcode, m.Authoritative, len(m.Answer), len(soas), len(nxnames), q.Name)
	}
	askCheck(t, "captured answer", classify(obs.KindRecords, zone, q, m), askWant{kind: "noname-compact", soa: soas[0].String()})

	// Without type 128, or with the NSEC at another name, the same answer
	// says only that the type is missing.
	m = parse()
	for i, r := range m.Authority {
		if n, ok := r.Data.(dnswire.NSEC); ok {
			n.Types = slices.DeleteFunc(slices.Clone(n.Types), func(t dnswire.Type) bool { return t == dnswire.TypeNXNAME })
			m.Authority[i].Data = n
		}
	}
	askCheck(t, "type 128 removed", classify(obs.KindRecords, zone, q, m), askWant{kind: "nodata", soa: soas[0].String()})
	m = parse()
	for i, r := range m.Authority {
		if r.Type() == dnswire.TypeNSEC {
			m.Authority[i].Name = askName(t, "other.ietf.org.")
		}
	}
	askCheck(t, "NSEC at another name", classify(obs.KindRecords, zone, q, m), askWant{kind: "nodata", soa: soas[0].String()})
}
