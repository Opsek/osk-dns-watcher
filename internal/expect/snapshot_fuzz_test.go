package expect

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// The fuzz bytes are a program that builds observations of corp.test. and
// of another domain: each observation is a key, a zone and its answers, and
// each answer is a server and a result whose names and data come from the
// bytes. Past the end of the bytes every read gives 0, so every input builds
// something.

type sfzReader struct{ b []byte }

func (r *sfzReader) byte() byte {
	if len(r.b) == 0 {
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

func (r *sfzReader) pick(n int) int { return int(r.byte()) % n }

func (r *sfzReader) text(max int) string {
	n := min(r.pick(max+1), len(r.b))
	s := string(r.b[:n])
	r.b = r.b[n:]
	return s
}

var (
	sfzNames = []string{"corp.test.", "www.corp.test.", "ns1.corp.test.", "ns2.corp.test.", "_mta-sts.corp.test.",
		"_dmarc.corp.test.", "_acme-challenge.corp.test.", "sub.corp.test.", "www.sub.corp.test.", "mail.other.test.",
		"other.test.", "*.corp.test.", "mta-sts.corp.test.", "test."}
	sfzTypes = []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeNS, dnswire.TypeMX, dnswire.TypeTXT, dnswire.TypeCAA,
		dnswire.TypeCNAME, dnswire.TypeDS, dnswire.TypeSOA, dnswire.TypeDNAME, dnswire.TypePTR, dnswire.TypeSPF, 99, 65280}
	sfzServers = []obs.Server{
		{Name: sfzName("ns.test."), Addr: netip.MustParseAddrPort("10.53.0.3:53")},
		{Name: sfzName("ns2.test."), Addr: netip.MustParseAddrPort("10.53.0.4:53")},
		{Name: sfzName("ns1.corp.test."), Addr: netip.MustParseAddrPort("10.53.0.11:53")},
		{Name: sfzName("ns2.corp.test."), Addr: netip.MustParseAddrPort("10.53.0.12:53")},
		{Name: sfzName("ns1.corp.test."), Addr: netip.MustParseAddrPort("[fd53::11]:53")},
		{},
	}
	sfzReasons = []obs.Reason{obs.ReasonTimeout, obs.ReasonNetwork, obs.ReasonRefused, obs.ReasonLame, obs.ReasonWalk, obs.ReasonDeadline, obs.ReasonNoRoute}
)

func sfzName(s string) dnswire.Name {
	n, err := dnswire.ParseName(s)
	if err != nil {
		panic(err)
	}
	return n
}

// name gives a fixed name, or one whose labels come from the bytes, under
// corp.test. or another domain, up to the longest name there is.
func (r *sfzReader) name() dnswire.Name {
	c := r.byte()
	switch {
	case c < 192:
		return sfzName(sfzNames[int(c)%len(sfzNames)])
	case c >= 250:
		fill := string([]byte{r.byte()})
		n, _ := dnswire.NameFromLabels([]string{strings.Repeat(fill, 63), strings.Repeat(fill, 63), strings.Repeat(fill, 63), strings.Repeat(fill, 61)})
		return n
	}
	var labels []string
	for range 1 + r.pick(3) {
		if l := r.text(63); l != "" {
			labels = append(labels, l)
		}
	}
	if c%2 == 0 {
		labels = append(labels, "corp", "test")
	} else {
		labels = append(labels, "other", "test")
	}
	n, err := dnswire.NameFromLabels(labels)
	if err != nil {
		return sfzName("corp.test.")
	}
	return n
}

func (r *sfzReader) rtype() dnswire.Type { return sfzTypes[r.pick(len(sfzTypes))] }

// data gives record data of type t from the bytes.
func (r *sfzReader) data(t dnswire.Type) dnswire.RData {
	switch t {
	case dnswire.TypeA:
		return dnswire.A{Addr: netip.AddrFrom4([4]byte{10, 53, r.byte() % 2, r.byte()})}
	case dnswire.TypeAAAA:
		return dnswire.AAAA{Addr: netip.AddrFrom16([16]byte{0: 0xfd, 1: 0x53, 15: r.byte()})}
	case dnswire.TypeNS:
		return dnswire.NS{Host: r.name()}
	case dnswire.TypeCNAME:
		return dnswire.CNAME{Target: r.name()}
	case dnswire.TypeDNAME:
		return dnswire.DNAME{Target: r.name()}
	case dnswire.TypePTR:
		return dnswire.PTR{Target: r.name()}
	case dnswire.TypeMX:
		return dnswire.MX{Preference: uint16(r.byte()), Exchange: r.name()}
	case dnswire.TypeTXT, dnswire.TypeSPF:
		var s []string
		for range 1 + r.pick(3) {
			s = append(s, r.text(255))
		}
		if t == dnswire.TypeSPF {
			return dnswire.SPF{Strings: s}
		}
		return dnswire.TXT{Strings: s}
	case dnswire.TypeCAA:
		tag := r.text(15)
		if tag == "" {
			tag = "issue"
		}
		return dnswire.CAA{Flags: r.byte(), Tag: tag, Value: r.text(64)}
	case dnswire.TypeDS:
		return dnswire.DS{KeyTag: uint16(r.byte()), Algorithm: r.byte(), DigestType: r.byte(), Digest: []byte(r.text(48))}
	case dnswire.TypeSOA:
		return dnswire.SOA{MName: r.name(), RName: r.name(), Serial: uint32(r.byte())}
	case dnswire.TypeOPT, dnswire.TypeRRSIG, dnswire.TypeNSEC, dnswire.TypeDNSKEY, dnswire.TypeNSEC3,
		dnswire.TypeNSEC3PARAM, dnswire.TypeNXNAME, dnswire.TypeTSIG, dnswire.TypeIXFR, dnswire.TypeAXFR,
		dnswire.TypeANY:
		// Left as Unknown data below, like every type that has no case.
	}
	return dnswire.Unknown{TypeCode: t, Data: []byte(r.text(32))}
}

// records gives a set: mostly of the type asked and owned by the name asked,
// sometimes of another type or owner; with the byte 255, a thousand and more
// A records.
func (r *sfzReader) records(name dnswire.Name, t dnswire.Type) []dnswire.Record {
	var set []dnswire.Record
	c := r.byte()
	if c == 255 {
		for i := range 995 + r.pick(10) {
			set = append(set, dnswire.Record{Name: name, Class: dnswire.ClassINET, TTL: 300,
				Data: dnswire.A{Addr: netip.AddrFrom4([4]byte{10, 53, byte(i >> 8), byte(i)})}})
		}
		return set
	}
	for range 1 + int(c)%6 {
		owner, typ := name, t
		switch c := r.byte(); c % 5 {
		case 4:
			owner = r.name()
		case 3:
			typ = r.rtype()
		}
		set = append(set, dnswire.Record{Name: owner, Class: dnswire.ClassINET, TTL: uint32(r.byte()), Data: r.data(typ)})
	}
	return set
}

func (r *sfzReader) answer(k obs.Key) obs.Answer {
	a := obs.Answer{Proof: obs.Proof{Server: sfzServers[r.pick(len(sfzServers))]}}
	switch c := r.pick(10); {
	case c < 6:
		rec := obs.Records{Set: r.records(k.Name, k.Type)}
		if k.Kind == obs.KindDelegation {
			for range r.pick(4) {
				h := r.name()
				t := dnswire.TypeA
				if r.byte()%2 == 1 {
					t = dnswire.TypeAAAA
				}
				rec.Glue = append(rec.Glue, dnswire.Record{Name: h, Class: dnswire.ClassINET, TTL: 300, Data: r.data(t)})
			}
		}
		a.Result = obs.RecordsResult(rec)
	case c == 6:
		a.Result = obs.NoDataResult(obs.NoData{SOA: dnswire.Record{Name: sfzName("corp.test."), Class: dnswire.ClassINET, Data: dnswire.SOA{}}})
	case c == 7:
		a.Result = obs.NoNameResult(obs.NoName{SOA: dnswire.Record{Name: sfzName("corp.test."), Class: dnswire.ClassINET, Data: dnswire.SOA{}}})
	default:
		a.Result = obs.FailureResult(obs.Failure{Reason: sfzReasons[r.pick(len(sfzReasons))], Detail: r.text(32)})
	}
	return a
}

// observation builds one check and its answers. A failed walk is one answer
// from no server and no zone, as observe gives it.
func (r *sfzReader) observation() obs.Observation {
	domain := sfzName("corp.test.")
	if r.byte() >= 224 {
		domain = sfzName("other.test.")
	}
	var k obs.Key
	switch r.pick(8) {
	case 0:
		k = obs.DelegationKey(domain)
	case 1:
		k = obs.DSKey(domain)
	case 2:
		k = obs.SerialKey(domain)
	case 3:
		k, _ = obs.PolicyKey(domain)
	case 4:
		k = obs.WildcardKey(domain, r.name())
	default:
		k = obs.RecordsKey(domain, r.name(), r.rtype())
	}
	if r.byte() == 7 {
		return obs.Observation{Key: k, Answers: []obs.Answer{{Result: obs.FailureResult(obs.Failure{Reason: obs.ReasonWalk})}}}
	}
	o := obs.Observation{Key: k, Zone: []dnswire.Name{domain, {}, sfzName("sub.corp.test."), sfzName("test."), k.Name}[r.pick(5)]}
	for range r.pick(5) {
		o.Answers = append(o.Answers, r.answer(k))
	}
	return o
}

func sfzObservations(data []byte) []obs.Observation {
	r := &sfzReader{b: data}
	var observations []obs.Observation
	for range 1 + r.pick(16) {
		observations = append(observations, r.observation())
	}
	return observations
}

// sfzPrintable reports whether s holds only printable ASCII.
func sfzPrintable(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r > 0x7e })
}

// sfzSeed writes a program: each part is a list of bytes, all joined.
func sfzSeed(parts ...[]byte) []byte { return slices.Concat(parts...) }

func FuzzSnapshot(f *testing.F) {
	// Programs of the reader above. An observation of corp.test. is: 0, its
	// kind (0 delegation, 3 policy, 5 records: then a name and a type of the
	// lists), 0 (7: a failed walk), a zone, the number of answers. An answer
	// is a server, 0 for records, the number of records less one, then for
	// each: 0, a TTL, its data.
	delegation := []byte{0, 0, 0, 3, 1, 0, 0, 1, 0, 0, 2, 0, 0, 3, // ns.test. gives {ns1, ns2}
		2, 2, 0, 0, 11, 3, 0, 0, 12} // and their A glue
	apex := []byte{0, 5, 0, 2, 0, 0, 2, // corp.test. NS from two servers
		2, 0, 2, 0, 0, 2, 0, 0, 3, 0, 0, 192, 0, 3, 'n', 's', '3', // ns1 gives {ns1, ns2, ns3}
		3, 0, 1, 0, 0, 2, 0, 0, 3} // ns2 gives {ns1, ns2}
	stsRecord := sfzSeed([]byte{0, 5, 4, 4, 0, 0, 2}, // _mta-sts.corp.test. TXT from two servers
		[]byte{2, 0, 0, 0, 0, 0, 20}, []byte("v=STSv1; id=20261118"),
		[]byte{3, 0, 0, 0, 0, 0, 20}, []byte("v=STSv1; id=20261118"))
	body := "version: STSv1\nmode: enforce\nmx: mail.corp.test\nmx: *.mx.example\nmax_age: 604800\n"
	policy := sfzSeed([]byte{0, 3, 0, 0, 1, 2, 0, 0, 0, 0, 0, byte(len(body))}, []byte(body))
	hostile := []byte{0, 5, 0, 2, 0, 0, 1, // corp.test. NS from one server
		3, 0, 0, 0, 0, 194, 0, 9, 'a', '\n', '#', '|', '"', '\\', ' ', '\x1b', 0x7f} // a name of hostile octets
	walk := []byte{0, 5, 0, 2, 7}                                      // corp.test. NS: the walk failed
	many := []byte{0, 5, 1, 0, 0, 0, 2, 2, 0, 255, 5, 3, 0, 255, 5}    // www.corp.test. A: 1000 records from both
	tooMany := []byte{0, 5, 1, 0, 0, 0, 2, 2, 0, 255, 9, 3, 0, 255, 9} // and 1004
	f.Add(sfzSeed([]byte{3}, delegation, apex, stsRecord, policy))
	f.Add(sfzSeed([]byte{3}, delegation, hostile, walk, apex))
	f.Add(sfzSeed([]byte{1}, delegation, many))
	f.Add(sfzSeed([]byte{1}, delegation, tooMany))
	f.Add([]byte{})
	domain := sfzName("corp.test.")
	f.Fuzz(func(t *testing.T, data []byte) {
		observations := sfzObservations(data)
		file, skips := Snapshot(domain, observations)
		text := file.String()
		if !file.Domain.Equal(domain) || !strings.HasPrefix(text, "domain corp.test.\n") || strings.Count(text, "domain ") != 1 {
			t.Fatalf("the file is not of corp.test.:\n%q", text)
		}
		// No answer gives a line that only a person can write.
		if file.Issuers != nil || file.CertNames != nil {
			t.Fatalf("issuers %q or names %v came from answers", file.Issuers, file.CertNames)
		}
		if file.Policy != nil && !slices.ContainsFunc(observations, func(o obs.Observation) bool {
			return o.Key.Kind == obs.KindPolicy && o.Key.Domain.Equal(domain)
		}) {
			t.Fatalf("an mta-sts line without a fetch of the policy of corp.test.: %q", file.Policy.String())
		}
		// Each line comes from a check of corp.test. of its own set, and is
		// one that the guard of the line form reads back.
		for _, e := range file.Expectations {
			if !slices.ContainsFunc(observations, func(o obs.Observation) bool {
				name, typ, ok := setOf(o.Key)
				return ok && o.Key.Domain.Equal(domain) && name.Equal(e.Name) && typ == e.Type
			}) {
				t.Fatalf("the line %q comes from no check of corp.test.", e.String())
			}
			if e.Form == FormSets {
				if why := readSets(&Expectation{Type: e.Type}, e.FormText()); why != "" {
					t.Fatalf("the line %q does not read back: %s", e.String(), why)
				}
			}
		}
		// One line for each part of the file, each printable: nothing in a
		// name or value ends a line or starts another.
		lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
		parts := 1 + len(file.Expectations)
		if file.Policy != nil {
			parts++
		}
		if len(lines) != parts || !strings.HasSuffix(text, "\n") {
			t.Fatalf("%d lines for %d parts:\n%q", len(lines), parts, text)
		}
		for _, l := range lines {
			if !sfzPrintable(l) {
				t.Fatalf("the line %q holds an octet that is not printable", l)
			}
		}
		// The text is a fixed point of Parse, also with the comments that
		// osk-dns-watcher snapshot writes around it.
		comments := "# Snapshot of corp.test. as seen now.\n"
		for _, s := range skips {
			if !sfzPrintable(s.Why) || s.Why == "" {
				t.Fatalf("the reason of %v %v is %q", s.Name, s.Type, s.Why)
			}
			if _, ok := file.Find(s.Name, s.Type); ok {
				t.Fatalf("%v %v has a line and a reason: %q", s.Name, s.Type, s.Why)
			}
			comments += "# not written: " + s.Name.Lower().String() + " " + s.Type.String() + ": " + s.Why + "\n"
		}
		for _, n := range NSNoAnswer(domain, observations) {
			comments += "# no answer about the NS set from " + n + "\n"
		}
		for _, s := range NSSources(domain, observations) {
			comments += "# NS set " + s.Text + ": " + strings.Join(slices.Concat(s.Parent, s.Zone), ", ") + "\n"
		}
		for _, in := range []string{text, comments + text, text + comments} {
			g, err := Parse([]byte(in))
			if err != nil {
				t.Fatalf("the snapshot does not parse: %v\n%q", err, in)
			}
			if g.String() != text {
				t.Fatalf("the snapshot parses as\n%q\nnot as itself\n%q", g.String(), text)
			}
		}
		// The same answers in another order give the same file.
		reversed := slices.Clone(observations)
		slices.Reverse(reversed)
		if again, _ := Snapshot(domain, reversed); again.String() != text {
			t.Fatalf("in another order\n%q\nnot\n%q", again.String(), text)
		}
	})
}
