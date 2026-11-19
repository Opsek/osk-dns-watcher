package obs_test

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

func dataName(t *testing.T, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func dataA(t *testing.T, owner string, ttl uint32, addr string) dnswire.Record {
	t.Helper()
	return dnswire.Record{Name: dataName(t, owner), Class: dnswire.ClassINET, TTL: ttl,
		Data: dnswire.A{Addr: netip.MustParseAddr(addr)}}
}

func dataSOA(t *testing.T, owner string, ttl, minimum uint32) dnswire.Record {
	t.Helper()
	return dnswire.Record{Name: dataName(t, owner), Class: dnswire.ClassINET, TTL: ttl,
		Data: dnswire.SOA{MName: dataName(t, "ns1."+owner), RName: dataName(t, "hostmaster."+owner),
			Serial: 7, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: minimum}}
}

// dataStrings gives records a form that compares with ==, which Name lacks.
func dataStrings(records []dnswire.Record) []string {
	var s []string
	for _, r := range records {
		s = append(s, r.String())
	}
	return s
}

// dataSeen is what Match did with one Result.
type dataSeen struct {
	calls   int
	which   string
	records obs.Records
	noData  obs.NoData
	noName  obs.NoName
	failure obs.Failure
}

func dataMatch(r obs.Result) dataSeen {
	var s dataSeen
	s.which = obs.Match(r,
		func(v obs.Records) string { s.calls++; s.records = v; return "records" },
		func(v obs.NoData) string { s.calls++; s.noData = v; return "nodata" },
		func(v obs.NoName) string { s.calls++; s.noName = v; return "noname" },
		func(v obs.Failure) string { s.calls++; s.failure = v; return "failure" })
	return s
}

func TestKindString(t *testing.T) {
	for _, c := range []struct {
		kind  obs.Kind
		value uint8
		word  string
	}{
		{obs.KindDelegation, 1, "delegation"},
		{obs.KindDS, 2, "ds"},
		{obs.KindRecords, 3, "records"},
		{obs.KindSerial, 4, "serial"},
		{0, 0, "kind0"},
		{obs.KindWildcard, 5, "wildcard"},
		{obs.KindCertificates, 6, "certificates"},
		{obs.KindPolicy, 7, "policy"},
		{8, 8, "kind8"},
		{255, 255, "kind255"},
	} {
		if uint8(c.kind) != c.value || c.kind.String() != c.word {
			t.Errorf("Kind %d prints %q; want value %d, %q", uint8(c.kind), c.kind.String(), c.value, c.word)
		}
	}
}

func TestKeyConstructors(t *testing.T) {
	domain := dataName(t, "corp.test.")
	elsewhere := dataName(t, "mail.other.test.")
	for _, c := range []struct {
		key  obs.Key
		kind obs.Kind
		name dnswire.Name
		typ  dnswire.Type
	}{
		{obs.DelegationKey(domain), obs.KindDelegation, domain, dnswire.TypeNS},
		{obs.DSKey(domain), obs.KindDS, domain, dnswire.TypeDS},
		{obs.SerialKey(domain), obs.KindSerial, domain, dnswire.TypeSOA},
		{obs.RecordsKey(domain, elsewhere, dnswire.TypeMX), obs.KindRecords, elsewhere, dnswire.TypeMX},
		{obs.CertificatesKey(domain), obs.KindCertificates, domain, 0},
		{obs.WildcardKey(domain, domain), obs.KindWildcard, domain, dnswire.TypeA},
		{obs.WildcardKey(domain, elsewhere), obs.KindWildcard, elsewhere, dnswire.TypeA},
		{mtsPolicyKey(t, domain), obs.KindPolicy, dataName(t, "mta-sts.corp.test."), dnswire.TypeTXT},
	} {
		k := c.key
		if k.Kind != c.kind || !k.Domain.Equal(domain) || !k.Name.Equal(c.name) || k.Type != c.typ {
			t.Errorf("key %v %v %v %v; want %v %v %v %v", k.Kind, k.Domain, k.Name, k.Type, c.kind, domain, c.name, c.typ)
		}
	}
}

// The text of a key names a check in progress, so two keys that differ only
// in letter case must give the same text, and a name with a blank must stay
// one field.
func TestKeyString(t *testing.T) {
	domain := dataName(t, "Corp.TEST.")
	for _, c := range []struct {
		key  obs.Key
		want string
	}{
		{obs.RecordsKey(dataName(t, "corp.test."), dataName(t, "www.corp.test."), dnswire.TypeA), "records corp.test. www.corp.test. A"},
		{obs.RecordsKey(domain, dataName(t, "WWW.Shop.Test."), dnswire.TypeTXT), "records corp.test. www.shop.test. TXT"},
		{obs.RecordsKey(domain, dataName(t, `A\032B.corp.test.`), dnswire.TypeCAA), `records corp.test. a\032b.corp.test. CAA`},
		{obs.DelegationKey(domain), "delegation corp.test. corp.test. NS"},
		{obs.DSKey(domain), "ds corp.test. corp.test. DS"},
		{obs.SerialKey(domain), "serial corp.test. corp.test. SOA"},
		{obs.WildcardKey(domain, domain), "wildcard corp.test. corp.test. A"},
		{obs.WildcardKey(domain, dataName(t, "Mail.Shop.TEST.")), "wildcard corp.test. mail.shop.test. A"},
		{obs.CertificatesKey(domain), "certificates corp.test."},
		{obs.CertificatesKey(dataName(t, "Shop.Example.COM.")), "certificates shop.example.com."},
		{mtsPolicyKey(t, domain), "policy corp.test. mta-sts.corp.test. TXT"},
	} {
		if got := c.key.String(); got != c.want {
			t.Errorf("key prints %q, want %q", got, c.want)
		}
	}
}

// mtsPolicyKey is the policy key of a domain whose policy name fits.
func mtsPolicyKey(t *testing.T, domain dnswire.Name) obs.Key {
	t.Helper()
	k, ok := obs.PolicyKey(domain)
	if !ok {
		t.Fatalf("PolicyKey(%v): not ok", domain)
	}
	return k
}

// mtsLabels makes a name of raw label octets, so that a label may hold a dot.
func mtsLabels(t *testing.T, labels ...string) dnswire.Name {
	t.Helper()
	n, err := dnswire.NameFromLabels(labels)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The policy name is mta-sts.<domain> (RFC 8461 section 3.3), made of the
// labels of the domain: a label that holds a dot stays one label. A name of
// more than 255 octets on the wire cannot be made.
func TestPolicyKey(t *testing.T) {
	a, b, c := strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63)
	// Three labels of 63 octets and one of last: 1+63 octets each, the last
	// label, the root octet; mta-sts. adds 8.
	long := func(last int) dnswire.Name { return mtsLabels(t, a, b, c, strings.Repeat("d", last)) }
	for _, tc := range []struct {
		name   string
		domain dnswire.Name
		labels []string // of the policy name, in lower case
	}{
		{"plain", dataName(t, "corp.test."), []string{"mta-sts", "corp", "test"}},
		{"upper case", dataName(t, "Corp.TEST."), []string{"mta-sts", "corp", "test"}},
		{"a dot inside a label", mtsLabels(t, "corp.test"), []string{"mta-sts", "corp.test"}},
		{"a slash and a colon", mtsLabels(t, "a/b", "test:443"), []string{"mta-sts", "a/b", "test:443"}},
		{"the root", dnswire.Name{}, []string{"mta-sts"}},
		{"a policy name of 255 octets", long(53), []string{"mta-sts", a, b, c, strings.Repeat("d", 53)}},
	} {
		k, ok := obs.PolicyKey(tc.domain)
		var got []string
		for _, l := range k.Name.Labels() {
			got = append(got, strings.ToLower(l))
		}
		if !ok || k.Kind != obs.KindPolicy || !k.Domain.Equal(tc.domain) || k.Type != dnswire.TypeTXT || !slices.Equal(got, tc.labels) {
			t.Errorf("%s: PolicyKey = %v %v %q %v, %v; want policy, the domain, %q, TXT, ok",
				tc.name, k.Kind, k.Domain, got, k.Type, ok, tc.labels)
		}
	}
	for _, domain := range []dnswire.Name{long(54), long(61)} {
		if k, ok := obs.PolicyKey(domain); ok {
			t.Errorf("PolicyKey of a domain of %d labels: %v, ok; want not ok, the policy name is too long", domain.LabelCount(), k)
		}
	}
}

func TestReasonString(t *testing.T) {
	reasons := []obs.Reason{obs.ReasonNoResult, obs.ReasonTimeout, obs.ReasonNetwork, obs.ReasonMalformed,
		obs.ReasonTruncated, obs.ReasonRefused, obs.ReasonServFail, obs.ReasonRcode, obs.ReasonLame,
		obs.ReasonBadAnswer, obs.ReasonNotPermitted, obs.ReasonRateLimited, obs.ReasonBudget, obs.ReasonWalk,
		obs.ReasonDeadline}
	words := []string{"none", "timeout", "network", "malformed", "truncated", "refused", "servfail", "rcode",
		"lame", "bad-answer", "not-permitted", "rate-limited", "budget", "walk", "deadline"}
	for i, r := range reasons {
		if int(r) != i || r.String() != words[i] {
			t.Errorf("Reason %d prints %q; want value %d, %q", uint8(r), r.String(), i, words[i])
		}
	}
	for _, r := range []obs.Reason{15, 255} {
		if want := fmt.Sprintf("reason%d", uint8(r)); r.String() != want {
			t.Errorf("Reason %d prints %q, want %q", uint8(r), r.String(), want)
		}
	}
}

func TestMatchCallsOneHandler(t *testing.T) {
	set := []dnswire.Record{dataA(t, "www.corp.test.", 300, "192.0.2.80"), dataA(t, "www.corp.test.", 300, "192.0.2.81")}
	glue := []dnswire.Record{dataA(t, "ns1.corp.test.", 3600, "192.0.2.11")}
	soa := dataSOA(t, "corp.test.", 900, 300)

	s := dataMatch(obs.RecordsResult(obs.Records{Set: set, Glue: glue}))
	if s.calls != 1 || s.which != "records" ||
		!slices.Equal(dataStrings(s.records.Set), dataStrings(set)) ||
		!slices.Equal(dataStrings(s.records.Glue), dataStrings(glue)) {
		t.Errorf("records: %d calls, %s, %+v", s.calls, s.which, s.records)
	}

	s = dataMatch(obs.NoDataResult(obs.NoData{SOA: soa}))
	if s.calls != 1 || s.which != "nodata" || s.noData.SOA.String() != soa.String() {
		t.Errorf("nodata: %d calls, %s, %+v", s.calls, s.which, s.noData)
	}

	for _, compact := range []bool{false, true} {
		s = dataMatch(obs.NoNameResult(obs.NoName{SOA: soa, Compact: compact}))
		if s.calls != 1 || s.which != "noname" || s.noName.SOA.String() != soa.String() || s.noName.Compact != compact {
			t.Errorf("noname, compact %v: %d calls, %s, %+v", compact, s.calls, s.which, s.noName)
		}
	}

	for _, f := range []obs.Failure{{Reason: obs.ReasonServFail, Detail: "15 \"blocked\""}, {Reason: obs.ReasonWalk}} {
		s = dataMatch(obs.FailureResult(f))
		if s.calls != 1 || s.which != "failure" || s.failure != f {
			t.Errorf("failure %+v: %d calls, %s, %+v", f, s.calls, s.which, s.failure)
		}
	}
}

// A Result keeps its own copy of the record slices, so a caller that reuses
// its slices does not change a result made from them.
func TestRecordsResultKeepsItsOwnSlices(t *testing.T) {
	set := []dnswire.Record{dataA(t, "www.corp.test.", 300, "192.0.2.80")}
	glue := []dnswire.Record{dataA(t, "ns1.corp.test.", 3600, "192.0.2.11")}
	wantSet, wantGlue := dataStrings(set), dataStrings(glue)
	r := obs.RecordsResult(obs.Records{Set: set, Glue: glue})
	set[0] = dataA(t, "evil.test.", 1, "192.0.2.66")
	glue[0] = set[0]
	s := dataMatch(r)
	if !slices.Equal(dataStrings(s.records.Set), wantSet) || !slices.Equal(dataStrings(s.records.Glue), wantGlue) {
		t.Errorf("after the caller changed its slices: Set %q, Glue %q; want %q, %q",
			dataStrings(s.records.Set), dataStrings(s.records.Glue), wantSet, wantGlue)
	}
}

// A result is copied once, when it is made: Match hands out the same slices
// on every call, so reading a result costs no copy.
func TestMatchDoesNotCopy(t *testing.T) {
	r := obs.RecordsResult(obs.Records{
		Set:  []dnswire.Record{dataA(t, "www.corp.test.", 300, "192.0.2.80")},
		Glue: []dnswire.Record{dataA(t, "ns1.corp.test.", 3600, "192.0.2.11")},
	})
	first, second := dataMatch(r).records, dataMatch(r).records
	if &first.Set[0] != &second.Set[0] || &first.Glue[0] != &second.Glue[0] {
		t.Errorf("two calls of Match handed out different copies of the slices")
	}
}

// A Result that nobody filled must never pass for an answer.
func TestZeroResultIsFailure(t *testing.T) {
	s := dataMatch(obs.Result{})
	if s.calls != 1 || s.which != "failure" || s.failure.Reason != obs.ReasonNoResult {
		t.Errorf("zero Result: %d calls, %s, %+v; want one failure with ReasonNoResult", s.calls, s.which, s.failure)
	}
	n := obs.Match(obs.Result{},
		func(obs.Records) int { return 1 }, func(obs.NoData) int { return 2 },
		func(obs.NoName) int { return 3 }, func(obs.Failure) int { return 4 })
	if n != 4 {
		t.Errorf("Match returned %d, want the value of the failure handler", n)
	}
}

// A case that cannot hold what it claims becomes a failure, so that no
// reader can take a broken answer for "no records".
func TestConstructorsRejectBadData(t *testing.T) {
	owner := dataName(t, "corp.test.")
	soaData := dnswire.SOA{MName: dataName(t, "ns1.corp.test."), RName: dataName(t, "hostmaster.corp.test."), Minimum: 300}
	notSOA := []dnswire.Record{
		{},
		dataA(t, "corp.test.", 300, "192.0.2.80"),
		{Name: owner, Class: dnswire.ClassINET, TTL: 300, Data: dnswire.Unknown{TypeCode: dnswire.TypeSOA, Data: []byte{0}}},
		{Name: owner, Class: dnswire.ClassINET, TTL: 300, Data: &soaData},
	}
	cases := map[string]obs.Result{
		"records with nil Set":     obs.RecordsResult(obs.Records{}),
		"records with empty Set":   obs.RecordsResult(obs.Records{Set: []dnswire.Record{}}),
		"records with only glue":   obs.RecordsResult(obs.Records{Glue: []dnswire.Record{dataA(t, "ns1.corp.test.", 300, "192.0.2.11")}}),
		"nodata with no SOA data":  obs.NoDataResult(obs.NoData{SOA: notSOA[0]}),
		"nodata with A data":       obs.NoDataResult(obs.NoData{SOA: notSOA[1]}),
		"nodata with unknown data": obs.NoDataResult(obs.NoData{SOA: notSOA[2]}),
		"nodata with *SOA data":    obs.NoDataResult(obs.NoData{SOA: notSOA[3]}),
		"noname with no SOA data":  obs.NoNameResult(obs.NoName{SOA: notSOA[0]}),
		"noname with A data":       obs.NoNameResult(obs.NoName{SOA: notSOA[1], Compact: true}),
		"noname with unknown data": obs.NoNameResult(obs.NoName{SOA: notSOA[2]}),
		"noname with *SOA data":    obs.NoNameResult(obs.NoName{SOA: notSOA[3]}),
	}
	for name, r := range cases {
		if s := dataMatch(r); s.calls != 1 || s.which != "failure" || s.failure.Reason != obs.ReasonBadAnswer {
			t.Errorf("%s: %d calls, %s, %+v; want one failure with ReasonBadAnswer", name, s.calls, s.which, s.failure)
		}
	}
}

func TestTTL(t *testing.T) {
	r := obs.Records{
		Set: []dnswire.Record{
			dataA(t, "www.corp.test.", 300, "192.0.2.80"),
			dataA(t, "www.corp.test.", 60, "192.0.2.81"),
			dataA(t, "www.corp.test.", 3600, "192.0.2.82"),
		},
		Glue: []dnswire.Record{dataA(t, "ns1.corp.test.", 5, "192.0.2.11")},
	}
	if got := r.TTL(); got != 60 {
		t.Errorf("Records TTL %d, want 60: the smallest of the set, glue not counted", got)
	}
	for _, c := range []struct{ ttl, minimum, want uint32 }{
		{900, 300, 300},
		{30, 300, 30},
		{300, 300, 300},
	} {
		soa := dataSOA(t, "corp.test.", c.ttl, c.minimum)
		if got := (obs.NoData{SOA: soa}).TTL(); got != c.want {
			t.Errorf("NoData TTL with SOA TTL %d, MINIMUM %d: %d, want %d", c.ttl, c.minimum, got, c.want)
		}
		if got := (obs.NoName{SOA: soa, Compact: true}).TTL(); got != c.want {
			t.Errorf("NoName TTL with SOA TTL %d, MINIMUM %d: %d, want %d", c.ttl, c.minimum, got, c.want)
		}
	}
}

// Match must stay the only way to read a Result.
func TestResultHasNoExportedField(t *testing.T) {
	rt := reflect.TypeFor[obs.Result]()
	for i := range rt.NumField() {
		if f := rt.Field(i); f.IsExported() {
			t.Errorf("Result has the exported field %s", f.Name)
		}
	}
}

// An answer carries its proof: who was asked, what, when, the octets and the
// transport.
func TestAnswerCarriesProof(t *testing.T) {
	sent := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	server := obs.Server{Name: dataName(t, "ns1.corp.test."), Addr: netip.MustParseAddrPort("192.0.2.11:53")}
	a := obs.Answer{
		Proof: obs.Proof{
			Server:   server,
			Question: dnswire.Question{Name: dataName(t, "www.corp.test."), Type: dnswire.TypeA, Class: dnswire.ClassINET},
			Sent:     sent,
			Received: sent.Add(time.Millisecond),
			Wire:     []byte{1, 2, 3},
			TCP:      true,
		},
		Result: obs.FailureResult(obs.Failure{Reason: obs.ReasonTimeout}),
	}
	o := obs.Observation{
		Key:      obs.RecordsKey(dataName(t, "corp.test."), dataName(t, "www.corp.test."), dnswire.TypeA),
		Start:    sent,
		Deadline: sent.Add(45 * time.Second),
		Zone:     dataName(t, "corp.test."),
		Walk:     []obs.Answer{a},
		Answers:  []obs.Answer{a},
	}
	got := o.Answers[0]
	if !got.Server.Name.Equal(server.Name) || got.Server.Addr != server.Addr || got.Question.Type != dnswire.TypeA ||
		got.Received.Sub(got.Sent) != time.Millisecond || len(got.Wire) != 3 || !got.TCP ||
		dataMatch(got.Result).failure.Reason != obs.ReasonTimeout || len(o.Walk) != 1 || !o.Zone.Equal(o.Key.Domain) {
		t.Errorf("observation does not hold what was put in: %+v", o)
	}
}

// 26 octets of base32 hold 128 random bits, so a server cannot guess the label
// and answer it differently.
func TestWildcardLabel(t *testing.T) {
	if obs.WildcardLabel != 26 {
		t.Errorf("WildcardLabel = %d, want 26", obs.WildcardLabel)
	}
}
