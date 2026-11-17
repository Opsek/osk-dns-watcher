package certlog_test

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/sources/certlog"
)

const crtTBS = "a7781bc044f9e19ba8009c0299b404f3816642d5185ed73bae6c05e8f7fa9d35"

// crtObj builds one issuance object. A value of over replaces the default
// raw JSON of its key; the value "-" leaves the key out.
func crtObj(over map[string]string) string {
	fields := map[string]string{
		"id":         `"1"`,
		"tbs_sha256": `"` + crtTBS + `"`,
		"not_before": `"2026-01-01T00:00:00Z"`,
		"not_after":  `"2026-02-01T00:00:00Z"`,
		"dns_names":  `["a.test"]`,
		"issuer":     `{"friendly_name":"Lab CA","caa_domains":["ca.test"]}`,
	}
	for k, v := range over {
		fields[k] = v
	}
	var parts []string
	for _, k := range []string{"id", "tbs_sha256", "not_before", "not_after", "dns_names", "issuer"} {
		if fields[k] != "-" {
			parts = append(parts, fmt.Sprintf("%q:%s", k, fields[k]))
		}
	}
	for k, v := range fields {
		switch k {
		case "id", "tbs_sha256", "not_before", "not_after", "dns_names", "issuer":
		default:
			parts = append(parts, fmt.Sprintf("%q:%s", k, v))
		}
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func crtArray(objs ...string) []byte { return []byte("[" + strings.Join(objs, ",") + "]") }

func crtNames(t *testing.T, in obs.Issuance) []string {
	t.Helper()
	var out []string
	for _, n := range in.Names {
		out = append(out, n.String())
	}
	return out
}

func crtOne(t *testing.T, over map[string]string) obs.Issuance {
	t.Helper()
	got, err := certlog.Parse(crtArray(crtObj(over)))
	if err != nil || len(got) != 1 {
		t.Fatalf("Parse(%v): %d issuances, %v; want one", over, len(got), err)
	}
	return got[0]
}

func TestParseMinimalAndFields(t *testing.T) {
	got, err := certlog.Parse(crtArray(crtObj(map[string]string{
		"id": `"12809115180"`, "dns_names": `[]`, "issuer": `{"caa_domains":[]}`,
		"cert_sha256": `"x"`, "revoked": `true`, "unknown": `{"a":[1,2,{"b":null}]}`,
	})))
	if err != nil || len(got) != 1 {
		t.Fatalf("Parse: %v, %v", got, err)
	}
	in := got[0]
	if in.ID != "12809115180" || in.TBS != crtTBS || len(in.Names) != 0 || in.Unread != 0 ||
		in.Issuer.Name != "-" || len(in.Issuer.CAA) != 0 ||
		!in.NotBefore.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) || !in.NotAfter.Equal(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("issuance %+v", in)
	}
}

func TestParseTopLevel(t *testing.T) {
	const want = "want a JSON array of at most 1000 issuances"
	for _, body := range []string{`{}`, `{"a":1}`, `"x"`, `5`, `null`, `true`} {
		if got, err := certlog.Parse([]byte(body)); err == nil || err.Error() != want || len(got) != 0 {
			t.Errorf("Parse(%s): %v, %v; want the error %q", body, got, err, want)
		}
	}
	for _, body := range []string{``, ` `, `[`, `[]]`, `[] []`, `[{]`, `garbage`, "[\x00]"} {
		if got, err := certlog.Parse([]byte(body)); err == nil || len(got) != 0 {
			t.Errorf("Parse(%q): %v, %v; want an error", body, got, err)
		}
	}
	for _, body := range []string{`[]`, " \n[ ]\n"} {
		if got, err := certlog.Parse([]byte(body)); err != nil || len(got) != 0 {
			t.Errorf("Parse(%q): %v, %v; want no issuances", body, got, err)
		}
	}
	// Elements that are no object.
	for _, el := range []string{`1`, `null`, `"x"`, `[]`, `true`} {
		if got, err := certlog.Parse(crtArray(el)); err == nil || len(got) != 0 {
			t.Errorf("Parse([%s]): %v, %v; want an error", el, got, err)
		}
	}
}

func crtPageOf(n int) []byte {
	objs := make([]string, n)
	for i := range objs {
		objs[i] = crtObj(map[string]string{"id": fmt.Sprintf(`"%d"`, i+1)})
	}
	return crtArray(objs...)
}

func TestParsePageSizeCap(t *testing.T) {
	if certlog.MaxPage != 1000 || certlog.MaxNames != 1000 || certlog.MaxCAA != 16 || certlog.MaxPages != 10 ||
		certlog.MaxKnown != 10000 || certlog.MaxBody != 4194304 {
		t.Errorf("caps %d %d %d %d %d %d", certlog.MaxPage, certlog.MaxNames, certlog.MaxCAA, certlog.MaxPages, certlog.MaxKnown, certlog.MaxBody)
	}
	got, err := certlog.Parse(crtPageOf(1000))
	if err != nil || len(got) != 1000 || got[999].ID != "1000" {
		t.Errorf("1000 issuances: %d, %v", len(got), err)
	}
	if got, err := certlog.Parse(crtPageOf(1001)); err == nil || err.Error() != "want a JSON array of at most 1000 issuances" || len(got) != 0 {
		t.Errorf("1001 issuances: %d, %v", len(got), err)
	}
}

func TestParseFaults(t *testing.T) {
	cases := []struct {
		name string
		over map[string]string
		want string // "" : only an error is asserted
	}{
		{"no id", map[string]string{"id": "-"}, "issuance 0: no id"},
		{"null id", map[string]string{"id": "null"}, "issuance 0: no id"},
		{"id empty", map[string]string{"id": `""`}, "issuance 0: bad id"},
		{"id zero", map[string]string{"id": `"0"`}, "issuance 0: bad id"},
		{"id leading zero", map[string]string{"id": `"01"`}, "issuance 0: bad id"},
		{"id 21 digits", map[string]string{"id": `"123456789012345678901"`}, "issuance 0: bad id"},
		{"id letter", map[string]string{"id": `"1a"`}, "issuance 0: bad id"},
		{"id sign", map[string]string{"id": `"+1"`}, "issuance 0: bad id"},
		{"id minus", map[string]string{"id": `"-1"`}, "issuance 0: bad id"},
		{"id space", map[string]string{"id": `" 1"`}, "issuance 0: bad id"},
		{"id arabic digit", map[string]string{"id": `"١"`}, "issuance 0: bad id"},
		{"id number", map[string]string{"id": `5`}, ""},
		{"id array", map[string]string{"id": `["1"]`}, ""},
		{"no tbs", map[string]string{"tbs_sha256": "-"}, "issuance 0: no tbs_sha256"},
		{"null tbs", map[string]string{"tbs_sha256": "null"}, "issuance 0: no tbs_sha256"},
		{"tbs 63", map[string]string{"tbs_sha256": `"` + crtTBS[:63] + `"`}, "issuance 0: bad tbs_sha256"},
		{"tbs 65", map[string]string{"tbs_sha256": `"` + crtTBS + `a"`}, "issuance 0: bad tbs_sha256"},
		{"tbs 66", map[string]string{"tbs_sha256": `"` + crtTBS + `ab"`}, "issuance 0: bad tbs_sha256"},
		{"tbs empty", map[string]string{"tbs_sha256": `""`}, "issuance 0: bad tbs_sha256"},
		{"tbs not hex", map[string]string{"tbs_sha256": `"g` + crtTBS[1:] + `"`}, "issuance 0: bad tbs_sha256"},
		{"tbs space", map[string]string{"tbs_sha256": `" ` + crtTBS[1:] + `"`}, "issuance 0: bad tbs_sha256"},
		{"tbs number", map[string]string{"tbs_sha256": `5`}, ""},
		{"no not_before", map[string]string{"not_before": "-"}, "issuance 0: no not_before"},
		{"null not_before", map[string]string{"not_before": "null"}, "issuance 0: no not_before"},
		{"no not_after", map[string]string{"not_after": "-"}, "issuance 0: no not_after"},
		{"null not_after", map[string]string{"not_after": "null"}, "issuance 0: no not_after"},
		{"date only", map[string]string{"not_before": `"2026-01-01"`}, ""},
		{"month 13", map[string]string{"not_after": `"2026-13-01T00:00:00Z"`}, ""},
		{"no zone", map[string]string{"not_after": `"2026-03-01T00:00:00"`}, ""},
		{"date number", map[string]string{"not_after": `1790000000`}, ""},
		{"equal dates", map[string]string{"not_after": `"2026-01-01T00:00:00Z"`}, "issuance 0: not_after is not after not_before"},
		{"after before", map[string]string{"not_after": `"2025-12-31T23:59:59Z"`}, "issuance 0: not_after is not after not_before"},
		{"no dns_names", map[string]string{"dns_names": "-"}, "issuance 0: no dns_names"},
		{"null dns_names", map[string]string{"dns_names": "null"}, "issuance 0: no dns_names"},
		{"dns_names object", map[string]string{"dns_names": `{}`}, ""},
		{"dns_names string", map[string]string{"dns_names": `"a.test"`}, ""},
		{"dns_names number element", map[string]string{"dns_names": `["a.test",5]`}, ""},
		{"1001 dns_names", map[string]string{"dns_names": crtNameList(1001)}, "issuance 0: more than 1000 dns_names"},
		{"no issuer", map[string]string{"issuer": "-"}, "issuance 0: no issuer"},
		{"null issuer", map[string]string{"issuer": "null"}, "issuance 0: no issuer"},
		{"issuer string", map[string]string{"issuer": `"x"`}, ""},
		{"issuer array", map[string]string{"issuer": `[]`}, ""},
		{"no caa_domains", map[string]string{"issuer": `{"friendly_name":"X"}`}, "issuance 0: no caa_domains"},
		{"null caa_domains", map[string]string{"issuer": `{"caa_domains":null}`}, "issuance 0: no caa_domains"},
		{"caa_domains string", map[string]string{"issuer": `{"caa_domains":"ca.test"}`}, ""},
		{"caa_domains number element", map[string]string{"issuer": `{"caa_domains":["ca.test",5]}`}, ""},
		{"17 caa_domains", map[string]string{"issuer": `{"caa_domains":` + crtCAAList(17) + `}`}, "issuance 0: more than 16 caa_domains"},
		{"friendly_name number", map[string]string{"issuer": `{"friendly_name":5,"caa_domains":[]}`}, ""},
		{"friendly_name object", map[string]string{"issuer": `{"friendly_name":{},"caa_domains":[]}`}, ""},
	}
	for _, tc := range cases {
		got, err := certlog.Parse(crtArray(crtObj(tc.over)))
		if err == nil || len(got) != 0 || tc.want != "" && err.Error() != tc.want {
			t.Errorf("%s: %v, %v; want the error %q", tc.name, got, err, tc.want)
		}
	}
}

func crtNameList(n int) string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf(`"h%d.a.test"`, i)
	}
	return "[" + strings.Join(names, ",") + "]"
}

func crtCAAList(n int) string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf(`"ca%d.test"`, i)
	}
	return "[" + strings.Join(names, ",") + "]"
}

// The index in the text of an error is that of the element, from 0, and one
// bad element spoils the page, whatever comes before and after it.
func TestParseErrorIndexAndWholePage(t *testing.T) {
	good := func(id string) string { return crtObj(map[string]string{"id": `"` + id + `"`}) }
	bad := crtObj(map[string]string{"id": `"3"`, "tbs_sha256": "-"})
	got, err := certlog.Parse(crtArray(good("1"), good("2"), bad, good("4")))
	if err == nil || err.Error() != "issuance 2: no tbs_sha256" || len(got) != 0 {
		t.Errorf("Parse: %d issuances, %v; want the error of element 2 and nothing else", len(got), err)
	}
	got, err = certlog.Parse(crtArray(good("1"), crtObj(map[string]string{"id": `"2"`, "issuer": "-"})))
	if err == nil || err.Error() != "issuance 1: no issuer" || len(got) != 0 {
		t.Errorf("Parse: %d issuances, %v", len(got), err)
	}
}

func TestParseIDsMustIncrease(t *testing.T) {
	obj := func(id string) string { return crtObj(map[string]string{"id": `"` + id + `"`}) }
	for _, tc := range []struct {
		ids  []string
		want string // "" : fine
	}{
		{[]string{"5", "7"}, ""},
		{[]string{"9", "10"}, ""},
		{[]string{"99", "100", "101"}, ""},
		{[]string{"18446744073709551615", "18446744073709551616"}, ""},
		{[]string{"99999999999999999998", "99999999999999999999"}, ""},
		{[]string{"7", "5"}, "issuance 1: id not above the one before"},
		{[]string{"7", "7"}, "issuance 1: id not above the one before"},
		{[]string{"10", "9"}, "issuance 1: id not above the one before"},
		{[]string{"100", "99"}, "issuance 1: id not above the one before"},
		{[]string{"18446744073709551616", "18446744073709551615"}, "issuance 1: id not above the one before"},
		{[]string{"1", "2", "2"}, "issuance 2: id not above the one before"},
		{[]string{"1", "3", "2"}, "issuance 2: id not above the one before"},
		{[]string{"5", "7", "6", "9"}, "issuance 2: id not above the one before"},
	} {
		var objs []string
		for _, id := range tc.ids {
			objs = append(objs, obj(id))
		}
		got, err := certlog.Parse(crtArray(objs...))
		if tc.want == "" {
			if err != nil || len(got) != len(tc.ids) {
				t.Errorf("ids %v: %d issuances, %v; want all", tc.ids, len(got), err)
			}
			continue
		}
		if err == nil || err.Error() != tc.want || len(got) != 0 {
			t.Errorf("ids %v: %d issuances, %v; want the error %q", tc.ids, len(got), err, tc.want)
		}
	}
}

func TestParseTBSKeptInLowerCase(t *testing.T) {
	upper := strings.ToUpper(crtTBS)
	if got := crtOne(t, map[string]string{"tbs_sha256": `"` + upper + `"`}); got.TBS != crtTBS {
		t.Errorf("TBS %q, want %q", got.TBS, crtTBS)
	}
	mixed := "aBcDeF0123456789" + strings.Repeat("0", 48)
	if got := crtOne(t, map[string]string{"tbs_sha256": `"` + mixed + `"`}); got.TBS != strings.ToLower(mixed) {
		t.Errorf("TBS %q", got.TBS)
	}
}

func TestParseTimes(t *testing.T) {
	got := crtOne(t, map[string]string{"not_before": `"2026-01-01T02:00:00+02:00"`, "not_after": `"2026-01-01T00:00:00.5Z"`})
	if !got.NotBefore.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		!got.NotAfter.Equal(time.Date(2026, 1, 1, 0, 0, 0, 500_000_000, time.UTC)) {
		t.Errorf("times %v %v", got.NotBefore, got.NotAfter)
	}
	// One second after is enough, and the order is by instant, not by text.
	got = crtOne(t, map[string]string{"not_before": `"2026-01-01T00:00:00Z"`, "not_after": `"2026-01-01T00:00:01Z"`})
	if !got.NotAfter.Equal(got.NotBefore.Add(time.Second)) {
		t.Errorf("times %v %v", got.NotBefore, got.NotAfter)
	}
	got = crtOne(t, map[string]string{"not_before": `"2026-01-01T05:00:00+03:00"`, "not_after": `"2026-01-01T03:00:00Z"`})
	if !got.NotAfter.After(got.NotBefore) {
		t.Errorf("times %v %v", got.NotBefore, got.NotAfter)
	}
	if _, err := certlog.Parse(crtArray(crtObj(map[string]string{"not_before": `"2026-01-01T05:00:00+03:00"`, "not_after": `"2026-01-01T02:00:00Z"`}))); err == nil {
		t.Error("not_after equal to not_before in another zone was read")
	}
}

func TestParseNames(t *testing.T) {
	cases := []struct {
		name       string
		dns        string
		want       []string
		wantUnread int
	}{
		{"none", `[]`, nil, 0},
		{"one", `["Www.A.test."]`, []string{"www.a.test."}, 0},
		{"order and dedupe", `["B.test","a.test","A.TEST.","b.test"]`, []string{"a.test.", "b.test."}, 0},
		{"canonical order", `["www.a.test","*.a.test","a.test","b.a.test"]`, []string{"a.test.", "*.a.test.", "b.a.test.", "www.a.test."}, 0},
		{"top label first", `["www.example.com","example.net","example.com","www.example.net"]`,
			[]string{"example.com.", "www.example.com.", "example.net.", "www.example.net."}, 0},
		{"unreadable", `["a.test","bad name","ü.test","a_b.test","a*.test","x.*.test","*.*.test","","a..test"]`, []string{"a.test."}, 8},
		{"null is unreadable", `[null,"a.test",null]`, []string{"a.test."}, 2},
		{"duplicates of unreadable count each", `["a_b.test","a_b.test"]`, nil, 2},
		{"all unreadable", `["_dmarc.a.test"]`, nil, 1},
	}
	for _, tc := range cases {
		got := crtOne(t, map[string]string{"dns_names": tc.dns})
		if names := crtNames(t, got); !slices.Equal(names, tc.want) || got.Unread != tc.wantUnread {
			t.Errorf("%s: names %q, unread %d; want %q, %d", tc.name, names, got.Unread, tc.want, tc.wantUnread)
		}
	}
	// Exactly the cap is read whole.
	got := crtOne(t, map[string]string{"dns_names": crtNameList(1000)})
	if len(got.Names) != 1000 || got.Unread != 0 {
		t.Errorf("1000 names: %d, unread %d", len(got.Names), got.Unread)
	}
	for i := 1; i < len(got.Names); i++ {
		if dnswire.Compare(got.Names[i-1], got.Names[i]) >= 0 {
			t.Fatalf("names %d and %d are not in order", i-1, i)
		}
	}
}

func TestParseIssuer(t *testing.T) {
	cases := []struct {
		name     string
		issuer   string
		wantName string
		wantCAA  []string
	}{
		{"no friendly name", `{"caa_domains":["ca.test"]}`, "-", []string{"ca.test"}},
		{"null friendly name", `{"friendly_name":null,"caa_domains":[]}`, "-", nil},
		{"empty friendly name", `{"friendly_name":"","caa_domains":[]}`, "-", nil},
		{"one octet", `{"friendly_name":"S","caa_domains":[]}`, "S", nil},
		{"64 octets", `{"friendly_name":"` + strings.Repeat("a", 64) + `","caa_domains":[]}`, strings.Repeat("a", 64), nil},
		{"65 octets", `{"friendly_name":"` + strings.Repeat("a", 65) + `","caa_domains":[]}`, "-", nil},
		{"spaces kept", `{"friendly_name":" SSL.com (R) ","caa_domains":[]}`, " SSL.com (R) ", nil},
		{"tilde", `{"friendly_name":"~","caa_domains":[]}`, "~", nil},
		{"space only", `{"friendly_name":" ","caa_domains":[]}`, " ", nil},
		{"control octet", `{"friendly_name":"a\u001fb","caa_domains":[]}`, "-", nil},
		{"tab", `{"friendly_name":"a\tb","caa_domains":[]}`, "-", nil},
		{"delete", `{"friendly_name":"a\u007fb","caa_domains":[]}`, "-", nil},
		{"non-ASCII", `{"friendly_name":"Sectigo é","caa_domains":[]}`, "-", nil},
		{"order lower unique", `{"friendly_name":"X","caa_domains":["sectigo.com","Comodo.COM","ca.test","COMODO.com"]}`, "X", []string{"ca.test", "comodo.com", "sectigo.com"}},
		{"outside the grammar dropped", `{"friendly_name":"X","caa_domains":["ok.test","bad name","-a.test","a-.test","a..test","","a.test.","ca_x.test","ü.test",".test","a.","a b.test"," a.test","a.test ","a--b.test","9.test"]}`,
			"X", []string{"9.test", "a--b.test", "ok.test"}},
		{"all dropped", `{"caa_domains":["bad name","a.test."]}`, "-", nil},
		{"null dropped", `{"caa_domains":[null,"a.test",null]}`, "-", []string{"a.test"}},
		{"16 entries", `{"caa_domains":` + crtCAAList(16) + `}`, "-", nil},
	}
	for _, tc := range cases {
		got := crtOne(t, map[string]string{"issuer": tc.issuer})
		want := tc.wantCAA
		if tc.name == "16 entries" {
			want = nil
			for i := 0; i < 16; i++ {
				want = append(want, fmt.Sprintf("ca%d.test", i))
			}
			slices.Sort(want)
		}
		if got.Issuer.Name != tc.wantName || !slices.Equal(got.Issuer.CAA, want) {
			t.Errorf("%s: issuer %q %q; want %q %q", tc.name, got.Issuer.Name, got.Issuer.CAA, tc.wantName, want)
		}
	}
}

func TestParseIssuerFriendlyNameIsTheShortName(t *testing.T) {
	// "name" holds a distinguished name that is not read.
	got := crtOne(t, map[string]string{"issuer": `{"name":"C=GB, O=Sectigo","friendly_name":"Sectigo","caa_domains":[]}`})
	if got.Issuer.Name != "Sectigo" {
		t.Errorf("issuer name %q, want Sectigo", got.Issuer.Name)
	}
	got = crtOne(t, map[string]string{"issuer": `{"name":"C=GB, O=Sectigo","caa_domains":[]}`})
	if got.Issuer.Name != "-" {
		t.Errorf("issuer name %q, want -", got.Issuer.Name)
	}
}

func TestParseKeepsPageOrderAndSameTBS(t *testing.T) {
	a := crtObj(map[string]string{"id": `"3"`})
	b := crtObj(map[string]string{"id": `"4"`}) // the same TBS as a
	c := crtObj(map[string]string{"id": `"20"`, "tbs_sha256": `"` + strings.Repeat("b", 64) + `"`})
	got, err := certlog.Parse(crtArray(a, b, c))
	if err != nil || len(got) != 3 || got[0].ID != "3" || got[1].ID != "4" || got[2].ID != "20" {
		t.Fatalf("Parse: %+v, %v; want the three issuances in page order", got, err)
	}
}

func TestParseCapture(t *testing.T) {
	body, err := os.ReadFile("testdata/example-com.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := certlog.Parse(body)
	if err != nil || len(got) != 17 {
		t.Fatalf("Parse: %d issuances, %v; want 17", len(got), err)
	}
	if got[0].ID != "12809115180" || got[16].ID != "17893609773" {
		t.Errorf("first and last id %s %s", got[0].ID, got[16].ID)
	}
}

var crtIDRE = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
var crtTBSRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var crtCAARE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

func crtIDLess(a, b string) bool { return len(a) < len(b) || len(a) == len(b) && a < b }

func FuzzParse(f *testing.F) {
	if body, err := os.ReadFile("testdata/example-com.json"); err == nil {
		f.Add(body)
	}
	f.Add(crtArray(crtObj(nil)))
	f.Add(crtArray(crtObj(nil), crtObj(map[string]string{"id": `"2"`, "dns_names": `["*.a.test","A.test.",null,"x_y"]`})))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"a":1}`))
	f.Add(crtArray(crtObj(map[string]string{"issuer": `{"friendly_name":"é","caa_domains":["A.b",null,"c d"]}`})))
	f.Fuzz(func(t *testing.T, body []byte) {
		got, err := certlog.Parse(body)
		if err != nil {
			if len(got) != 0 {
				t.Fatalf("an error and %d issuances", len(got))
			}
			return
		}
		if len(got) > certlog.MaxPage {
			t.Fatalf("%d issuances", len(got))
		}
		for i, in := range got {
			if !crtIDRE.MatchString(in.ID) || i > 0 && !crtIDLess(got[i-1].ID, in.ID) {
				t.Fatalf("issuance %d: id %q after %q", i, in.ID, got[max(i-1, 0)].ID)
			}
			if !crtTBSRE.MatchString(in.TBS) {
				t.Fatalf("issuance %d: tbs %q", i, in.TBS)
			}
			if !in.NotAfter.After(in.NotBefore) {
				t.Fatalf("issuance %d: %v not after %v", i, in.NotAfter, in.NotBefore)
			}
			if len(in.Names) > certlog.MaxNames || in.Unread < 0 {
				t.Fatalf("issuance %d: %d names, %d unread", i, len(in.Names), in.Unread)
			}
			for j, n := range in.Names {
				if j > 0 && dnswire.Compare(in.Names[j-1], n) >= 0 {
					t.Fatalf("issuance %d: names %v and %v are not sorted and unique", i, in.Names[j-1], n)
				}
				if back, ok := certlog.Name(n.String()); !ok || !back.Equal(n) || n.String() != strings.ToLower(n.String()) {
					t.Fatalf("issuance %d: name %v is not one that Name reads", i, n)
				}
			}
			if len(in.Issuer.Name) < 1 || len(in.Issuer.Name) > 64 || strings.ContainsFunc(in.Issuer.Name, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
				t.Fatalf("issuance %d: issuer name %q", i, in.Issuer.Name)
			}
			if len(in.Issuer.CAA) > certlog.MaxCAA || !slices.IsSorted(in.Issuer.CAA) || len(slices.Compact(slices.Clone(in.Issuer.CAA))) != len(in.Issuer.CAA) {
				t.Fatalf("issuance %d: CAA names %q", i, in.Issuer.CAA)
			}
			for _, c := range in.Issuer.CAA {
				if !crtCAARE.MatchString(c) {
					t.Fatalf("issuance %d: CAA name %q", i, c)
				}
			}
		}
	})
}
