package certlog_test

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/certlog"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// TestRecordedCertificatesFixture reads a real answer of the certificate
// source for example.com, recorded on 17 Nov 2026 at 12:34:22Z, and judges it
// against a small file. The expected findings are written out from the
// recording by hand.
func TestRecordedCertificatesFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/example-com.json")
	if err != nil {
		t.Fatal(err)
	}
	fileText, err := os.ReadFile("testdata/example-com.expect")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 17, 12, 34, 22, 0, time.UTC)

	issuances, err := certlog.Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	crtCheckRecording(t, issuances)

	var valid []obs.Issuance
	for _, in := range issuances {
		if in.NotAfter.After(now) {
			valid = append(valid, in)
		}
	}
	if len(valid) != 17 {
		t.Fatalf("%d issuances are valid at the time of the request, want 17", len(valid))
	}
	domain := crtName(t, "example.com.")
	c := obs.Certificates{Key: obs.CertificatesKey(domain), Start: now, Usable: true, Asked: true, Complete: true, Issuances: valid}
	f, err := expect.Parse(fileText)
	if err != nil {
		t.Fatalf("the expectations file: %v", err)
	}

	got := decide.CertificateFindings(f, c)
	type want struct {
		rule     decide.Rule
		severity decide.Severity
		expected string
		seen     []string
	}
	wants := []want{
		{decide.RuleIssuer, decide.SeverityHigh, `example.com. CAA 0 issue "sectigo.com"`, []string{
			"*.example.com. from ssl.com",
			"emudhra-lab.example.com. from emsign.com",
			"example.com. from ssl.com",
		}},
		{decide.RuleCertName, decide.SeverityHigh, "", []string{"*.example.com."}},
		{decide.RuleHostnames, decide.SeverityLow, "", []string{"emudhra-lab.example.com.", "www.example.com."}},
	}
	if len(got) != len(wants) {
		t.Fatalf("%d findings, want %d: %+v", len(got), len(wants), got)
	}
	for i, w := range wants {
		g := got[i]
		var texts []string
		for _, s := range g.Seen {
			texts = append(texts, s.Text)
			zero := s.Answer
			zero.Received = time.Time{}
			if !s.Answer.Received.Equal(now) || !zero.Sent.IsZero() || zero.Wire != nil || zero.Server.Addr.IsValid() || zero.TCP {
				t.Errorf("%v: Seen %q holds an answer %+v, want only Received = the start of the run", w.rule, s.Text, s.Answer)
			}
		}
		if g.Rule != w.rule || g.Severity != w.severity || g.Expected != w.expected || !slices.Equal(texts, w.seen) ||
			g.Value != strings.Join(w.seen, "\n") || g.Check.String() != "certificates example.com." || g.Check.Kind != obs.KindCertificates {
			t.Errorf("finding %d: rule %v, severity %v, check %v, expected %q, seen %q, value %q\nwant rule %v, severity %v, expected %q, seen %q",
				i, g.Rule, g.Severity, g.Check, g.Expected, texts, g.Value, w.rule, w.severity, w.expected, w.seen)
		}
	}

	// A file of another domain covers nothing, and no file gives nothing.
	other, err := expect.Parse([]byte("domain example.net.\nexample.net. A 192.0.2.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if g := decide.CertificateFindings(other, c); len(g) != 0 {
		t.Errorf("a file of another domain gives %+v", g)
	}
	if g := decide.CertificateFindings(nil, c); len(g) != 0 {
		t.Errorf("no file gives %+v", g)
	}
	// Judged by the file of its own domain only, a run with no issuance gives nothing.
	c.Issuances = nil
	if g := decide.CertificateFindings(f, c); len(g) != 0 {
		t.Errorf("no issuance gives %+v", g)
	}
}

// crtCheckRecording checks what Parse reads from the recording against the
// JSON, read by hand: the 17 issuances in order, with their names (in
// canonical order, the top label first), authorities and end dates.
func crtCheckRecording(t *testing.T, got []obs.Issuance) {
	t.Helper()
	sectigo := []string{"affirmtrust.com", "comodo.com", "comodoca.com", "entrust.net", "sectigo.com", "trust-provider.com", "usertrust.com"}
	twins := []string{"example.com.", "example.edu.", "example.net.", "example.org."}
	twinsWWW := []string{"example.com.", "www.example.com.", "example.edu.", "www.example.edu.", "example.net.", "www.example.net.", "example.org.", "www.example.org."}
	wild := []string{"example.com.", "*.example.com."}
	lab := []string{"emudhra-lab.example.com."}
	rows := []struct {
		id, issuer string
		caa, names []string
		notAfter   string
	}{
		{"12809115180", "Sectigo", sectigo, twins, "2026-11-20T23:59:59Z"},
		{"12822827438", "Sectigo", sectigo, twinsWWW, "2026-11-21T23:59:59Z"},
		{"12937142056", "Sectigo", sectigo, twinsWWW, "2026-12-02T23:59:59Z"},
		{"17232708246", "Sectigo", sectigo, wild, "2026-12-13T21:47:42Z"},
		{"17383412688", "Sectigo", sectigo, wild, "2026-12-21T09:32:54Z"},
		{"17433287100", "SSL.com", []string{"ssl.com"}, wild, "2026-12-25T22:43:19Z"},
		{"17433287993", "SSL.com", []string{"ssl.com"}, wild, "2026-12-25T22:43:20Z"},
		{"17433445379", "SSL.com", []string{"ssl.com"}, wild, "2026-12-25T22:56:35Z"},
		{"17433446883", "SSL.com", []string{"ssl.com"}, wild, "2026-12-25T22:56:35Z"},
		{"17893124858", "emSign", []string{"emsign.com"}, lab, "2027-05-03T20:27:24Z"},
		{"17893446547", "emSign", []string{"emsign.com"}, lab, "2027-01-18T19:58:47Z"},
		{"17893546019", "emSign", []string{"emsign.com"}, lab, "2027-05-03T21:15:44Z"},
		{"17893562952", "emSign", []string{"emsign.com"}, lab, "2027-05-03T20:53:14Z"},
		{"17893563094", "emSign", []string{"emsign.com"}, lab, "2027-05-03T20:53:15Z"},
		{"17893563159", "emSign", []string{"emsign.com"}, lab, "2027-05-03T20:53:18Z"},
		{"17893563374", "emSign", []string{"emsign.com"}, lab, "2027-05-03T20:53:17Z"},
		{"17893609773", "emSign", []string{"emsign.com"}, lab, "2027-08-01T21:19:03Z"},
	}
	if len(got) != len(rows) {
		t.Fatalf("%d issuances, want %d", len(got), len(rows))
	}
	tbs := map[string]bool{}
	for i, r := range rows {
		in := got[i]
		na, err := time.Parse(time.RFC3339, r.notAfter)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, n := range in.Names {
			names = append(names, n.String())
		}
		if in.ID != r.id || in.Issuer.Name != r.issuer || !slices.Equal(in.Issuer.CAA, r.caa) || !slices.Equal(names, r.names) ||
			in.Unread != 0 || !in.NotAfter.Equal(na) || !in.NotAfter.After(in.NotBefore) {
			t.Errorf("issuance %d: id %s, issuer %q %q, names %q, unread %d, not after %v; want id %s, issuer %q %q, names %q, not after %s",
				i, in.ID, in.Issuer.Name, in.Issuer.CAA, names, in.Unread, in.NotAfter, r.id, r.issuer, r.caa, r.names, r.notAfter)
		}
		tbs[in.TBS] = true
	}
	if len(tbs) != 17 {
		t.Errorf("%d distinct TBS, want 17", len(tbs))
	}
	if got[0].TBS != "a7781bc044f9e19ba8009c0299b404f3816642d5185ed73bae6c05e8f7fa9d35" ||
		got[16].TBS != "52ca63be7dbfd34cf906fc5b42443f605896877926d9081abcf7ef03139260d0" {
		t.Errorf("first and last TBS %s %s", got[0].TBS, got[16].TBS)
	}
	if first := got[0]; !first.NotBefore.Equal(time.Date(2025, 11, 20, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("first not_before %v", first.NotBefore)
	}
}
