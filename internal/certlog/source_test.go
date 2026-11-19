package certlog_test

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/certlog"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

var crtT0 = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

const (
	crtBase  = "https://certs.test/v1/issuances"
	crtQuery = "?domain=corp.test&include_subdomains=true&expand=dns_names&expand=issuer&expand=issuer.caa_domains"
)

type crtReply struct {
	resp httpclient.Response
	err  error
}

type crtCall struct {
	ctx     context.Context
	url     string
	limit   int64
	headers []httpclient.Header
}

// crtGetter plays the source: it answers the scripted replies in order and
// fails every request after them.
type crtGetter struct {
	replies []crtReply
	calls   []crtCall
	last    crtReply // the reply given last
}

func (g *crtGetter) Get(ctx context.Context, rawURL string, limit int64, headers ...httpclient.Header) (httpclient.Response, error) {
	g.calls = append(g.calls, crtCall{ctx, rawURL, limit, headers})
	if len(g.replies) == 0 {
		return httpclient.Response{}, errors.New("no reply scripted")
	}
	r := g.replies[0]
	g.last = r
	g.replies = g.replies[1:]
	return r.resp, r.err
}

// take gives the URLs asked since the last call.
func (g *crtGetter) take() []string {
	var urls []string
	for _, c := range g.calls {
		urls = append(urls, c.url)
	}
	g.calls = nil
	return urls
}

func (g *crtGetter) script(r ...crtReply) { g.replies = append(g.replies, r...) }

func crtPageReply(objs ...string) crtReply {
	return crtReply{resp: httpclient.Response{Status: 200, Body: crtArray(objs...)}}
}

func crtEmpty(retry time.Duration) crtReply {
	return crtReply{resp: httpclient.Response{Status: 200, Body: []byte("[]"), RetryAfter: retry}}
}

func crtStatus(status int, retry time.Duration) crtReply {
	return crtReply{resp: httpclient.Response{Status: status, Body: []byte(`{"code":"x"}`), RetryAfter: retry}}
}

func crtErr(err error) crtReply { return crtReply{err: err} }

func crtTime(t time.Time) string { return `"` + t.Format(time.RFC3339) + `"` }

// crtIss is the issuance with this id, whose TBS is made from seed.
func crtIss(id, seed int, na time.Time) string {
	return crtObj(map[string]string{
		"id": `"` + strconv.Itoa(id) + `"`, "tbs_sha256": fmt.Sprintf(`"%064x"`, seed),
		"not_before": crtTime(na.Add(-24 * time.Hour)), "not_after": crtTime(na),
		"dns_names": `["www.corp.test"]`,
	})
}

func crtLong(id int) string { return crtIss(id, id, crtT0.Add(90*24*time.Hour)) }

func crtName(t *testing.T, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func crtSource(t *testing.T, g *crtGetter, key string) *certlog.Source {
	return certlog.New(g, crtBase, key, crtName(t, "corp.test."))
}

type crtWant struct {
	usable, asked, complete bool
	failure                 string
	ids                     []string
}

func crtIDsOf(c obs.Certificates) []string {
	var ids []string
	for _, in := range c.Issuances {
		ids = append(ids, in.ID)
	}
	return ids
}

func crtCheck(t *testing.T, label string, got obs.Certificates, start time.Time, w crtWant) {
	t.Helper()
	if got.Key.Kind != obs.KindCertificates || got.Key.String() != "certificates corp.test." || got.Key.Type != 0 ||
		!got.Key.Domain.Equal(crtName(t, "corp.test.")) || !got.Key.Name.Equal(crtName(t, "corp.test.")) {
		t.Errorf("%s: key %v", label, got.Key)
	}
	if !got.Start.Equal(start) {
		t.Errorf("%s: start %v, want %v", label, got.Start, start)
	}
	if got.Usable != w.usable || got.Asked != w.asked || got.Complete != w.complete || got.Failure != w.failure ||
		!slices.Equal(crtIDsOf(got), w.ids) {
		t.Errorf("%s: usable %v, asked %v, complete %v, failure %q, ids %q; want usable %v, asked %v, complete %v, failure %q, ids %q",
			label, got.Usable, got.Asked, got.Complete, got.Failure, crtIDsOf(got), w.usable, w.asked, w.complete, w.failure, w.ids)
	}
}

func crtURLs(t *testing.T, label string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s: requests %q, want %q", label, got, want)
	}
}

func TestRunPagesUrlsAndHeaders(t *testing.T) {
	if certlog.DefaultURL != "https://api.certspotter.com/v1/issuances" {
		t.Errorf("DefaultURL %q", certlog.DefaultURL)
	}
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "mine")
	for _, key := range []string{"", "k3y"} {
		g := &crtGetter{}
		g.script(crtPageReply(crtLong(1), crtLong(2)), crtPageReply(crtLong(5)), crtEmpty(0))
		got := crtSource(t, g, key).Run(ctx, crtT0)
		for i, c := range g.calls {
			var want []httpclient.Header
			if key != "" {
				want = []httpclient.Header{{Name: "Authorization", Value: "Bearer k3y"}}
			}
			if !slices.Equal(c.headers, want) || c.limit != 4194304 || c.ctx.Value(ctxKey{}) != "mine" {
				t.Errorf("key %q, request %d: headers %v, limit %d, context value %v", key, i, c.headers, c.limit, c.ctx.Value(ctxKey{}))
			}
		}
		crtURLs(t, "key "+key, g.take(), []string{
			crtBase + crtQuery,
			crtBase + crtQuery + "&after=2",
			crtBase + crtQuery + "&after=5",
		})
		crtCheck(t, "key "+key, got, crtT0, crtWant{usable: true, asked: true, complete: true, ids: []string{"1", "2", "5"}})
	}
}

func TestRunDomainInTheURL(t *testing.T) {
	for _, tc := range []struct{ domain, want string }{
		{"corp.test.", "corp.test"},
		{"Corp.TEST.", "corp.test"},
		{"corp.test", "corp.test"},
		{"a&b+c=d.test.", "a%26b%2Bc%3Dd.test"},
		{"a#b?c%d.test.", "a%23b%3Fc%25d.test"},
		{"xn--bcher-kva.test.", "xn--bcher-kva.test"},
	} {
		g := &crtGetter{}
		g.script(crtEmpty(0))
		certlog.New(g, "https://h.test:8443/v1/x", "", crtName(t, tc.domain)).Run(context.Background(), crtT0)
		want := "https://h.test:8443/v1/x?domain=" + tc.want + "&include_subdomains=true&expand=dns_names&expand=issuer&expand=issuer.caa_domains"
		crtURLs(t, tc.domain, g.take(), []string{want})
	}
}

func TestRunKeyIsNeverInTheResult(t *testing.T) {
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(1)), crtStatus(500, 0))
	got := crtSource(t, g, "SECRETKEY").Run(context.Background(), crtT0)
	if text := fmt.Sprintf("%+v", got); strings.Contains(text, "SECRETKEY") {
		t.Errorf("the result holds the key: %s", text)
	}
}

func TestRunResultOfOneFirstPage(t *testing.T) {
	g := &crtGetter{}
	g.script(crtReply{resp: httpclient.Response{Status: 200, Body: crtArray(crtObj(map[string]string{
		"id": `"7"`, "not_after": crtTime(crtT0.Add(time.Hour)), "not_before": crtTime(crtT0.Add(-time.Hour)),
		"dns_names": `["b.corp.test","A.corp.test."]`,
		"issuer":    `{"friendly_name":"Lab CA","caa_domains":["Ca.test"]}`,
	}))}}, crtEmpty(0))
	got := crtSource(t, g, "").Run(context.Background(), crtT0)
	crtCheck(t, "run", got, crtT0, crtWant{usable: true, asked: true, complete: true, ids: []string{"7"}})
	in := got.Issuances[0]
	if in.TBS != crtTBS || !slices.Equal(crtNames(t, in), []string{"a.corp.test.", "b.corp.test."}) || in.Issuer.Name != "Lab CA" ||
		!slices.Equal(in.Issuer.CAA, []string{"ca.test"}) || !in.NotAfter.Equal(crtT0.Add(time.Hour)) {
		t.Errorf("issuance %+v", in)
	}
}

// After an empty page the source's Retry-After sets the gap, cut at one hour,
// and a run inside it is usable and asks nothing.
func TestRunWaitAfterAnEmptyPage(t *testing.T) {
	s := time.Second
	for _, tc := range []struct {
		retry time.Duration
		// the starts of the second run, and whether each asks
		no  []time.Duration
		yes time.Duration
	}{
		{0, nil, 0},
		{10 * s, []time.Duration{0, 9 * s}, 10 * s},
		{1800 * s, []time.Duration{1799 * s}, 1800 * s},
		{3599 * s, []time.Duration{3598 * s}, 3599 * s},
		{3600 * s, []time.Duration{3599 * s}, 3600 * s},
		{3601 * s, []time.Duration{3599 * s}, 3600 * s},
		{7200 * s, []time.Duration{1800 * s, 3599 * s}, 3600 * s},
		{86400 * s, []time.Duration{3599 * s}, 3600 * s},
	} {
		label := fmt.Sprintf("Retry-After %v", tc.retry)
		for _, later := range tc.no {
			g := &crtGetter{}
			g.script(crtPageReply(crtLong(1)), crtEmpty(tc.retry))
			src := crtSource(t, g, "")
			crtCheck(t, label, src.Run(context.Background(), crtT0), crtT0, crtWant{usable: true, asked: true, complete: true, ids: []string{"1"}})
			g.take()
			got := src.Run(context.Background(), crtT0.Add(later))
			crtURLs(t, label+" inside", g.take(), nil)
			crtCheck(t, label+" inside at +"+later.String(), got, crtT0.Add(later), crtWant{usable: true, complete: true, ids: []string{"1"}})
		}
		g := &crtGetter{}
		g.script(crtPageReply(crtLong(1)), crtEmpty(tc.retry), crtEmpty(0))
		src := crtSource(t, g, "")
		src.Run(context.Background(), crtT0)
		g.take()
		got := src.Run(context.Background(), crtT0.Add(tc.yes))
		crtURLs(t, label+" at the end", g.take(), []string{crtBase + crtQuery + "&after=1"})
		crtCheck(t, label+" at the end", got, crtT0.Add(tc.yes), crtWant{usable: true, asked: true, complete: true, ids: []string{"1"}})
	}
}

// After a 429 the wait is kept whole, and a run inside it is not usable.
func TestRunWaitAfterTooManyRequests(t *testing.T) {
	s := time.Second
	for _, tc := range []struct {
		retry time.Duration
		no    []time.Duration
		yes   time.Duration
	}{
		{0, nil, 0},
		{1 * s, []time.Duration{0}, 1 * s},
		{60 * s, []time.Duration{1 * s, 59 * s}, 60 * s},
		{3600 * s, []time.Duration{3599 * s}, 3600 * s},
		{3601 * s, []time.Duration{3600 * s}, 3601 * s},
		{7200 * s, []time.Duration{3601 * s, 7199 * s}, 7200 * s},
		{86400 * s, []time.Duration{3601 * s, 86399 * s}, 86400 * s},
	} {
		label := fmt.Sprintf("429 with Retry-After %v", tc.retry)
		for _, later := range tc.no {
			g := &crtGetter{}
			g.script(crtPageReply(crtLong(1), crtLong(2)), crtStatus(429, tc.retry))
			src := crtSource(t, g, "")
			crtCheck(t, label, src.Run(context.Background(), crtT0), crtT0,
				crtWant{asked: true, failure: "rate-limited", ids: []string{"1", "2"}})
			crtURLs(t, label, g.take(), []string{crtBase + crtQuery, crtBase + crtQuery + "&after=2"})
			got := src.Run(context.Background(), crtT0.Add(later))
			crtURLs(t, label+" inside", g.take(), nil)
			crtCheck(t, label+" inside at +"+later.String(), got, crtT0.Add(later),
				crtWant{failure: "rate-limited", ids: []string{"1", "2"}})
		}
		g := &crtGetter{}
		g.script(crtPageReply(crtLong(1), crtLong(2)), crtStatus(429, tc.retry), crtPageReply(crtLong(3)), crtEmpty(0))
		src := crtSource(t, g, "")
		src.Run(context.Background(), crtT0)
		g.take()
		got := src.Run(context.Background(), crtT0.Add(tc.yes))
		// The listing is not complete, so even after 24 hours no relist
		// starts it again.
		crtURLs(t, label+" at the end", g.take(), []string{crtBase + crtQuery + "&after=2", crtBase + crtQuery + "&after=3"})
		crtCheck(t, label+" at the end", got, crtT0.Add(tc.yes),
			crtWant{usable: true, asked: true, complete: true, ids: []string{"1", "2", "3"}})
	}
}

// The wait is measured from the start of the run that got the answer, not
// from the start of a run before or after it.
func TestRunWaitCountsFromTheRunThatGotIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply crtReply
		want  crtWant
	}{
		{"empty page", crtEmpty(60 * time.Second), crtWant{usable: true, complete: true}},
		{"429", crtStatus(429, 60*time.Second), crtWant{failure: "rate-limited"}},
		{"503", crtStatus(503, 60*time.Second), crtWant{failure: "rate-limited"}},
	} {
		g := &crtGetter{}
		g.script(tc.reply, crtEmpty(0))
		src := crtSource(t, g, "")
		late := crtT0.Add(100 * time.Second)
		src.Run(context.Background(), late) // the wait ends at late + 60 s
		g.take()
		for _, d := range []time.Duration{-50 * time.Second, 0, 59 * time.Second} {
			got := src.Run(context.Background(), late.Add(d))
			crtURLs(t, tc.name, g.take(), nil)
			crtCheck(t, fmt.Sprintf("%s at %v", tc.name, d), got, late.Add(d), tc.want)
		}
		got := src.Run(context.Background(), late.Add(60*time.Second))
		crtURLs(t, tc.name+" at the end", g.take(), []string{crtBase + crtQuery})
		crtCheck(t, tc.name+" at the end", got, late.Add(60*time.Second), crtWant{usable: true, asked: true, complete: true})
	}
}

// A page with issuances sets no wait, whatever Retry-After says.
func TestRunPageWithIssuancesSetsNoWait(t *testing.T) {
	g := &crtGetter{}
	page := crtPageReply(crtLong(1))
	page.resp.RetryAfter = time.Hour
	g.script(page, crtEmpty(0), crtEmpty(0))
	src := crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	g.take()
	got := src.Run(context.Background(), crtT0.Add(time.Second))
	crtURLs(t, "later run", g.take(), []string{crtBase + crtQuery + "&after=1"})
	crtCheck(t, "later run", got, crtT0.Add(time.Second), crtWant{usable: true, asked: true, complete: true, ids: []string{"1"}})
}

// The last answer decides whether a run inside the wait is usable.
func TestRunWaitFollowsTheLastAnswer(t *testing.T) {
	s := time.Second
	g := &crtGetter{}
	g.script(crtEmpty(100*s), crtStatus(503, 30*s), crtEmpty(50*s), crtEmpty(0))
	src := crtSource(t, g, "")
	steps := []struct {
		at   time.Duration
		asks bool
		want crtWant
	}{
		{0, true, crtWant{usable: true, asked: true, complete: true}},
		{99 * s, false, crtWant{usable: true, complete: true}},
		{100 * s, true, crtWant{asked: true, complete: true, failure: "status 503"}},
		{110 * s, false, crtWant{complete: true, failure: "rate-limited"}},
		{129 * s, false, crtWant{complete: true, failure: "rate-limited"}},
		{130 * s, true, crtWant{usable: true, asked: true, complete: true}},
		{179 * s, false, crtWant{usable: true, complete: true}},
		{180 * s, true, crtWant{usable: true, asked: true, complete: true}},
	}
	for _, st := range steps {
		got := src.Run(context.Background(), crtT0.Add(st.at))
		if n := len(g.take()); (n > 0) != st.asks {
			t.Errorf("at +%v: %d requests, want asks %v", st.at, n, st.asks)
		}
		crtCheck(t, fmt.Sprintf("at +%v", st.at), got, crtT0.Add(st.at), st.want)
	}
}

func TestRunFailureWords(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply crtReply
		want  string
	}{
		{"timeout", crtErr(httpclient.ErrTimeout), "timeout"},
		{"too large", crtErr(httpclient.ErrTooLarge), "too large"},
		{"host", crtErr(httpclient.ErrHost), "network"},
		{"url", crtErr(httpclient.ErrURL), "network"},
		{"other", crtErr(errors.New("network: cannot connect")), "network"},
		{"canceled", crtErr(context.Canceled), "network"},
		{"429", crtStatus(429, 0), "rate-limited"},
		{"500", crtStatus(500, 0), "status 500"},
		{"502", crtStatus(502, 0), "status 502"},
		{"503", crtStatus(503, 0), "status 503"},
		{"404", crtStatus(404, 0), "status 404"},
		{"403", crtStatus(403, 0), "status 403"},
		{"401", crtStatus(401, 0), "status 401"},
		{"402", crtStatus(402, 0), "status 402"},
		{"301", crtStatus(301, 0), "status 301"},
		{"204", crtStatus(204, 0), "status 204"},
		{"201", crtStatus(201, 0), "status 201"},
		{"199", crtStatus(199, 0), "status 199"},
		{"malformed object", crtReply{resp: httpclient.Response{Status: 200, Body: []byte(`{}`)}}, "malformed"},
		{"malformed empty", crtReply{resp: httpclient.Response{Status: 200}}, "malformed"},
		{"malformed junk", crtReply{resp: httpclient.Response{Status: 200, Body: []byte(`[{"id":`)}}, "malformed"},
		{"malformed element", crtReply{resp: httpclient.Response{Status: 200, Body: crtArray(crtObj(map[string]string{"issuer": "-"}))}}, "malformed"},
		{"ids not increasing", crtPageReply(crtLong(7), crtLong(5)), "malformed"},
		{"same id twice", crtPageReply(crtLong(7), crtIss(7, 70, crtT0.Add(time.Hour))), "malformed"},
	} {
		// The failure comes after a good page, whose issuances stay known.
		g := &crtGetter{}
		g.script(crtPageReply(crtLong(1), crtLong(2)), tc.reply, crtPageReply(crtLong(3)), crtEmpty(0))
		src := crtSource(t, g, "")
		got := src.Run(context.Background(), crtT0)
		crtCheck(t, tc.name, got, crtT0, crtWant{asked: true, failure: tc.want, ids: []string{"1", "2"}})
		crtURLs(t, tc.name, g.take(), []string{crtBase + crtQuery, crtBase + crtQuery + "&after=2"})
		// No wait: the next run asks at once, from the same cursor.
		got = src.Run(context.Background(), crtT0.Add(time.Second))
		crtURLs(t, tc.name+" next", g.take(), []string{crtBase + crtQuery + "&after=2", crtBase + crtQuery + "&after=3"})
		crtCheck(t, tc.name+" next", got, crtT0.Add(time.Second), crtWant{usable: true, asked: true, complete: true, ids: []string{"1", "2", "3"}})
	}
}

// A status other than 200 with a Retry-After sets a wait that is not usable;
// without one it sets none. The body of such an answer is never read.
func TestRunStatusWithRetryAfter(t *testing.T) {
	for _, status := range []int{500, 502, 503, 404, 301} {
		g := &crtGetter{}
		bad := crtStatus(status, 45*time.Second)
		bad.resp.Body = crtArray(crtLong(9))
		g.script(bad, crtEmpty(0))
		src := crtSource(t, g, "")
		label := fmt.Sprint(status)
		crtCheck(t, label, src.Run(context.Background(), crtT0), crtT0, crtWant{asked: true, failure: "status " + label})
		g.take()
		crtCheck(t, label+" inside", src.Run(context.Background(), crtT0.Add(44*time.Second)), crtT0.Add(44*time.Second), crtWant{failure: "rate-limited"})
		crtURLs(t, label+" inside", g.take(), nil)
		crtCheck(t, label+" at the end", src.Run(context.Background(), crtT0.Add(45*time.Second)), crtT0.Add(45*time.Second),
			crtWant{usable: true, asked: true, complete: true})
	}
}

// A failure after a complete listing leaves it complete and known.
func TestRunFailureKeepsWhatIsKnown(t *testing.T) {
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(1)), crtEmpty(0), crtStatus(500, 0), crtErr(httpclient.ErrTimeout))
	src := crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	crtCheck(t, "500", src.Run(context.Background(), crtT0.Add(time.Second)), crtT0.Add(time.Second),
		crtWant{asked: true, complete: true, failure: "status 500", ids: []string{"1"}})
	crtCheck(t, "timeout", src.Run(context.Background(), crtT0.Add(2*time.Second)), crtT0.Add(2*time.Second),
		crtWant{asked: true, complete: true, failure: "timeout", ids: []string{"1"}})
}

// An empty page is the end; a page that holds issuances, all skipped, is not.
func TestRunSkippedPageIsNotTheEnd(t *testing.T) {
	g := &crtGetter{}
	expired := crtIss(1, 1, crtT0.Add(-time.Hour))
	g.script(crtPageReply(expired), crtStatus(500, 0))
	got := crtSource(t, g, "").Run(context.Background(), crtT0)
	crtCheck(t, "run", got, crtT0, crtWant{asked: true, failure: "status 500"})
	crtURLs(t, "run", g.take(), []string{crtBase + crtQuery, crtBase + crtQuery + "&after=1"})
}

// Ids are compared as numbers, however long.
func TestRunComparesIDsAsNumbers(t *testing.T) {
	g := &crtGetter{}
	hour := crtT0.Add(time.Hour)
	obj := func(id string, seed int) string {
		return crtObj(map[string]string{"id": `"` + id + `"`, "tbs_sha256": fmt.Sprintf(`"%064x"`, seed),
			"not_before": crtTime(crtT0), "not_after": crtTime(hour)})
	}
	g.script(
		crtPageReply(obj("9", 1)), crtPageReply(obj("10", 2)), crtPageReply(obj("99", 3)), crtPageReply(obj("100", 4)),
		crtPageReply(obj("18446744073709551615", 5)), crtPageReply(obj("18446744073709551616", 6)),
		crtPageReply(obj("99999999999999999999", 7)), crtEmpty(0),
	)
	got := crtSource(t, g, "").Run(context.Background(), crtT0)
	crtURLs(t, "run", g.take(), []string{
		crtBase + crtQuery, crtBase + crtQuery + "&after=9", crtBase + crtQuery + "&after=10", crtBase + crtQuery + "&after=99",
		crtBase + crtQuery + "&after=100", crtBase + crtQuery + "&after=18446744073709551615",
		crtBase + crtQuery + "&after=18446744073709551616", crtBase + crtQuery + "&after=99999999999999999999",
	})
	crtCheck(t, "run", got, crtT0, crtWant{usable: true, asked: true, complete: true,
		ids: []string{"9", "10", "99", "100", "18446744073709551615", "18446744073709551616", "99999999999999999999"}})
}

// The first TBS kept wins; later ones are skipped, in the same run or not.
func TestRunKnownTBS(t *testing.T) {
	g := &crtGetter{}
	hour := crtT0.Add(time.Hour)
	g.script(
		crtPageReply(crtIss(3, 33, hour), crtIss(4, 44, hour)),
		crtPageReply(crtIss(5, 33, hour)),
		crtEmpty(0),
		crtPageReply(crtIss(6, 44, hour), crtIss(7, 77, hour)),
		crtEmpty(0),
	)
	src := crtSource(t, g, "")
	crtCheck(t, "first", src.Run(context.Background(), crtT0), crtT0, crtWant{usable: true, asked: true, complete: true, ids: []string{"3", "4"}})
	crtCheck(t, "second", src.Run(context.Background(), crtT0.Add(time.Second)), crtT0.Add(time.Second),
		crtWant{usable: true, asked: true, complete: true, ids: []string{"3", "4", "7"}})
}

func TestRunExpiryEndsIssuancesEvenInsideAWait(t *testing.T) {
	s := time.Second
	g := &crtGetter{}
	g.script(crtPageReply(crtIss(1, 1, crtT0.Add(10*s)), crtIss(2, 2, crtT0.Add(20*s)), crtIss(3, 3, crtT0.Add(time.Hour))), crtEmpty(3600*s))
	src := crtSource(t, g, "")
	crtCheck(t, "first", src.Run(context.Background(), crtT0), crtT0, crtWant{usable: true, asked: true, complete: true, ids: []string{"1", "2", "3"}})
	for _, st := range []struct {
		at  time.Duration
		ids []string
	}{{9 * s, []string{"1", "2", "3"}}, {10 * s, []string{"2", "3"}}, {19 * s, []string{"2", "3"}}, {20 * s, []string{"3"}}, {3599 * s, []string{"3"}}} {
		got := src.Run(context.Background(), crtT0.Add(st.at))
		crtCheck(t, fmt.Sprintf("+%v", st.at), got, crtT0.Add(st.at), crtWant{usable: true, complete: true, ids: st.ids})
		for _, in := range got.Issuances {
			if !in.NotAfter.After(crtT0.Add(st.at)) {
				t.Errorf("+%v: issuance %s expired at %v", st.at, in.ID, in.NotAfter)
			}
		}
	}
	if n := len(g.take()); n != 2 {
		t.Errorf("%d requests, want the 2 of the first run", n)
	}
}

func TestRunMaxPages(t *testing.T) {
	var pages []crtReply
	for i := 1; i <= 11; i++ {
		pages = append(pages, crtPageReply(crtLong(i)))
	}
	g := &crtGetter{}
	g.script(pages...)
	src := crtSource(t, g, "")
	got := src.Run(context.Background(), crtT0)
	urls := g.take()
	if len(urls) != 10 || urls[9] != crtBase+crtQuery+"&after=9" {
		t.Errorf("%d requests, last %q; want 10, the last after 9", len(urls), urls[len(urls)-1])
	}
	crtCheck(t, "ten pages", got, crtT0, crtWant{usable: true, asked: true, ids: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}})

	g.script(crtEmpty(0))
	got = src.Run(context.Background(), crtT0.Add(time.Second))
	crtURLs(t, "next", g.take(), []string{crtBase + crtQuery + "&after=10", crtBase + crtQuery + "&after=11"})
	crtCheck(t, "next", got, crtT0.Add(time.Second), crtWant{usable: true, asked: true, complete: true,
		ids: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"}})

	// Nine pages and the empty one fit one run.
	g = &crtGetter{}
	g.script(pages[:9]...)
	g.script(crtEmpty(0))
	got = crtSource(t, g, "").Run(context.Background(), crtT0)
	if n := len(g.take()); n != 10 {
		t.Errorf("%d requests, want 10", n)
	}
	crtCheck(t, "nine and empty", got, crtT0, crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 9)})

	// Ten pages after a complete listing: the list is not known to be whole.
	g = &crtGetter{}
	g.script(crtPageReply(crtLong(1)), crtEmpty(0))
	src = crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	g.take()
	var more []crtReply
	for i := 2; i <= 12; i++ {
		more = append(more, crtPageReply(crtLong(i)))
	}
	g.script(more...)
	got = src.Run(context.Background(), crtT0.Add(time.Second))
	if n := len(g.take()); n != 10 {
		t.Errorf("%d requests, want 10", n)
	}
	crtCheck(t, "ten more", got, crtT0.Add(time.Second), crtWant{usable: true, asked: true, ids: crtIDRange(1, 11)})
	// A run that ends at an empty page makes it whole again.
	g.script(crtEmpty(0))
	got = src.Run(context.Background(), crtT0.Add(2*time.Second))
	crtCheck(t, "then empty", got, crtT0.Add(2*time.Second), crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 12)})
}

func crtIDRange(from, to int) []string {
	var ids []string
	for i := from; i <= to; i++ {
		ids = append(ids, strconv.Itoa(i))
	}
	return ids
}

// crtBulk is a page of issuances with ids from..to, in the smallest form.
func crtBulk(from, to int, na time.Time) crtReply {
	var b strings.Builder
	b.WriteString("[")
	for id := from; id <= to; id++ {
		if id > from {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":"%d","tbs_sha256":"%064x","not_before":%s,"not_after":%s,"dns_names":[],"issuer":{"caa_domains":[]}}`,
			id, id, crtTime(na.Add(-24*time.Hour)), crtTime(na))
	}
	b.WriteString("]")
	return crtReply{resp: httpclient.Response{Status: 200, Body: []byte(b.String())}}
}

func crtBulkSource(t *testing.T, na func(page int) time.Time) (*certlog.Source, *crtGetter, obs.Certificates) {
	g := &crtGetter{}
	for p := 0; p < 10; p++ {
		g.script(crtBulk(p*1000+1, p*1000+1000, na(p)))
	}
	src := crtSource(t, g, "")
	got := src.Run(context.Background(), crtT0)
	if n := len(g.take()); n != 10 {
		t.Fatalf("%d requests, want 10", n)
	}
	return src, g, got
}

func TestRunTenThousandKnownIsFine(t *testing.T) {
	far := func(int) time.Time { return crtT0.Add(90 * 24 * time.Hour) }
	src, g, got := crtBulkSource(t, far)
	if !got.Usable || !got.Asked || got.Complete || got.Failure != "" || len(got.Issuances) != 10000 {
		t.Fatalf("first run: usable %v, asked %v, complete %v, failure %q, %d issuances", got.Usable, got.Asked, got.Complete, got.Failure, len(got.Issuances))
	}
	g.script(crtEmpty(0))
	got = src.Run(context.Background(), crtT0.Add(time.Second))
	if !got.Usable || !got.Complete || got.Failure != "" || len(got.Issuances) != 10000 || got.Issuances[9999].ID != "10000" {
		t.Errorf("second run: usable %v, complete %v, failure %q, %d issuances", got.Usable, got.Complete, got.Failure, len(got.Issuances))
	}
	crtURLs(t, "second", g.take(), []string{crtBase + crtQuery + "&after=10000"})
}

// The count is of valid issuances: one that has expired is not counted.
func TestRunExpiredIssuancesDoNotCount(t *testing.T) {
	src, g, got := crtBulkSource(t, func(p int) time.Time {
		if p == 0 {
			return crtT0.Add(10 * time.Second)
		}
		return crtT0.Add(90 * 24 * time.Hour)
	})
	if len(got.Issuances) != 10000 {
		t.Fatalf("%d issuances", len(got.Issuances))
	}
	start := crtT0.Add(10 * time.Second)
	g.script(crtBulk(10001, 10001, crtT0.Add(90*24*time.Hour)), crtEmpty(0))
	got = src.Run(context.Background(), start)
	crtCheck(t, "after expiry", got, start, crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1001, 10001)})
}

func TestRunRestartListsAgain(t *testing.T) {
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(1), crtLong(2)), crtEmpty(3600*time.Second), crtPageReply(crtLong(1), crtLong(2)), crtEmpty(0))
	crtSource(t, g, "").Run(context.Background(), crtT0)
	g.take()
	got := crtSource(t, g, "").Run(context.Background(), crtT0.Add(time.Second))
	crtURLs(t, "restart", g.take(), []string{crtBase + crtQuery, crtBase + crtQuery + "&after=2"})
	crtCheck(t, "restart", got, crtT0.Add(time.Second), crtWant{usable: true, asked: true, complete: true, ids: []string{"1", "2"}})
}

func TestRunIsFirstListingNotComplete(t *testing.T) {
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(1)), crtStatus(500, 0))
	got := crtSource(t, g, "").Run(context.Background(), crtT0)
	if got.Complete {
		t.Error("a listing that stopped by a failure is complete")
	}
}

// The result is a copy: changing it changes nothing that the source knows.
func TestRunResultIsACopy(t *testing.T) {
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(1), crtLong(2)), crtEmpty(3600*time.Second))
	src := crtSource(t, g, "")
	got := src.Run(context.Background(), crtT0)
	got.Issuances[0] = obs.Issuance{ID: "x"}
	got.Issuances = got.Issuances[:1]
	again := src.Run(context.Background(), crtT0.Add(time.Second))
	crtCheck(t, "again", again, crtT0.Add(time.Second), crtWant{usable: true, complete: true, ids: []string{"1", "2"}})
}

func TestRunIssuancesAreByIDAndHoldNoCursorGap(t *testing.T) {
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(3), crtLong(4)), crtPageReply(crtLong(10), crtLong(11)), crtEmpty(0))
	got := crtSource(t, g, "").Run(context.Background(), crtT0)
	crtCheck(t, "run", got, crtT0, crtWant{usable: true, asked: true, complete: true, ids: []string{"3", "4", "10", "11"}})
}

var crtURLRE = regexp.MustCompile(`^` + regexp.QuoteMeta(crtBase+crtQuery) + `(&after=[1-9][0-9]{0,19})?$`)
var crtFailureRE = regexp.MustCompile(`^(timeout|network|too large|rate-limited|malformed|too many|status [0-9]+)$`)

// crtFuzzReader reads the fuzz input as a stream of choices; past its end it
// gives 0.
type crtFuzzReader struct {
	data []byte
	pos  int
}

func (r *crtFuzzReader) next() int {
	if r.pos >= len(r.data) {
		return 0
	}
	r.pos++
	return int(r.data[r.pos-1])
}

func (r *crtFuzzReader) reply(start time.Time, nextID *int) crtReply {
	retries := []time.Duration{0, 0, time.Second, 30 * time.Second, time.Hour, 2 * time.Hour, 24 * time.Hour}
	retry := retries[r.next()%len(retries)]
	switch r.next() % 9 {
	case 0, 1, 2, 3:
		var objs []string
		for range r.next() % 4 {
			*nextID += 1 + r.next()%3
			na := []time.Time{start.Add(-time.Hour), start, start.Add(time.Second), start.Add(time.Hour), start.Add(90 * 24 * time.Hour)}[r.next()%5]
			objs = append(objs, crtIss(*nextID, r.next()%6, na))
		}
		return crtReply{resp: httpclient.Response{Status: 200, Body: crtArray(objs...), RetryAfter: retry}}
	case 4:
		return crtEmpty(retry)
	case 5:
		return crtStatus(429, retry)
	case 6:
		return crtStatus([]int{500, 503, 404, 301, 201}[r.next()%5], retry)
	case 7:
		return crtErr([]error{httpclient.ErrTimeout, httpclient.ErrTooLarge, errors.New("x"), httpclient.ErrHost}[r.next()%4])
	}
	return crtReply{resp: httpclient.Response{Status: 200, Body: []byte(`[{"id":"1"}]`), RetryAfter: retry}}
}

func FuzzSourceRun(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{3, 1, 0, 2, 1, 1, 0, 0, 4, 0, 0, 0, 1, 4, 5, 0, 3, 7, 0, 1, 0, 2, 0, 2, 4})
	f.Add([]byte{5, 2, 4, 2, 4, 1, 5, 4, 6, 5, 0, 6, 0, 1, 2, 3, 2, 0, 1, 3, 4, 4, 0, 4, 0, 4, 4, 7, 0, 3})
	f.Add([]byte{9, 0, 0, 3, 3, 1, 2, 0, 1, 0, 1, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		rd := &crtFuzzReader{data: data}
		g := &crtGetter{}
		src := certlog.New(g, crtBase, "k", crtName(t, "corp.test."))
		starts := []time.Duration{0, time.Second, 30 * time.Second, 59 * time.Minute, 61 * time.Minute, 3 * time.Hour, 48 * time.Hour, -5 * time.Second}
		now := crtT0
		nextID := 0
		prevComplete := false
		var prev []obs.Issuance
		for range 1 + rd.next()%6 {
			now = now.Add(starts[rd.next()%len(starts)])
			for range 12 {
				g.script(rd.reply(now, &nextID))
			}
			g.calls = nil
			got := src.Run(context.Background(), now)
			g.replies = nil // the script of one run is not the next one's

			if n := len(g.calls); n > certlog.MaxPages {
				t.Fatalf("%d requests in one run", n)
			}
			for _, c := range g.calls {
				if !crtURLRE.MatchString(c.url) || c.limit != certlog.MaxBody ||
					!slices.Equal(c.headers, []httpclient.Header{{Name: "Authorization", Value: "Bearer k"}}) {
					t.Fatalf("request %q, limit %d, headers %v", c.url, c.limit, c.headers)
				}
			}
			if got.Asked != (len(g.calls) > 0) {
				t.Fatalf("asked %v with %d requests", got.Asked, len(g.calls))
			}
			if got.Usable != (got.Failure == "") || got.Failure != "" && !crtFailureRE.MatchString(got.Failure) {
				t.Fatalf("usable %v, failure %q", got.Usable, got.Failure)
			}
			if got.Failure != "" && !prevComplete && got.Complete {
				t.Fatalf("a failed run (%s) turned the listing complete", got.Failure)
			}
			if got.Key.String() != "certificates corp.test." || !got.Start.Equal(now) {
				t.Fatalf("key %v, start %v", got.Key, got.Start)
			}
			names := 0
			for _, in := range got.Issuances {
				names += len(in.Names)
			}
			if names > certlog.MaxDomainNames {
				t.Fatalf("%d names", names)
			}
			// complete changes only at the end of a run that was usable and asked:
			// true after an empty page; false after MaxPages requests without one,
			// unless it was true and the run was a relist, which leaves it. A failure,
			// "too many" included, and a run inside a wait leave it as it was.
			switch lastEmpty := g.last.err == nil && string(g.last.resp.Body) == "[]"; {
			case !got.Asked || !got.Usable:
				if got.Complete != prevComplete {
					t.Fatalf("complete %v after %v, asked %v, failure %q", got.Complete, prevComplete, got.Asked, got.Failure)
				}
			case lastEmpty:
				if !got.Complete {
					t.Fatal("a run that ended at an empty page is not complete")
				}
			case !prevComplete && got.Complete:
				t.Fatal("a run with no empty page turned the list complete")
			}
			if len(got.Issuances) > certlog.MaxKnown {
				t.Fatalf("%d issuances", len(got.Issuances))
			}
			tbs := map[string]bool{}
			for i, in := range got.Issuances {
				if i > 0 && !crtIDLess(got.Issuances[i-1].ID, in.ID) {
					t.Fatalf("ids %s then %s", got.Issuances[i-1].ID, in.ID)
				}
				if !in.NotAfter.After(now) || tbs[in.TBS] {
					t.Fatalf("issuance %s: expires %v at %v, or its TBS is known twice", in.ID, in.NotAfter, now)
				}
				tbs[in.TBS] = true
			}
			// What was known and is still valid stays known, whatever fails.
			for _, old := range prev {
				if old.NotAfter.After(now) && !slices.ContainsFunc(got.Issuances, func(in obs.Issuance) bool { return in.ID == old.ID }) {
					t.Fatalf("issuance %s was lost (failure %q)", old.ID, got.Failure)
				}
			}
			prev = got.Issuances
			prevComplete = got.Complete
		}
	})
}

// A status other than 200 and 429 with no Retry-After sets no wait: a run
// that starts before or at the start of the failed run asks again.
func TestRunStatusWithoutRetryAfterSetsNoWait(t *testing.T) {
	for _, status := range []int{500, 503, 404} {
		g := &crtGetter{}
		g.script(crtStatus(status, 0), crtStatus(500, 0), crtEmpty(0))
		src := crtSource(t, g, "")
		label := strconv.Itoa(status)
		crtCheck(t, label, src.Run(context.Background(), crtT0), crtT0, crtWant{asked: true, failure: "status " + label})
		g.take()
		before := crtT0.Add(-time.Second)
		crtCheck(t, label+" one second before", src.Run(context.Background(), before), before, crtWant{asked: true, failure: "status 500"})
		crtURLs(t, label+" one second before", g.take(), []string{crtBase + crtQuery})
		crtCheck(t, label+" at the same start", src.Run(context.Background(), crtT0), crtT0, crtWant{usable: true, asked: true, complete: true})
		crtURLs(t, label+" at the same start", g.take(), []string{crtBase + crtQuery})
	}
}

// The cursor of a run, from a listing of ids 5 and 7 that ended at an empty
// page.
func crtCursor7(t *testing.T) (*certlog.Source, *crtGetter) {
	t.Helper()
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(5), crtLong(7)), crtEmpty(0))
	src := crtSource(t, g, "")
	crtCheck(t, "listing", src.Run(context.Background(), crtT0), crtT0, crtWant{usable: true, asked: true, complete: true, ids: []string{"5", "7"}})
	g.take()
	return src, g
}

// A page that does not begin above the cursor is malformed and adds
// nothing, not even its later issuances, and the cursor stays.
func TestRunPageMustBeginAboveTheCursor(t *testing.T) {
	after7 := crtBase + crtQuery + "&after=7"
	for _, tc := range []struct {
		name  string
		page  []string
		valid bool
	}{
		{"first id equal to the cursor", []string{crtLong(7), crtLong(9)}, false},
		{"first id one below", []string{crtLong(6), crtLong(9)}, false},
		{"first id far below", []string{crtLong(1), crtLong(9)}, false},
		{"first id one above", []string{crtLong(8), crtLong(9)}, true},
	} {
		src, g := crtCursor7(t)
		g.script(crtPageReply(tc.page...), crtEmpty(0), crtEmpty(0))
		start := crtT0.Add(time.Second)
		got := src.Run(context.Background(), start)
		if tc.valid {
			crtURLs(t, tc.name, g.take(), []string{after7, crtBase + crtQuery + "&after=9"})
			crtCheck(t, tc.name, got, start, crtWant{usable: true, asked: true, complete: true, ids: []string{"5", "7", "8", "9"}})
			continue
		}
		crtURLs(t, tc.name, g.take(), []string{after7})
		crtCheck(t, tc.name, got, start, crtWant{asked: true, complete: true, failure: "malformed", ids: []string{"5", "7"}})
		// The cursor did not move: the next run asks for the same ids.
		next := crtT0.Add(2 * time.Second)
		got = src.Run(context.Background(), next)
		crtURLs(t, tc.name+" next", g.take(), []string{after7})
		crtCheck(t, tc.name+" next", got, next, crtWant{usable: true, asked: true, complete: true, ids: []string{"5", "7"}})
	}
	// With no cursor any first id is read.
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(1)), crtEmpty(0))
	crtCheck(t, "no cursor", crtSource(t, g, "").Run(context.Background(), crtT0), crtT0, crtWant{usable: true, asked: true, complete: true, ids: []string{"1"}})
}

// A source that ignores the cursor and gives the same page every time makes
// every run fail; no run reads as usable.
func TestRunSourceThatIgnoresTheCursor(t *testing.T) {
	g := &crtGetter{}
	for range 6 {
		g.script(crtPageReply(crtLong(1), crtLong(2)))
	}
	src := crtSource(t, g, "")
	for i := range 3 {
		start := crtT0.Add(time.Duration(i) * time.Second)
		got := src.Run(context.Background(), start)
		want := crtWant{asked: true, failure: "malformed", ids: []string{"1", "2"}}
		crtCheck(t, fmt.Sprint("run ", i), got, start, want)
		wantURLs := []string{crtBase + crtQuery + "&after=2"}
		if i == 0 {
			wantURLs = []string{crtBase + crtQuery, crtBase + crtQuery + "&after=2"}
		}
		crtURLs(t, fmt.Sprint("run ", i), g.take(), wantURLs)
	}
}

// complete is true only after a run that ended at an empty page.
func TestRunCompleteOnlyAtAnEmptyPage(t *testing.T) {
	g := &crtGetter{}
	var ten []crtReply
	for i := 1; i <= 10; i++ {
		ten = append(ten, crtPageReply(crtLong(i)))
	}
	g.script(ten...)
	src := crtSource(t, g, "")
	crtCheck(t, "ten pages", src.Run(context.Background(), crtT0), crtT0, crtWant{usable: true, asked: true, ids: crtIDRange(1, 10)})
	g.script(crtPageReply(crtLong(11)), crtEmpty(0))
	crtCheck(t, "page and empty", src.Run(context.Background(), crtT0.Add(time.Second)), crtT0.Add(time.Second),
		crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 11)})
	g.take()
	var more []crtReply
	for i := 12; i <= 21; i++ {
		more = append(more, crtPageReply(crtLong(i)))
	}
	g.script(more...)
	got := src.Run(context.Background(), crtT0.Add(2*time.Second))
	if n := len(g.take()); n != 10 {
		t.Errorf("%d requests, want 10", n)
	}
	crtCheck(t, "ten more", got, crtT0.Add(2*time.Second), crtWant{usable: true, asked: true, ids: crtIDRange(1, 21)})
	// A run inside a wait or a failure changes nothing: the list is still not whole.
	g.script(crtStatus(500, 0))
	crtCheck(t, "failure", src.Run(context.Background(), crtT0.Add(3*time.Second)), crtT0.Add(3*time.Second),
		crtWant{asked: true, failure: "status 500", ids: crtIDRange(1, 21)})
}

// The listing starts again from the beginning at the first run that asks 24
// hours or more after the last start, never inside a wait.
func TestRunRelistsOnceInADay(t *testing.T) {
	day := 24 * time.Hour
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(1), crtLong(2)), crtEmpty(0))
	src := crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	g.take()
	after2 := crtBase + crtQuery + "&after=2"
	for _, tc := range []struct {
		at      time.Duration
		cursor  bool // the request keeps the cursor
		relists bool
	}{
		{time.Hour, true, false},
		{day - time.Second, true, false},
		{day, false, true},
		{day + time.Hour, true, false},
		{2*day - time.Second, true, false}, // 24 hours after the relist at +24h is +48h
		{2 * day, false, true},
	} {
		g.script(crtEmpty(0))
		if tc.relists {
			g.replies = nil
			g.script(crtPageReply(crtLong(1), crtLong(2)), crtEmpty(0))
		}
		got := src.Run(context.Background(), crtT0.Add(tc.at))
		want := []string{after2}
		if !tc.cursor {
			want = []string{crtBase + crtQuery, after2}
		}
		crtURLs(t, fmt.Sprint("at +", tc.at), g.take(), want)
		crtCheck(t, fmt.Sprint("at +", tc.at), got, crtT0.Add(tc.at), crtWant{usable: true, asked: true, complete: true, ids: []string{"1", "2"}})
	}
}

func TestRunRelistWaitsForTheWait(t *testing.T) {
	day := 24 * time.Hour
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(1), crtLong(2)), crtEmpty(0), crtStatus(429, day), crtPageReply(crtLong(1), crtLong(2)), crtEmpty(0))
	src := crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	// 23 hours after the start the cursor is kept; the 429 asks for 24 hours.
	src.Run(context.Background(), crtT0.Add(23*time.Hour))
	g.take()
	for _, at := range []time.Duration{24 * time.Hour, 30 * time.Hour, 47*time.Hour - time.Second} {
		got := src.Run(context.Background(), crtT0.Add(at))
		crtURLs(t, fmt.Sprint("inside the wait at +", at), g.take(), nil)
		crtCheck(t, fmt.Sprint("inside the wait at +", at), got, crtT0.Add(at), crtWant{failure: "rate-limited", complete: true, ids: []string{"1", "2"}})
	}
	// The first run that asks after the wait relists.
	got := src.Run(context.Background(), crtT0.Add(47*time.Hour))
	crtURLs(t, "after the wait", g.take(), []string{crtBase + crtQuery, crtBase + crtQuery + "&after=2"})
	crtCheck(t, "after the wait", got, crtT0.Add(47*time.Hour), crtWant{usable: true, asked: true, complete: true, ids: []string{"1", "2"}})
}

// A relist keeps what is known: a known id or TBS is skipped (the first TBS
// of an id wins), and an issuance below the known ids that was missed is
// added in its place.
func TestRunRelistKeepsAndMerges(t *testing.T) {
	g := &crtGetter{}
	hour := crtT0.Add(90 * 24 * time.Hour)
	g.script(crtPageReply(crtIss(5, 5, hour), crtIss(9, 9, hour)), crtEmpty(0))
	src := crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	g.take()
	at := crtT0.Add(24 * time.Hour)
	g.script(
		crtPageReply(crtIss(3, 3, hour), crtIss(5, 50, hour), crtIss(6, 9, hour), crtIss(7, 7, hour), crtIss(9, 90, hour)),
		crtPageReply(crtIss(11, 11, hour)),
		crtEmpty(0),
	)
	got := src.Run(context.Background(), at)
	crtURLs(t, "relist", g.take(), []string{crtBase + crtQuery, crtBase + crtQuery + "&after=9", crtBase + crtQuery + "&after=11"})
	crtCheck(t, "relist", got, at, crtWant{usable: true, asked: true, complete: true, ids: []string{"3", "5", "7", "9", "11"}})
	for _, in := range got.Issuances {
		if in.TBS != fmt.Sprintf("%064x", mustAtoi(t, in.ID)) {
			t.Errorf("issuance %s holds the TBS %s", in.ID, in.TBS)
		}
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// An id that is far too high moves the cursor past the real ids that follow;
// the relist reads them.
func TestRunRelistHealsAHugeID(t *testing.T) {
	const huge = "99999999999999999999"
	hugeObj := crtObj(map[string]string{"id": `"` + huge + `"`, "tbs_sha256": fmt.Sprintf(`"%064x"`, 777),
		"not_before": crtTime(crtT0), "not_after": crtTime(crtT0.Add(90 * 24 * time.Hour))})
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(1), crtLong(2), hugeObj), crtEmpty(0), crtEmpty(0))
	src := crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	// A real issuance with id 3 is never offered above the cursor.
	got := src.Run(context.Background(), crtT0.Add(time.Hour))
	crtURLs(t, "later", g.take(), []string{crtBase + crtQuery, crtBase + crtQuery + "&after=" + huge, crtBase + crtQuery + "&after=" + huge})
	crtCheck(t, "later", got, crtT0.Add(time.Hour), crtWant{usable: true, asked: true, complete: true, ids: []string{"1", "2", huge}})
	at := crtT0.Add(24 * time.Hour)
	g.script(crtPageReply(crtLong(1), crtLong(2), crtLong(3), hugeObj), crtEmpty(0))
	got = src.Run(context.Background(), at)
	crtURLs(t, "relist", g.take(), []string{crtBase + crtQuery, crtBase + crtQuery + "&after=" + huge})
	crtCheck(t, "relist", got, at, crtWant{usable: true, asked: true, complete: true, ids: []string{"1", "2", "3", huge}})
}

// crtNamedPage is a page of n issuances from id first, each with names
// names.
func crtNamedPage(first, n, names int, na time.Time) crtReply {
	list := make([]string, names)
	for i := range list {
		list[i] = fmt.Sprintf(`"h%d.corp.test"`, i)
	}
	var objs []string
	for id := first; id < first+n; id++ {
		objs = append(objs, crtObj(map[string]string{
			"id": fmt.Sprintf(`"%d"`, id), "tbs_sha256": fmt.Sprintf(`"%064x"`, id),
			"not_before": crtTime(na.Add(-time.Hour)), "not_after": crtTime(na),
			"dns_names": "[" + strings.Join(list, ",") + "]",
		}))
	}
	return crtPageReply(objs...)
}

var crtFar = crtT0.Add(90 * 24 * time.Hour)

// "too many" is a failure of the run: the page is not added, the cursor, the
// known set and complete stay, no request is made for one hour and the runs
// inside it fail the same way, and the first run after it asks again.
func TestRunTooManyKnownIsAFailureOfOneHour(t *testing.T) {
	src, g, _ := crtBulkSource(t, func(int) time.Time { return crtFar })
	all := crtIDRange(1, 10000)
	g.script(crtBulk(10001, 10001, crtFar), crtBulk(10001, 10001, crtFar), crtEmpty(0))
	second := crtT0.Add(time.Second)
	got := src.Run(context.Background(), second)
	crtURLs(t, "second", g.take(), []string{crtBase + crtQuery + "&after=10000"})
	crtCheck(t, "second", got, second, crtWant{asked: true, failure: "too many", ids: all})
	for _, in := range []time.Duration{time.Second, 30 * time.Minute, time.Hour - time.Second} {
		at := second.Add(in)
		got = src.Run(context.Background(), at)
		crtURLs(t, "inside", g.take(), nil)
		crtCheck(t, fmt.Sprint("inside at +", in), got, at, crtWant{failure: "too many", ids: all})
	}
	// A domain that is truly too large fails every hour.
	at := second.Add(time.Hour)
	got = src.Run(context.Background(), at)
	crtURLs(t, "after the hour", g.take(), []string{crtBase + crtQuery + "&after=10000"})
	crtCheck(t, "after the hour", got, at, crtWant{asked: true, failure: "too many", ids: all})
	got = src.Run(context.Background(), at.Add(time.Hour-time.Second))
	crtURLs(t, "inside again", g.take(), nil)
	crtCheck(t, "inside again", got, at.Add(time.Hour-time.Second), crtWant{failure: "too many", ids: all})
	// When the source is right again the run is usable.
	at = at.Add(time.Hour)
	got = src.Run(context.Background(), at)
	crtURLs(t, "recovered", g.take(), []string{crtBase + crtQuery + "&after=10000"})
	crtCheck(t, "recovered", got, at, crtWant{usable: true, asked: true, complete: true, ids: all})
}

// The pages of the run that came before the one that is too much stay, and
// the cursor is the last of them; complete, true before, stays true.
func TestRunTooManyKeepsEarlierPagesOfTheRun(t *testing.T) {
	g := &crtGetter{}
	for p := 0; p < 9; p++ {
		g.script(crtBulk(p*1000+1, p*1000+1000, crtFar))
	}
	g.script(crtEmpty(0))
	src := crtSource(t, g, "")
	crtCheck(t, "listing", src.Run(context.Background(), crtT0), crtT0, crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 9000)})
	g.take()
	g.script(crtBulk(9001, 9500, crtFar), crtBulk(9501, 10500, crtFar), crtEmpty(0))
	second := crtT0.Add(time.Second)
	got := src.Run(context.Background(), second)
	crtURLs(t, "second", g.take(), []string{crtBase + crtQuery + "&after=9000", crtBase + crtQuery + "&after=9500"})
	crtCheck(t, "second", got, second, crtWant{asked: true, complete: true, failure: "too many", ids: crtIDRange(1, 9500)})
	inside := second.Add(30 * time.Minute)
	got = src.Run(context.Background(), inside)
	crtURLs(t, "inside", g.take(), nil)
	crtCheck(t, "inside", got, inside, crtWant{complete: true, failure: "too many", ids: crtIDRange(1, 9500)})
	at := second.Add(time.Hour)
	got = src.Run(context.Background(), at)
	crtURLs(t, "after the hour", g.take(), []string{crtBase + crtQuery + "&after=9500"})
	crtCheck(t, "after the hour", got, at, crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 9500)})
}

func TestRunDomainNameCap(t *testing.T) {
	if certlog.MaxDomainNames != 100000 {
		t.Errorf("MaxDomainNames %d", certlog.MaxDomainNames)
	}
	// Exactly the cap is read.
	g := &crtGetter{}
	g.script(crtNamedPage(1, 100, 1000, crtFar), crtEmpty(0))
	got := crtSource(t, g, "").Run(context.Background(), crtT0)
	crtCheck(t, "100000 names", got, crtT0, crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 100)})

	// One name more is too many as for the issuances: the page is not added.
	for _, complete := range []bool{false, true} {
		g = &crtGetter{}
		g.script(crtNamedPage(1, 100, 1000, crtFar))
		if complete {
			g.script(crtEmpty(0))
		}
		g.script(crtNamedPage(101, 1, 1, crtFar), crtEmpty(0))
		src := crtSource(t, g, "")
		start := crtT0
		if complete {
			src.Run(context.Background(), crtT0)
			start = crtT0.Add(time.Second)
		}
		g.take()
		got = src.Run(context.Background(), start)
		label := fmt.Sprint("complete before: ", complete)
		crtCheck(t, label, got, start, crtWant{asked: true, complete: complete, failure: "too many", ids: crtIDRange(1, 100)})
		wantURLs := []string{crtBase + crtQuery + "&after=100"}
		if !complete {
			wantURLs = []string{crtBase + crtQuery, crtBase + crtQuery + "&after=100"}
		}
		crtURLs(t, label, g.take(), wantURLs)
		for _, in := range []time.Duration{time.Second, time.Hour - time.Second} {
			got = src.Run(context.Background(), start.Add(in))
			crtURLs(t, label+" inside", g.take(), nil)
			crtCheck(t, label+" inside", got, start.Add(in), crtWant{complete: complete, failure: "too many", ids: crtIDRange(1, 100)})
		}
		g.script(crtEmpty(0))
		got = src.Run(context.Background(), start.Add(time.Hour))
		crtURLs(t, label+" after the hour", g.take(), []string{crtBase + crtQuery + "&after=100"})
		crtCheck(t, label+" after the hour", got, start.Add(time.Hour), crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 100)})
	}

	// An issuance that expired is not counted.
	g = &crtGetter{}
	g.script(crtNamedPage(1, 100, 1000, crtT0.Add(10*time.Second)), crtEmpty(0), crtNamedPage(101, 1, 1, crtFar), crtEmpty(0))
	src := crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	later := crtT0.Add(10 * time.Second)
	got = src.Run(context.Background(), later)
	crtCheck(t, "after expiry", got, later, crtWant{usable: true, asked: true, complete: true, ids: []string{"101"}})
}

// A listing that takes many runs is never started again, whatever the time
// and whatever fails in between; the first run that completes it starts the
// 24 hours of the relist.
func TestRunNoRelistBeforeComplete(t *testing.T) {
	h := time.Hour
	g := &crtGetter{}
	next := 1
	pages := func(n int) []crtReply {
		var r []crtReply
		for range n {
			r = append(r, crtPageReply(crtLong(next)))
			next++
		}
		return r
	}
	cursor := func(id int) string { return crtBase + crtQuery + "&after=" + strconv.Itoa(id) }
	src := crtSource(t, g, "")

	g.script(pages(10)...)
	got := src.Run(context.Background(), crtT0)
	crtCheck(t, "run 1", got, crtT0, crtWant{usable: true, asked: true, ids: crtIDRange(1, 10)})
	if urls := g.take(); urls[0] != crtBase+crtQuery || urls[9] != cursor(9) {
		t.Errorf("run 1 asked %q", urls)
	}
	for i, at := range []time.Duration{25 * h, 60 * h} {
		g.script(pages(10)...)
		got = src.Run(context.Background(), crtT0.Add(at))
		first := 10 + 10*i
		crtCheck(t, fmt.Sprint("run ", i+2), got, crtT0.Add(at), crtWant{usable: true, asked: true, ids: crtIDRange(1, first+10)})
		if urls := g.take(); urls[0] != cursor(first) || len(urls) != 10 {
			t.Errorf("run %d asked %q", i+2, urls)
		}
	}
	// Failures and a 429 do not start it again either.
	g.script(crtStatus(500, 0))
	got = src.Run(context.Background(), crtT0.Add(100*h))
	crtURLs(t, "500", g.take(), []string{cursor(30)})
	crtCheck(t, "500", got, crtT0.Add(100*h), crtWant{asked: true, failure: "status 500", ids: crtIDRange(1, 30)})
	g.script(crtStatus(429, time.Minute))
	got = src.Run(context.Background(), crtT0.Add(101*h))
	crtURLs(t, "429", g.take(), []string{cursor(30)})
	crtCheck(t, "429", got, crtT0.Add(101*h), crtWant{asked: true, failure: "rate-limited", ids: crtIDRange(1, 30)})
	inside := crtT0.Add(101*h + 30*time.Second)
	crtCheck(t, "inside", src.Run(context.Background(), inside), inside, crtWant{failure: "rate-limited", ids: crtIDRange(1, 30)})
	crtURLs(t, "inside", g.take(), nil)

	// It ends at an empty page; that run starts the 24 hours.
	end := crtT0.Add(110 * h)
	g.script(crtPageReply(crtLong(31)), crtEmpty(0))
	got = src.Run(context.Background(), end)
	crtURLs(t, "end", g.take(), []string{cursor(30), cursor(31)})
	crtCheck(t, "end", got, end, crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 31)})
	g.script(crtEmpty(0))
	got = src.Run(context.Background(), end.Add(24*h-time.Second))
	crtURLs(t, "a second short of 24 hours", g.take(), []string{cursor(31)})
	crtCheck(t, "a second short of 24 hours", got, end.Add(24*h-time.Second), crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 31)})
	g.script(crtPageReply(crtLong(1)), crtEmpty(0))
	got = src.Run(context.Background(), end.Add(24*h))
	crtURLs(t, "24 hours", g.take(), []string{crtBase + crtQuery, cursor(1)})
	crtCheck(t, "24 hours", got, end.Add(24*h), crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 31)})
}

// A relist that ends at an empty page gives the main cursor the last id that
// it read: lower than the old one when the source has dropped the id that
// moved it, the same while the source still lists it; an empty list leaves
// it as it is. The relist run polls for nothing new; the next run does.
func TestRunRelistSetsTheCursor(t *testing.T) {
	day := 24 * time.Hour
	at := func(id int) string { return crtBase + crtQuery + "&after=" + strconv.Itoa(id) }
	for _, tc := range []struct {
		name    string
		relist  []crtReply
		asked   []string
		ids     []string
		next    string // the URL of the next poll
		nextIDs []string
	}{
		{"source dropped the id", []crtReply{crtPageReply(crtLong(1), crtLong(2), crtLong(3)), crtEmpty(0)},
			[]string{crtBase + crtQuery, at(3)}, []string{"1", "2", "3", "50"}, at(3), nil},
		{"source still lists it", []crtReply{crtPageReply(crtLong(1), crtLong(2), crtLong(3), crtLong(50)), crtEmpty(0)},
			[]string{crtBase + crtQuery, at(50)}, []string{"1", "2", "3", "50"}, at(50), nil},
		{"source lists less", []crtReply{crtPageReply(crtLong(1)), crtEmpty(0)},
			[]string{crtBase + crtQuery, at(1)}, []string{"1", "2", "50"}, at(1), nil},
		{"empty list", []crtReply{crtEmpty(0)},
			[]string{crtBase + crtQuery}, []string{"1", "2", "50"}, at(50), nil},
		{"two pages", []crtReply{crtPageReply(crtLong(1)), crtPageReply(crtLong(60)), crtEmpty(0)},
			[]string{crtBase + crtQuery, at(1), at(60)}, []string{"1", "2", "50", "60"}, at(60), nil},
	} {
		g := &crtGetter{}
		g.script(crtPageReply(crtLong(1), crtLong(2), crtLong(50)), crtEmpty(0))
		src := crtSource(t, g, "")
		src.Run(context.Background(), crtT0)
		g.take()
		g.script(tc.relist...)
		relist := crtT0.Add(day)
		got := src.Run(context.Background(), relist)
		crtURLs(t, tc.name, g.take(), tc.asked)
		crtCheck(t, tc.name, got, relist, crtWant{usable: true, asked: true, complete: true, ids: tc.ids})
		g.script(crtEmpty(0))
		poll := relist.Add(time.Second)
		got = src.Run(context.Background(), poll)
		crtURLs(t, tc.name+" next", g.take(), []string{tc.next})
		crtCheck(t, tc.name+" next", got, poll, crtWant{usable: true, asked: true, complete: true, ids: tc.ids})
	}
}

// What a relist adds is a new issuance of the page that is valid, not known
// by id or by TBS; the known ones stay as they were.
func TestRunRelistAddsOnlyWhatIsValidAndNew(t *testing.T) {
	g := &crtGetter{}
	g.script(crtPageReply(crtIss(5, 5, crtFar), crtIss(9, 9, crtFar)), crtEmpty(0))
	src := crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	g.take()
	relist := crtT0.Add(24 * time.Hour)
	g.script(
		crtPageReply(
			crtIss(3, 3, relist.Add(-time.Hour)), // expired
			crtIss(4, 4, relist),                 // expires now
			crtIss(6, 6, crtFar),                 // new
			crtIss(7, 5, crtFar),                 // known TBS
			crtIss(8, 80, crtFar),                // new
			crtIss(9, 90, crtFar)),               // known id, new TBS
		crtEmpty(0))
	got := src.Run(context.Background(), relist)
	crtCheck(t, "relist", got, relist, crtWant{usable: true, asked: true, complete: true, ids: []string{"5", "6", "8", "9"}})
	for _, in := range got.Issuances {
		if want := map[string]int{"5": 5, "6": 6, "8": 80, "9": 9}[in.ID]; in.TBS != fmt.Sprintf("%064x", want) {
			t.Errorf("issuance %s holds the TBS %s", in.ID, in.TBS)
		}
	}
}

// A relist that fills MaxPages requests with no empty page keeps what it
// added; the main cursor and complete stay, the run is usable, and no relist
// is tried again.
func TestRunRelistTooLong(t *testing.T) {
	h := time.Hour
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(1), crtLong(2)), crtEmpty(0))
	src := crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	g.take()
	at := func(id int) string { return crtBase + crtQuery + "&after=" + strconv.Itoa(id) }

	g.script(crtPageReply(crtLong(1), crtLong(2)))
	for id := 3; id <= 11; id++ {
		g.script(crtPageReply(crtLong(id)))
	}
	g.script(crtPageReply(crtLong(12))) // never asked
	relist := crtT0.Add(24 * h)
	got := src.Run(context.Background(), relist)
	urls := g.take()
	if len(urls) != 10 || urls[0] != crtBase+crtQuery || urls[9] != at(10) {
		t.Errorf("relist asked %q", urls)
	}
	crtCheck(t, "relist", got, relist, crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 11)})

	// The main cursor is still 2: the next poll asks above it.
	g.replies = nil
	g.script(crtPageReply(crtLong(3)), crtEmpty(0))
	poll := relist.Add(time.Second)
	got = src.Run(context.Background(), poll)
	crtURLs(t, "poll", g.take(), []string{at(2), at(3)})
	crtCheck(t, "poll", got, poll, crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 11)})

	// No relist ever again.
	for _, d := range []time.Duration{48 * h, 49 * h, 100 * h, 1000 * h} {
		g.script(crtEmpty(0))
		got = src.Run(context.Background(), crtT0.Add(d))
		crtURLs(t, fmt.Sprint("at +", d), g.take(), []string{at(3)})
		crtCheck(t, fmt.Sprint("at +", d), got, crtT0.Add(d), crtWant{usable: true, asked: true, complete: true, ids: crtIDRange(1, 11)})
	}
}

// A relist that fails in the middle keeps what it read and is due at the
// next run that asks.

// A relist that meets "too many" fails as any run does: the page is not
// added, complete and the cursor stay, an hour passes without a request, and
// then the relist is tried again.
func TestRunRelistTooMany(t *testing.T) {
	g := &crtGetter{}
	for p := 0; p < 9; p++ {
		g.script(crtBulk(p*1000+1, p*1000+1000, crtFar))
	}
	g.script(crtBulk(9001, 9500, crtFar))
	src := crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	g.script(crtEmpty(0))
	src.Run(context.Background(), crtT0.Add(time.Second))
	g.take()
	at := func(id int) string { return crtBase + crtQuery + "&after=" + strconv.Itoa(id) }
	all := crtIDRange(1, 9500)

	// The listing completed one second after the first run.
	relist := crtT0.Add(24*time.Hour + time.Second)
	g.script(crtBulk(20001, 20600, crtFar))
	got := src.Run(context.Background(), relist)
	crtURLs(t, "relist", g.take(), []string{crtBase + crtQuery})
	crtCheck(t, "relist", got, relist, crtWant{asked: true, complete: true, failure: "too many", ids: all})
	inside := relist.Add(time.Hour - time.Second)
	crtCheck(t, "inside", src.Run(context.Background(), inside), inside, crtWant{complete: true, failure: "too many", ids: all})
	crtURLs(t, "inside", g.take(), nil)

	again := relist.Add(time.Hour)
	g.script(crtBulk(20001, 20100, crtFar), crtEmpty(0))
	got = src.Run(context.Background(), again)
	crtURLs(t, "again", g.take(), []string{crtBase + crtQuery, at(20100)})
	crtCheck(t, "again", got, again, crtWant{usable: true, asked: true, complete: true, ids: append(crtIDRange(1, 9500), crtIDRange(20001, 20100)...)})
}

// The relist is never inside a wait, and the first run that asks after the
// wait makes it.
func TestRunRelistNeverInsideAWait(t *testing.T) {
	day := 24 * time.Hour
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(1)), crtEmpty(time.Hour), crtStatus(503, day))
	src := crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	// The 503 comes just before the relist is due and asks for 24 hours.
	src.Run(context.Background(), crtT0.Add(day-time.Second))
	g.take()
	for _, in := range []time.Duration{0, time.Second, day - time.Second - time.Second} {
		at := crtT0.Add(day - time.Second + in)
		got := src.Run(context.Background(), at)
		crtURLs(t, "inside", g.take(), nil)
		crtCheck(t, fmt.Sprint("inside at +", in), got, at, crtWant{failure: "rate-limited", complete: true, ids: []string{"1"}})
	}
	end := crtT0.Add(2*day - time.Second)
	g.script(crtPageReply(crtLong(1)), crtEmpty(0))
	got := src.Run(context.Background(), end)
	crtURLs(t, "after the wait", g.take(), []string{crtBase + crtQuery, crtBase + crtQuery + "&after=1"})
	crtCheck(t, "after the wait", got, end, crtWant{usable: true, asked: true, complete: true, ids: []string{"1"}})
}

// A wrong empty answer to the relist must not turn every later poll into a
// request without a cursor: the cursor stays, and a new issuance above it is
// read by the next poll.
func TestRunEmptyRelistKeepsTheCursor(t *testing.T) {
	at := func(id int) string { return crtBase + crtQuery + "&after=" + strconv.Itoa(id) }
	g := &crtGetter{}
	g.script(crtPageReply(crtLong(1), crtLong(2), crtLong(50)), crtEmpty(0))
	src := crtSource(t, g, "")
	src.Run(context.Background(), crtT0)
	g.take()
	relist := crtT0.Add(24 * time.Hour)
	g.script(crtEmpty(0))
	got := src.Run(context.Background(), relist)
	crtURLs(t, "relist", g.take(), []string{crtBase + crtQuery})
	crtCheck(t, "relist", got, relist, crtWant{usable: true, asked: true, complete: true, ids: []string{"1", "2", "50"}})
	for i, poll := range []time.Duration{time.Second, 2 * time.Second} {
		g.script(crtPageReply(crtLong(51+i)), crtEmpty(0))
		got = src.Run(context.Background(), relist.Add(poll))
		crtURLs(t, "poll", g.take(), []string{at(50 + i), at(51 + i)})
		crtCheck(t, "poll", got, relist.Add(poll), crtWant{usable: true, asked: true, complete: true, ids: append([]string{"1", "2", "50"}, crtIDRange(51, 51+i)...)})
	}
}

// A relist that fails is tried again one hour later; the runs between poll as
// usual; a wait that the failure set holds every request back, so the relist
// comes at the later of the two. What the relist read stays.
func TestRunFailedRelistIsTriedAgainAnHourLater(t *testing.T) {
	h, m, s := time.Hour, time.Minute, time.Second
	at := func(id int) string { return crtBase + crtQuery + "&after=" + strconv.Itoa(id) }
	for _, tc := range []struct {
		name   string
		reply  crtReply
		failed string
		poll   time.Duration // the first run that can poll, 0: none before the retry
		retry  time.Duration
	}{
		{"500", crtStatus(500, 0), "status 500", s, h},
		{"503", crtStatus(503, 0), "status 503", s, h},
		{"timeout", crtErr(httpclient.ErrTimeout), "timeout", s, h},
		{"503 for 30 minutes", crtStatus(503, 30*m), "status 503", 30 * m, h},
		{"429 for 30 minutes", crtStatus(429, 30*m), "rate-limited", 30 * m, h},
		{"429 for 2 hours", crtStatus(429, 2*h), "rate-limited", 0, 2 * h},
		{"503 for 2 hours", crtStatus(503, 2*h), "status 503", 0, 2 * h},
		{"429 for exactly 1 hour", crtStatus(429, h), "rate-limited", 0, h},
	} {
		g := &crtGetter{}
		g.script(crtPageReply(crtLong(1), crtLong(2)), crtEmpty(0))
		src := crtSource(t, g, "")
		src.Run(context.Background(), crtT0)
		g.take()
		relist := crtT0.Add(24 * h)
		g.script(crtPageReply(crtLong(1), crtLong(2), crtLong(3)), tc.reply)
		got := src.Run(context.Background(), relist)
		crtURLs(t, tc.name, g.take(), []string{crtBase + crtQuery, at(3)})
		crtCheck(t, tc.name, got, relist, crtWant{asked: true, complete: true, failure: tc.failed, ids: []string{"1", "2", "3"}})

		ids, cursor := []string{"1", "2", "3"}, 2
		if tc.poll > 0 {
			// A poll before the retry reads a new issuance above the cursor.
			g.script(crtPageReply(crtLong(4)), crtEmpty(0))
			got = src.Run(context.Background(), relist.Add(tc.poll))
			crtURLs(t, tc.name+" poll", g.take(), []string{at(2), at(4)})
			ids, cursor = crtIDRange(1, 4), 4
			crtCheck(t, tc.name+" poll", got, relist.Add(tc.poll), crtWant{usable: true, asked: true, complete: true, ids: ids})
		}
		// One second before the hour: an ordinary poll with the cursor, or
		// still inside the wait.
		before := relist.Add(tc.retry - s)
		if tc.poll > 0 {
			g.script(crtEmpty(0))
			got = src.Run(context.Background(), before)
			crtURLs(t, tc.name+" before", g.take(), []string{at(cursor)})
			crtCheck(t, tc.name+" before", got, before, crtWant{usable: true, asked: true, complete: true, ids: ids})
		} else {
			got = src.Run(context.Background(), before)
			crtURLs(t, tc.name+" before", g.take(), nil)
			crtCheck(t, tc.name+" before", got, before, crtWant{complete: true, failure: "rate-limited", ids: ids})
		}
		// At the hour: the relist.
		retry := relist.Add(tc.retry)
		g.script(crtPageReply(crtLong(1)), crtPageReply(crtLong(cursor)), crtEmpty(0))
		got = src.Run(context.Background(), retry)
		crtURLs(t, tc.name+" retry", g.take(), []string{crtBase + crtQuery, at(1), at(cursor)})
		crtCheck(t, tc.name+" retry", got, retry, crtWant{usable: true, asked: true, complete: true, ids: ids})
	}
}
