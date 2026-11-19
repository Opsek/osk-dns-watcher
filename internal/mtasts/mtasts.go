// Package mtasts fetches the MTA-STS policy file of a domain (RFC 8461
// section 3.3). The one host it asks is mta-sts.<domain>, which the name of
// the domain fixes: no DNS answer and no body can change it.
package mtasts

import (
	"context"
	"crypto/x509"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// Host gives "mta-sts.<domain>:443", in lower case and without the trailing
// dot: the form that httpclient.New takes. ok is false when that name would
// be too long, for the root, when a label holds an octet other than a
// letter, a digit, "-" or "_" (an octet such as "/", ":" or "#" would make
// the URL name another host), and when the client would refuse the host,
// such as one whose last label is all digits.
func Host(domain dnswire.Name) (string, bool) {
	k, ok := obs.PolicyKey(domain)
	if !ok || domain.LabelCount() == 0 {
		return "", false
	}
	labels := k.Name.Lower().Labels()
	for _, l := range labels {
		if strings.ContainsFunc(l, notHostOctet) {
			return "", false
		}
	}
	host := strings.Join(labels, ".") + ":443"
	// The client's own rule, so that the two never differ on a host.
	if got, err := httpclient.HostOf(policyURL(host)); err != nil || got != host {
		return "", false
	}
	return host, true
}

// notHostOctet also refuses every octet outside ASCII: strings.ContainsFunc
// hands it over as utf8.RuneError or as a rune above 0x7F.
func notHostOctet(r rune) bool {
	return !('a' <= r && r <= 'z' || '0' <= r && r <= '9' || r == '-' || r == '_')
}

// Fetcher gives the function that runs a check of kind policy, for
// observe.Config.Policy: one GET of
// https://mta-sts.<domain>/.well-known/mta-sts.txt through a client made for
// that one host, which trusts the certificates of the system. The zone of the
// domain chooses the addresses of the host, so the client connects only to
// an address that a DNS check may ask: a public one, or one in extra. Every
// outcome is in the Answer, and a failure is never read as "no policy".
func Fetcher(extra []netip.Prefix) func(context.Context, obs.Key) obs.Answer {
	return func(ctx context.Context, k obs.Key) obs.Answer {
		return fetch(ctx, k, extra, nil, policyURL, time.Now)
	}
}

// policyURL takes a host in the form that Host gives.
func policyURL(host string) string {
	return "https://" + strings.TrimSuffix(host, ":443") + "/.well-known/mta-sts.txt"
}

// fetch is the function of Fetcher with the trust store, the URL of the host
// and the clock given, so that a test can serve the file itself. The client
// takes its one host from that URL; in use it is policyURL, so that host is
// the policy host.
func fetch(ctx context.Context, k obs.Key, extra []netip.Prefix, roots *x509.CertPool, url func(host string) string, now func() time.Time) obs.Answer {
	a := obs.Answer{Proof: obs.Proof{
		Server:   obs.Server{Name: k.Name},
		Question: dnswire.Question{Name: k.Name, Type: dnswire.TypeTXT, Class: dnswire.ClassINET},
		TCP:      true,
	}}
	host, ok := Host(k.Domain)
	if p, _ := obs.PolicyKey(k.Domain); !ok || k.String() != p.String() {
		a.Received = now()
		a.Result = failure(obs.ReasonNotPermitted, "not a policy check")
		return a
	}
	rawURL := url(host)
	// Get would refuse such a URL with the same ErrURL, but only after Sent
	// is set. Get cannot give ErrHost: the client is made for this URL's host.
	allowed, err := httpclient.HostOf(rawURL)
	if err != nil {
		a.Received = now()
		a.Result = failure(obs.ReasonNotPermitted, err.Error())
		return a
	}
	permit := func(ip netip.Addr) bool { return observe.Permitted(ip, extra) }
	c := httpclient.NewGuarded([]string{allowed}, roots, permit)
	a.Sent = now()
	// The policy file is text/plain (RFC 8461 section 3.2), not the JSON that Get asks for by default.
	resp, err := c.Get(ctx, rawURL, httpclient.MaxPolicy, httpclient.Header{Name: "Accept", Value: "text/plain"})
	a.Received = now()
	if errors.Is(err, httpclient.ErrNotPermitted) {
		a.Sent = time.Time{} // no connection was opened
	}
	a.Server.Addr = resp.Addr
	a.Result = result(k.Name, resp, err)
	return a
}

func result(name dnswire.Name, resp httpclient.Response, err error) obs.Result {
	switch {
	case errors.Is(err, httpclient.ErrNotPermitted):
		// The text names the first address refused, as netip writes it: the
		// operator sees where the name of the policy host led.
		return failure(obs.ReasonNotPermitted, err.Error())
	case errors.Is(err, httpclient.ErrTimeout):
		return failure(obs.ReasonTimeout, "timeout")
	case errors.Is(err, httpclient.ErrTooLarge):
		return failure(obs.ReasonBadAnswer, "the policy file is larger than "+strconv.Itoa(httpclient.MaxPolicy)+" octets")
	case err != nil:
		// The errors of httpclient are fixed texts that hold nothing of the answer.
		return failure(obs.ReasonNetwork, err.Error())
	case resp.Status != 200:
		// Only 200 is valid, and a redirect is not followed (RFC 8461 section 3.3).
		return failure(obs.ReasonBadAnswer, "HTTP status "+strconv.Itoa(resp.Status))
	}
	set := []dnswire.Record{{Name: name, Class: dnswire.ClassINET, Data: dnswire.TXT{Strings: split(resp.Body)}}}
	return obs.RecordsResult(obs.Records{Set: set})
}

// split cuts body into strings of at most 255 octets, the most that a TXT
// string holds. An empty body gives one empty string.
func split(body []byte) []string {
	var s []string
	for len(body) > 255 {
		s = append(s, string(body[:255]))
		body = body[255:]
	}
	return append(s, string(body))
}

func failure(r obs.Reason, detail string) obs.Result {
	return obs.FailureResult(obs.Failure{Reason: r, Detail: detail})
}
