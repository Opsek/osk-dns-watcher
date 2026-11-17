// Package certlog reads, from the search API of SSLMate's Cert Spotter, the
// valid certificates that the public certificate logs hold for the names of
// a domain. A run that a failure, a refusal or an answer of another form
// stops is not usable, and what it did not read never counts as no
// certificate: the issuances read before stay known, and the list is
// complete only after a run that ended at an empty page.
package certlog

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/httpclient"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// DefaultURL is the issuances endpoint of SSLMate's Cert Spotter.
const DefaultURL = "https://api.certspotter.com/v1/issuances"

// Caps of one run and of one domain. A page that would take the known set
// over a cap of the domain is not added: the run fails with "too many".
const (
	MaxBody        = 4194304 // octets of one page
	MaxPages       = 10      // requests in one run
	MaxKnown       = 10000   // valid issuances of one domain
	MaxDomainNames = 100000  // names of the valid issuances of one domain
)

// Relist is the time between two readings of the whole list from the
// beginning, beside what is known, so that an issuance that a faulty cursor
// passed over is found within it.
const Relist = 24 * time.Hour

// Getter is what a run needs of the HTTPS client.
type Getter interface {
	Get(ctx context.Context, rawURL string, limit int64, headers ...httpclient.Header) (httpclient.Response, error)
}

// Source reads the certificates of one domain. It keeps what earlier runs
// read in memory only, and runs one run at a time.
type Source struct {
	get         Getter
	request     string              // the URL of a request, without the cursor
	headers     []httpclient.Header // the key, when one is set
	check       obs.Key
	cursor      string         // the highest ID read; a request asks only for IDs above it
	known       []obs.Issuance // valid issuances, in ID order, no ID or TBS twice
	wait        time.Time      // no request before it
	waitFailure string         // the failure of a run inside the wait; "" after an empty page
	relistAt    time.Time      // a relist is due from then on; set by the first complete listing
	relistLong  bool           // a relist did not fit one run; none is tried again
	// complete: known holds every valid issuance of the source. A run that
	// ends at an empty page sets it, a run that ends after MaxPages requests
	// clears it; a failure and a relist leave it as it is.
	complete bool
}

// New makes the source of domain. rawURL is the endpoint, with no query; key
// is the API key, "" for none. Only the domain and the cursor, which holds
// digits only, enter the URL of a request.
func New(g Getter, rawURL, key string, domain dnswire.Name) *Source {
	s := &Source{
		get: g,
		request: rawURL + "?domain=" + url.QueryEscape(strings.TrimSuffix(domain.Lower().String(), ".")) +
			"&include_subdomains=true&expand=dns_names&expand=issuer&expand=issuer.caa_domains",
		check: obs.CertificatesKey(domain),
	}
	if key != "" {
		s.headers = []httpclient.Header{{Name: "Authorization", Value: "Bearer " + key}}
	}
	return s
}

// Run asks the source for the issuances above the cursor, in at most
// MaxPages requests, or makes the relist when one is due, and gives every
// known issuance that is valid at start.
func (s *Source) Run(ctx context.Context, start time.Time) obs.Certificates {
	s.known = slices.DeleteFunc(s.known, func(is obs.Issuance) bool { return !is.NotAfter.After(start) })
	c := obs.Certificates{Key: s.check, Start: start}
	// Inside a wait no request is made. After an empty page the wait means
	// "nothing new before then", so the run is usable; after a refusal or
	// "too many" it means "not now".
	if start.Before(s.wait) {
		c.Failure = s.waitFailure
	} else {
		c.Asked = true
		c.Failure = s.ask(ctx, start)
	}
	c.Usable = c.Failure == ""
	c.Complete = s.complete
	c.Issuances = slices.Clone(s.known)
	return c
}

// ask makes the requests of one run and gives its failure, "" for none.
func (s *Source) ask(ctx context.Context, start time.Time) string {
	if s.complete && !s.relistLong && !start.Before(s.relistAt) {
		return s.relist(ctx, start)
	}
	var done bool
	failure := s.pages(ctx, start, &s.cursor, &done)
	if failure == "" {
		s.complete = done
	}
	if done && s.relistAt.IsZero() {
		s.relistAt = start.Add(Relist)
	}
	return failure
}

// relist reads the list from the beginning with a cursor of its own, in this
// run only. It never starts the main listing again and never makes the list
// incomplete. A list too long for one run is not read again.
//
// A failed relist is tried again an hour later, and the runs between poll as
// usual, so that a relist that keeps failing does not stop the polls. A wait
// that the failure set still holds every request back, the relist included.
//
// A relist that ends at an empty page has read the source's real highest ID
// and known every ID below it, so the main cursor takes that ID: a cursor
// that a faulty ID moved too far heals, also when the source drops that ID
// later. An empty list leaves the cursor as it is, so that a wrong empty
// answer does not turn every later poll into a request without a cursor.
func (s *Source) relist(ctx context.Context, start time.Time) string {
	cursor := ""
	var done bool
	failure := s.pages(ctx, start, &cursor, &done)
	switch {
	case done:
		s.relistAt = start.Add(Relist)
		if cursor != "" {
			s.cursor = cursor
		}
	case failure == "":
		s.relistLong = true
	default:
		s.relistAt = start.Add(time.Hour)
	}
	return failure
}

// pages asks for the pages above *cursor, at most MaxPages, adds what is new
// to the known set and gives the failure, "" for none. It sets *done only
// when a page came back empty. The pages read before a failure stay known:
// they are real.
func (s *Source) pages(ctx context.Context, start time.Time, cursor *string, done *bool) string {
	for range MaxPages {
		u := s.request
		if *cursor != "" {
			u += "&after=" + *cursor
		}
		resp, err := s.get.Get(ctx, u, MaxBody, s.headers...)
		switch {
		case errors.Is(err, httpclient.ErrTimeout):
			return "timeout"
		case errors.Is(err, httpclient.ErrTooLarge):
			return "too large"
		case err != nil:
			return "network"
		case resp.Status == 429:
			s.wait, s.waitFailure = start.Add(resp.RetryAfter), "rate-limited"
			return "rate-limited"
		case resp.Status != 200:
			if resp.RetryAfter > 0 {
				s.wait, s.waitFailure = start.Add(resp.RetryAfter), "rate-limited"
			}
			return "status " + strconv.Itoa(resp.Status)
		}
		page, err := Parse(resp.Body)
		// A source that ignores the cursor repeats old pages: the run would
		// never reach an empty page and still read as usable.
		if err != nil || len(page) > 0 && compareID(page[0].ID, *cursor) <= 0 {
			return "malformed"
		}
		if len(page) == 0 {
			// A long wait after an empty page would blind the check while
			// every run reads as usable. A wait after a refusal is kept
			// whole: its runs are failures, which are told.
			s.wait, s.waitFailure = start.Add(min(resp.RetryAfter, time.Hour)), ""
			*done = true
			return ""
		}
		known := merged(s.known, page, start)
		if len(known) > MaxKnown || nameCount(known) > MaxDomainNames {
			// One faulty answer costs an hour; a domain that is truly too
			// large fails each hour, which is told.
			s.wait, s.waitFailure = start.Add(time.Hour), "too many"
			return "too many"
		}
		s.known, *cursor = known, page[len(page)-1].ID
	}
	return ""
}

// merged gives a copy of known with each issuance of the page that is valid
// at start and new: of two issuances with one ID or one TBS, the first wins.
// A relist can find an ID below known ones, so each goes to its place.
func merged(known, page []obs.Issuance, start time.Time) []obs.Issuance {
	known = slices.Clone(known)
	for _, is := range page {
		i, idKnown := slices.BinarySearchFunc(known, is.ID, func(k obs.Issuance, id string) int { return compareID(k.ID, id) })
		sameTBS := func(k obs.Issuance) bool { return k.TBS == is.TBS }
		if is.NotAfter.After(start) && !idKnown && !slices.ContainsFunc(known, sameTBS) {
			known = slices.Insert(known, i, is)
		}
	}
	return known
}

func nameCount(list []obs.Issuance) int {
	n := 0
	for _, is := range list {
		n += len(is.Names)
	}
	return n
}
