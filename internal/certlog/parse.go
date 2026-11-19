package certlog

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// Caps of one page. A list longer than its cap makes the page malformed: a
// cut list could hide a name.
const (
	MaxPage  = 1000 // issuances of one page
	MaxNames = 1000 // dns_names of one issuance
	MaxCAA   = 16   // caa_domains of one issuer
)

var errPage = fmt.Errorf("want a JSON array of at most %d issuances", MaxPage)

// issuance is one element of a page. A pointer is nil when its key is absent
// or null, which must not read as an empty value.
type issuance struct {
	ID        *string    `json:"id"`
	TBS       *string    `json:"tbs_sha256"`
	NotBefore *time.Time `json:"not_before"`
	NotAfter  *time.Time `json:"not_after"`
	DNSNames  *[]string  `json:"dns_names"`
	Issuer    *struct {
		FriendlyName *string   `json:"friendly_name"`
		CAADomains   *[]string `json:"caa_domains"`
	} `json:"issuer"`
}

// Parse reads one page of the source: the issuances in page order and, in
// each, the names that could not be read. Any fault of the form is an error:
// a page that cannot be read whole is never taken as fewer certificates.
func Parse(body []byte) ([]obs.Issuance, error) {
	var page *[]json.RawMessage
	if err := json.Unmarshal(body, &page); err != nil || page == nil || len(*page) > MaxPage {
		return nil, errPage
	}
	var list []obs.Issuance
	for i, raw := range *page {
		is, err := parseIssuance(raw)
		if err != nil {
			return nil, fmt.Errorf("issuance %d: %w", i, err)
		}
		// The next request asks only for IDs above the last of this page, so
		// a page out of ID order could hide the issuances it skips.
		if i > 0 && compareID(is.ID, list[i-1].ID) <= 0 {
			return nil, fmt.Errorf("issuance %d: id not above the one before", i)
		}
		list = append(list, is)
	}
	return list, nil
}

func parseIssuance(raw json.RawMessage) (obs.Issuance, error) {
	var in issuance
	if err := json.Unmarshal(raw, &in); err != nil {
		return obs.Issuance{}, err
	}
	if key := absent(in); key != "" {
		return obs.Issuance{}, errors.New("no " + key)
	}
	tbs, err := hex.DecodeString(*in.TBS)
	switch {
	case !isID(*in.ID):
		return obs.Issuance{}, errors.New("bad id")
	case err != nil || len(tbs) != sha256.Size:
		return obs.Issuance{}, errors.New("bad tbs_sha256")
	case !in.NotAfter.After(*in.NotBefore):
		return obs.Issuance{}, errors.New("not_after is not after not_before")
	case len(*in.DNSNames) > MaxNames:
		return obs.Issuance{}, fmt.Errorf("more than %d dns_names", MaxNames)
	case len(*in.Issuer.CAADomains) > MaxCAA:
		return obs.Issuance{}, fmt.Errorf("more than %d caa_domains", MaxCAA)
	}
	names, unread := readNames(*in.DNSNames)
	return obs.Issuance{
		ID:        *in.ID,
		TBS:       hex.EncodeToString(tbs),
		Names:     names,
		Unread:    unread,
		Issuer:    obs.Issuer{Name: shortName(in.Issuer.FriendlyName), CAA: caaNames(*in.Issuer.CAADomains)},
		NotBefore: *in.NotBefore,
		NotAfter:  *in.NotAfter,
	}, nil
}

// absent gives the first required key that is absent or null, or "".
func absent(in issuance) string {
	switch {
	case in.ID == nil:
		return "id"
	case in.TBS == nil:
		return "tbs_sha256"
	case in.NotBefore == nil:
		return "not_before"
	case in.NotAfter == nil:
		return "not_after"
	case in.DNSNames == nil:
		return "dns_names"
	case in.Issuer == nil:
		return "issuer"
	case in.Issuer.CAADomains == nil:
		return "caa_domains"
	}
	return ""
}

// isID: 1 to 20 decimal digits with no leading zero, so that of two IDs the
// longer is the higher.
func isID(s string) bool {
	return s != "" && len(s) <= 20 && s[0] != '0' && strings.Trim(s, "0123456789") == ""
}

// compareID orders IDs by value. Twenty digits may not fit in 64 bits.
func compareID(a, b string) int {
	return cmp.Or(cmp.Compare(len(a), len(b)), strings.Compare(a, b))
}

// readNames gives the names of a certificate that Name reads, sorted and
// unique, and the count of the others.
func readNames(list []string) ([]dnswire.Name, int) {
	var names []dnswire.Name
	unread := 0
	for _, s := range list {
		n, ok := Name(s)
		if !ok {
			unread++
			continue
		}
		names = append(names, n)
	}
	slices.SortFunc(names, dnswire.Compare)
	return slices.CompactFunc(names, dnswire.Name.Equal), unread
}

// caaNames gives the names that CAA records use for an issuer, in lower case,
// sorted and unique. Only names of the grammar of RFC 8659 section 4.2 are
// kept: they are compared with CAA records and shown in messages.
func caaNames(list []string) []string {
	var names []string
	for _, s := range list {
		if s = lower(s); issuerName(s) {
			names = append(names, s)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// issuerName reports whether s is an issuer-domain-name in lower case: labels
// of letters, digits and hyphens, with no hyphen first or last.
func issuerName(s string) bool {
	for _, l := range strings.Split(s, ".") {
		if l == "" || strings.Trim(l, ldh) != "" || strings.Trim(l, "-") != l {
			return false
		}
	}
	return true
}

// shortName gives the issuer's name for people when it is 1 to 64 octets of
// printable ASCII, else "-". It reaches messages.
func shortName(p *string) string {
	if p == nil || *p == "" || len(*p) > 64 ||
		strings.ContainsFunc(*p, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		return "-"
	}
	return *p
}
