package decide

import (
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// CertInput is what DecideCertificates judges: one run of the certificates
// check of a domain.
type CertInput struct {
	Expect       *expect.File
	Open         []Finding // the open findings of the certificates check of the domain
	Certificates obs.Certificates
	Now          time.Time
	FailingSince time.Time     // start of the unbroken series of runs that were not usable; zero after a usable run
	FailLimit    time.Duration // how long such a series may last before check-failing; 0: never
}

// CertificateFindings judges the certificates of one run against f, in Rule
// order. A file of another domain covers nothing. Only names at or under the
// domain are judged; another watched domain judges the rest in its own run.
//
// No text holds an ID, a date or a count, so a renewed certificate for the
// same names and authority gives the same findings and sends nothing.
func CertificateFindings(f *expect.File, c obs.Certificates) []Finding {
	if f == nil || !c.Key.Domain.Equal(f.Domain) {
		return nil
	}
	// A certificate that exists was allowed under its authority's own reading
	// of the line, so the line blames the authority only when the reading that
	// is permissive in every part does not name it.
	lines := newCAALines(f, PermissiveReading, PermissiveReading)
	known := knownNames(f)
	issued := map[string]struct{}{} // issuer: the Seen texts
	var expected []string           // issuer: the parts of Expected
	names := map[string]struct{}{}  // hostnames and certname: the Seen texts
	wilds := map[string]struct{}{}
	for _, iss := range c.Issuances {
		for _, n := range iss.Names {
			if !n.IsSubdomainOf(f.Domain) {
				continue
			}
			wild := IsWildcardOwner(n)
			text := n.Lower().String()
			if !known[n.Key()] {
				if wild {
					wilds[text] = struct{}{}
				} else {
					names[text] = struct{}{}
				}
			}
			base := n
			if wild {
				base = n.Parent()
			}
			l, ok := lines.at(base)
			caaOK := !ok || slices.ContainsFunc(l.alts[PermissiveReading], func(p Policy) bool { return p.Names(wild, iss.Issuer.CAA) })
			linesOK := len(f.Issuers) == 0 || slices.ContainsFunc(iss.Issuer.CAA, func(a string) bool { return slices.Contains(f.Issuers, a) })
			if caaOK && linesOK {
				continue
			}
			issued[text+" from "+authority(iss.Issuer)] = struct{}{}
			if !caaOK {
				expected = append(expected, l.line.Name.Lower().String()+" CAA "+l.line.FormText())
			}
			if !linesOK {
				expected = append(expected, "issuer "+strings.Join(f.Issuers, " "))
			}
		}
	}
	var found []Finding
	found = appendCertFinding(found, RuleIssuer, c, joinSorted(expected, "; "), issued)
	found = appendCertFinding(found, RuleCertName, c, "", wilds)
	return appendCertFinding(found, RuleHostnames, c, "", names)
}

// authority is how a Seen text names the authority of a certificate.
func authority(i obs.Issuer) string {
	if len(i.CAA) == 0 {
		return "an authority with no CAA name (" + i.Name + ")"
	}
	return strings.Join(i.CAA, ",")
}

// knownNames gives the names that the file accounts for: the domain, the owner
// of each line that is not a wildcard and each certname line. A wildcard owner
// of a line is left out, so a wildcard name is known only when a certname line
// lists it.
func knownNames(f *expect.File) map[string]bool {
	known := map[string]bool{f.Domain.Key(): true}
	for _, e := range f.Expectations {
		if !IsWildcardOwner(e.Name) {
			known[e.Name.Key()] = true
		}
	}
	for _, n := range f.CertNames {
		known[n.Key()] = true
	}
	return known
}

// appendCertFinding adds a finding of rule r with one Seen for each text, in
// octet order, when there is any text.
func appendCertFinding(found []Finding, r Rule, c obs.Certificates, expected string, texts map[string]struct{}) []Finding {
	if len(texts) == 0 {
		return found
	}
	var seen []Seen
	for _, t := range slices.Sorted(maps.Keys(texts)) {
		seen = append(seen, Seen{Answer: obs.Answer{Received: c.Start}, Text: t})
	}
	return append(found, Finding{Rule: r, Severity: severity(r, 0), Check: c.Key, Expected: expected, Seen: seen, Value: certValue(seen)})
}

func certValue(seen []Seen) string {
	texts := make([]string, len(seen))
	for i, s := range seen {
		texts[i] = s.Text
	}
	return strings.Join(texts, "\n")
}

// joinSorted joins the distinct parts in octet order.
func joinSorted(parts []string, sep string) string {
	slices.Sort(parts)
	return strings.Join(slices.Compact(parts), sep)
}

// DecideCertificates gives the changes of the open alerts of the certificates
// check of a domain. While the listing is not complete the three certificate
// rules stay as they are: the lists would grow from run to run, and a
// certificate that an open alert shows may not be known yet.
func DecideCertificates(in CertInput) []Change {
	c := in.Certificates
	var found []Finding
	if c.Complete {
		found = CertificateFindings(in.Expect, c)
	}
	if !c.Usable && !in.FailingSince.IsZero() && in.FailLimit > 0 && in.Now.Sub(in.FailingSince) >= in.FailLimit {
		found = append(found, Finding{Rule: RuleCheckFailing, Severity: severity(RuleCheckFailing, 0), Check: c.Key,
			Value: "no usable answer for " + in.FailLimit.String()})
	}
	open := firstOpen(in.Open, c.Key.String())
	changes := openOrUpdate(found, open, in.Now)
	for _, was := range open {
		ends := c.Complete && !hasRule(found, was.Rule)
		if was.Rule == RuleCheckFailing {
			ends = c.Usable
		}
		if ends {
			changes = append(changes, Change{Op: OpResolve, Finding: was, At: in.Now})
		}
	}
	return changes
}
