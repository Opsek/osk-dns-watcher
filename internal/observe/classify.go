package observe

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// The response codes that classify tells apart; dnswire only names them.
const (
	rcodeNoError   dnswire.Rcode = 0
	rcodeServFail  dnswire.Rcode = 2
	rcodeNXDomain  dnswire.Rcode = 3
	rcodeRefused   dnswire.Rcode = 5
	rcodeBadCookie dnswire.Rcode = 23
)

// classify reads m, the answer of a server of zone to q. Only an
// authoritative answer whose SOA lies between zone and the asked name may
// say that records do not exist; every other answer without the records is
// a failure, so a lame, lying or broken server never reads as an empty set.
// RRSIG and NSEC records enter a set only when they are the type asked;
// records of a class other than IN are ignored.
func classify(kind obs.Kind, zone dnswire.Name, q dnswire.Question, m *dnswire.Message) obs.Result {
	switch {
	case m.Truncated:
		// Exchange asks again over TCP, so this answer came truncated over TCP.
		return failResult(obs.ReasonTruncated, "the answer is truncated")
	case m.Rcode == rcodeRefused:
		return failResult(obs.ReasonRefused, extendedErrors(m))
	case m.Rcode == rcodeServFail:
		return failResult(obs.ReasonServFail, extendedErrors(m))
	case m.Rcode != rcodeNoError && m.Rcode != rcodeNXDomain:
		return failResult(obs.ReasonRcode, m.Rcode.String())
	}
	// The NS set at a cut belongs to the child zone, so a parent server
	// answers for it with a referral, not with authority (RFC 2181 §6.1).
	if kind == obs.KindDelegation {
		if cut, _, glue, ok := referral(zone, q.Name, m); ok && cut.Equal(q.Name) {
			return obs.RecordsResult(obs.Records{Set: rrset(m.Authority, cut, dnswire.TypeNS), Glue: glue})
		}
	}
	if !m.Authoritative {
		return failResult(obs.ReasonLame, "the answer is not authoritative (AA clear)")
	}
	if set := rrset(m.Answer, q.Name, q.Type); len(set) > 0 {
		r := obs.Records{Set: set}
		if kind == obs.KindDelegation {
			r.Glue = glueOf(zone, nsHosts(set), m.Additional)
		}
		return obs.RecordsResult(r)
	}
	if q.Type != dnswire.TypeCNAME {
		// The CNAME wins over the rcode: with NXDOMAIN, the rcode is that
		// of the alias target, not of the name asked (RFC 6604).
		cnames := rrset(m.Answer, q.Name, dnswire.TypeCNAME)
		if len(cnames) > 1 {
			// A name has at most one CNAME (RFC 2181 §10.1).
			return failResult(obs.ReasonBadAnswer, fmt.Sprintf("%d CNAME records at %s", len(cnames), q.Name))
		}
		if len(cnames) == 1 {
			return obs.RecordsResult(obs.Records{Set: cnames})
		}
	}
	soa, problem := negativeSOA(zone, q.Name, m.Authority)
	if problem != "" {
		return failResult(obs.ReasonBadAnswer, problem)
	}
	if m.Rcode == rcodeNXDomain {
		return obs.NoNameResult(obs.NoName{SOA: soa})
	}
	if compactDenial(q.Name, m.Authority) {
		return obs.NoNameResult(obs.NoName{SOA: soa, Compact: true})
	}
	return obs.NoDataResult(obs.NoData{SOA: soa})
}

// referral reads m as a referral from a server of zone toward target: a
// NOERROR answer without AA and without answer records, whose NS records all
// name one cut strictly under zone, with target at or under the cut. A
// referral that does not lead down toward target is refused, so a server
// cannot send a walk sideways, up or around in a loop.
func referral(zone, target dnswire.Name, m *dnswire.Message) (cut dnswire.Name, hosts []dnswire.Name, glue []dnswire.Record, ok bool) {
	if m.Rcode != rcodeNoError || m.Authoritative || len(m.Answer) > 0 {
		return cut, nil, nil, false
	}
	var ns []dnswire.Record
	for _, r := range m.Authority {
		if _, isNS := r.Data.(dnswire.NS); isNS && r.Class == dnswire.ClassINET {
			ns = append(ns, r)
		}
	}
	if len(ns) == 0 {
		return cut, nil, nil, false
	}
	cut = ns[0].Name
	for _, r := range ns {
		if !r.Name.Equal(cut) {
			return cut, nil, nil, false
		}
	}
	if cut.Equal(zone) || !cut.IsSubdomainOf(zone) || !target.IsSubdomainOf(cut) {
		return cut, nil, nil, false
	}
	seen := map[string]bool{}
	for _, h := range nsHosts(ns) {
		if !seen[h.Key()] {
			seen[h.Key()] = true
			hosts = append(hosts, h)
		}
	}
	return cut, hosts, glueOf(zone, hosts, m.Additional), true
}

func rrset(records []dnswire.Record, owner dnswire.Name, t dnswire.Type) []dnswire.Record {
	var set []dnswire.Record
	for _, r := range records {
		if r.Class == dnswire.ClassINET && r.Type() == t && r.Name.Equal(owner) {
			set = append(set, r)
		}
	}
	return set
}

func nsHosts(records []dnswire.Record) []dnswire.Name {
	var hosts []dnswire.Name
	for _, r := range records {
		if d, ok := r.Data.(dnswire.NS); ok {
			hosts = append(hosts, d.Host)
		}
	}
	return hosts
}

// glueOf returns the A and AAAA records of additional that give an address
// of one of hosts. A server speaks only for its own zone, so an address
// record outside zone is dropped: it could send the queries anywhere.
func glueOf(zone dnswire.Name, hosts []dnswire.Name, additional []dnswire.Record) []dnswire.Record {
	isHost := map[string]bool{}
	for _, h := range hosts {
		isHost[h.Key()] = true
	}
	var glue []dnswire.Record
	for _, r := range additional {
		t := r.Type()
		if r.Class == dnswire.ClassINET && (t == dnswire.TypeA || t == dnswire.TypeAAAA) &&
			r.Name.IsSubdomainOf(zone) && isHost[r.Name.Key()] {
			glue = append(glue, r)
		}
	}
	return glue
}

// negativeSOA returns the SOA of a denial, or a problem. The SOA must be the
// only one and lie between zone and name: else a server could deny names
// of a zone it does not serve.
func negativeSOA(zone, name dnswire.Name, authority []dnswire.Record) (dnswire.Record, string) {
	var soas []dnswire.Record
	for _, r := range authority {
		if r.Class == dnswire.ClassINET && r.Type() == dnswire.TypeSOA {
			soas = append(soas, r)
		}
	}
	if len(soas) != 1 {
		return dnswire.Record{}, fmt.Sprintf("%d SOA records in the authority section of a denial", len(soas))
	}
	owner := soas[0].Name
	if !name.IsSubdomainOf(owner) || !owner.IsSubdomainOf(zone) {
		return dnswire.Record{}, fmt.Sprintf("the SOA of %s does not lie between the zone %s and the name %s", owner, zone, name)
	}
	return soas[0], ""
}

// compactDenial reports the compact form of "no such name" (RFC 9824): a
// NOERROR answer whose NSEC at the name lists the type NXNAME.
func compactDenial(name dnswire.Name, authority []dnswire.Record) bool {
	for _, r := range authority {
		d, ok := r.Data.(dnswire.NSEC)
		if ok && r.Class == dnswire.ClassINET && r.Name.Equal(name) && slices.Contains(d.Types, dnswire.TypeNXNAME) {
			return true
		}
	}
	return false
}

// extendedErrors lists the extended errors of m (RFC 8914), each as its
// code and its quoted text, which the server chose.
func extendedErrors(m *dnswire.Message) string {
	var parts []string
	for _, e := range m.EDNS.ExtendedErrors() {
		parts = append(parts, fmt.Sprintf("%d %q", e.InfoCode, e.ExtraText))
	}
	return strings.Join(parts, "; ")
}

func failResult(reason obs.Reason, detail string) obs.Result {
	return obs.FailureResult(obs.Failure{Reason: reason, Detail: detail})
}
