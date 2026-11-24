package decide

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// ---- helpers: policies ----

func caaC(flags uint8, tag, value string) dnswire.CAA {
	return dnswire.CAA{Flags: flags, Tag: tag, Value: value}
}

func caaIssue(v string) dnswire.CAA { return caaC(0, "issue", v) }
func caaWild(v string) dnswire.CAA  { return caaC(0, "issuewild", v) }

func caaData(set []dnswire.CAA) []dnswire.RData {
	out := make([]dnswire.RData, len(set))
	for i, r := range set {
		out[i] = r
	}
	return out
}

func caaPolicyUnder(r Reading, set ...dnswire.CAA) (Policy, bool) { return PolicyOf(caaData(set), r) }

func caaGrants(gs ...Grant) Class { return Class{Grants: gs} }

// caaBoth is a policy that treats plain names and wildcards alike.
func caaBoth(c Class) Policy { return Policy{Name: c, Wild: c} }

// caaOnly is a policy of one authority for both classes.
func caaOnly(issuers ...string) Policy {
	var gs []Grant
	for _, i := range issuers {
		gs = append(gs, Grant{Issuer: i})
	}
	return caaBoth(caaGrants(gs...))
}

func caaSameGrant(a, b Grant) bool {
	return a.Issuer == b.Issuer && a.Account == b.Account && a.Extra == b.Extra &&
		(a.Methods == nil) == (b.Methods == nil) && slices.Equal(a.Methods, b.Methods)
}

// caaSameClass ignores Grants of a class that allows everything and tells
// no grants from an empty slice.
func caaSameClass(a, b Class) bool {
	if a.Any || b.Any {
		return a.Any == b.Any
	}
	return slices.EqualFunc(a.Grants, b.Grants, caaSameGrant)
}

func caaSamePolicy(a, b Policy) bool {
	return caaSameClass(a.Name, b.Name) && caaSameClass(a.Wild, b.Wild)
}

func caaShow(p Policy) string {
	class := func(c Class) string {
		if c.Any {
			return "any"
		}
		return fmt.Sprintf("%+v", c.Grants)
	}
	return "name " + class(p.Name) + ", wild " + class(p.Wild)
}

// ---- TestCAAPolicyConformance ----

func TestCAAPolicyConformance(t *testing.T) {
	t.Run("PolicyOf", caaPolicyOfRows)
	t.Run("Permits", caaPermitsRows)
	t.Run("Weaker", caaWeakerRows)
	t.Run("Names", caaNamesRows)
	t.Run("Weaker under each reading", caaWeakerReadingRows)
}

func caaMethods(n int) string {
	labels := make([]string, n)
	for i := range labels {
		labels[i] = fmt.Sprintf("m%02d", i+1)
	}
	return strings.Join(labels, ",")
}

func caaMany(n int, tag string) []dnswire.CAA {
	var set []dnswire.CAA
	for i := 0; i < n; i++ {
		set = append(set, caaC(0, tag, fmt.Sprintf("ca%02d.test", i)))
	}
	return set
}

func caaManyGrants(n int) []Grant {
	var gs []Grant
	for i := 0; i < n; i++ {
		gs = append(gs, Grant{Issuer: fmt.Sprintf("ca%02d.test", i)})
	}
	return gs
}

func caaPolicyOfRows(t *testing.T) {
	g := func(issuer string) Grant { return Grant{Issuer: issuer} }
	none := Class{}
	anyClass := Class{Any: true}
	rows := []struct {
		name string
		set  []dnswire.CAA
		want Policy
	}{
		{"RFC 8659 4.1 tag case of issue", []dnswire.CAA{caaC(0, "ISSUE", "ca.test")}, caaOnly("ca.test")},
		{"RFC 8659 4.1 tag case of issuewild", []dnswire.CAA{caaC(0, "IssueWild", "ca.test")},
			Policy{Name: anyClass, Wild: caaGrants(g("ca.test"))}},
		{"RFC 8659 4.1 critical unknown tag beside an issue allows nothing", []dnswire.CAA{caaC(128, "tbs", "x"), caaIssue("ca.test")}, Policy{}},
		{"RFC 8659 4.1 critical unknown tag alone allows nothing", []dnswire.CAA{caaC(128, "tbs", "x")}, Policy{}},
		{"RFC 8659 4.1 critical unknown tag in capitals", []dnswire.CAA{caaC(128, "TBS", "x"), caaIssue("ca.test")}, Policy{}},
		{"RFC 8659 4.1 critical flag with other bits set", []dnswire.CAA{caaC(129, "tbs", "x"), caaIssue("ca.test")}, Policy{}},
		{"RFC 8659 4.1 critical flag on issue is ordinary", []dnswire.CAA{caaC(128, "issue", "ca.test")}, caaOnly("ca.test")},
		{"RFC 8659 4.1 critical flag on a tag of issue in capitals is ordinary", []dnswire.CAA{caaC(128, "ISSUE", "ca.test")}, caaOnly("ca.test")},
		{"RFC 8659 4.1 critical flag on issuewild is ordinary", []dnswire.CAA{caaC(128, "issuewild", "ca.test")},
			Policy{Name: anyClass, Wild: caaGrants(g("ca.test"))}},
		{"RFC 8659 4.1 critical flag on iodef is ordinary", []dnswire.CAA{caaC(128, "iodef", "mailto:a@corp.test")}, OpenPolicy},
		{"RFC 8659 4.1 unknown tag without the flag restricts nothing", []dnswire.CAA{caaC(0, "tbs", "x")}, OpenPolicy},
		{"RFC 8659 4.1 unknown tag beside an issue", []dnswire.CAA{caaC(0, "tbs", "x"), caaIssue("ca.test")}, caaOnly("ca.test")},
		{"RFC 8659 4.1 reserved flag bit is ignored", []dnswire.CAA{caaC(1, "issue", "ca.test")}, caaOnly("ca.test")},
		{"RFC 8659 4.1 reserved flag bits on an unknown tag", []dnswire.CAA{caaC(127, "tbs", "x")}, OpenPolicy},
		{"RFC 8659 3 and 4.4 iodef alone restricts nothing", []dnswire.CAA{caaC(0, "iodef", "mailto:a@corp.test")}, OpenPolicy},
		{"RFC 8659 4.4 iodef beside an issue gives no permission", []dnswire.CAA{caaC(0, "iodef", "mailto:a@corp.test"), caaIssue("ca.test")}, caaOnly("ca.test")},
		{"RFC 8659 4.2 issue semicolon allows nobody", []dnswire.CAA{caaIssue(";")}, caaBoth(none)},
		{"RFC 8659 4.2 empty issue value allows nobody", []dnswire.CAA{caaIssue("")}, caaBoth(none)},
		{"RFC 8659 4.2 semicolon beside a named issuer", []dnswire.CAA{caaIssue(";"), caaIssue("ca.test")}, caaOnly("ca.test")},
		{"RFC 8659 4.2 two issuers", []dnswire.CAA{caaIssue("ca2.test"), caaIssue("ca1.test")}, caaOnly("ca1.test", "ca2.test")},
		{"RFC 8659 4.2 issuer in capitals", []dnswire.CAA{caaIssue("CA.Test")}, caaOnly("ca.test")},
		{"RFC 8659 4.2 blanks around the issuer", []dnswire.CAA{caaIssue(" \tca.test \t")}, caaOnly("ca.test")},
		{"RFC 8659 4.2 the same issuer twice is one grant", []dnswire.CAA{caaIssue("ca.test"), caaIssue("CA.test")}, caaOnly("ca.test")},
		{"RFC 8659 4.3 issuewild alone leaves plain names unrestricted", []dnswire.CAA{caaWild("ca.test")},
			Policy{Name: anyClass, Wild: caaGrants(g("ca.test"))}},
		{"RFC 8659 4.3 issue and issuewild each class its own", []dnswire.CAA{caaIssue("ca1.test"), caaWild("ca2.test")},
			Policy{Name: caaGrants(g("ca1.test")), Wild: caaGrants(g("ca2.test"))}},
		{"RFC 8659 4.3 issue alone covers wildcards", []dnswire.CAA{caaIssue("ca1.test"), caaIssue("ca2.test")}, caaOnly("ca1.test", "ca2.test")},
		{"RFC 8659 4.3 issuewild semicolon beside an issue", []dnswire.CAA{caaIssue("ca.test"), caaWild(";")},
			Policy{Name: caaGrants(g("ca.test")), Wild: none}},
		{"RFC 8659 4.3 issuewild semicolon alone", []dnswire.CAA{caaWild(";")}, Policy{Name: anyClass, Wild: none}},
		{"RFC 8659 4.3 two issuewild add up", []dnswire.CAA{caaWild("ca2.test"), caaWild("ca1.test")},
			Policy{Name: anyClass, Wild: caaGrants(g("ca1.test"), g("ca2.test"))}},
		{"RFC 8657 3 accounturi", []dnswire.CAA{caaIssue("ca.test; accounturi=https://ca.test/acct/1")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Account: "https://ca.test/acct/1"}))},
		{"RFC 8657 3 accounturi with blanks around the tag and the value", []dnswire.CAA{caaIssue("ca.test ; accounturi = x")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Account: "x"}))},
		{"RFC 8657 3 two accounturi allow nothing", []dnswire.CAA{caaIssue("ca.test; accounturi=a; accounturi=b")}, caaBoth(none)},
		{"RFC 8657 3 two accounturi drop only that grant", []dnswire.CAA{caaIssue("ca.test; accounturi=a; accounturi=b"), caaIssue("ca2.test")}, caaOnly("ca2.test")},
		{"RFC 8657 3 the same accounturi twice is still two", []dnswire.CAA{caaIssue("ca.test; accounturi=a; accounturi=a")}, caaBoth(none)},
		{"RFC 8657 3 empty accounturi allows nothing", []dnswire.CAA{caaIssue("ca.test; accounturi=")}, caaBoth(none)},
		{"RFC 8657 4 validationmethods in lower case and sorted", []dnswire.CAA{caaIssue("ca.test; validationmethods=HTTP-01,dns-01")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Methods: []string{"dns-01", "http-01"}}))},
		{"RFC 8657 4 validationmethods without duplicates", []dnswire.CAA{caaIssue("ca.test; validationmethods=dns-01,DNS-01")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Methods: []string{"dns-01"}}))},
		{"RFC 8657 4 validationmethods with no label allows nothing", []dnswire.CAA{caaIssue("ca.test; validationmethods=")}, caaBoth(none)},
		{"RFC 8657 4 validationmethods with an empty label allows nothing", []dnswire.CAA{caaIssue("ca.test; validationmethods=dns-01,")}, caaBoth(none)},
		{"RFC 8657 4 validationmethods with a bad octet allows nothing", []dnswire.CAA{caaIssue("ca.test; validationmethods=dns_01")}, caaBoth(none)},
		{"RFC 8657 4 two validationmethods allow nothing", []dnswire.CAA{caaIssue("ca.test; validationmethods=dns-01; validationmethods=http-01")}, caaBoth(none)},
		{"RFC 8657 4 sixteen labels are kept", []dnswire.CAA{caaIssue("ca.test; validationmethods=" + caaMethods(16))},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Methods: strings.Split(caaMethods(16), ",")}))},
		{"RFC 8657 4 seventeen labels count as any method", []dnswire.CAA{caaIssue("ca.test; validationmethods=" + caaMethods(17))}, caaOnly("ca.test")},
		{"RFC 8657 3 and 4 account and methods together", []dnswire.CAA{caaIssue("ca.test; accounturi=a; validationmethods=dns-01")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Account: "a", Methods: []string{"dns-01"}}))},
		{"RFC 8659 4.2 opaque parameter is required as written", []dnswire.CAA{caaIssue("ca.test; policy=ev")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Extra: "policy=ev"}))},
		{"RFC 8659 4.2 opaque parameters sorted and joined by a semicolon", []dnswire.CAA{caaIssue("ca.test; z=1; a=2")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Extra: "a=2;z=1"}))},
		{"RFC 8659 4.2 opaque parameter with blanks around the equals sign", []dnswire.CAA{caaIssue("ca.test; policy = ev")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Extra: "policy=ev"}))},
		{"RFC 8659 4.2 parameter without an equals sign is opaque", []dnswire.CAA{caaIssue("ca.test; flag")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Extra: "flag"}))},
		{"RFC 8657 3 accounturi tag in capitals is an opaque parameter", []dnswire.CAA{caaIssue("ca.test; AccountURI=x")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Extra: "AccountURI=x"}))},
		{"RFC 8657 4 validationmethods tag in capitals is an opaque parameter", []dnswire.CAA{caaIssue("ca.test; ValidationMethods=dns-01")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Extra: "ValidationMethods=dns-01"}))},
		{"RFC 8659 4.2 empty pieces between semicolons are skipped", []dnswire.CAA{caaIssue("ca.test;;")}, caaOnly("ca.test")},
		{"RFC 8659 4.2 a value that has no issuer but parameters allows nothing", []dnswire.CAA{caaIssue("; accounturi=x")}, caaBoth(none)},
		{"RFC 8659 4.2 a value of semicolons allows nothing", []dnswire.CAA{caaIssue(";;")}, caaBoth(none)},
		{"RFC 8659 4.2 a value of blanks allows nothing", []dnswire.CAA{caaIssue("   ")}, caaBoth(none)},
		{"RFC 8659 4.2 grammar departure: a trailing semicolon that the RFC reads as no issuer grants", []dnswire.CAA{caaIssue("evil.test;")}, caaOnly("evil.test")},
		{"RFC 8659 4.2 grammar departure: two semicolons that the RFC reads as no issuer grant", []dnswire.CAA{caaIssue("evil.test;;")}, caaOnly("evil.test")},
		{"RFC 8659 4.2 grammar departure: a blank inside the name is a parameter, not the end of a grant", []dnswire.CAA{caaIssue("ca1 test")},
			caaBoth(caaGrants(Grant{Issuer: "ca1", Extra: "test"}))},
		{"RFC 8657 3 grammar departure: a parameter without the semicolon still counts", []dnswire.CAA{caaIssue("ca.test accounturi=x")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Account: "x"}))},
		{"RFC 8659 4.2 grammar departure: an octet outside the name ends the issuer", []dnswire.CAA{caaIssue("ca_1.test")},
			caaBoth(caaGrants(Grant{Issuer: "ca", Extra: "_1.test"}))},
		{"order: grants sorted by issuer", []dnswire.CAA{caaIssue("b.test"), caaIssue("a.test"), caaIssue("c.test")}, caaOnly("a.test", "b.test", "c.test")},
		{"order: the same issuer sorted by account", []dnswire.CAA{caaIssue("ca.test; accounturi=b"), caaIssue("ca.test; accounturi=a"), caaIssue("ca.test")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test"}, Grant{Issuer: "ca.test", Account: "a"}, Grant{Issuer: "ca.test", Account: "b"}))},
		{"bound: 64 grants are kept", caaMany(64, "issue"), caaBoth(caaGrants(caaManyGrants(64)...))},
		{"bound: 65 issue grants are any", caaMany(65, "issue"), Policy{Name: anyClass, Wild: anyClass}},
		{"order: the same account sorted by the methods joined by a comma", []dnswire.CAA{caaIssue("ca.test; validationmethods=http-01"), caaIssue("ca.test; validationmethods=dns-01,http-01"),
			caaIssue("ca.test; validationmethods=dns-01"), caaIssue("ca.test")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test"}, Grant{Issuer: "ca.test", Methods: []string{"dns-01"}}, Grant{Issuer: "ca.test", Methods: []string{"dns-01", "http-01"}}, Grant{Issuer: "ca.test", Methods: []string{"http-01"}}))},
		{"order: the account before the methods", []dnswire.CAA{caaIssue("ca.test; accounturi=a"), caaIssue("ca.test; validationmethods=dns-01")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Methods: []string{"dns-01"}}, Grant{Issuer: "ca.test", Account: "a"}))},
		{"order: the methods before the extra", []dnswire.CAA{caaIssue("ca.test; validationmethods=dns-01; a=1"), caaIssue("ca.test; validationmethods=dns-01"), caaIssue("ca.test; z=1")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Extra: "z=1"}, Grant{Issuer: "ca.test", Methods: []string{"dns-01"}}, Grant{Issuer: "ca.test", Methods: []string{"dns-01"}, Extra: "a=1"}))},
		{"order: the extra", []dnswire.CAA{caaIssue("ca.test; z=1"), caaIssue("ca.test; a=1")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Extra: "a=1"}, Grant{Issuer: "ca.test", Extra: "z=1"}))},
		{"order: octets, not numbers", []dnswire.CAA{caaIssue("ca.test; accounturi=a10"), caaIssue("ca.test; accounturi=a9")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Account: "a10"}, Grant{Issuer: "ca.test", Account: "a9"}))},
		{"bound: 65 records with 64 different grants are kept", append(caaMany(64, "issue"), caaIssue("CA00.test")), caaBoth(caaGrants(caaManyGrants(64)...))},
		{"bound: 17 labels of the same name count as any method", []dnswire.CAA{caaIssue("ca.test; validationmethods=" + strings.Repeat("dns-01,", 16) + "dns-01")}, caaOnly("ca.test")},
		{"bound: 16 labels of the same name are one method", []dnswire.CAA{caaIssue("ca.test; validationmethods=" + strings.Repeat("dns-01,", 15) + "dns-01")},
			caaBoth(caaGrants(Grant{Issuer: "ca.test", Methods: []string{"dns-01"}}))},
		{"bound: one bad label among 17 gives no grant", []dnswire.CAA{caaIssue("ca.test; validationmethods=" + caaMethods(16) + ",a_b")}, caaBoth(none)},
		{"bound: an empty label among 17 gives no grant", []dnswire.CAA{caaIssue("ca.test; validationmethods=" + caaMethods(16) + ",")}, caaBoth(none)},
		{"bound: 65 issuewild grants make only wildcards any", append(caaMany(65, "issuewild"), caaIssue("ca.test")),
			Policy{Name: caaGrants(g("ca.test")), Wild: anyClass}},
	}
	// The table states the strict reading. The permissive reading differs in
	// the rows named here, and gives the table's policy in every other.
	permissive := map[string]Policy{
		"RFC 8659 4.1 critical unknown tag beside an issue allows nothing": caaOnly("ca.test"),
		"RFC 8659 4.1 critical unknown tag alone allows nothing":           OpenPolicy,
		"RFC 8659 4.1 critical unknown tag in capitals":                    caaOnly("ca.test"),
		"RFC 8659 4.1 critical flag with other bits set":                   caaOnly("ca.test"),
		"RFC 8657 3 two accounturi allow nothing":                          caaOnly("ca.test"),
		"RFC 8657 3 two accounturi drop only that grant":                   caaOnly("ca.test", "ca2.test"),
		"RFC 8657 3 the same accounturi twice is still two":                caaOnly("ca.test"),
		"RFC 8657 3 empty accounturi allows nothing":                       caaOnly("ca.test"),
		"RFC 8657 4 validationmethods with no label allows nothing":        caaOnly("ca.test"),
		"RFC 8657 4 validationmethods with an empty label allows nothing":  caaOnly("ca.test"),
		"RFC 8657 4 validationmethods with a bad octet allows nothing":     caaOnly("ca.test"),
		"RFC 8657 4 two validationmethods allow nothing":                   caaOnly("ca.test"),
		"bound: one bad label among 17 gives no grant":                     caaOnly("ca.test"),
		"bound: an empty label among 17 gives no grant":                    caaOnly("ca.test"),
	}
	for _, r := range rows {
		for _, rd := range []Reading{StrictReading, PermissiveReading} {
			want := r.want
			if p, ok := permissive[r.name]; ok && rd == PermissiveReading {
				want = p
			}
			t.Run(fmt.Sprintf("%s/reading%d", r.name, rd), func(t *testing.T) {
				got, ok := caaPolicyUnder(rd, r.set...)
				if !ok {
					t.Fatalf("PolicyOf is not ok for a set of CAA records")
				}
				if !caaSamePolicy(got, want) {
					t.Errorf("PolicyOf is\n  %s\nwant\n  %s", caaShow(got), caaShow(want))
				}
			})
		}
	}
	inTable := map[string]bool{}
	for _, r := range rows {
		inTable[r.name] = true
	}
	for name := range permissive {
		if !inTable[name] {
			t.Errorf("the row %q of the permissive reading is not in the table", name)
		}
	}

	t.Run("no set and no policy", func(t *testing.T) {
		for _, set := range [][]dnswire.RData{
			nil,
			{},
			{dnswire.CNAME{Target: decName(t, "edge.dnshost.test.")}},
			{caaIssue("ca.test"), dnswire.CNAME{Target: decName(t, "edge.dnshost.test.")}},
			{dnswire.TXT{Strings: []string{"x"}}},
		} {
			for _, rd := range []Reading{StrictReading, PermissiveReading} {
				if p, ok := PolicyOf(set, rd); ok || !reflect.DeepEqual(p, Policy{}) {
					t.Errorf("PolicyOf(%v, %d) is (%v, %v), want (Policy{}, false)", set, rd, caaShow(p), ok)
				}
			}
		}
	})
	t.Run("OpenPolicy", func(t *testing.T) {
		if !OpenPolicy.Name.Any || !OpenPolicy.Wild.Any || len(OpenPolicy.Name.Grants) != 0 || len(OpenPolicy.Wild.Grants) != 0 {
			t.Errorf("OpenPolicy is %+v", OpenPolicy)
		}
	})
}

func caaPermitsRows(t *testing.T) {
	ca := "ca.test"
	pol := func(name, wild Class) Policy { return Policy{Name: name, Wild: wild} }
	anyC := Class{Any: true}
	none := Class{}
	one := func(g Grant) Class { return caaGrants(g) }
	rows := []struct {
		name string
		p    Policy
		r    Request
		want bool
	}{
		{"any class, plain", pol(anyC, none), Request{Issuer: "x.test"}, true},
		{"any class, empty request", pol(anyC, none), Request{}, true},
		{"any class, wildcard asks the other class", pol(anyC, none), Request{Wildcard: true, Issuer: "x.test"}, false},
		{"wildcard class any", pol(none, anyC), Request{Wildcard: true, Issuer: "x.test"}, true},
		{"wildcard class any, plain asks the other class", pol(none, anyC), Request{Issuer: "x.test"}, false},
		{"no grants", pol(none, none), Request{Issuer: ca}, false},
		{"a grant, the issuer", pol(one(Grant{Issuer: ca}), none), Request{Issuer: ca}, true},
		{"a grant, another issuer", pol(one(Grant{Issuer: ca}), none), Request{Issuer: "evil.test"}, false},
		{"a grant, the empty issuer", pol(one(Grant{Issuer: ca}), none), Request{}, false},
		{"a grant of any account and method allows an account and a method", pol(one(Grant{Issuer: ca}), none), Request{Issuer: ca, Account: "a", Method: "dns-01"}, true},
		{"a grant of the wildcard class does not allow a plain name", pol(none, one(Grant{Issuer: ca})), Request{Issuer: ca}, false},
		{"a grant of the wildcard class allows a wildcard", pol(none, one(Grant{Issuer: ca})), Request{Wildcard: true, Issuer: ca}, true},
		{"a grant of the plain class does not allow a wildcard", pol(one(Grant{Issuer: ca}), none), Request{Wildcard: true, Issuer: ca}, false},
		{"an account, the same", pol(one(Grant{Issuer: ca, Account: "a"}), none), Request{Issuer: ca, Account: "a"}, true},
		{"an account, none asked", pol(one(Grant{Issuer: ca, Account: "a"}), none), Request{Issuer: ca}, false},
		{"an account, another", pol(one(Grant{Issuer: ca, Account: "a"}), none), Request{Issuer: ca, Account: "b"}, false},
		{"methods, one listed", pol(one(Grant{Issuer: ca, Methods: []string{"dns-01", "http-01"}}), none), Request{Issuer: ca, Method: "http-01"}, true},
		{"methods, none asked", pol(one(Grant{Issuer: ca, Methods: []string{"dns-01"}}), none), Request{Issuer: ca}, false},
		{"methods, another", pol(one(Grant{Issuer: ca, Methods: []string{"dns-01"}}), none), Request{Issuer: ca, Method: "http-01"}, false},
		{"extra, the same", pol(one(Grant{Issuer: ca, Extra: "p=1"}), none), Request{Issuer: ca, Extra: "p=1"}, true},
		{"extra, none asked", pol(one(Grant{Issuer: ca, Extra: "p=1"}), none), Request{Issuer: ca}, false},
		{"extra, another", pol(one(Grant{Issuer: ca, Extra: "p=1"}), none), Request{Issuer: ca, Extra: "p=2"}, false},
		{"extra, asked of a grant with none", pol(one(Grant{Issuer: ca}), none), Request{Issuer: ca, Extra: "p=1"}, false},
		{"the second grant allows", pol(caaGrants(Grant{Issuer: "a.test"}, Grant{Issuer: ca, Account: "x"}), none), Request{Issuer: ca, Account: "x"}, true},
		{"every part of a grant must match", pol(one(Grant{Issuer: ca, Account: "a", Methods: []string{"dns-01"}, Extra: "p=1"}), none),
			Request{Issuer: ca, Account: "a", Method: "dns-01", Extra: "p=1"}, true},
		{"every part, the method fails", pol(one(Grant{Issuer: ca, Account: "a", Methods: []string{"dns-01"}, Extra: "p=1"}), none),
			Request{Issuer: ca, Account: "a", Method: "http-01", Extra: "p=1"}, false},
		{"every part, the account fails", pol(one(Grant{Issuer: ca, Account: "a", Methods: []string{"dns-01"}, Extra: "p=1"}), none),
			Request{Issuer: ca, Account: "b", Method: "dns-01", Extra: "p=1"}, false},
		{"every part, the extra fails", pol(one(Grant{Issuer: ca, Account: "a", Methods: []string{"dns-01"}, Extra: "p=1"}), none),
			Request{Issuer: ca, Account: "a", Method: "dns-01"}, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := r.p.Permits(r.r); got != r.want {
				t.Errorf("Permits(%+v) under %s is %v, want %v", r.r, caaShow(r.p), got, r.want)
			}
		})
	}
}

func caaWeakerRows(t *testing.T) {
	ca, ca1, ca2, ca3, evil := "ca.test", "ca1.test", "ca2.test", "ca3.test", "evil.test"
	set := func(rs ...dnswire.CAA) Policy {
		p, ok := caaPolicyUnder(StrictReading, rs...)
		if !ok {
			t.Fatalf("PolicyOf is not ok for %v", rs)
		}
		return p
	}
	g := func(issuer string) Grant { return Grant{Issuer: issuer} }
	rows := []struct {
		name      string
		now, want Policy
		witness   Request
		weaker    bool
	}{
		{"removal of the whole policy, witness the empty issuer", OpenPolicy, set(caaIssue(ca)), Request{}, true},
		{"removal of the wildcard policy alone", Policy{Name: caaGrants(g(ca)), Wild: Class{Any: true}}, caaOnly(ca), Request{Wildcard: true}, true},
		{"removal against a policy that allows nobody", OpenPolicy, Policy{}, Request{}, true},
		{"an issuer added", set(caaIssue(ca1), caaIssue(ca2)), set(caaIssue(ca1)), Request{Issuer: ca2}, true},
		{"an issuer added, the first of the grants that fails", set(caaIssue("a.test"), caaIssue("b.test")), set(caaIssue("b.test")), Request{Issuer: "a.test"}, true},
		{"RFC 8659 3 the witness is the first grant in the order of the grants", set(caaIssue("ca2.test"), caaIssue("ca1.test")), set(caaIssue("ca3.test")), Request{Issuer: ca1}, true},
		{"the witness of one issuer is the first account in order", set(caaIssue("ca.test; accounturi=b"), caaIssue("ca.test; accounturi=a")), set(caaIssue(evil)), Request{Issuer: ca, Account: "a"}, true},
		{"the witness of a grant with methods is its first method in sorted order", set(caaIssue("ca.test; validationmethods=http-01,dns-01")), set(caaIssue("ca.test; validationmethods=tls-alpn-01")),
			Request{Issuer: ca, Method: "dns-01"}, true},
		{"three grants, the first that fails is the witness",
			caaBoth(caaGrants(g(ca1), g(ca2), g(ca3))), caaBoth(caaGrants(g(ca1))), Request{Issuer: ca2}, true},
		{"an issuer replaced", set(caaIssue(evil)), set(caaIssue(ca)), Request{Issuer: evil}, true},
		{"the plain class is judged before the wildcard class", set(caaIssue(evil)), set(caaIssue(ca)), Request{Wildcard: false, Issuer: evil}, true},
		{"RFC 8657 3 accounturi removed", set(caaIssue(ca)), set(caaIssue("ca.test; accounturi=x")), Request{Issuer: ca}, true},
		{"RFC 8657 3 accounturi changed", set(caaIssue("ca.test; accounturi=y")), set(caaIssue("ca.test; accounturi=x")), Request{Issuer: ca, Account: "y"}, true},
		{"RFC 8657 3 accounturi added is stricter", set(caaIssue("ca.test; accounturi=x")), set(caaIssue(ca)), Request{}, false},
		{"RFC 8657 4 a method added", set(caaIssue("ca.test; validationmethods=dns-01,http-01")), set(caaIssue("ca.test; validationmethods=dns-01")),
			Request{Issuer: ca, Method: "http-01"}, true},
		{"RFC 8657 4 the list removed, witness the empty method", set(caaIssue(ca)), set(caaIssue("ca.test; validationmethods=dns-01")), Request{Issuer: ca}, true},
		{"RFC 8657 4 a method removed is stricter", set(caaIssue("ca.test; validationmethods=dns-01")), set(caaIssue("ca.test; validationmethods=dns-01,http-01")), Request{}, false},
		{"RFC 8657 4 a list against any method is stricter", set(caaIssue("ca.test; validationmethods=dns-01")), set(caaIssue(ca)), Request{}, false},
		{"methods are tried in order, the first that fails is the witness",
			caaBoth(caaGrants(Grant{Issuer: ca, Methods: []string{"dns-01", "http-01", "tls-alpn-01"}})),
			caaBoth(caaGrants(Grant{Issuer: ca, Methods: []string{"http-01"}})), Request{Issuer: ca, Method: "dns-01"}, true},
		{"RFC 8659 4.3 an issuewild lets another authority issue wildcards", set(caaIssue(ca), caaWild(evil)), set(caaIssue(ca)), Request{Wildcard: true, Issuer: evil}, true},
		{"RFC 8659 4.3 an issuewild that forbids wildcards is stricter", set(caaIssue(ca), caaWild(";")), set(caaIssue(ca)), Request{}, false},
		{"RFC 8659 4.3 an issuewild semicolon removed", set(caaIssue(ca)), set(caaIssue(ca), caaWild(";")), Request{Wildcard: true, Issuer: ca}, true},
		{"RFC 8659 4.3 issuewild alone lets any authority issue plain names", set(caaWild(ca)), set(caaIssue(ca)), Request{}, true},
		{"RFC 8659 4.1 critical flag cleared", set(caaC(0, "tbs", "x"), caaIssue(ca)), set(caaC(128, "tbs", "x"), caaIssue(ca)), Request{Issuer: ca}, true},
		{"RFC 8659 4.1 critical flag set is stricter", set(caaC(128, "tbs", "x"), caaIssue(ca)), set(caaC(0, "tbs", "x"), caaIssue(ca)), Request{}, false},
		{"RFC 8659 4.2 issue semicolon to a named issuer", set(caaIssue(ca)), set(caaIssue(";")), Request{Issuer: ca}, true},
		{"RFC 8659 4.2 a named issuer to semicolon is stricter", set(caaIssue(";")), set(caaIssue(ca)), Request{}, false},
		{"the policy that allows nobody is stricter than any", Policy{}, set(caaIssue(ca)), Request{}, false},
		{"a tighter set", set(caaIssue(ca1)), set(caaIssue(ca1), caaIssue(ca2)), Request{}, false},
		{"RFC 8659 4.4 an iodef change", set(caaIssue(ca), caaC(0, "iodef", "mailto:a@corp.test")), set(caaIssue(ca), caaC(0, "iodef", "mailto:b@corp.test")), Request{}, false},
		{"RFC 8659 4.4 an iodef added", set(caaIssue(ca), caaC(0, "iodef", "mailto:a@corp.test")), set(caaIssue(ca)), Request{}, false},
		{"the same policy", set(caaIssue(ca)), set(caaIssue(ca)), Request{}, false},
		{"the same open policy", OpenPolicy, OpenPolicy, Request{}, false},
		{"want open: nothing is weaker", set(caaIssue(ca)), OpenPolicy, Request{}, false},
		{"want open, now allows nobody", Policy{}, OpenPolicy, Request{}, false},
		{"want open on plain names only, wildcards still judged",
			Policy{Name: Class{Any: true}, Wild: caaGrants(g(evil))}, Policy{Name: Class{Any: true}, Wild: caaGrants(g(ca))}, Request{Wildcard: true, Issuer: evil}, true},
		{"the union case: two grants against one grant with both methods",
			caaBoth(caaGrants(Grant{Issuer: ca, Methods: []string{"dns-01"}}, Grant{Issuer: ca, Methods: []string{"http-01"}})),
			caaBoth(caaGrants(Grant{Issuer: ca, Methods: []string{"dns-01", "http-01"}})), Request{}, false},
		{"the union case, from two records",
			set(caaIssue("ca.test; validationmethods=dns-01"), caaIssue("ca.test; validationmethods=http-01")),
			set(caaIssue("ca.test; validationmethods=dns-01,http-01")), Request{}, false},
		{"the union case, the other way",
			set(caaIssue("ca.test; validationmethods=dns-01,http-01")),
			set(caaIssue("ca.test; validationmethods=dns-01"), caaIssue("ca.test; validationmethods=http-01")), Request{}, false},
		{"a grant of any account against two grants of accounts",
			set(caaIssue(ca)), set(caaIssue("ca.test; accounturi=a"), caaIssue("ca.test; accounturi=b")), Request{Issuer: ca}, true},
		{"RFC 8659 4.2 an opaque parameter added", set(caaIssue("ca.test; policy=ev")), set(caaIssue(ca)), Request{Issuer: ca, Extra: "policy=ev"}, true},
		{"RFC 8659 4.2 an opaque parameter removed", set(caaIssue(ca)), set(caaIssue("ca.test; policy=ev")), Request{Issuer: ca}, true},
		{"RFC 8659 4.2 an opaque parameter changed", set(caaIssue("ca.test; policy=dv")), set(caaIssue("ca.test; policy=ev")), Request{Issuer: ca, Extra: "policy=dv"}, true},
		{"the witness carries account, method and extra of the grant",
			caaBoth(caaGrants(Grant{Issuer: ca, Account: "a", Methods: []string{"dns-01"}, Extra: "p=1"})), Policy{},
			Request{Issuer: ca, Account: "a", Method: "dns-01", Extra: "p=1"}, true},
		{"a grant of now with a list is tried at each listed method",
			caaBoth(caaGrants(Grant{Issuer: ca, Account: "a", Methods: []string{"dns-01", "http-01"}})),
			caaBoth(caaGrants(Grant{Issuer: ca, Account: "a", Methods: []string{"dns-01"}})), Request{Issuer: ca, Account: "a", Method: "http-01"}, true},
		{"an any-account grant against a grant of one account",
			caaBoth(caaGrants(Grant{Issuer: ca, Methods: []string{"dns-01"}})),
			caaBoth(caaGrants(Grant{Issuer: ca, Account: "a", Methods: []string{"dns-01"}})), Request{Issuer: ca, Method: "dns-01"}, true},
		{"a grant of one account against an any-account grant",
			caaBoth(caaGrants(Grant{Issuer: ca, Account: "a", Methods: []string{"dns-01"}})),
			caaBoth(caaGrants(Grant{Issuer: ca, Methods: []string{"dns-01"}})), Request{}, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got, ok := Weaker(r.now, r.want)
			if ok != r.weaker || (ok && got != r.witness) {
				t.Errorf("Weaker(\n  %s,\n  %s) is (%+v, %v), want (%+v, %v)", caaShow(r.now), caaShow(r.want), got, ok, r.witness, r.weaker)
			}
			if !ok && got != (Request{}) {
				t.Errorf("Weaker gave the request %+v with false", got)
			}
			if ok {
				if !r.now.Permits(got) || r.want.Permits(got) {
					t.Errorf("the witness %+v is permitted by now: %v, by want: %v", got, r.now.Permits(got), r.want.Permits(got))
				}
			}
		})
	}
}

func caaNamesRows(t *testing.T) {
	g := func(issuer string) Grant {
		return Grant{Issuer: issuer, Account: "a", Methods: []string{"dns-01"}, Extra: "p=1"}
	}
	p := Policy{Name: caaGrants(g("ca1.test"), g("ca2.test")), Wild: caaGrants(g("ca3.test"))}
	anyName := Policy{Name: Class{Any: true}, Wild: Class{}}
	anyWild := Policy{Name: Class{}, Wild: Class{Any: true}}
	rows := []struct {
		name     string
		p        Policy
		wildcard bool
		issuers  []string
		want     bool
	}{
		{"a plain grant", p, false, []string{"ca1.test"}, true},
		{"the second plain grant", p, false, []string{"x.test", "ca2.test"}, true},
		{"an issuer of the wildcard class asked of the plain class", p, false, []string{"ca3.test"}, false},
		{"a wildcard grant", p, true, []string{"ca3.test"}, true},
		{"a plain issuer asked of the wildcard class", p, true, []string{"ca1.test"}, false},
		{"no issuers", p, false, nil, false},
		{"another issuer", p, false, []string{"evil.test"}, false},
		{"any plain class names every issuer", anyName, false, []string{"x.test"}, true},
		{"any plain class names even no issuer", anyName, false, nil, true},
		{"any plain class is not the wildcard class", anyName, true, []string{"x.test"}, false},
		{"any wildcard class", anyWild, true, nil, true},
		{"any wildcard class is not the plain class", anyWild, false, []string{"x.test"}, false},
		{"a policy that allows nobody", Policy{}, false, []string{"ca1.test"}, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := r.p.Names(r.wildcard, r.issuers); got != r.want {
				t.Errorf("Names(%v, %v) is %v, want %v", r.wildcard, r.issuers, got, r.want)
			}
		})
	}
}

// ---- TestCAAWeakerProperty and FuzzCAAPolicy ----

type caaGen struct{ rng *rand.Rand }

func (g *caaGen) pick(xs ...string) string { return xs[g.rng.IntN(len(xs))] }

// inGrammar is a value of RFC 8659 section 4.2 whose parameters are those of
// RFC 8657.
func (g *caaGen) inGrammar() string {
	issuer := g.pick("ca1.test", "CA2.test", "")
	var parts []string
	for i := g.rng.IntN(3); i > 0; i-- {
		parts = append(parts, "accounturi="+g.pick("u1", "u2", "https://ca1.test/a"))
	}
	for i := g.rng.IntN(3); i > 0; i-- {
		var labels []string
		for j := g.rng.IntN(3); j > 0; j-- {
			labels = append(labels, g.pick("dns-01", "http-01", "DNS-01", ""))
		}
		parts = append(parts, "validationmethods="+strings.Join(labels, ","))
	}
	if g.rng.IntN(2) == 0 {
		parts = append(parts, "x=1")
	}
	g.rng.Shuffle(len(parts), func(i, j int) { parts[i], parts[j] = parts[j], parts[i] })
	pad := g.pick("", " ")
	if len(parts) == 0 {
		return pad + issuer + g.pick("", ";", " ;") + pad
	}
	return pad + issuer + g.pick(";", " ; ", "; ") + strings.Join(parts, g.pick(";", " ; ", "; ")) + pad
}

func (g *caaGen) value() string {
	if g.rng.IntN(7) == 0 {
		return g.pick("ca1.test;", "ca1 test", ";;", "ca2.test;;", "ca1.test accounturi=u1")
	}
	return g.inGrammar()
}

func (g *caaGen) record() dnswire.CAA {
	return caaC([]uint8{0, 1, 128}[g.rng.IntN(3)], g.pick("issue", "issue", "issuewild", "iodef", "ISSUE", "tbs"), g.value())
}

func (g *caaGen) set(max int) []dnswire.CAA {
	set := make([]dnswire.CAA, g.rng.IntN(max+1))
	for i := range set {
		set[i] = g.record()
	}
	return set
}

// related is a set near s: some records dropped, some added.
func (g *caaGen) related(s []dnswire.CAA) []dnswire.CAA {
	var out []dnswire.CAA
	for _, r := range s {
		if g.rng.IntN(4) != 0 {
			out = append(out, r)
		}
	}
	for i := g.rng.IntN(3); i > 0; i-- {
		out = append(out, g.record())
	}
	return out
}

func caaUniverse(a, b Policy) []Request {
	set := func(xs ...string) map[string]bool {
		m := map[string]bool{}
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	issuers, accounts, methods, extras := set("", "zz.test"), set("", "zz-acct"), set("", "zz-method"), set("", "zz=1")
	for _, p := range []Policy{a, b} {
		for _, c := range []Class{p.Name, p.Wild} {
			for _, g := range c.Grants {
				issuers[g.Issuer], accounts[g.Account], extras[g.Extra] = true, true, true
				for _, m := range g.Methods {
					methods[m] = true
				}
			}
		}
	}
	keys := func(m map[string]bool) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	var u []Request
	for _, w := range []bool{false, true} {
		for _, i := range keys(issuers) {
			for _, a := range keys(accounts) {
				for _, m := range keys(methods) {
					for _, x := range keys(extras) {
						u = append(u, Request{Wildcard: w, Issuer: i, Account: a, Method: m, Extra: x})
					}
				}
			}
		}
	}
	return u
}

// caaPolicyOrOpen is the policy of a name under a reading: no set at all is
// OpenPolicy.
func caaPolicyOrOpen(set []dnswire.CAA, rd Reading) Policy {
	p, ok := caaPolicyUnder(rd, set...)
	if !ok {
		return OpenPolicy
	}
	return p
}

// caaABNF reads the value of an issue property by the grammar of RFC 8659
// section 4.2, and by RFC 8657 for accounturi and validationmethods; the
// other parameters are opaque. An account or a method list that cannot hold
// gives no grant under the strict reading and a grant for any account or
// method under the permissive one. It is written without reference to
// PolicyOf.
func caaABNF(v string, rd Reading) (Grant, bool) {
	s := strings.Trim(v, " \t")
	name, rest, _ := strings.Cut(s, ";")
	name = strings.Trim(name, " \t")
	if name == "" {
		return Grant{}, false
	}
	var accounts, lists, extras []string
	for _, piece := range strings.Split(rest, ";") {
		piece = strings.Trim(piece, " \t")
		if piece == "" {
			continue
		}
		tag, val, _ := strings.Cut(piece, "=")
		tag, val = strings.Trim(tag, " \t"), strings.Trim(val, " \t")
		switch tag {
		case "accounturi":
			accounts = append(accounts, val)
		case "validationmethods":
			lists = append(lists, val)
		default:
			extras = append(extras, tag+"="+val)
		}
	}
	g := Grant{Issuer: strings.ToLower(name)}
	switch {
	case len(accounts) == 1 && accounts[0] != "":
		g.Account = accounts[0]
	case len(accounts) > 0 && !caaCasesOf(rd).anyAccount:
		return Grant{}, false
	}
	if len(lists) == 1 {
		valid := true
		var methods []string
		for _, l := range strings.Split(lists[0], ",") {
			valid = valid && l != "" && strings.Trim(l, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") == ""
			methods = append(methods, strings.ToLower(l))
		}
		if valid {
			slices.Sort(methods)
			g.Methods = slices.Compact(methods)
		} else if !caaCasesOf(rd).anyMethod {
			return Grant{}, false
		}
	} else if len(lists) > 1 && !caaCasesOf(rd).anyMethod {
		return Grant{}, false
	}
	slices.Sort(extras)
	g.Extra = strings.Join(extras, ";")
	return g, true
}

func caaCheckClass(c Class) string {
	if len(c.Grants) > 64 {
		return fmt.Sprintf("%d grants", len(c.Grants))
	}
	for i, g := range c.Grants {
		if g.Issuer == "" || g.Issuer != strings.ToLower(g.Issuer) {
			return fmt.Sprintf("grant %d has the issuer %q", i, g.Issuer)
		}
		if !slices.IsSorted(g.Methods) || len(slices.Compact(slices.Clone(g.Methods))) != len(g.Methods) {
			return fmt.Sprintf("grant %d has the methods %v", i, g.Methods)
		}
		if i > 0 && c.Grants[i-1].Issuer > g.Issuer {
			return fmt.Sprintf("grants %d and %d are not sorted by issuer", i-1, i)
		}
		for j := 0; j < i; j++ {
			if caaSameGrant(c.Grants[j], g) {
				return fmt.Sprintf("grants %d and %d are equal", j, i)
			}
		}
	}
	return ""
}

func TestCAAWeakerProperty(t *testing.T) {
	const cases = 1500
	var premises, weakerSeen, notWeakerSeen int
	for seed := uint64(1); seed <= cases; seed++ {
		g := &caaGen{rng: rand.New(rand.NewPCG(seed, 0xca4))}
		setA := g.set(6)
		setB := setA
		if g.rng.IntN(3) != 0 {
			setB = g.related(setA)
		} else {
			setB = g.set(6)
		}
		setC := g.related(setB)
		reading := ""
		fail := func(format string, args ...any) {
			t.Helper()
			t.Fatalf("seed %d, %s reading: "+format+"\n  a %v\n  b %v\n  c %v", append(append([]any{seed, reading}, args...), setA, setB, setC)...)
		}
		for rd := range Readings {
			reading = fmt.Sprint("reading ", rd)
			a, b, c := caaPolicyOrOpen(setA, rd), caaPolicyOrOpen(setB, rd), caaPolicyOrOpen(setC, rd)
			for _, p := range []Policy{a, b, c} {
				if m := caaCheckClass(p.Name) + caaCheckClass(p.Wild); m != "" {
					fail("a policy breaks its own form: %s", m)
				}
				if _, w := Weaker(p, p); w {
					fail("Weaker(p, p) is true for %s", caaShow(p))
				}
			}

			// The witness law, soundness and completeness over the universe.
			for _, pair := range [][2]Policy{{a, b}, {b, a}, {b, c}, {a, c}} {
				now, want := pair[0], pair[1]
				r, weaker := Weaker(now, want)
				var missed *Request
				for _, q := range caaUniverse(now, want) {
					if now.Permits(q) && !want.Permits(q) {
						missed = &q
						break
					}
				}
				switch {
				case weaker && (!now.Permits(r) || want.Permits(r)):
					fail("the witness %+v of Weaker is permitted by now: %v, by want: %v\n  now %s\n  want %s", r, now.Permits(r), want.Permits(r), caaShow(now), caaShow(want))
				case !weaker && missed != nil:
					fail("Weaker is false, but %+v is permitted by now and not by want\n  now %s\n  want %s", *missed, caaShow(now), caaShow(want))
				case weaker && missed == nil:
					fail("Weaker is true with the witness %+v, but the universe has none\n  now %s\n  want %s", r, caaShow(now), caaShow(want))
				}
				if weaker {
					weakerSeen++
				} else {
					notWeakerSeen++
				}
			}

			// Transitivity.
			if _, ab := Weaker(a, b); !ab {
				if _, bc := Weaker(b, c); !bc {
					premises++
					if _, ac := Weaker(a, c); ac {
						fail("Weaker(a, b) and Weaker(b, c) are false, but Weaker(a, c) is true")
					}
				}
			}

			// The order of the records does not matter.
			shuffled := slices.Clone(setA)
			g.rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
			p1, ok1 := caaPolicyUnder(rd, setA...)
			p2, ok2 := caaPolicyUnder(rd, shuffled...)
			if ok1 != ok2 || !reflect.DeepEqual(p1, p2) {
				fail("PolicyOf differs for a reordered copy:\n  %s\n  %s", caaShow(p1), caaShow(p2))
			}
			if ok1 != (len(setA) > 0) {
				fail("PolicyOf is ok: %v for %d records", ok1, len(setA))
			}

			// Names.
			issuers := []string{g.pick("ca1.test", "ca2.test", "zz.test")}
			if g.rng.IntN(2) == 0 {
				issuers = append(issuers, "ca2.test")
			}
			for _, w := range []bool{false, true} {
				cl := a.Name
				if w {
					cl = a.Wild
				}
				want := cl.Any || slices.ContainsFunc(cl.Grants, func(gr Grant) bool { return slices.Contains(issuers, gr.Issuer) })
				if got := a.Names(w, issuers); got != want {
					fail("Names(%v, %v) is %v, want %v for %s", w, issuers, got, want, caaShow(a))
				}
			}

			// A value inside the grammar reads as the grammar says.
			v := g.inGrammar()
			p, ok := caaPolicyUnder(rd, caaIssue(v))
			want, granted := caaABNF(v, rd)
			wantClass := Class{}
			if granted {
				wantClass = caaGrants(want)
			}
			if !ok || !caaSameClass(p.Name, wantClass) || !caaSameClass(p.Wild, wantClass) {
				fail("the value %q reads as %s, the grammar gives %+v (granted %v)", v, caaShow(p), want, granted)
			}
		}

		// Under the strict reading a set never permits what the permissive
		// reading does not permit.
		reading = "both"
		for _, set := range [][]dnswire.CAA{setA, setB, setC} {
			s, p := caaPolicyOrOpen(set, StrictReading), caaPolicyOrOpen(set, PermissiveReading)
			if r, w := Weaker(s, p); w {
				fail("the strict reading permits %+v, the permissive one does not\n  strict %s\n  permissive %s", r, caaShow(s), caaShow(p))
			}
			for _, q := range caaUniverse(s, p) {
				if s.Permits(q) && !p.Permits(q) {
					fail("the strict reading permits %+v, the permissive one does not", q)
				}
			}
		}
	}
	if premises < 100 || weakerSeen < 400 || notWeakerSeen < 400 {
		t.Errorf("the generator is too tame: %d transitive premises, %d weaker, %d not weaker", premises, weakerSeen, notWeakerSeen)
	}
}

func FuzzCAAPolicy(f *testing.F) {
	f.Add(uint8(0), "issue", "ca.test")
	f.Add(uint8(128), "tbs", "x")
	f.Add(uint8(1), "issuewild", "ca.test; accounturi=a; validationmethods=dns-01,http-01")
	f.Add(uint8(0), "iodef", ";;")
	f.Add(uint8(0), "ISSUE", "ca1 test")
	f.Add(uint8(0), "issue", strings.Repeat("x", 70))
	f.Add(uint8(255), "", "\x00\xff;=;")
	f.Fuzz(func(t *testing.T, flags uint8, tag, value string) {
		set := []dnswire.RData{dnswire.CAA{Flags: flags, Tag: tag, Value: value}}
		for i := 0; i < len(value)%90; i++ {
			set = append(set, dnswire.CAA{Tag: "issue", Value: "ca.test; x=" + strconv.Itoa(i)})
		}
		var read [Readings]Policy
		for rd := range Readings {
			p, ok := PolicyOf(set, rd)
			if !ok {
				t.Fatalf("PolicyOf is not ok for a set of CAA records")
			}
			read[rd] = p
			if _, w := Weaker(p, p); w {
				t.Errorf("Weaker(p, p) is true for %s", caaShow(p))
			}
			if _, w := Weaker(p, OpenPolicy); w {
				t.Errorf("Weaker(p, OpenPolicy) is true for %s", caaShow(p))
			}
			for _, c := range []Class{p.Name, p.Wild} {
				if len(c.Grants) > 64 {
					t.Errorf("a class holds %d grants", len(c.Grants))
				}
			}
			p.Names(true, []string{"ca.test"})
			p.Permits(Request{Issuer: "ca.test", Account: value, Method: tag})
		}
		for i := range read {
			if r, w := Weaker(read[StrictReading], read[i]); w {
				t.Errorf("the strict reading permits %+v, reading %d does not", r, i)
			}
			if r, w := Weaker(read[i], read[PermissiveReading]); w {
				t.Errorf("reading %d permits %+v, the permissive one does not", i, r)
			}
		}
	})
}

// ---- TestCAAClimbConformance ----

const (
	caaApex     = `corp.test. CAA 0 issue "ca.test"`
	caaStrong   = `0 issue "ca.test"`
	caaWeak     = `0 issue "ca.test" | 0 issue "evil.test"`
	caaApexWeak = `corp.test. CAA 0 issue "ca.test" | 0 issue "evil.test"`
	caaWWWLine  = `www.corp.test. CAA 0 issue "ca.test"`
	caaWWWA     = "www.corp.test. A 10.53.0.81"

	// Values that authorities read in different ways.
	caaRepeated    = `0 issue "evil.test; validationmethods=dns-01; validationmethods=dns-01"`
	caaEmptyLabel  = `0 issue "evil.test; validationmethods=dns-01,"`
	caaTwoAccounts = `0 issue "evil.test; accounturi=a; accounturi=b"`
	caaCritical    = `0 issue "evil.test" | 128 contactemail "x"`
	caaRepeated2   = `0 issue "ca.test; validationmethods=dns-01; validationmethods=dns-01"`
	caaCritical2   = `0 issue "ca.test" | 128 contactemail "x"`
)

func caaTexts(ns []dnswire.Name) []string {
	var out []string
	for _, n := range ns {
		out = append(out, n.Lower().String())
	}
	return out
}

func TestCAAClimbConformance(t *testing.T) {
	t.Run("CAAPolicy", caaPolicyRows)
	t.Run("CAANames", caaNamesOfFileRows)
	t.Run("rule", caaRuleRows)
}

func caaPolicyRows(t *testing.T) {
	ca := func(i ...string) []Policy { return []Policy{caaOnly(i...)} }
	rows := []struct {
		name  string
		lines []string
		file  string // default domain corp.test.
		query string
		ok    bool
		gov   string // owner of the line that governs
		form  string // its FormText
		alts  []Policy
	}{
		{"RFC 8659 3 no set on the path", []string{caaWWWA, `c.corp.test. CAA 0 issue "ca.test"`}, "", "a.b.corp.test.", false, "", "", nil},
		{"RFC 8659 3 a set at B.C stops the climb for A.B.C", []string{caaApex, `b.corp.test. CAA 0 issue "ca2.test"`}, "", "a.b.corp.test.", true,
			"b.corp.test.", `0 issue "ca2.test"`, ca("ca2.test")},
		{"RFC 8659 3 the set at the name itself", []string{caaApex, `a.b.corp.test. CAA 0 issue "ca3.test"`, `b.corp.test. CAA 0 issue "ca2.test"`}, "", "a.b.corp.test.", true,
			"a.b.corp.test.", `0 issue "ca3.test"`, ca("ca3.test")},
		{"RFC 8659 3 the climb reaches the domain", []string{caaApex, caaWWWA}, "", "a.b.corp.test.", true, "corp.test.", caaStrong, ca("ca.test")},
		{"RFC 8659 3 the domain itself", []string{caaApex}, "", "corp.test.", true, "corp.test.", caaStrong, ca("ca.test")},
		{"RFC 8659 3 a none line goes on to the parent", []string{caaApex, `b.corp.test. CAA none`}, "", "a.b.corp.test.", true, "corp.test.", caaStrong, ca("ca.test")},
		{"RFC 8659 3 a none line at the name goes on", []string{caaApex, `b.corp.test. CAA none`}, "", "b.corp.test.", true, "corp.test.", caaStrong, ca("ca.test")},
		{"RFC 8659 3 a none line with nothing above states no policy", []string{`b.corp.test. CAA none`}, "", "a.b.corp.test.", false, "", "", nil},
		{"RFC 8659 3 none at both levels states no policy", []string{`corp.test. CAA none`, `b.corp.test. CAA none`}, "", "a.b.corp.test.", false, "", "", nil},
		{"RFC 8659 3 a wildcard uses the climb of its parent", []string{caaApex, `b.corp.test. CAA 0 issue "ca2.test"`}, "", "*.b.corp.test.", true,
			"b.corp.test.", `0 issue "ca2.test"`, ca("ca2.test")},
		{"RFC 8659 3 a wildcard at the domain", []string{caaApex, `b.corp.test. CAA 0 issue "ca2.test"`}, "", "*.corp.test.", true, "corp.test.", caaStrong, ca("ca.test")},
		{"RFC 8659 3 a wildcard below a name with a set", []string{caaApex, `b.corp.test. CAA 0 issue "ca2.test"`}, "", "*.a.b.corp.test.", true,
			"b.corp.test.", `0 issue "ca2.test"`, ca("ca2.test")},
		{"RFC 8659 3 a wildcard with no set on the path", []string{caaWWWA}, "", "*.b.corp.test.", false, "", "", nil},
		{"RFC 8659 3 the climb stops at the domain: the TLD", []string{caaApex}, "", "test.", false, "", "", nil},
		{"RFC 8659 3 the climb stops at the domain: the root", []string{caaApex}, "", ".", false, "", "", nil},
		{"RFC 8659 3 a name outside the domain", []string{caaApex}, "", "www.other.test.", false, "", "", nil},
		{"RFC 8659 3 a sibling of the domain", []string{caaApex}, "", "other.test.", false, "", "", nil},
		{"RFC 8659 3 a wildcard outside the domain", []string{caaApex}, "", "*.other.test.", false, "", "", nil},
		{"RFC 8659 3 a wildcard above the domain", []string{caaApex}, "", "*.test.", false, "", "", nil},
		{"RFC 8659 3 the parent of a deeper domain", []string{`shop.corp.test. CAA 0 issue "ca.test"`}, "shop.corp.test.", "corp.test.", false, "", "", nil},
		{"RFC 8659 3 a deeper domain, a name under it", []string{`shop.corp.test. CAA 0 issue "ca.test"`}, "shop.corp.test.", "www.shop.corp.test.", true,
			"shop.corp.test.", caaStrong, ca("ca.test")},
		{"RFC 8659 3 a name in capitals", []string{caaApex, `B.Corp.Test. CAA 0 issue "ca2.test"`}, "", "A.B.CORP.TEST.", true, "b.corp.test.", `0 issue "ca2.test"`, ca("ca2.test")},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			domain := r.file
			if domain == "" {
				domain = "corp.test."
			}
			f := decFile(t, append([]string{"domain " + domain}, r.lines...)...)
			alts, line, ok := CAAPolicy(f, decName(t, r.query))
			if ok != r.ok {
				t.Fatalf("ok is %v, want %v (line %v)", ok, r.ok, line)
			}
			if !ok {
				if len(alts[StrictReading]) != 0 || len(alts[PermissiveReading]) != 0 {
					t.Errorf("not ok, but alternatives %d and %d", len(alts[StrictReading]), len(alts[PermissiveReading]))
				}
				return
			}
			if !line.Name.Equal(decName(t, r.gov)) || line.Type != dnswire.TypeCAA {
				t.Errorf("the line is %v %v, want %s CAA", line.Name, line.Type, r.gov)
			}
			if r.form != "" && line.FormText() != r.form {
				t.Errorf("the line says %q, want %q", line.FormText(), r.form)
			}
			for rd, a := range alts {
				if len(a) != 1 || !caaSamePolicy(a[0], r.alts[0]) {
					t.Errorf("reading %d: alternatives are %d, first %s, want %s", rd, len(a), caaShow(firstPolicy(a)), caaShow(r.alts[0]))
				}
			}
		})
	}

	// sameAlts reports whether alts holds exactly want, in any order.
	sameAlts := func(alts []Policy, want ...Policy) bool {
		if len(alts) != len(want) {
			return false
		}
		for _, w := range want {
			if !slices.ContainsFunc(alts, func(a Policy) bool { return caaSamePolicy(a, w) }) {
				return false
			}
		}
		return true
	}
	t.Run("two alternatives, one policy for each, under each reading", func(t *testing.T) {
		f := decFile(t, "domain corp.test.", `corp.test. CAA 0 issue "ca1.test" || 0 issue "ca2.test"`)
		alts, line, ok := CAAPolicy(f, decName(t, "www.corp.test."))
		if !ok {
			t.Fatalf("not ok")
		}
		if line.FormText() != `0 issue "ca1.test" || 0 issue "ca2.test"` {
			t.Errorf("the line says %q", line.FormText())
		}
		for rd, a := range alts {
			if !sameAlts(a, caaOnly("ca1.test"), caaOnly("ca2.test")) {
				t.Errorf("reading %d: alternatives are %d", rd, len(a))
			}
		}
	})
	t.Run("an alternative that is not CAA text does not exist", func(t *testing.T) {
		f := decFile(t, "domain corp.test.", `corp.test. CAA 0 issue "ca.test" | 0 iodef "mailto:a@corp.test" || 0 issue ";"`)
		alts, _, ok := CAAPolicy(f, decName(t, "corp.test."))
		if !ok {
			t.Fatalf("not ok")
		}
		for rd, a := range alts {
			if !sameAlts(a, caaOnly("ca.test"), caaBoth(Class{})) {
				t.Errorf("reading %d: alternatives are %d", rd, len(a))
			}
		}
	})
	t.Run("a line that is open is returned as open", func(t *testing.T) {
		f := decFile(t, "domain corp.test.", `corp.test. CAA 0 iodef "mailto:a@corp.test"`)
		alts, _, ok := CAAPolicy(f, decName(t, "www.corp.test."))
		if !ok || !sameAlts(alts[StrictReading], OpenPolicy) || !sameAlts(alts[PermissiveReading], OpenPolicy) {
			t.Errorf("CAAPolicy is (%v, ok %v)", alts, ok)
		}
	})
	t.Run("a critical unknown tag is read under each reading", func(t *testing.T) {
		f := decFile(t, "domain corp.test.", `corp.test. CAA 128 tbs "x" | 0 issue "ca.test"`)
		alts, line, ok := CAAPolicy(f, decName(t, "www.corp.test."))
		if !ok || line.Name.Lower().String() != "corp.test." {
			t.Fatalf("ok %v, line %v", ok, line.Name)
		}
		if !sameAlts(alts[StrictReading], Policy{}) || !sameAlts(alts[PermissiveReading], caaOnly("ca.test")) {
			t.Errorf("alternatives are strict %v, permissive %v", alts[StrictReading], alts[PermissiveReading])
		}
	})
	t.Run("a repeated accounturi and a repeated validationmethods are read under each reading", func(t *testing.T) {
		f := decFile(t, "domain corp.test.",
			`corp.test. CAA 0 issue "ca.test; accounturi=a; accounturi=b" || 0 issue "ca2.test; validationmethods=dns-01; validationmethods=dns-01"`)
		alts, _, ok := CAAPolicy(f, decName(t, "corp.test."))
		if !ok {
			t.Fatalf("not ok")
		}
		if !sameAlts(alts[StrictReading], caaBoth(Class{}), caaBoth(Class{})) {
			t.Errorf("strict alternatives are %v", alts[StrictReading])
		}
		if !sameAlts(alts[PermissiveReading], caaOnly("ca.test"), caaOnly("ca2.test")) {
			t.Errorf("permissive alternatives are %v", alts[PermissiveReading])
		}
	})
	t.Run("a nil file and a name outside give nothing", func(t *testing.T) {
		alts, line, ok := CAAPolicy(nil, decName(t, "www.corp.test."))
		if alts[0] != nil || alts[1] != nil || ok || !reflect.DeepEqual(line, expect.Expectation{}) {
			t.Errorf("nil file: (%v, %v, %v)", alts, line, ok)
		}
		f := decFile(t, "domain corp.test.", caaApex)
		alts, line, ok = CAAPolicy(f, decName(t, "www.other.test."))
		if alts[0] != nil || alts[1] != nil || ok || !reflect.DeepEqual(line, expect.Expectation{}) {
			t.Errorf("name outside: (%v, %v, %v)", alts, line, ok)
		}
	})
}

func firstPolicy(ps []Policy) Policy {
	if len(ps) == 0 {
		return Policy{}
	}
	return ps[0]
}

func caaNamesOfFileRows(t *testing.T) {
	rows := []struct {
		name  string
		lines []string
		want  []string
	}{
		{"no CAA line", []string{caaWWWA}, nil},
		{"the apex with a line", []string{caaApex}, []string{"corp.test."}},
		{"a name below an apex with a line", []string{caaApex, caaWWWA}, []string{"corp.test.", "www.corp.test."}},
		{"the parents of a name", []string{caaApex, "a.b.corp.test. A 10.53.0.81"}, []string{"corp.test.", "b.corp.test.", "a.b.corp.test."}},
		{"canonical order, each name once", []string{caaApex, "c.corp.test. A 10.53.0.81", "b.corp.test. A 10.53.0.82", "a.b.corp.test. A 10.53.0.83", `a.b.corp.test. TXT "x"`, "b.corp.test. MX 10 mail.corp.test."},
			[]string{"corp.test.", "b.corp.test.", "a.b.corp.test.", "c.corp.test."}},
		{"a name with an underscore label is left out", []string{caaApex, "_x.corp.test. A 10.53.0.81"}, []string{"corp.test."}},
		{"a name under an underscore label is left out with its parents of that label", []string{caaApex, "x._tcp.corp.test. A 10.53.0.81"}, []string{"corp.test."}},
		{"the parent of an underscore name is kept", []string{caaApex, "_a.x.corp.test. A 10.53.0.81"}, []string{"corp.test.", "x.corp.test."}},
		{"the challenge name leaves its parent", []string{caaApex, "_acme-challenge.www.corp.test. TXT none"}, []string{"corp.test.", "www.corp.test."}},
		{"a wildcard owner is left out and its parent kept", []string{caaApex, "*.shop.corp.test. A none"}, []string{"corp.test.", "shop.corp.test."}},
		{"a wildcard at the domain adds nothing", []string{caaApex, "*.corp.test. A none"}, []string{"corp.test."}},
		{"a CAA line at an underscore name is left out", []string{caaApex, `_x.corp.test. CAA 0 issue "ca2.test"`}, []string{"corp.test."}},
		{"a none line at a name goes on to the apex", []string{caaApex, "www.corp.test. CAA none"}, []string{"corp.test.", "www.corp.test."}},
		{"no line at the apex, a line below", []string{`www.corp.test. CAA 0 issue "ca.test"`}, []string{"www.corp.test."}},
		{"only a none line", []string{"corp.test. CAA none", caaWWWA}, nil},
		{"an open apex leaves nothing", []string{`corp.test. CAA 0 iodef "mailto:a@corp.test"`, caaWWWA}, nil},
		{"an alternative that is open leaves nothing", []string{`corp.test. CAA 0 issue "ca.test" || 0 iodef "mailto:a@corp.test"`, caaWWWA}, nil},
		{"an open line below a strict apex leaves that name and the names under it",
			[]string{caaApex, `www.corp.test. CAA 0 iodef "mailto:a@corp.test"`, "a.www.corp.test. A 10.53.0.81"}, []string{"corp.test."}},
		{"a strict line below an open apex keeps that name and the names under it",
			[]string{`corp.test. CAA 0 iodef "mailto:a@corp.test"`, `www.corp.test. CAA 0 issue "ca.test"`, "a.www.corp.test. A 10.53.0.81", "mail.corp.test. A 10.53.0.82"},
			[]string{"www.corp.test.", "a.www.corp.test."}},
		{"a line at the domain that allows nobody is a policy", []string{`corp.test. CAA 0 issue ";"`, caaWWWA}, []string{"corp.test.", "www.corp.test."}},
		{"a line that is guarded under the strict reading only", []string{`corp.test. CAA 128 tbs "x"`, caaWWWA}, []string{"corp.test.", "www.corp.test."}},
		{"a line that is open under both readings", []string{`corp.test. CAA 128 tbs "x" || 0 iodef "mailto:a@corp.test"`, caaWWWA}, nil},
		{"a line with an open plain class and a closed wildcard class is a policy", []string{`corp.test. CAA 0 issuewild "ca.test"`, caaWWWA}, []string{"corp.test.", "www.corp.test."}},
		{"names in capitals once", []string{caaApex, "WWW.Corp.Test. A 10.53.0.81", `www.corp.test. TXT "x"`}, []string{"corp.test.", "www.corp.test."}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			f := decFile(t, append([]string{"domain corp.test."}, r.lines...)...)
			got := CAANames(f)
			if !slices.Equal(caaTexts(got), r.want) {
				t.Errorf("CAANames is %v, want %v", caaTexts(got), r.want)
			}
			if !slices.IsSortedFunc(got, dnswire.Compare) {
				t.Errorf("CAANames is not in canonical order: %v", caaTexts(got))
			}
		})
	}
	t.Run("a nil file", func(t *testing.T) {
		if got := CAANames(nil); len(got) != 0 {
			t.Errorf("CAANames(nil) is %v", caaTexts(got))
		}
	})
}

// ---- the rule caa ----

var caaServers = []struct{ host, addr string }{
	{"ns1.corp.test.", "10.53.0.11:53"},
	{"ns2.corp.test.", "10.53.0.12:53"},
	{"ns3.corp.test.", "10.53.0.13:53"},
}

// caaResult builds an answer from a word: "nodata", "noname", "fail",
// "CNAME <target>" or CAA records separated by " | ".
func caaResult(t testing.TB, owner, spec string) obs.Result {
	t.Helper()
	switch spec {
	case "nodata":
		return decNoData(t, "corp.test.")
	case "noname":
		return decNoName(t, "corp.test.")
	case "fail":
		return decFailure(obs.ReasonTimeout)
	}
	var set []dnswire.Record
	for _, d := range strings.Split(spec, " | ") {
		typ := dnswire.TypeCAA
		if rest, ok := strings.CutPrefix(d, "CNAME "); ok {
			typ, d = dnswire.TypeCNAME, rest
		}
		set = append(set, decRR(t, owner, typ, d))
	}
	return decAs(t, obs.RecordsResult(obs.Records{Set: set}), "records")
}

func caaObserve(t testing.TB, owner, zone string, specs ...string) obs.Observation {
	t.Helper()
	var answers []obs.Answer
	for i, s := range specs {
		answers = append(answers, decAnswer(t, caaServers[i].host, caaServers[i].addr, caaResult(t, owner, s)))
	}
	return decObservation(decRecordsKey(t, "corp.test.", owner, dnswire.TypeCAA), decName(t, zone), nil, answers...)
}

type caaWant struct {
	rule     Rule
	severity Severity
	expected string // "@": the FormText of the line that governs
	seen     []string
}

func caaHigh(expected string, seen ...string) caaWant {
	return caaWant{RuleCAA, SeverityHigh, expected, seen}
}

func caaRecordSet(expected string, seen ...string) caaWant {
	return caaWant{RuleRecordSet, SeverityMedium, expected, seen}
}

func caaRuleRows(t *testing.T) {
	const www = "www.corp.test."
	two := func(s string) []string { return []string{s, s} }
	rows := []struct {
		name   string
		lines  []string // after the domain line; default the apex line
		file   string   // domain of the file, default corp.test.
		owner  string   // default corp.test.
		gov    string   // owner of the governing line, default owner
		zone   string   // zone of the observation, default corp.test.
		specs  []string
		wanted []caaWant
	}{
		{name: "a weakened set at both servers", specs: two(caaWeak), wanted: []caaWant{caaHigh("@", "0 "+caaWeak, "1 "+caaWeak)}},
		{name: "a weakened set at the first server only", specs: []string{caaWeak, caaStrong}, wanted: []caaWant{caaHigh("@", "0 "+caaWeak)}},
		{name: "a weakened set at the second server only", specs: []string{caaStrong, caaWeak}, wanted: []caaWant{caaHigh("@", "1 "+caaWeak)}},
		{name: "a failure beside a weakened set is not seen", specs: []string{"fail", caaWeak}, wanted: []caaWant{caaHigh("@", "1 "+caaWeak)}},
		{name: "three answers, two weakened", specs: []string{caaWeak, "fail", caaWeak}, wanted: []caaWant{caaHigh("@", "0 "+caaWeak, "2 "+caaWeak)}},
		{name: "every answer failed", specs: []string{"fail", "fail"}},
		{name: "the set is gone: no data", specs: []string{"nodata", "nodata"}, wanted: []caaWant{caaHigh("@", "0 none", "1 none")}},
		{name: "the set is gone: no such name, beside the file's set", specs: []string{"noname", caaStrong}, wanted: []caaWant{caaHigh("@", "0 none")}},
		{name: "the servers give the file's set", specs: two(caaStrong)},
		{name: "a server that is weakened and one that is tighter: only the weakened one is seen", specs: []string{caaWeak, `0 issue ";"`}, wanted: []caaWant{caaHigh("@", "0 "+caaWeak)}},
		{name: "a tighter set is an ordinary change", lines: []string{`corp.test. CAA 0 issue "ca.test" | 0 issue "ca2.test"`}, specs: two(caaStrong),
			wanted: []caaWant{caaRecordSet("@", "0 "+caaStrong, "1 "+caaStrong)}},
		{name: "a stricter set at one server and the file's at the other", lines: []string{`corp.test. CAA 0 issue "ca.test" | 0 issue "ca2.test"`},
			specs: []string{caaStrong, `0 issue "ca.test" | 0 issue "ca2.test"`}, wanted: []caaWant{caaRecordSet("@", "0 "+caaStrong)}},
		{name: "an iodef change is an ordinary change", specs: two(`0 iodef "mailto:a@corp.test" | 0 issue "ca.test"`),
			wanted: []caaWant{caaRecordSet("@", `0 0 iodef "mailto:a@corp.test" | 0 issue "ca.test"`, `1 0 iodef "mailto:a@corp.test" | 0 issue "ca.test"`)}},
		{name: "RFC 8659 4.1 a critical flag cleared permits more", lines: []string{`corp.test. CAA 128 tbs "x" | 0 issue "ca.test"`}, specs: two(caaStrong),
			wanted: []caaWant{caaHigh("@", "0 "+caaStrong, "1 "+caaStrong)}},
		{name: "RFC 8659 4.1 a critical flag set is stricter", lines: []string{`corp.test. CAA 0 tbs "x" | 0 issue "ca.test"`}, specs: two(`0 issue "ca.test" | 128 tbs "x"`),
			wanted: []caaWant{caaRecordSet("@", `0 0 issue "ca.test" | 128 tbs "x"`, `1 0 issue "ca.test" | 128 tbs "x"`)}},
		{name: "RFC 8657 3 an account binding removed permits more", lines: []string{`corp.test. CAA 0 issue "ca.test; accounturi=https://ca.test/a/1"`}, specs: two(caaStrong),
			wanted: []caaWant{caaHigh("@", "0 "+caaStrong, "1 "+caaStrong)}},
		{name: "RFC 8659 4.3 a wildcard authority added permits more", specs: two(`0 issue "ca.test" | 0 issuewild "evil.test"`),
			wanted: []caaWant{caaHigh("@", `0 0 issue "ca.test" | 0 issuewild "evil.test"`, `1 0 issue "ca.test" | 0 issuewild "evil.test"`)}},
		{name: "RFC 8659 4.3 wildcards forbidden is stricter", specs: two(`0 issue "ca.test" | 0 issuewild ";"`),
			wanted: []caaWant{caaRecordSet("@", `0 0 issue "ca.test" | 0 issuewild ";"`, `1 0 issue "ca.test" | 0 issuewild ";"`)}},
		{name: "two alternatives: weaker than both", lines: []string{`corp.test. CAA 0 issue "ca1.test" || 0 issue "ca2.test"`},
			specs: two(`0 issue "ca1.test" | 0 issue "ca2.test"`), wanted: []caaWant{caaHigh("@", `0 0 issue "ca1.test" | 0 issue "ca2.test"`, `1 0 issue "ca1.test" | 0 issue "ca2.test"`)}},
		{name: "two alternatives: a third authority", lines: []string{`corp.test. CAA 0 issue "ca1.test" || 0 issue "ca2.test"`},
			specs: []string{`0 issue "ca3.test"`, `0 issue "ca1.test"`}, wanted: []caaWant{caaHigh("@", `0 0 issue "ca3.test"`)}},
		{name: "two alternatives: the second matches", lines: []string{`corp.test. CAA 0 issue "ca1.test" || 0 issue "ca2.test"`}, specs: two(`0 issue "ca2.test"`)},
		{name: "two alternatives: not weaker than one of them gives no caa",
			lines:  []string{`corp.test. CAA 0 issue "ca2.test" || 0 issue "ca1.test" | 0 issue "ca3.test"`},
			specs:  two(`0 iodef "mailto:a@corp.test" | 0 issue "ca1.test"`),
			wanted: []caaWant{caaRecordSet("@", `0 0 iodef "mailto:a@corp.test" | 0 issue "ca1.test"`, `1 0 iodef "mailto:a@corp.test" | 0 issue "ca1.test"`)}},

		// An alias and an empty answer take the policy above the name.
		{name: "an empty answer at a line takes the parent's policy: weaker", lines: []string{caaApexWeak, caaWWWLine}, owner: www, specs: two("nodata"),
			wanted: []caaWant{caaHigh("@", "0 none", "1 none")}},
		{name: "an empty answer at a line takes the parent's policy: the same", lines: []string{caaApex, caaWWWLine}, owner: www, specs: two("nodata"),
			wanted: []caaWant{caaRecordSet("@", "0 none", "1 none")}},
		{name: "an alias at an exact line compares the inherited policy: weaker", lines: []string{caaApexWeak, caaWWWLine}, owner: www,
			specs: two("CNAME edge.dnshost.test."), wanted: []caaWant{caaHigh("@", "0 CNAME edge.dnshost.test.", "1 CNAME edge.dnshost.test.")}},
		{name: "an alias at an exact line compares the inherited policy: the same", lines: []string{caaApex, caaWWWLine}, owner: www,
			specs: two("CNAME edge.dnshost.test."), wanted: []caaWant{caaRecordSet("@", "0 CNAME edge.dnshost.test.", "1 CNAME edge.dnshost.test.")}},
		{name: "an alias at an exact line, the inherited policy is stricter", lines: []string{caaApex, `www.corp.test. CAA 0 issue "ca.test" | 0 issue "ca2.test"`}, owner: www,
			specs: two("CNAME edge.dnshost.test."), wanted: []caaWant{caaRecordSet("@", "0 CNAME edge.dnshost.test.", "1 CNAME edge.dnshost.test.")}},
		{name: "an alias at the domain: nothing is inherited", specs: two("CNAME edge.dnshost.test."),
			wanted: []caaWant{caaHigh("@", "0 CNAME edge.dnshost.test.", "1 CNAME edge.dnshost.test.")}},
		{name: "an alias at one server and the file's set at the other", lines: []string{caaApexWeak, caaWWWLine}, owner: www,
			specs: []string{"CNAME edge.dnshost.test.", caaStrong}, wanted: []caaWant{caaHigh("@", "0 CNAME edge.dnshost.test.")}},
		{name: "an exact line two levels up, the inherited policy is that of the nearest line", lines: []string{`corp.test. CAA 0 issue "ca9.test"`, `www.corp.test. CAA 0 issue "ca.test"`, "a.www.corp.test. CAA 0 issue \"ca.test\""},
			owner: "a.www.corp.test.", specs: two("nodata"), wanted: []caaWant{caaRecordSet("@", "0 none", "1 none")}},

		// A probe: a CAA check of a name that has no line.
		{name: "a probe finds a weakened set", lines: []string{caaApex, caaWWWA}, owner: www, gov: "corp.test.", specs: []string{caaWeak, caaStrong},
			wanted: []caaWant{caaHigh("@", "0 "+caaWeak)}},
		{name: "a probe with no set", lines: []string{caaApex, caaWWWA}, owner: www, specs: two("nodata")},
		{name: "a probe with no such name", lines: []string{caaApex, caaWWWA}, owner: www, specs: two("noname")},
		{name: "a probe with an alias gives nothing", lines: []string{caaApex, caaWWWA}, owner: www, specs: two("CNAME edge.dnshost.test.")},
		{name: "a probe with the apex's set gives nothing", lines: []string{caaApex, caaWWWA}, owner: www, specs: two(caaStrong)},
		{name: "a probe with a stricter set gives nothing: no record-set, no not-covered", lines: []string{caaApex, caaWWWA}, owner: www, specs: two(`0 issue ";"`)},
		{name: "a probe with a failure gives nothing", lines: []string{caaApex, caaWWWA}, owner: www, specs: two("fail")},
		{name: "a probe in capitals", lines: []string{caaApex, caaWWWA}, owner: "WWW.Corp.Test.", gov: "corp.test.", specs: two(caaWeak),
			wanted: []caaWant{caaHigh("@", "0 "+caaWeak, "1 "+caaWeak)}},
		{name: "a probe is judged against the nearest line, which is not the apex", gov: "www.corp.test.",
			lines: []string{`corp.test. CAA 0 issue "ca9.test"`, `www.corp.test. CAA 0 issue "ca.test" | 0 issue "ca2.test"`, "a.www.corp.test. A 10.53.0.82"},
			owner: "a.www.corp.test.", specs: two(`0 issue "ca.test"`)},
		{name: "a probe weaker than the nearest line", gov: "www.corp.test.",
			lines: []string{`corp.test. CAA 0 issue "ca9.test"`, `www.corp.test. CAA 0 issue "ca.test" | 0 issue "ca2.test"`, "a.www.corp.test. A 10.53.0.82"},
			owner: "a.www.corp.test.", specs: two(`0 issue "ca9.test"`), wanted: []caaWant{caaHigh("@", `0 0 issue "ca9.test"`, `1 0 issue "ca9.test"`)}},
		{name: "a probe below a none line is judged against the apex", gov: "corp.test.", lines: []string{caaApex, "www.corp.test. CAA none", "a.www.corp.test. A 10.53.0.82"},
			owner: "a.www.corp.test.", specs: two(caaWeak), wanted: []caaWant{caaHigh("@", "0 "+caaWeak, "1 "+caaWeak)}},

		// A CAA check with no line that is no probe is not covered.
		{name: "a name that is not in the plan is not covered", lines: []string{caaApex, caaWWWA}, owner: "_srv.corp.test.", specs: two(caaWeak),
			wanted: []caaWant{{RuleNotCovered, SeverityMedium, "", []string{"0 " + caaWeak, "1 " + caaWeak}}}},
		{name: "a file with no CAA policy covers no CAA check", lines: []string{caaWWWA}, owner: www, specs: []string{caaStrong, "nodata"},
			wanted: []caaWant{{RuleNotCovered, SeverityMedium, "", []string{"0 " + caaStrong, "1 none"}}}},
		{name: "a file with a none line only covers no CAA check", lines: []string{"corp.test. CAA none", caaWWWA}, owner: www, specs: two(caaWeak),
			wanted: []caaWant{{RuleNotCovered, SeverityMedium, "", []string{"0 " + caaWeak, "1 " + caaWeak}}}},
		{name: "a file of another domain", lines: []string{`shop.test. CAA 0 issue "ca.test"`}, file: "shop.test.", specs: two(caaWeak),
			wanted: []caaWant{{RuleNotCovered, SeverityMedium, "", []string{"0 " + caaWeak, "1 " + caaWeak}}}},
		// A policy with one open class is not open.
		{name: "an issuewild line: a wildcard authority added", lines: []string{`corp.test. CAA 0 issuewild "ca.test"`}, specs: two(`0 issuewild "evil.test"`),
			wanted: []caaWant{caaHigh("@", `0 0 issuewild "evil.test"`, `1 0 issuewild "evil.test"`)}},
		{name: "an issuewild line: the servers give the line's set", lines: []string{`corp.test. CAA 0 issuewild "ca.test"`}, specs: two(`0 issuewild "ca.test"`)},
		{name: "an issuewild line: a probe finds a weakened wildcard policy", lines: []string{`corp.test. CAA 0 issuewild "ca.test"`, caaWWWA}, owner: www, gov: "corp.test.",
			specs: two(`0 issuewild "evil.test"`), wanted: []caaWant{caaHigh("@", `0 0 issuewild "evil.test"`, `1 0 issuewild "evil.test"`)}},

		// A value that authorities read in different ways is judged under both readings.
		{name: "a probe: a repeated validationmethods", lines: []string{caaApex, caaWWWA}, owner: www, gov: "corp.test.", specs: two(caaRepeated),
			wanted: []caaWant{caaHigh("@", "0 "+caaRepeated, "1 "+caaRepeated)}},
		{name: "a probe: an empty method label", lines: []string{caaApex, caaWWWA}, owner: www, gov: "corp.test.", specs: two(caaEmptyLabel),
			wanted: []caaWant{caaHigh("@", "0 "+caaEmptyLabel, "1 "+caaEmptyLabel)}},
		{name: "a probe: a repeated accounturi", lines: []string{caaApex, caaWWWA}, owner: www, gov: "corp.test.", specs: two(caaTwoAccounts),
			wanted: []caaWant{caaHigh("@", "0 "+caaTwoAccounts, "1 "+caaTwoAccounts)}},
		{name: "a probe: a critical tag that the authority may know", lines: []string{caaApex, caaWWWA}, owner: www, gov: "corp.test.", specs: two(caaCritical),
			wanted: []caaWant{caaHigh("@", "0 "+caaCritical, "1 "+caaCritical)}},
		{name: "at a line: a repeated validationmethods is caa, not only record-set", specs: two(caaRepeated),
			wanted: []caaWant{caaHigh("@", "0 "+caaRepeated, "1 "+caaRepeated)}},
		{name: "at a line: an empty method label", specs: two(caaEmptyLabel), wanted: []caaWant{caaHigh("@", "0 "+caaEmptyLabel, "1 "+caaEmptyLabel)}},
		{name: "at a line: an empty accounturi", specs: two(`0 issue "evil.test; accounturi="`),
			wanted: []caaWant{caaHigh("@", `0 0 issue "evil.test; accounturi="`, `1 0 issue "evil.test; accounturi="`)}},
		{name: "at a line: a repeated accounturi", specs: two(caaTwoAccounts), wanted: []caaWant{caaHigh("@", "0 "+caaTwoAccounts, "1 "+caaTwoAccounts)}},
		{name: "at a line: a critical tag beside a new authority", specs: two(caaCritical), wanted: []caaWant{caaHigh("@", "0 "+caaCritical, "1 "+caaCritical)}},
		{name: "a line that holds a critical unknown tag, the zone equals the file", lines: []string{`corp.test. CAA 128 tbs "x" | 0 issue "ca.test"`}, specs: two(`0 issue "ca.test" | 128 tbs "x"`)},
		{name: "a line that holds a repeated accounturi, the zone equals the file", lines: []string{`corp.test. CAA 0 issue "ca.test; accounturi=a; accounturi=b"`},
			specs: two(`0 issue "ca.test; accounturi=a; accounturi=b"`)},
		{name: "a line that holds a repeated validationmethods, the zone equals the file", lines: []string{`corp.test. CAA 0 issue "ca.test; validationmethods=dns-01; validationmethods=dns-01"`},
			specs: two(`0 issue "ca.test; validationmethods=dns-01; validationmethods=dns-01"`)},
		{name: "a line with an empty method label, the zone equals the file", lines: []string{`corp.test. CAA 0 issue "ca.test; validationmethods=dns-01,"`}, specs: two(`0 issue "ca.test; validationmethods=dns-01,"`)},
		{name: "a probe below a critical unknown tag with no set", lines: []string{`corp.test. CAA 128 tbs "x" | 0 issue "ca.test"`, caaWWWA}, owner: www, specs: two("nodata")},
		{name: "a probe below a repeated accounturi with no set", lines: []string{`corp.test. CAA 0 issue "ca.test; accounturi=a; accounturi=b"`, caaWWWA}, owner: www, specs: two("nodata")},
		{name: "a probe below a repeated validationmethods with no set", lines: []string{`corp.test. CAA 0 issue "ca.test; validationmethods=dns-01; validationmethods=dns-01"`, caaWWWA}, owner: www,
			specs: two("nodata")},
		{name: "a probe below a critical unknown tag with a new authority", lines: []string{`corp.test. CAA 128 tbs "x" | 0 issue "ca.test"`, caaWWWA}, owner: www, gov: "corp.test.", specs: two(`0 issue "evil.test"`),
			wanted: []caaWant{caaHigh("@", `0 0 issue "evil.test"`, `1 0 issue "evil.test"`)}},

		// Only a reading that is permissive in one case and strict in another shows these.
		{name: "mixed readings: a critical line, a repeated validationmethods below it", lines: []string{`corp.test. CAA 0 issue "ca.test" | 128 tbs "x"`, caaWWWA}, owner: www, gov: "corp.test.",
			specs: two(caaRepeated2), wanted: []caaWant{caaHigh("@", "0 "+caaRepeated2, "1 "+caaRepeated2)}},
		{name: "mixed readings: a repeated accounturi in the line, a critical tag below it", lines: []string{`corp.test. CAA 0 issue "ca.test; accounturi=https://ca.test/1; accounturi=https://ca.test/2"`, caaWWWA},
			owner: www, gov: "corp.test.", specs: two(caaCritical2), wanted: []caaWant{caaHigh("@", "0 "+caaCritical2, "1 "+caaCritical2)}},
		{name: "mixed readings, at the line itself", lines: []string{`corp.test. CAA 0 issue "ca.test" | 128 tbs "x"`}, specs: two(caaRepeated2),
			wanted: []caaWant{caaHigh("@", "0 "+caaRepeated2, "1 "+caaRepeated2)}},
		{name: "no reading shows more: the same critical set below the line", lines: []string{`corp.test. CAA 0 issue "ca.test" | 128 tbs "x"`, caaWWWA}, owner: www, specs: two(`0 issue "ca.test" | 128 tbs "x"`)},
		{name: "no reading shows more: another critical tag below the line", lines: []string{`corp.test. CAA 0 issue "ca.test" | 128 tbs "x"`, caaWWWA}, owner: www, specs: two(`0 issue "ca.test" | 128 other "y"`)},

		// A policy that is guarded under one reading only still guards.
		{name: "a name that is not in the plan is judged under a guarded policy: weaker", lines: []string{caaApex, caaWWWA}, owner: "x.corp.test.", gov: "corp.test.", specs: two(caaWeak),
			wanted: []caaWant{caaHigh("@", "0 "+caaWeak, "1 "+caaWeak)}},
		{name: "a name that is not in the plan is judged under a guarded policy: no set", lines: []string{caaApex, caaWWWA}, owner: "x.corp.test.", specs: two("nodata")},
		{name: "a name that is not in the plan under an open policy is not covered", lines: []string{`corp.test. CAA 0 iodef "mailto:a@corp.test"`, caaWWWA}, owner: "x.corp.test.", specs: two(caaWeak),
			wanted: []caaWant{{RuleNotCovered, SeverityMedium, "", []string{"0 " + caaWeak, "1 " + caaWeak}}}},
		{name: "a name under a policy that is open under one reading only is judged", lines: []string{`corp.test. CAA 128 tbs "x"`, caaWWWA}, owner: "x.corp.test.", gov: "corp.test.", specs: two(caaStrong),
			wanted: []caaWant{caaHigh("@", "0 "+caaStrong, "1 "+caaStrong)}},
		{name: "a name under a policy that is open under both readings is not covered", lines: []string{`corp.test. CAA 128 tbs "x" || 0 iodef "mailto:a@corp.test"`, caaWWWA}, owner: "x.corp.test.",
			specs: two(caaStrong), wanted: []caaWant{{RuleNotCovered, SeverityMedium, "", []string{"0 " + caaStrong, "1 " + caaStrong}}}},

		// Names with a star or an underscore label are compared as plain sets.
		{name: "a line at a wildcard owner: a weakened set is record-set", lines: []string{caaApex, `*.x.corp.test. CAA 0 issue "ca.test"`}, owner: "*.x.corp.test.",
			specs: two(`0 issue "evil.test"`), wanted: []caaWant{caaRecordSet("@", `0 0 issue "evil.test"`, `1 0 issue "evil.test"`)}},
		{name: "a line at a wildcard owner: a superset is record-set", lines: []string{caaApex, `*.x.corp.test. CAA 0 issue "ca.test"`}, owner: "*.x.corp.test.",
			specs: two(caaWeak), wanted: []caaWant{caaRecordSet("@", "0 "+caaWeak, "1 "+caaWeak)}},
		{name: "a line at a wildcard owner: the set is gone", lines: []string{caaApex, `*.x.corp.test. CAA 0 issue "ca.test"`}, owner: "*.x.corp.test.",
			specs: two("nodata"), wanted: []caaWant{caaRecordSet("@", "0 none", "1 none")}},
		{name: "a line at a wildcard owner: the zone equals the file", lines: []string{caaApex, `*.x.corp.test. CAA 0 issue "ca.test"`}, owner: "*.x.corp.test.", specs: two(caaStrong)},
		{name: "a line at an underscore name: a weakened set is record-set", lines: []string{caaApex, `_x.corp.test. CAA 0 issue "ca.test"`}, owner: "_x.corp.test.",
			specs: two(caaWeak), wanted: []caaWant{caaRecordSet("@", "0 "+caaWeak, "1 "+caaWeak)}},
		{name: "a line at an underscore name: an empty answer is record-set", lines: []string{caaApexWeak, `_x.corp.test. CAA 0 issue "ca.test"`}, owner: "_x.corp.test.",
			specs: two("nodata"), wanted: []caaWant{caaRecordSet("@", "0 none", "1 none")}},
		{name: "a line at a name under an underscore label", lines: []string{caaApex, `a._tcp.corp.test. CAA 0 issue "ca.test"`}, owner: "a._tcp.corp.test.",
			specs: two(caaWeak), wanted: []caaWant{caaRecordSet("@", "0 "+caaWeak, "1 "+caaWeak)}},
		{name: "a none line at a challenge name gives challenge and no caa", lines: []string{caaApex, `_acme-challenge.corp.test. CAA none`}, owner: "_acme-challenge.corp.test.",
			specs: two(caaWeak), wanted: []caaWant{{RuleChallenge, SeverityHigh, "none", []string{"0 " + caaWeak, "1 " + caaWeak}}}},
		{name: "a none line at a challenge name, no set", lines: []string{caaApex, `_acme-challenge.corp.test. CAA none`}, owner: "_acme-challenge.corp.test.", specs: two("nodata")},
		{name: "a wildcard owner without a line is not covered", lines: []string{caaApex, caaWWWA}, owner: "*.corp.test.", specs: two(caaWeak),
			wanted: []caaWant{{RuleNotCovered, SeverityMedium, "", []string{"0 " + caaWeak, "1 " + caaWeak}}}},

		// The relabel keeps the other rules.
		{name: "the zone rule stays beside caa", zone: "evil.test.", specs: two(caaWeak),
			wanted: []caaWant{{RuleZone, SeverityHigh, "corp.test.", []string{"0 evil.test.", "1 evil.test."}}, caaHigh("@", "0 "+caaWeak, "1 "+caaWeak)}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if r.lines == nil {
				r.lines = []string{caaApex}
			}
			if r.file == "" {
				r.file = "corp.test."
			}
			if r.owner == "" {
				r.owner = "corp.test."
			}
			if r.gov == "" {
				r.gov = r.owner
			}
			if r.zone == "" {
				r.zone = "corp.test."
			}
			f := decFile(t, append([]string{"domain " + r.file}, r.lines...)...)
			o := caaObserve(t, r.owner, r.zone, r.specs...)
			var want []decWant
			for _, w := range r.wanted {
				if w.expected == "@" {
					w.expected = decFormText(t, f, r.gov, dnswire.TypeCAA)
				}
				want = append(want, decWant{w.rule, w.severity, w.expected, dngSeenOf(t, o.Answers, w.seen...)})
			}
			regCheck(t, Findings(f, o), o.Key, want...)
		})
	}
}

// ---- the rule in Decide ----

var caaNow = decT0.Add(time.Hour)

func caaFinding(o obs.Observation, rule Rule, sev Severity, expected string, seen []Seen) Finding {
	return Finding{Rule: rule, Severity: sev, Check: o.Key, Expected: expected, Seen: seen, Value: regValue(seen)}
}

func caaSeenAt(t *testing.T, o obs.Observation, texts ...string) []Seen {
	return dngSeenOf(t, o.Answers, texts...)
}

func caaInput(t *testing.T, lines []string, owner string, specs ...string) Input {
	t.Helper()
	f := decFile(t, append([]string{"domain corp.test."}, lines...)...)
	return Input{Expect: f, Observation: caaObserve(t, owner, "corp.test.", specs...), Now: caaNow}
}

func TestCAARuleWordNumberAndSeverity(t *testing.T) {
	if RuleCAA != 17 {
		t.Errorf("RuleCAA is rule number %d, want 17: the store keeps the number", RuleCAA)
	}
	if RuleCAA != RuleWildcard+1 {
		t.Errorf("RuleCAA is %d, want the number after RuleWildcard (%d)", RuleCAA, RuleWildcard)
	}
	if got := RuleCAA.String(); got != "caa" {
		t.Errorf("RuleCAA.String() is %q, want caa", got)
	}
	for _, typ := range []dnswire.Type{0, dnswire.TypeA, dnswire.TypeTXT, dnswire.TypeCAA} {
		if got := severity(RuleCAA, typ); got != SeverityHigh {
			t.Errorf("caa severity for type %v is %v, want high", typ, got)
		}
	}
	if got := severity(RuleRecordSet, dnswire.TypeCAA); got != SeverityMedium {
		t.Errorf("record-set severity for CAA is %v, want medium", got)
	}
}

// A record-set line of a CAA check that states no policy stays a record-set.
func TestCAALineWithNoPolicyStaysRecordSet(t *testing.T) {
	f := decFile(t, "domain corp.test.", "corp.test. CAA none", "www.corp.test. CAA none")
	for _, owner := range []string{"corp.test.", "www.corp.test."} {
		o := caaObserve(t, owner, "corp.test.", caaWeak, caaWeak)
		regCheck(t, Findings(f, o), o.Key, decWant{RuleRecordSet, SeverityMedium, "none", dngSeenOf(t, o.Answers, "0 "+caaWeak, "1 "+caaWeak)})
	}
	f = decFile(t, "domain corp.test.", `corp.test. CAA 0 iodef "mailto:a@corp.test"`)
	o := caaObserve(t, "corp.test.", "corp.test.", caaWeak, "nodata")
	regCheck(t, Findings(f, o), o.Key, decWant{RuleRecordSet, SeverityMedium, `0 iodef "mailto:a@corp.test"`, dngSeenOf(t, o.Answers, "0 "+caaWeak, "1 none")})
}

func TestCAAAlerts(t *testing.T) {
	lines := []string{caaApex, caaWWWA}
	open := func(o obs.Observation, texts ...string) Change {
		return Change{Op: OpOpen, Finding: caaFinding(o, RuleCAA, SeverityHigh, caaStrong, caaSeenAt(t, o, texts...)), At: caaNow}
	}
	// openAt is an open alert that saw the servers by index.
	openAt := func(o obs.Observation, expected string, servers ...int) Finding {
		var seen []Seen
		for _, i := range servers {
			seen = append(seen, Seen{Answer: decAnswer(t, caaServers[i].host, caaServers[i].addr, caaResult(t, "corp.test.", caaWeak)), Text: caaWeak})
		}
		return caaFinding(o, RuleCAA, SeverityHigh, expected, seen)
	}

	t.Run("a weakened set opens one high alert", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", caaWeak, caaWeak)
		decSameChanges(t, Decide(in), []Change{open(in.Observation, "0 "+caaWeak, "1 "+caaWeak)})
	})
	t.Run("an open record-set alert is left as it is while caa is given", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", caaWeak, caaWeak)
		in.Open = []Finding{caaFinding(in.Observation, RuleRecordSet, SeverityMedium, caaStrong, caaSeenAt(t, in.Observation, "0 "+caaStrong))}
		decSameChanges(t, Decide(in), []Change{open(in.Observation, "0 "+caaWeak, "1 "+caaWeak)})
	})
	t.Run("an open record-set alert with other lines is not updated while caa is given", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", caaWeak, caaWeak)
		in.Open = []Finding{caaFinding(in.Observation, RuleRecordSet, SeverityMedium, `0 issue "old.test"`, caaSeenAt(t, in.Observation, "0 none"))}
		decSameChanges(t, Decide(in), []Change{open(in.Observation, "0 "+caaWeak, "1 "+caaWeak)})
	})
	t.Run("both alerts end when the set equals the line again", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", caaStrong, caaStrong)
		in.Open = []Finding{
			caaFinding(in.Observation, RuleRecordSet, SeverityMedium, caaStrong, caaSeenAt(t, in.Observation, "0 "+caaStrong)),
			openAt(in.Observation, caaStrong, 0, 1),
		}
		decSameChanges(t, Decide(in), []Change{{Op: OpResolve, Finding: in.Open[0], At: caaNow}, {Op: OpResolve, Finding: in.Open[1], At: caaNow}})
	})
	t.Run("an open caa alert does not resolve when the set changes to a value read in two ways", func(t *testing.T) {
		for _, v := range []string{caaRepeated, caaEmptyLabel, caaTwoAccounts, caaCritical} {
			in := caaInput(t, lines, "corp.test.", v, v)
			in.Open = []Finding{openAt(in.Observation, caaStrong, 0, 1)}
			want := open(in.Observation, "0 "+v, "1 "+v)
			want.Op = OpUpdate
			decSameChanges(t, Decide(in), []Change{want})
		}
	})
	t.Run("an open alert with the same lines changes nothing", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", caaWeak, caaWeak)
		in.Open = []Finding{openAt(in.Observation, caaStrong, 0, 1)}
		decSameChanges(t, Decide(in), nil)
	})
	t.Run("one more server with the same set is no news, and the alert keeps it", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", caaWeak, caaWeak)
		in.Open = []Finding{openAt(in.Observation, caaStrong, 0)}
		want := open(in.Observation, "0 "+caaWeak, "1 "+caaWeak)
		want.Op = OpRefresh
		decSameChanges(t, Decide(in), []Change{want})
	})
	t.Run("a server that is gone is no news", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", caaWeak, "fail")
		in.Open = []Finding{openAt(in.Observation, caaStrong, 0, 1)}
		decSameChanges(t, Decide(in), nil)
	})
	t.Run("a new line in the file is news", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", caaWeak, caaWeak)
		in.Open = []Finding{openAt(in.Observation, `0 issue "old.test"`, 0, 1)}
		want := open(in.Observation, "0 "+caaWeak, "1 "+caaWeak)
		want.Op = OpUpdate
		decSameChanges(t, Decide(in), []Change{want})
	})
	t.Run("the alert ends when the policy is as strict again, and keeps its words", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", caaStrong, caaStrong)
		in.Open = []Finding{openAt(in.Observation, `0 issue "ca.test" | 0 issue "old.test"`, 0, 1)}
		decSameChanges(t, Decide(in), []Change{{Op: OpResolve, Finding: in.Open[0], At: caaNow}})
	})
	t.Run("the alert ends at a stricter set", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", `0 issue ";"`, `0 issue ";"`)
		in.Open = []Finding{openAt(in.Observation, caaStrong, 0, 1)}
		got := Decide(in)
		if len(got) != 2 || got[0].Op != OpOpen || got[0].Finding.Rule != RuleRecordSet || got[1].Op != OpResolve || got[1].Finding.Rule != RuleCAA {
			t.Errorf("changes are%s, want an open record-set and a resolve of caa", decShowChanges(got))
		}
	})
	t.Run("a failure at a server that showed it keeps the alert", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", "fail", caaStrong)
		in.Open = []Finding{openAt(in.Observation, caaStrong, 0)}
		decSameChanges(t, Decide(in), nil)
	})
	t.Run("a failure at another server does not", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", caaStrong, caaStrong, "fail")
		in.Open = []Finding{openAt(in.Observation, caaStrong, 0)}
		decSameChanges(t, Decide(in), []Change{{Op: OpResolve, Finding: in.Open[0], At: caaNow}})
	})
	t.Run("every answer failed keeps the alert", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", "fail", "fail")
		in.Open = []Finding{openAt(in.Observation, caaStrong, 0)}
		decSameChanges(t, Decide(in), nil)
	})
	t.Run("a probe that finds a weakened set opens an alert about the line that governs", func(t *testing.T) {
		in := caaInput(t, lines, "www.corp.test.", caaWeak, caaStrong)
		decSameChanges(t, Decide(in), []Change{open(in.Observation, "0 "+caaWeak)})
	})
	t.Run("a probe with a set as strict as the file's gives no change", func(t *testing.T) {
		in := caaInput(t, lines, "www.corp.test.", caaStrong, "nodata")
		decSameChanges(t, Decide(in), nil)
	})
	t.Run("a long split does not open disagree beside caa", func(t *testing.T) {
		in := caaInput(t, lines, "corp.test.", caaWeak, caaStrong)
		in.DisagreeLong = true
		decSameChanges(t, Decide(in), []Change{open(in.Observation, "0 "+caaWeak)})
	})
	t.Run("a long split between two alternatives of a line opens disagree", func(t *testing.T) {
		alt := `corp.test. CAA 0 issue "ca1.test" || 0 issue "ca2.test"`
		in := caaInput(t, []string{alt}, "corp.test.", `0 issue "ca1.test"`, `0 issue "ca2.test"`)
		in.DisagreeLong = true
		expected := decFormText(t, in.Expect, "corp.test.", dnswire.TypeCAA)
		seen := caaSeenAt(t, in.Observation, `0 0 issue "ca1.test"`, `1 0 issue "ca2.test"`)
		want := Finding{Rule: RuleDisagree, Severity: SeverityMedium, Check: in.Observation.Key, Expected: expected, Seen: seen,
			Value: `0 issue "ca1.test"` + "\n" + `0 issue "ca2.test"`}
		decSameChanges(t, Decide(in), []Change{{Op: OpOpen, Finding: want, At: caaNow}})
	})
	t.Run("a split that caa explains opens no disagree even for a probe", func(t *testing.T) {
		in := caaInput(t, lines, "www.corp.test.", caaStrong, caaWeak)
		in.DisagreeLong = true
		decSameChanges(t, Decide(in), []Change{open(in.Observation, "1 "+caaWeak)})
	})
}

// A check of another type never gives caa, whatever the CAA lines say.
func TestCAANeverJudgesAnotherType(t *testing.T) {
	const a1, a2 = "192.0.2.1", "192.0.2.2"
	f := decFile(t, "domain corp.test.", caaApex, "corp.test. A "+a1, `www.corp.test. CAA 0 issue ";"`, "www.corp.test. A "+a1)
	for _, owner := range []string{"corp.test.", "www.corp.test."} {
		key := decRecordsKey(t, "corp.test.", owner, dnswire.TypeA)
		run := func(addr string) (obs.Observation, []Finding) {
			o := decObservation(key, decName(t, "corp.test."), nil,
				decAnswer(t, caaServers[0].host, caaServers[0].addr, decSet(t, owner, dnswire.TypeA, addr)),
				decAnswer(t, caaServers[1].host, caaServers[1].addr, decSet(t, owner, dnswire.TypeA, addr)))
			return o, Findings(f, o)
		}
		if _, got := run(a1); len(got) != 0 {
			t.Errorf("%s A, the right address gave:%s", owner, decShow(got))
		}
		o, got := run(a2)
		regCheck(t, got, key, decWant{RuleRecordSet, SeverityHigh, a1, dngSeenOf(t, o.Answers, "0 "+a2, "1 "+a2)})
	}
}

// A CAA check that the file does not cover gives not-covered and never caa,
// also when its name is not under the domain or has fewer labels than it.
func TestCAANeverJudgesAnUncoveredCheck(t *testing.T) {
	const evil = `0 issue "evil.test"`
	f := decFile(t, "domain corp.test.", caaApex, caaWWWA)
	rows := []struct {
		name   string
		file   *expect.File
		domain string
		owner  string
	}{
		{"another domain, the name of that domain's apex", f, "shop.test.", "corp.test."},
		{"another domain, a name below the apex", f, "shop.test.", "www.corp.test."},
		{"no file", nil, "corp.test.", "corp.test."},
		{"no file, a name below the apex", nil, "corp.test.", "www.corp.test."},
		{"a name above the domain", f, "corp.test.", "test."},
		{"the root", f, "corp.test.", "."},
		{"a sibling of the domain", f, "corp.test.", "other.test."},
		{"a name under a sibling", f, "corp.test.", "www.other.test."},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			key := decRecordsKey(t, r.domain, r.owner, dnswire.TypeCAA)
			var answers []obs.Answer
			for i := 0; i < 2; i++ {
				answers = append(answers, decAnswer(t, caaServers[i].host, caaServers[i].addr, caaResult(t, r.owner, evil)))
			}
			o := decObservation(key, decName(t, "corp.test."), nil, answers...)
			regCheck(t, Findings(r.file, o), key, decWant{RuleNotCovered, SeverityMedium, "", dngSeenOf(t, answers, "0 "+evil, "1 "+evil)})
		})
	}
}

// The readings differ in Weaker too: each side of a comparison is read the same way.
func caaWeakerReadingRows(t *testing.T) {
	rows := []struct {
		name      string
		now, want []dnswire.CAA
		strict    Request
		permitted Request // the witness under the permissive reading; the zero value for none
		strictOK  bool
		permOK    bool
	}{
		{"a critical unknown tag cleared", []dnswire.CAA{caaC(0, "tbs", "x"), caaIssue("ca.test")}, []dnswire.CAA{caaC(128, "tbs", "x"), caaIssue("ca.test")},
			Request{Issuer: "ca.test"}, Request{}, true, false},
		{"a repeated accounturi against a bound account", []dnswire.CAA{caaIssue("ca.test; accounturi=a; accounturi=b")}, []dnswire.CAA{caaIssue("ca.test; accounturi=x")},
			Request{}, Request{Issuer: "ca.test"}, false, true},
		{"an empty accounturi against a bound account", []dnswire.CAA{caaIssue("ca.test; accounturi=")}, []dnswire.CAA{caaIssue("ca.test; accounturi=x")},
			Request{}, Request{Issuer: "ca.test"}, false, true},
		{"an empty method label against a method list", []dnswire.CAA{caaIssue("ca.test; validationmethods=dns-01,")}, []dnswire.CAA{caaIssue("ca.test; validationmethods=dns-01")},
			Request{}, Request{Issuer: "ca.test"}, false, true},
		{"a repeated validationmethods against a method list", []dnswire.CAA{caaIssue("ca.test; validationmethods=dns-01; validationmethods=dns-01")},
			[]dnswire.CAA{caaIssue("ca.test; validationmethods=dns-01")}, Request{}, Request{Issuer: "ca.test"}, false, true},
		{"a bad method octet against a method list", []dnswire.CAA{caaIssue("ca.test; validationmethods=dns_01")}, []dnswire.CAA{caaIssue("ca.test; validationmethods=dns-01")},
			Request{}, Request{Issuer: "ca.test"}, false, true},
		{"the same repeated accounturi on both sides", []dnswire.CAA{caaIssue("ca.test; accounturi=a; accounturi=b")}, []dnswire.CAA{caaIssue("ca.test; accounturi=a; accounturi=b")},
			Request{}, Request{}, false, false},
		{"the same critical tag on both sides", []dnswire.CAA{caaC(128, "tbs", "x"), caaIssue("ca.test")}, []dnswire.CAA{caaC(128, "tbs", "x"), caaIssue("ca.test")},
			Request{}, Request{}, false, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			for _, c := range []struct {
				rd      Reading
				witness Request
				weaker  bool
			}{{StrictReading, r.strict, r.strictOK}, {PermissiveReading, r.permitted, r.permOK}} {
				now, _ := caaPolicyUnder(c.rd, r.now...)
				want, _ := caaPolicyUnder(c.rd, r.want...)
				got, ok := Weaker(now, want)
				if ok != c.weaker || got != c.witness {
					t.Errorf("reading %d: Weaker is (%+v, %v), want (%+v, %v)", c.rd, got, ok, c.witness, c.weaker)
				}
			}
		})
	}
}

// ---- the eight readings ----

// caaCases says which of the three cases in which authorities read a set
// differently a reading reads permissively. The indexes of the readings are
// not named here: each is derived from single-case sets, one set for each
// case, whose policy tells how the reading reads that case (the strict form
// or the permissive one). The two ends are StrictReading and
// PermissiveReading.
type caaCases struct{ knownTag, anyAccount, anyMethod bool }

var (
	caaCasesOnce  sync.Once
	caaCasesTable [Readings]caaCases
)

func caaCasesOf(rd Reading) caaCases {
	caaCasesOnce.Do(func() {
		probe := func(rd Reading, strict, permissive Policy, set ...dnswire.CAA) bool {
			p, ok := caaPolicyUnder(rd, set...)
			switch {
			case ok && caaSamePolicy(p, permissive):
				return true
			case ok && caaSamePolicy(p, strict):
				return false
			}
			panic(fmt.Sprintf("reading %d gives neither form for %v: %s", rd, set, caaShow(p)))
		}
		for r := range Readings {
			caaCasesTable[r] = caaCases{
				knownTag:   probe(r, Policy{}, caaOnly("ca.test"), caaIssue("ca.test"), caaC(128, "tbs", "x")),
				anyAccount: probe(r, caaBoth(Class{}), caaOnly("ca.test"), caaIssue("ca.test; accounturi=a; accounturi=b")),
				anyMethod:  probe(r, caaBoth(Class{}), caaOnly("ca.test"), caaIssue("ca.test; validationmethods=dns-01; validationmethods=dns-01")),
			}
		}
	})
	return caaCasesTable[rd]
}

func TestCAAReadingsAreTheEightCombinations(t *testing.T) {
	if Readings != 8 {
		t.Fatalf("Readings is %d, want 8", Readings)
	}
	if c := caaCasesOf(StrictReading); c != (caaCases{}) {
		t.Errorf("StrictReading reads %+v permissively, want nothing", c)
	}
	if c := caaCasesOf(PermissiveReading); c != (caaCases{true, true, true}) {
		t.Errorf("PermissiveReading reads %+v permissively, want everything", c)
	}
	seen := map[caaCases]bool{}
	for r := range Readings {
		seen[caaCasesOf(r)] = true
	}
	if len(seen) != 8 {
		t.Errorf("the readings stand for %d different combinations of the three cases, want 8", len(seen))
	}
}

// The three cases are decided independently: a set that holds all of them,
// and each subset of its records, is read under each reading as the cases of
// that reading say, whatever the other two cases are.
func TestCAAPolicyUnderEachReading(t *testing.T) {
	records := []dnswire.CAA{
		caaIssue("ca.test; accounturi=a; accounturi=b"),                             // an account that cannot hold
		caaIssue("ca2.test; validationmethods=dns-01; validationmethods=dns-01"),    // a method list that cannot hold
		caaIssue("ca3.test; accounturi=a; accounturi=b; validationmethods=dns-01,"), // both
		caaC(128, "tbs", "x"), // a critical tag that an authority may know
	}
	for mask := 1; mask < 16; mask++ {
		var set []dnswire.CAA
		var has [4]bool
		for i, r := range records {
			if mask&(1<<i) != 0 {
				set = append(set, r)
				has[i] = true
			}
		}
		for rd := range Readings {
			c := caaCasesOf(rd)
			var want Policy
			switch {
			case has[3] && !c.knownTag:
				want = Policy{}
			case !has[0] && !has[1] && !has[2]:
				want = OpenPolicy
			default:
				var issuers []string
				if has[0] && c.anyAccount {
					issuers = append(issuers, "ca.test")
				}
				if has[1] && c.anyMethod {
					issuers = append(issuers, "ca2.test")
				}
				if has[2] && c.anyAccount && c.anyMethod {
					issuers = append(issuers, "ca3.test")
				}
				want = caaOnly(issuers...)
			}
			got, ok := caaPolicyUnder(rd, set...)
			if !ok || !caaSamePolicy(got, want) {
				t.Errorf("records %v under reading %d (%+v): %s, want %s", has, rd, c, caaShow(got), caaShow(want))
			}
		}
	}
}

// Making a case permissive never permits less, for any set.
func TestCAAReadingsMonotone(t *testing.T) {
	const cases = 600
	pairs := 0
	for seed := uint64(1); seed <= cases; seed++ {
		g := &caaGen{rng: rand.New(rand.NewPCG(seed, 0xca5))}
		set := g.set(6)
		for r1 := range Readings {
			for r2 := range Readings {
				a, b := caaCasesOf(r1), caaCasesOf(r2)
				if (a.knownTag && !b.knownTag) || (a.anyAccount && !b.anyAccount) || (a.anyMethod && !b.anyMethod) {
					continue
				}
				pairs++
				p1, p2 := caaPolicyOrOpen(set, r1), caaPolicyOrOpen(set, r2)
				if r, w := Weaker(p1, p2); w {
					t.Fatalf("seed %d: reading %d (%+v) permits %+v, reading %d (%+v), which is more permissive, does not\n  %v", seed, r1, a, r, r2, b, set)
				}
			}
		}
	}
	if pairs != cases*27 {
		t.Errorf("%d pairs of readings, want %d (3^3 for each set)", pairs, cases*27)
	}
}

// A zone that equals the file gives no finding, whatever its CAA sets hold:
// each side is read in the same way.
func TestCAAZoneEqualsFileProperty(t *testing.T) {
	const cases = 1000
	text := func(set []dnswire.CAA) string {
		parts := make([]string, len(set))
		for i, r := range set {
			parts[i] = r.String()
		}
		return strings.Join(parts, " | ")
	}
	for seed := uint64(1); seed <= cases; seed++ {
		g := &caaGen{rng: rand.New(rand.NewPCG(seed, 0xca6))}
		var alts []string
		var sets [][]dnswire.CAA
		for n := 1 + g.rng.IntN(2); len(sets) < n; {
			if set := g.set(4); len(set) > 0 {
				sets = append(sets, set)
				alts = append(alts, text(set))
			}
		}
		// guarded: under some reading no alternative is open.
		guarded := false
		for rd := range Readings {
			open := false
			for _, set := range sets {
				p := caaPolicyOrOpen(set, rd)
				open = open || (p.Name.Any && p.Wild.Any)
			}
			guarded = guarded || !open
		}
		line := "corp.test. CAA " + strings.Join(alts, " || ")
		f := decFile(t, "domain corp.test.", line, caaWWWA)
		for _, owner := range []string{"corp.test.", "www.corp.test."} {
			if owner != "corp.test." && !guarded {
				continue // below a policy that is open under every reading nothing is judged
			}
			specs := make([]string, 2)
			for i := range specs {
				specs[i] = alts[g.rng.IntN(len(alts))]
				if owner != "corp.test." && g.rng.IntN(3) == 0 {
					specs[i] = "nodata"
				}
			}
			o := caaObserve(t, owner, "corp.test.", specs...)
			if got := Findings(f, o); len(got) != 0 {
				t.Fatalf("seed %d: the zone equals the file at %s, but findings are:%s\n  %s\n  %v", seed, owner, decShow(got), line, specs)
			}
		}
	}
}
