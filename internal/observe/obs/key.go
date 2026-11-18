package obs

import (
	"strconv"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// Kind is what a check looks at. The zero Kind is no kind, so a Key that was
// never filled in is not a check.
type Kind uint8

const (
	KindDelegation   Kind = iota + 1 // NS set and glue of Domain, at every server of the parent zone
	KindDS                           // DS set of Domain, at every server of the parent zone
	KindRecords                      // record set Name/Type, at every server of the zone that holds Name
	KindSerial                       // SOA of Domain, at every server of Domain
	KindWildcard                     // A set of a random name just under Name, at every server of the zone that holds Name
	KindCertificates                 // the certificates that a certificate log shows for Domain; no DNS check
	KindPolicy                       // the MTA-STS policy file of Domain, over HTTPS from the host Name; no DNS check
)

var kindWords = map[Kind]string{
	KindDelegation:   "delegation",
	KindDS:           "ds",
	KindRecords:      "records",
	KindSerial:       "serial",
	KindWildcard:     "wildcard",
	KindCertificates: "certificates",
	KindPolicy:       "policy",
}

func (k Kind) String() string {
	if w, ok := kindWords[k]; ok {
		return w
	}
	return "kind" + strconv.Itoa(int(k))
}

// WildcardLabel is the length in octets of the random label that a wildcard
// check asks under its name: the 26 characters of crypto/rand.Text, which no
// one can guess and create ahead of the check to hide a wildcard from it.
const WildcardLabel = 26

// Key names one check.
type Key struct {
	Kind   Kind
	Domain dnswire.Name // the watched domain the check belongs to
	Name   dnswire.Name // equals Domain, except: anywhere for KindRecords and KindWildcard; mta-sts.<Domain> for KindPolicy
	Type   dnswire.Type
}

func DelegationKey(domain dnswire.Name) Key {
	return Key{Kind: KindDelegation, Domain: domain, Name: domain, Type: dnswire.TypeNS}
}

func DSKey(domain dnswire.Name) Key {
	return Key{Kind: KindDS, Domain: domain, Name: domain, Type: dnswire.TypeDS}
}

func SerialKey(domain dnswire.Name) Key {
	return Key{Kind: KindSerial, Domain: domain, Name: domain, Type: dnswire.TypeSOA}
}

// RecordsKey is the key of the record set name/t. The name may lie outside
// domain, as the target of an alias or of an MX record does.
func RecordsKey(domain, name dnswire.Name, t dnswire.Type) Key {
	return Key{Kind: KindRecords, Domain: domain, Name: name, Type: t}
}

// WildcardKey is the key of the check that asks a random name just under
// name. The key holds no label, so that every run, with its own label, is
// the same check.
func WildcardKey(domain, name dnswire.Name) Key {
	return Key{Kind: KindWildcard, Domain: domain, Name: name, Type: dnswire.TypeA}
}

// CertificatesKey is the key of the check that reads the certificate logs
// for domain. Name is the domain and Type is 0: the check has no name or
// type of its own.
func CertificatesKey(domain dnswire.Name) Key {
	return Key{Kind: KindCertificates, Domain: domain, Name: domain}
}

// PolicyKey is the key of the fetch of the MTA-STS policy file of domain
// from the host mta-sts.<domain> (RFC 8461 section 3.3). Type is TXT
// because the file comes back as the data of one TXT record. ok is false
// when that name would be too long.
func PolicyKey(domain dnswire.Name) (Key, bool) {
	name, err := dnswire.NameFromLabels(append([]string{"mta-sts"}, domain.Labels()...))
	if err != nil {
		return Key{}, false
	}
	return Key{Kind: KindPolicy, Domain: domain, Name: name, Type: dnswire.TypeTXT}, true
}

// String gives every field, with the names lowercased, so two keys have the
// same text exactly when they name the same check: the text serves as a map
// key, because a Key itself cannot be one. A certificates key has no name
// or type to give.
func (k Key) String() string {
	if k.Kind == KindCertificates {
		return k.Kind.String() + " " + k.Domain.Lower().String()
	}
	return k.Kind.String() + " " + k.Domain.Lower().String() + " " + k.Name.Lower().String() + " " + k.Type.String()
}
