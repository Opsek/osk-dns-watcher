package obs

import (
	"strconv"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// Kind is what a check looks at. The zero Kind is no kind, so a Key that was
// never filled in is not a check.
type Kind uint8

const (
	KindDelegation Kind = iota + 1 // NS set and glue of Domain, at every server of the parent zone
	KindDS                         // DS set of Domain, at every server of the parent zone
	KindRecords                    // record set Name/Type, at every server of the zone that holds Name
	KindSerial                     // SOA of Domain, at every server of Domain
)

var kindWords = map[Kind]string{
	KindDelegation: "delegation",
	KindDS:         "ds",
	KindRecords:    "records",
	KindSerial:     "serial",
}

func (k Kind) String() string {
	if w, ok := kindWords[k]; ok {
		return w
	}
	return "kind" + strconv.Itoa(int(k))
}

// Key names one check.
type Key struct {
	Kind   Kind
	Domain dnswire.Name // the watched domain the check belongs to
	Name   dnswire.Name // equals Domain, except for KindRecords, where it may lie anywhere
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

// String gives every field, with the names lowercased, so two keys have the
// same text exactly when they name the same check: the text serves as a map
// key, because a Key itself cannot be one.
func (k Key) String() string {
	return k.Kind.String() + " " + k.Domain.Lower().String() + " " + k.Name.Lower().String() + " " + k.Type.String()
}
