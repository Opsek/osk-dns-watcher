package obs

import (
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

// Issuer is the authority that signed a certificate.
type Issuer struct {
	Name string   // the source's short name of the authority, for people: 1 to 64 octets of printable ASCII, else "-"
	CAA  []string // the names that a CAA policy uses for this authority: lower case, sorted, unique; may be empty
}

// Issuance is one certificate that a certificate log shows for a domain.
type Issuance struct {
	ID        string         // the source's id: 1 to 20 decimal digits, no leading zero; higher for later finds
	TBS       string         // SHA-256 of the to-be-signed part, 64 lower-case hex digits; a precertificate and its certificate share it
	Names     []dnswire.Name // the DNS names that could be read, sorted by dnswire.Compare, unique; a wildcard has the first label "*"
	Unread    int            // names of the certificate that could not be read
	Issuer    Issuer
	NotBefore time.Time
	NotAfter  time.Time
}

// Certificates is one run of the certificates check of a domain. A run is
// no DNS answer, so it has its own type.
type Certificates struct {
	Key       Key // CertificatesKey of the domain
	Start     time.Time
	Usable    bool       // the run read the source, or did not need to ask it
	Asked     bool       // the run made at least one request; false inside a wait that the source asked for
	Failure   string     // when not usable: "timeout", "network", "too large", "rate-limited", "malformed", "too many" or "status <n>"
	Complete  bool       // Issuances holds every valid issuance that the source has for the domain
	Issuances []Issuance // valid at Start (NotAfter after Start), by ID
}
