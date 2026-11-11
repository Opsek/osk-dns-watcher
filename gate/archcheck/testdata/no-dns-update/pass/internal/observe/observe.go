package observe

import (
	"crypto/tls"

	"osk/internal/dnswire"
)

// TLS uses a name of crypto/tls that does not dial.
var TLS = tls.Config{MinVersion: tls.VersionTLS13}

// Dial is not a name of net or crypto/tls.
func Dial() string {
	return dnswire.Loopback.String()
}
