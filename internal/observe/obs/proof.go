package obs

import (
	"net/netip"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

// Server is one address of one name server.
type Server struct {
	Name dnswire.Name   // NS host; the root for a configured root server, whose name is not known
	Addr netip.AddrPort // zero when no address was found for Name
}

// Proof is what was asked of whom and when, and what came back, so that a
// result can be checked later against the octets the server sent. For a
// check of kind policy, Server is the policy host and the address that
// answered over HTTPS, Question is that host's name with type TXT, and Wire
// is nil.
type Proof struct {
	Server   Server
	Question dnswire.Question // what was asked; class IN
	Sent     time.Time        // zero when nothing was sent
	Received time.Time        // when the answer was accepted, or when the query ended without one
	Wire     []byte           // the accepted answer as received, shared by every copy: read only, through dnswire.Parse; nil when none
	TCP      bool             // the answer came over TCP
}

// Answer is one server's answer to one question.
type Answer struct {
	Proof
	Result Result
}

// Observation is the outcome of one run of one check. When servers disagree,
// each Answer holds its own server's result: nothing is merged.
type Observation struct {
	Key      Key
	Start    time.Time
	Deadline time.Time    // Start plus three quarters of the check's interval; no query outlives it
	Zone     dnswire.Name // zone whose servers were asked: parent zone (delegation, ds) or zone of Name; root if the walk failed
	Walk     []Answer     // every answer the walk tried or used, in order; proof only, decisions read Answers
	Answers  []Answer     // one per (NS host, address) of Zone, sorted by host (dnswire.Compare), then address; never empty
}
