// Package obs holds what a check of the DNS observed, with each answer kept
// as proof. It is plain data and does no I/O, so the code that judges, stores
// or reports observations can use it without the code that sends queries.
package obs

import (
	"slices"
	"strconv"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// Result is what one server answered to one question: Records, NoData,
// NoName or Failure. Its case can be read only through Match, which needs a
// handler for each, so no reader can mistake a failure for "no records". The
// zero Result reads as a Failure with ReasonNoResult, so a result that was
// never set never passes for an answer.
type Result struct {
	_ [0]func() // no ==, which would read the case without Match
	c any       // Records, NoData, NoName or Failure; nil in the zero Result
}

// Records is an answer that holds the record set asked for. Every reader of
// a Result shares its slices and the data of their records: read them, never
// change them.
type Records struct {
	Set  []dnswire.Record // never empty; in the order of the message
	Glue []dnswire.Record // delegation checks and walk referrals only: A/AAAA of the NS hosts, under the zone asked
}

// NoData says that the name exists and has no records of the type asked
// (RFC 2308 section 2.2).
type NoData struct {
	SOA dnswire.Record // SOA.Data is a dnswire.SOA
}

// NoName says that the name does not exist (RFC 2308 section 2.1).
type NoName struct {
	SOA dnswire.Record // SOA.Data is a dnswire.SOA
	// Compact: the server said it with NOERROR and an NSEC record at the
	// name that lists NXNAME (RFC 9824), not with NXDOMAIN.
	Compact bool
}

type Failure struct {
	Reason Reason
	Detail string // for people only; may hold text from the network, so print it escaped
}

// Reason is why there is no answer to read.
type Reason uint8

const (
	ReasonNoResult     Reason = iota // the zero Result: nothing was observed
	ReasonTimeout                    // no matching answer in time
	ReasonNetwork                    // unreachable, or the TCP connection was refused or reset
	ReasonMalformed                  // the answer did not parse, did not match the query, or carried a foreign cookie
	ReasonTruncated                  // still truncated over TCP
	ReasonRefused                    // rcode REFUSED
	ReasonServFail                   // rcode SERVFAIL
	ReasonRcode                      // another rcode than NOERROR or NXDOMAIN
	ReasonLame                       // no authority for the data: a referral, or a cached or recursive answer
	ReasonBadAnswer                  // authoritative, but not readable as records, nodata or noname
	ReasonNotPermitted               // the address may not be asked
	ReasonRateLimited                // the address had no free slot before the deadline
	ReasonBudget                     // the check had used all its queries
	ReasonWalk                       // the walk from the root hit a bound, or found no address for the server
	ReasonDeadline                   // the check ended before the query could be sent
)

var reasonWords = map[Reason]string{
	ReasonNoResult:     "none",
	ReasonTimeout:      "timeout",
	ReasonNetwork:      "network",
	ReasonMalformed:    "malformed",
	ReasonTruncated:    "truncated",
	ReasonRefused:      "refused",
	ReasonServFail:     "servfail",
	ReasonRcode:        "rcode",
	ReasonLame:         "lame",
	ReasonBadAnswer:    "bad-answer",
	ReasonNotPermitted: "not-permitted",
	ReasonRateLimited:  "rate-limited",
	ReasonBudget:       "budget",
	ReasonWalk:         "walk",
	ReasonDeadline:     "deadline",
}

func (r Reason) String() string {
	if w, ok := reasonWords[r]; ok {
		return w
	}
	return "reason" + strconv.Itoa(int(r))
}

// TTL is the smallest TTL of Set, because a resolver treats a set whose TTLs
// differ as if all had the lowest (RFC 2181 section 5.2). An empty Set gives 0.
func (r Records) TTL() uint32 {
	var ttl uint32
	for i, rr := range r.Set {
		if i == 0 || rr.TTL < ttl {
			ttl = rr.TTL
		}
	}
	return ttl
}

// TTL is how long a resolver keeps the negative answer (RFC 2308 section 5).
func (n NoData) TTL() uint32 { return negativeTTL(n.SOA) }

// TTL is how long a resolver keeps the negative answer (RFC 2308 section 5).
func (n NoName) TTL() uint32 { return negativeTTL(n.SOA) }

// negativeTTL is the smaller of the SOA record's TTL and its MINIMUM field. A
// record without SOA data gives 0: nothing says how long it may be kept.
func negativeTTL(soa dnswire.Record) uint32 {
	d, ok := soa.Data.(dnswire.SOA)
	if !ok {
		return 0
	}
	return min(soa.TTL, d.Minimum)
}

// RecordsResult gives a Failure with ReasonBadAnswer for an empty Set. It
// keeps copies of the slices, so the caller may reuse its own.
func RecordsResult(r Records) Result {
	if len(r.Set) == 0 {
		return FailureResult(Failure{Reason: ReasonBadAnswer, Detail: "an answer of records holds none"})
	}
	return Result{c: Records{Set: slices.Clone(r.Set), Glue: slices.Clone(r.Glue)}}
}

// NoDataResult gives a Failure with ReasonBadAnswer when SOA.Data is not a
// dnswire.SOA.
func NoDataResult(n NoData) Result {
	if _, ok := n.SOA.Data.(dnswire.SOA); !ok {
		return noSOA()
	}
	return Result{c: n}
}

// NoNameResult gives a Failure with ReasonBadAnswer when SOA.Data is not a
// dnswire.SOA.
func NoNameResult(n NoName) Result {
	if _, ok := n.SOA.Data.(dnswire.SOA); !ok {
		return noSOA()
	}
	return Result{c: n}
}

func noSOA() Result {
	return FailureResult(Failure{Reason: ReasonBadAnswer, Detail: "a negative answer without SOA data"})
}

func FailureResult(f Failure) Result {
	return Result{c: f}
}

// Match calls exactly one handler, the one of r's case, and returns its
// value. Every handler must be non-nil: Match panics at once when one is nil,
// so the mistake shows on the first call, not only when that case comes up.
// The records handler gets the slices of r itself: it must not change them.
func Match[T any](r Result, records func(Records) T, noData func(NoData) T,
	noName func(NoName) T, failure func(Failure) T) T {
	if records == nil || noData == nil || noName == nil || failure == nil {
		panic("obs.Match: a handler is nil")
	}
	switch c := r.c.(type) {
	case Records:
		return records(c)
	case NoData:
		return noData(c)
	case NoName:
		return noName(c)
	case Failure:
		return failure(c)
	}
	return failure(Failure{Reason: ReasonNoResult})
}
