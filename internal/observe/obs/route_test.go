package obs_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

func routeAnswer(addr string, r obs.Result) obs.Answer {
	return obs.Answer{Proof: obs.Proof{Server: obs.Server{Addr: netip.MustParseAddrPort(addr)}}, Result: r}
}

func routeFail(reason obs.Reason) obs.Result {
	return obs.FailureResult(obs.Failure{Reason: reason})
}

func routeAddrs(answers []obs.Answer) []string {
	var addrs []string
	for _, a := range answers {
		addrs = append(addrs, a.Server.Addr.String())
	}
	return addrs
}

// Only a failure for lack of a route is one; an answer of any other case,
// and a failure for any other reason, is not.
func TestNoRoute(t *testing.T) {
	set := []dnswire.Record{dataA(t, "www.corp.test.", 300, "192.0.2.80")}
	for _, c := range []struct {
		name string
		r    obs.Result
		want bool
	}{
		{"no route", routeFail(obs.ReasonNoRoute), true},
		{"network", routeFail(obs.ReasonNetwork), false},
		{"timeout", routeFail(obs.ReasonTimeout), false},
		{"the zero result", obs.Result{}, false},
		{"records", obs.RecordsResult(obs.Records{Set: set}), false},
		{"no data", obs.NoDataResult(obs.NoData{SOA: dataSOA(t, "corp.test.", 300, 300)}), false},
		{"no such name", obs.NoNameResult(obs.NoName{SOA: dataSOA(t, "corp.test.", 300, 300)}), false},
	} {
		if got := obs.NoRoute(routeAnswer("[2001:db8::1]:53", c.r)); got != c.want {
			t.Errorf("%s: NoRoute = %v, want %v", c.name, got, c.want)
		}
	}
}

// A no-route failure is left out only when another answer is usable; every
// other failure stays, at an IPv6 address too.
func TestRouted(t *testing.T) {
	records := obs.RecordsResult(obs.Records{Set: []dnswire.Record{dataA(t, "www.corp.test.", 300, "192.0.2.80")}})
	noData := obs.NoDataResult(obs.NoData{SOA: dataSOA(t, "corp.test.", 300, 300)})
	noName := obs.NoNameResult(obs.NoName{SOA: dataSOA(t, "corp.test.", 300, 300)})
	v4, v6, v6b := "192.0.2.11:53", "[2001:db8::11]:53", "[2001:db8::12]:53"
	for _, c := range []struct {
		name             string
		answers          []obs.Answer
		routed, unrouted []string
	}{
		{"records and no route", []obs.Answer{routeAnswer(v4, records), routeAnswer(v6, routeFail(obs.ReasonNoRoute))},
			[]string{v4}, []string{v6}},
		{"no data and no route", []obs.Answer{routeAnswer(v6, routeFail(obs.ReasonNoRoute)), routeAnswer(v4, noData)},
			[]string{v4}, []string{v6}},
		{"no such name and no route", []obs.Answer{routeAnswer(v6, routeFail(obs.ReasonNoRoute)), routeAnswer(v4, noName)},
			[]string{v4}, []string{v6}},
		{"records, no route and a network failure at IPv6",
			[]obs.Answer{routeAnswer(v4, records), routeAnswer(v6, routeFail(obs.ReasonNoRoute)), routeAnswer(v6b, routeFail(obs.ReasonNetwork))},
			[]string{v4, v6b}, []string{v6}},
		{"records and a timeout", []obs.Answer{routeAnswer(v4, records), routeAnswer(v6, routeFail(obs.ReasonTimeout))},
			[]string{v4, v6}, nil},
		{"only no route", []obs.Answer{routeAnswer(v6, routeFail(obs.ReasonNoRoute)), routeAnswer(v6b, routeFail(obs.ReasonNoRoute))},
			[]string{v6, v6b}, nil},
		{"no route and a timeout", []obs.Answer{routeAnswer(v6, routeFail(obs.ReasonNoRoute)), routeAnswer(v4, routeFail(obs.ReasonTimeout))},
			[]string{v6, v4}, nil},
		{"no answer", nil, nil, nil},
	} {
		routed, unrouted := obs.Routed(c.answers)
		if got := routeAddrs(routed); !slices.Equal(got, c.routed) {
			t.Errorf("%s: routed %v, want %v", c.name, got, c.routed)
		}
		if got := routeAddrs(unrouted); !slices.Equal(got, c.unrouted) {
			t.Errorf("%s: unrouted %v, want %v", c.name, got, c.unrouted)
		}
	}
}
