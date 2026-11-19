package obs_test

import (
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// Match refuses a nil handler at once, also when the case of the result is
// not the one that the handler is for.
func TestMatchPanicsOnAnyNilHandler(t *testing.T) {
	r := obs.RecordsResult(obs.Records{Set: []dnswire.Record{dataA(t, "www.corp.test.", 300, "192.0.2.80")}})
	records := func(obs.Records) int { return 1 }
	noData := func(obs.NoData) int { return 2 }
	noName := func(obs.NoName) int { return 3 }
	failure := func(obs.Failure) int { return 4 }
	for _, tc := range []struct {
		name string
		call func()
	}{
		{"records", func() { obs.Match(r, nil, noData, noName, failure) }},
		{"nodata", func() { obs.Match(r, records, nil, noName, failure) }},
		{"noname", func() { obs.Match(r, records, noData, nil, failure) }},
		{"failure", func() { obs.Match(r, records, noData, noName, nil) }},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Match with a nil %s handler did not panic", tc.name)
				}
			}()
			tc.call()
		}()
	}
}
