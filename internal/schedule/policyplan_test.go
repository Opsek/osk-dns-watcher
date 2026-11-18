package schedule

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

const plpLine = "mta-sts enforce 604800 mail.corp.test."

// plpPolicyChecks are the checks of kind policy of a plan.
func plpPolicyChecks(plan []Check) []Check {
	return slices.DeleteFunc(slices.Clone(plan), func(c Check) bool { return c.Key.Kind != obs.KindPolicy })
}

func plpKey(t testing.TB, domain string) obs.Key {
	t.Helper()
	k, ok := obs.PolicyKey(schName(t, domain))
	if !ok {
		t.Fatalf("no policy key for %s", domain)
	}
	return k
}

// The plan gives a policy check exactly when the file has an mta-sts line.
func TestPlpPlanGivesOnePolicyCheckExactlyWithTheLine(t *testing.T) {
	rows := []struct {
		name  string
		right string
		lines []string
		fast  []string
		want  bool // a check, in the domain's own zone
		zone  bool
	}{
		{"no line", "no mta-sts line, no policy check", []string{"corp.test. A 10.53.0.80"}, nil, false, false},
		{"only the record", "a TXT line at _mta-sts is a records check only", []string{`_mta-sts.corp.test. TXT "v=STSv1; id=1"`}, nil, false, false},
		{"the line", "one policy check, a zone check", []string{plpLine}, nil, true, true},
		{"the line and the record", "the records check and the policy check are two checks",
			[]string{`_mta-sts.corp.test. TXT "v=STSv1; id=1"`, plpLine}, nil, true, true},
		{"mode none", "mode none is still a line: one policy check", []string{"mta-sts none 0"}, nil, true, true},
		{"the host is a fast name", "a fast name does not change the tier of the policy check",
			[]string{plpLine}, []string{"mta-sts.corp.test."}, true, true},
		{"the record is in a declared subzone", "the check is not a zone check of the domain",
			[]string{plpLine, "_mta-sts.corp.test. NS ns1.corp.test."}, nil, true, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			plan := Plan(schFile(t, r.lines...), schNames(t, r.fast...), schIv)
			got := plpPolicyChecks(plan)
			if !r.want {
				if len(got) != 0 {
					t.Fatalf("%s, but got%s", r.right, schShow(schTexts(got)))
				}
				return
			}
			want := Check{Key: plpKey(t, "corp.test."), Tier: TierOther, Interval: schIv.Other, Zone: r.zone}
			if len(got) != 1 || schText(got[0]) != schText(want) {
				t.Fatalf("%s, but got%s\nwant%s", r.right, schShow(schTexts(got)), schShow(schTexts([]Check{want})))
			}
			if got[0].Key.String() != "policy corp.test. mta-sts.corp.test. TXT" {
				t.Errorf("the key is %q, want the key of the fetch of mta-sts.corp.test.", got[0].Key)
			}
		})
	}
}

// Two domains give two checks, each for its own host.
func TestPlpTwoDomainsGiveTwoChecks(t *testing.T) {
	var keys []string
	for _, domain := range []string{"corp.test.", "other.test."} {
		f, err := expect.Parse([]byte("domain " + domain + "\nmta-sts enforce 86400 mx." + domain + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		got := plpPolicyChecks(Plan(f, nil, schIv))
		if len(got) != 1 || got[0].Key.Domain.String() != domain || got[0].Key.Name.String() != "mta-sts."+domain {
			t.Fatalf("%s: want one policy check for mta-sts.%s, got%s", domain, domain, schShow(schTexts(got)))
		}
		keys = append(keys, got[0].Key.String())
	}
	if keys[0] == keys[1] {
		t.Errorf("two domains share the key %q", keys[0])
	}
}

// The policy check comes after the wildcard checks and before the
// certificate check.
func TestPlpPolicyCheckComesAfterWildcardsAndBeforeCertificates(t *testing.T) {
	iv := schIv
	iv.Certificates = time.Hour
	plan := Plan(schFile(t, "*.corp.test. A none", plpLine, "www.corp.test. A 10.53.0.81"), nil, iv)
	var kinds []obs.Kind
	for _, c := range plan {
		kinds = append(kinds, c.Key.Kind)
	}
	want := []obs.Kind{obs.KindSerial, obs.KindDelegation, obs.KindDS, obs.KindRecords, obs.KindWildcard, obs.KindPolicy, obs.KindCertificates}
	if !slices.Equal(kinds, want) {
		t.Fatalf("kinds of the plan %v, want %v: the policy check follows the wildcard check and precedes the certificate check", kinds, want)
	}
}

// plpMoved gives a schedule whose serial moved from 1 to 2 in the run that
// ended at T0+8s, and the keys of its zone checks: the apex A set, then the
// policy check.
func plpMoved(t *testing.T, lines ...string) (*Schedule, []obs.Key) {
	t.Helper()
	f := schFile(t, append([]string{"corp.test. A 10.53.0.80"}, lines...)...)
	keys := []obs.Key{schKey(t, "corp.test.", dnswire.TypeA), plpKey(t, "corp.test.")}
	s := New(f, nil, schIv)
	schSettle(t, s)
	schStart(t, s, schSec(7), schSerialKey(t))
	schEnd(t, s, schSerialObs(t, schSec(7), 2, 2), schSec(8))
	return s, keys
}

// A move of the serial makes the policy check due at once, with the zone
// checks, and not up to an interval later.
func TestPlpMoveMakesThePolicyCheckDueAtOnce(t *testing.T) {
	s, keys := plpMoved(t, plpLine)
	want := schKeyTexts([]Check{{Key: keys[0]}, {Key: keys[1]}})
	if got := schKeyTexts(s.Due(schSec(8))); !slices.Equal(got, want) {
		t.Fatalf("Due right after the move gave%s\nwant%s", schShow(got), schShow(want))
	}
}

// A policy check that is not of the domain's zone waits for its interval.
func TestPlpPolicyCheckOfASubzoneIsNotDueAtOnce(t *testing.T) {
	s, keys := plpMoved(t, plpLine, "_mta-sts.corp.test. NS ns1.corp.test.")
	for _, c := range s.Due(schSec(8)) {
		if c.Key.Kind == obs.KindPolicy {
			t.Fatalf("Due right after the move gave the policy check %s of a declared subzone", keys[1])
		}
	}
}

// A policy change in the round of a move explains the round, as the change of
// a set does; a round with no change ends unexplained.
func TestPlpPolicyChangeExplainsTheRoundOfAMove(t *testing.T) {
	for _, op := range []decide.Op{decide.OpOpen, decide.OpUpdate, decide.OpResolve} {
		t.Run(op.String(), func(t *testing.T) {
			s, keys := plpMoved(t, plpLine)
			schStart(t, s, schSec(8), keys...)
			for i, k := range keys {
				var changes []decide.Change
				if i == 1 {
					changes = []decide.Change{{Op: op, Finding: decide.Finding{Rule: decide.RuleMTASTS, Check: k}, At: schSec(9)}}
				}
				_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9+i), changes...)
				schWantJudged(t, fmt.Sprintf("%s mta-sts, then %s", op, k), moves, ok, false, nil)
			}
		})
	}
	t.Run("no change", func(t *testing.T) {
		s, keys := plpMoved(t, plpLine)
		schStart(t, s, schSec(8), keys...)
		for i, k := range keys {
			_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9+i))
			if i == 1 {
				schWantJudged(t, "the last zone check", moves, ok, true, schBothMoved)
			}
		}
	})
}

// The round waits for the policy check: a round does not end while it has not
// run since the move.
func TestPlpRoundWaitsForThePolicyCheck(t *testing.T) {
	s, keys := plpMoved(t, plpLine)
	schStart(t, s, schSec(8), keys...)
	_, moves, ok := schEnd(t, s, schUsable(t, keys[0], schSec(8)), schSec(9))
	schWantJudged(t, "the apex run only", moves, ok, false, nil)
	_, moves, ok = schEnd(t, s, schUsable(t, keys[1], schSec(8)), schSec(10))
	schWantJudged(t, "the policy run", moves, ok, true, schBothMoved)
}
