package schedule

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// crtIv gives every tier its own interval, the certificate tier included, so
// that a tier that reads the interval of another one shows.
var crtIv = Intervals{Serial: 7 * time.Second, Parent: 61 * time.Second, Fast: 43 * time.Second,
	Other: 300 * time.Second, Certificates: 90 * time.Second}

func crtKey(t testing.TB) obs.Key { return obs.CertificatesKey(schName(t, "corp.test.")) }

func crtCheck(t testing.TB, iv Intervals) Check {
	return Check{Key: crtKey(t), Tier: TierCertificates, Interval: iv.Certificates}
}

// crtRun is a run of the certificates check that started at start.
func crtRun(t testing.TB, start time.Time, usable, asked bool) obs.Certificates {
	run := obs.Certificates{Key: crtKey(t), Start: start, Usable: usable, Asked: asked, Complete: usable && asked}
	if !usable {
		run.Failure = "status 503"
	}
	return run
}

func TestCertificatesTierIsTheFifthAndHasItsWord(t *testing.T) {
	if TierCertificates != 5 {
		t.Errorf("TierCertificates = %d, want 5", uint8(TierCertificates))
	}
	if got := TierCertificates.String(); got != "certificates" {
		t.Errorf("TierCertificates.String() = %q, want %q", got, "certificates")
	}
	if got := Tier(6).String(); got != "tier6" {
		t.Errorf("Tier(6).String() = %q, want %q", got, "tier6")
	}
}

func TestDefaultsKeepTheCertificatesIntervalOff(t *testing.T) {
	if got := Defaults().Certificates; got != 0 {
		t.Fatalf("Defaults().Certificates = %v, want 0", got)
	}
	f := schFile(t, "corp.test. A 10.53.0.80")
	for _, c := range Plan(f, nil, Defaults()) {
		if c.Key.Kind == obs.KindCertificates || c.Tier == TierCertificates {
			t.Errorf("the plan at the defaults holds %s", schText(c))
		}
	}
}

func TestOfAndFailLimitOfTheCertificatesTier(t *testing.T) {
	for _, c := range []struct {
		iv    Intervals
		tier  Tier
		every time.Duration
		limit time.Duration
	}{
		{crtIv, TierCertificates, 90 * time.Second, 270 * time.Second},
		{Intervals{Certificates: 10 * time.Minute}, TierCertificates, 10 * time.Minute, 30 * time.Minute},
		{Intervals{Certificates: 5 * time.Second}, TierCertificates, 5 * time.Second, 15 * time.Second},
		{Intervals{Certificates: Ceiling}, TierCertificates, Ceiling, 3 * Ceiling},
		{Intervals{}, TierCertificates, 0, 0},
		// The other tiers do not read the certificate interval.
		{crtIv, TierSerial, 7 * time.Second, 60 * 7 * time.Second},
		{crtIv, TierParent, 61 * time.Second, 5 * 61 * time.Second},
		{crtIv, TierFast, 43 * time.Second, 5 * 43 * time.Second},
		{crtIv, TierOther, 300 * time.Second, 3 * 300 * time.Second},
	} {
		if got := c.iv.Of(c.tier); got != c.every {
			t.Errorf("%+v Of(%s) = %v, want %v", c.iv, c.tier, got, c.every)
		}
		if got := c.iv.FailLimit(c.tier); got != c.limit {
			t.Errorf("%+v FailLimit(%s) = %v, want %v", c.iv, c.tier, got, c.limit)
		}
	}
}

func TestPlanEndsWithTheCertificatesCheckWhenItsIntervalIsSet(t *testing.T) {
	for name, lines := range map[string][]string{
		"empty":     nil,
		"apex":      {"corp.test. A 10.53.0.80"},
		"caa probe": {"corp.test. CAA 0 issue \"ca.test\"", "www.corp.test. A 10.53.0.81"},
		"wildcard":  {"*.corp.test. A none", "mail.corp.test. A 10.53.0.82"},
		"target":    {"www.corp.test. CNAME edge.corp.test."},
	} {
		f := schFile(t, lines...)
		fast := schNames(t, "www.corp.test.")
		off := crtIv
		off.Certificates = 0
		without := Plan(f, fast, off)
		with := Plan(f, fast, crtIv)
		if len(with) != len(without)+1 {
			t.Fatalf("%s: %d checks with the source, %d without; want one more", name, len(with), len(without))
		}
		schSameChecks(t, name+": the checks before the last", with[:len(without)], without)
		last := with[len(with)-1]
		if want := crtCheck(t, crtIv); schText(last) != schText(want) {
			t.Errorf("%s: last check %s, want %s", name, schText(last), schText(want))
		}
		if last.Zone {
			t.Errorf("%s: the certificates check has Zone true", name)
		}
		if last.Key.Kind != obs.KindCertificates || last.Tier != TierCertificates || last.Interval != 90*time.Second {
			t.Errorf("%s: last check %+v", name, last)
		}
		for _, c := range without {
			if c.Key.Kind == obs.KindCertificates || c.Tier == TierCertificates {
				t.Errorf("%s: with the interval 0 the plan holds %s", name, schText(c))
			}
		}
	}
}

func TestPlanCertificatesCheckIsOnceAndTakesItsOwnInterval(t *testing.T) {
	f := schFile(t, "corp.test. A 10.53.0.80")
	for _, every := range []time.Duration{5 * time.Second, 10 * time.Minute, Ceiling} {
		iv := schIv
		iv.Certificates = every
		n := 0
		for _, c := range Plan(f, nil, iv) {
			if c.Key.Kind != obs.KindCertificates {
				continue
			}
			n++
			if c.Interval != every || c.Tier != TierCertificates || c.Zone {
				t.Errorf("interval %v: check %s", every, schText(c))
			}
		}
		if n != 1 {
			t.Errorf("interval %v: %d certificates checks, want 1", every, n)
		}
	}
}

func TestPlanMatchesTheModelWithTheCertificatesCheck(t *testing.T) {
	for c := range 300 {
		rng := schRand(c)
		where := fmt.Sprintf("seed %d case %d", schSeed, c)
		f := schRandomFile(t, rng, 20)
		fast := schRandomFast(t, rng)
		iv := schIv
		iv.Certificates = schPick(rng, time.Duration(0), 5*time.Second, 10*time.Minute)
		got := Plan(f, fast, iv)
		schSameChecks(t, where+": Plan", got, schModelPlan(t, f, fast, iv))
		if iv.Certificates > 0 && schText(got[len(got)-1]) != schText(crtCheck(t, iv)) {
			t.Fatalf("%s: last check %s", where, schText(got[len(got)-1]))
		}
	}
}

func TestNewScheduleStartsTheCertificatesCheckWithTheOthers(t *testing.T) {
	s := New(schFile(t, "corp.test. A 10.53.0.80"), nil, crtIv)
	checks := s.Checks()
	if last := checks[len(checks)-1]; schText(last) != schText(crtCheck(t, crtIv)) {
		t.Fatalf("last check of the schedule %s", schText(last))
	}
	schStart(t, s, schT0, crtKey(t))
	// Running, it is not started again; after Done it is due one interval
	// after its start, not one interval of another tier.
	if got := s.Due(schAfter(time.Hour)); slices.ContainsFunc(got, func(c Check) bool { return c.Key.Kind == obs.KindCertificates }) {
		t.Fatalf("a running certificates check was started again")
	}
	s.DoneCertificates(crtRun(t, schT0, true, true), schSec(1))
	for _, c := range []struct {
		at  time.Duration
		due bool
	}{{89 * time.Second, false}, {90 * time.Second, true}} {
		got := s.Due(schAfter(c.at))
		if has := slices.ContainsFunc(got, func(x Check) bool { return x.Key.Kind == obs.KindCertificates }); has != c.due {
			t.Fatalf("Due(T0+%v) started the certificates check: %v, want %v", c.at, has, c.due)
		}
		if c.due {
			break
		}
	}
}

func TestDoneCertificatesReportsTierAndLimitAndLeavesNoSeriesOfDisagreement(t *testing.T) {
	s := New(schFile(t, "corp.test. A 10.53.0.80"), nil, crtIv)
	schStart(t, s, schT0, crtKey(t))
	for i, usable := range []bool{true, false} {
		start := schAfter(time.Duration(i) * time.Minute)
		r := s.DoneCertificates(crtRun(t, start, usable, true), start.Add(2*time.Second))
		if !r.Known || r.Tier != TierCertificates || r.FailLimit != 270*time.Second {
			t.Errorf("usable %v: Report %+v, want known, tier certificates, limit 4m30s", usable, r)
		}
		if len(r.Moves) != 0 || r.DisagreeLong || r.DisagreeOver {
			t.Errorf("usable %v: Report %+v holds moves or a disagree series", usable, r)
		}
	}
}

// The checks of the file and the certificates check, which is last, make 16
// checks; a 13th line makes 17, so one check waits for a free place.
func TestDoneCertificatesGivesBackItsPlace(t *testing.T) {
	lines := schManyLines()
	s := New(schFile(t, lines[:12]...), nil, crtIv)
	if got := s.Due(schT0); len(got) != MaxRunning || got[MaxRunning-1].Key.Kind != obs.KindCertificates {
		t.Fatalf("Due(T0) gave%s, want %d checks, the last the certificates check", schShow(schKeyTexts(got)), MaxRunning)
	}
	s.Replace(schFile(t, lines[:13]...))
	if got := s.Due(schSec(1)); len(got) != 0 {
		t.Fatalf("Due started%s while %d checks run", schShow(schKeyTexts(got)), MaxRunning)
	}
	s.DoneCertificates(crtRun(t, schT0, true, true), schSec(2))
	if got := s.Due(schSec(2)); len(got) != 1 {
		t.Fatalf("Due after DoneCertificates gave%s, want one check", schShow(schKeyTexts(got)))
	}
}

func TestDoneCertificatesOfAKeyOutsideThePlanIsUnknown(t *testing.T) {
	other := obs.CertificatesKey(schName(t, "shop.test."))
	for name, c := range map[string]struct {
		s   *Schedule
		key obs.Key
	}{
		"another domain": {New(schFile(t, "corp.test. A 10.53.0.80"), nil, crtIv), other},
		"the source off": {New(schFile(t, "corp.test. A 10.53.0.80"), nil, schIv), crtKey(t)},
	} {
		schStart(t, c.s, schT0)
		run := crtRun(t, schT0, false, true)
		run.Key = c.key
		r := c.s.DoneCertificates(run, schSec(1))
		if r.Known || r.Tier != 0 || r.FailLimit != 0 || !r.FailingSince.IsZero() || len(r.Moves) != 0 {
			t.Errorf("%s: Report %+v, want the zero Report", name, r)
		}
	}
}

func TestDoneCertificatesOfAnUnknownKeyStartsNoSeries(t *testing.T) {
	// The same key later, in a schedule that has it, must not inherit a series.
	s := New(schFile(t, "corp.test. A 10.53.0.80"), nil, schIv)
	s.DoneCertificates(crtRun(t, schT0, false, true), schSec(1))
	s.DoneCertificates(crtRun(t, schSec(10), false, true), schSec(11))
	r := s.DoneCertificates(crtRun(t, schSec(20), true, true), schSec(21))
	if r.Known || !r.FailingSince.IsZero() {
		t.Fatalf("Report %+v of an unknown key", r)
	}
}

func TestCertificatesFailingSinceIsTheStartOfTheFirstRunThatWasNotUsable(t *testing.T) {
	s := New(schFile(t, "corp.test. A 10.53.0.80"), nil, crtIv)
	runs := []struct {
		usable, asked bool
		at            int
		want          time.Time
	}{
		{false, true, 0, schSec(0)},
		{false, true, 90, schSec(0)},
		{false, false, 180, schSec(0)},
		{true, true, 270, time.Time{}},
		{false, true, 360, schSec(360)},
		{false, true, 450, schSec(360)},
		// A usable run that made no request ends the series too.
		{true, false, 540, time.Time{}},
		{false, true, 630, schSec(630)},
		{true, true, 720, time.Time{}},
		{true, true, 810, time.Time{}},
		{true, false, 900, time.Time{}},
		{false, false, 990, schSec(990)},
	}
	for i, run := range runs {
		start := schSec(run.at)
		schStart(t, s, start, crtKey(t))
		// Done comes 2 s after the start: the series counts from the start.
		r := s.DoneCertificates(crtRun(t, start, run.usable, run.asked), start.Add(2*time.Second))
		if !r.FailingSince.Equal(run.want) {
			t.Fatalf("run %d at %s (usable %v, asked %v): FailingSince %s, want %s", i, schWhen(start), run.usable,
				run.asked, schWhen(r.FailingSince), schWhen(run.want))
		}
		if r.FailLimit != 270*time.Second || r.Tier != TierCertificates || !r.Known {
			t.Fatalf("run %d: Report %+v", i, r)
		}
	}
}

func TestCertificatesFailureSeriesKeepsItsFailureTextOutOfTheJudgement(t *testing.T) {
	// Only Usable counts: a run with a failure text and Usable true is
	// usable, and a run with no text and Usable false is not.
	s := New(schFile(t, "corp.test. A 10.53.0.80"), nil, crtIv)
	schStart(t, s, schT0, crtKey(t))
	odd := crtRun(t, schT0, false, true)
	odd.Failure = ""
	if r := s.DoneCertificates(odd, schSec(1)); !r.FailingSince.Equal(schT0) {
		t.Fatalf("unusable run with no failure text: FailingSince %s, want T0", schWhen(r.FailingSince))
	}
	schStart(t, s, schSec(90), crtKey(t))
	odd = crtRun(t, schSec(90), true, true)
	odd.Failure = "status 503"
	if r := s.DoneCertificates(odd, schSec(91)); !r.FailingSince.IsZero() {
		t.Fatalf("usable run with a failure text: FailingSince %s, want zero", schWhen(r.FailingSince))
	}
}

func TestCertificatesSeriesIsKeptByReplaceAndSeparateFromTheOtherChecks(t *testing.T) {
	f := schFile(t, "corp.test. A 10.53.0.80")
	s := New(f, nil, crtIv)
	schStart(t, s, schT0)
	s.DoneCertificates(crtRun(t, schT0, false, true), schSec(1))
	// A failed DNS run of another check does not start or end the series.
	s.Done(schFailed(t, schKey(t, "corp.test.", dnswire.TypeA), schSec(5)), schSec(6))
	s.Done(schUsable(t, schKey(t, "corp.test.", dnswire.TypeA), schSec(7)), schSec(8))
	s.Replace(schFile(t, "corp.test. A 10.53.0.80", "www.corp.test. A 10.53.0.81"))
	schStart(t, s, schSec(100), crtKey(t))
	r := s.DoneCertificates(crtRun(t, schSec(100), false, true), schSec(101))
	if !r.FailingSince.Equal(schT0) {
		t.Fatalf("FailingSince %s after Replace, want T0", schWhen(r.FailingSince))
	}
	// A DNS run that fails must not take the series of the certificates check.
	if r := s.Done(schFailed(t, schKey(t, "www.corp.test.", dnswire.TypeA), schSec(200)), schSec(201)); !r.FailingSince.Equal(schSec(200)) {
		t.Fatalf("a DNS check has FailingSince %s, want T0+200s", schWhen(r.FailingSince))
	}
}

func TestDoneCertificatesStartsNoRoundAndHoldsNoMoves(t *testing.T) {
	s := New(schBase(t), nil, crtIv)
	schSettle(t, s, crtKey(t))
	for i := range 5 {
		start := schAfter(time.Duration(90*i) * time.Second)
		r := s.DoneCertificates(crtRun(t, start, i%2 == 0, true), start.Add(time.Second))
		if len(r.Moves) != 0 || r.DisagreeLong || r.DisagreeOver {
			t.Fatalf("run %d: Report %+v", i, r)
		}
	}
	if moves := s.Flush(schAfter(24 * time.Hour)); len(moves) != 0 {
		t.Fatalf("Flush gave moves %q after certificates runs", schMoveTexts(moves))
	}
	// No round: no zone check is due before its own interval ends.
	if got := s.Due(schSec(2)); len(got) != 0 {
		t.Fatalf("Due(T0+2s) gave%s, want none: a certificates run started a round", schShow(schKeyTexts(got)))
	}
}
