//go:build lab

package main

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

const cofNotJudged = ": the issuer and certname lines are not judged: certificates is not set in the config"

// cofFastRuns counts the finished runs of the fast check of www.corp.test.
func cofFastRuns(svc *cliLabService) int {
	n := 0
	for _, l := range svc.all() {
		if l.Event == "checked" && strings.HasPrefix(l.Text, "checked fast records corp.test. www.corp.test. A ") {
			n++
		}
	}
	return n
}

// cofCertificateLines lists the log lines that belong to the certificates
// check, whether it ran or was planned.
func cofCertificateLines(svc *cliLabService) []string {
	var out []string
	for _, l := range svc.all() {
		if strings.Contains(l.Text, "certificates") && !strings.HasPrefix(l.Text, "warning ") {
			out = append(out, l.Text)
		}
	}
	return out
}

// cofLookups is the number of requests that the fake source got since the
// last clear.
func cofLookups(t *testing.T) int {
	t.Helper()
	out := dataTool(t, "labctl", "certs", "count")
	n, err := strconv.Atoi(out)
	if err != nil {
		t.Fatalf("labctl certs count printed %q, want a number", out)
	}
	return n
}

// The certificate source tells a third party which domains the owner
// watches, so a config without a certificates member never makes the service
// ask it. The second half of the test, with the member, shows that the
// silence of the first half is not a fault of the lab.
func TestCertificateSourceIsOffByDefault(t *testing.T) {
	const certInterval = 5 * time.Second
	window := dngWindow(certInterval)
	w := cliLabSetup(t, false, func(n string) string {
		return cliLabFile(n, "certname *.corp.test.")
	}, map[string]string{"fast": "5s"})
	expCtl(t, "certs", "clear")

	// No certificates member: the service runs its other checks and never
	// the certificates check.
	started := time.Now()
	svc := cliLabStart(t, w)
	svc.wait(t, "the warning that the certificate lines are not judged", started.Add(20*time.Second), func(l cliLabLog) bool {
		return strings.HasPrefix(l.Text, "warning ") && strings.HasSuffix(l.Text, cofNotJudged)
	})
	cliLabUntil(t, "two runs of the fast check and a whole window of the certificates check", started.Add(60*time.Second), 100*time.Millisecond,
		func() bool { return cofFastRuns(svc) >= 2 && time.Since(started) >= window })
	if got := cofCertificateLines(svc); len(got) != 0 {
		t.Errorf("log lines about certificates without a certificates member:\n%s", strings.Join(got, "\n"))
	}
	crtLabAlerts(t, svc)
	crtLabSlack(t, w, 0)
	if n := cofLookups(t); n != 0 {
		t.Errorf("the source got %d requests without a certificates member, want 0", n)
	}
	svc.stop(t)

	// The same config with the member: the check runs and the source is
	// asked, so the zero above is not a fault of the lab.
	crtLabEnable(t, w)
	svc = cliLabStart(t, w)
	svc.wait(t, "the first run of the certificates check", time.Now().Add(60*time.Second), crtLabRan(`.*`))
	if n := cofLookups(t); n < 1 {
		t.Errorf("the source got %d requests with a certificates member, want at least 1", n)
	}
	svc.stop(t)
}
