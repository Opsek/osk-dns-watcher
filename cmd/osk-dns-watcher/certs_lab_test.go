//go:build lab

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	crtLabOpenIssuer     = "alert open high issuer certificates corp.test."
	crtLabOpenCertname   = "alert open high certname certificates corp.test."
	crtLabOpenHostnames  = "alert open low hostnames certificates corp.test."
	crtLabResolveIssuer  = "alert resolve high issuer certificates corp.test."
	crtLabResolveCertnam = "alert resolve high certname certificates corp.test."
	crtLabResolveHosts   = "alert resolve low hostnames certificates corp.test."

	crtLabHeadIssuer    = ":red_circle: *HIGH* · a certificate for a name of `corp.test.` comes from an authority that the expectations do not permit"
	crtLabHeadCertname  = ":red_circle: *HIGH* · a wildcard certificate for `corp.test.` holds a name that the expectations do not list"
	crtLabHeadHostnames = ":large_yellow_circle: *LOW* · certificates name hosts under `corp.test.` that the expectations do not list"

	crtLabResolvedIssuer   = ":white_check_mark: *RESOLVED* · no valid certificate for a name of `corp.test.` comes from an authority that the expectations do not permit"
	crtLabResolvedCertname = ":white_check_mark: *RESOLVED* · no valid certificate for `corp.test.` holds an unlisted wildcard"
	crtLabResolvedHostname = ":white_check_mark: *RESOLVED* · every host under `corp.test.` on a valid certificate is in the expectations"

	crtLabActionIssuer = ":point_right: If you did not ask for this certificate, ask its authority to revoke it, and check your CAA records and your DNS provider account." +
		" If you did, allow the authority where the file restricts it: in your CAA records and their lines, and in the issuer lines."
	crtLabActionCertname = ":point_right: If you did not ask for it, ask its authority to revoke it: it is valid for every name at its level." +
		" If it is yours, run osk-dns-watcher accept to list it."
	crtLabActionHostnames = ":point_right: Check that each host is yours. Run osk-dns-watcher accept to list them, or add a line for each host that osk-dns-watcher should watch."

	crtLabNowNoIssuer   = "now        no valid certificate from an authority that is not permitted"
	crtLabNowNoWildcard = "now        no unlisted wildcard on a valid certificate"
)

// crtLabIssuance is one issuance in the form of the source.
type crtLabIssuance struct {
	ID        string       `json:"id"`
	TBS       string       `json:"tbs_sha256"`
	NotBefore string       `json:"not_before"`
	NotAfter  string       `json:"not_after"`
	DNSNames  []string     `json:"dns_names"`
	Issuer    crtLabIssuer `json:"issuer"`
}

type crtLabIssuer struct {
	FriendlyName string   `json:"friendly_name"`
	CAADomains   []string `json:"caa_domains"`
}

var (
	crtLabCA      = crtLabIssuer{"Lab CA", []string{"ca.test"}}
	crtLabOtherCA = crtLabIssuer{"Other CA", []string{"evil.test"}}
)

// crtLabMake builds the issuance with this id. Its TBS hash differs from that of
// every other id, so that the tool never takes two issuances for one.
func crtLabMake(id string, names []string, issuer crtLabIssuer, notAfter time.Time) crtLabIssuance {
	sum := sha256.Sum256([]byte("tbs " + id))
	return crtLabIssuance{
		ID:        id,
		TBS:       hex.EncodeToString(sum[:]),
		NotBefore: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		NotAfter:  notAfter.UTC().Format(time.RFC3339),
		DNSNames:  names,
		Issuer:    issuer,
	}
}

// crtLabSet replaces the set of the source in the lab. The source serves only
// ids above the last one that the tool has read, so the ids of the sets of
// one test only ever grow.
func crtLabSet(t *testing.T, set ...crtLabIssuance) {
	t.Helper()
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd := exec.Command("labctl", "certs", "set")
	cmd.Stdin = bytes.NewReader(body)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("labctl certs set: %v\n%s", err, stderr.String())
	}
}

// crtLabEnable adds the certificate source to the config of the world. The lab
// receiver plays the source; its name is the one that the lab CA signs.
func crtLabEnable(t *testing.T, w *cliLabWorld) {
	t.Helper()
	b, err := os.ReadFile(w.config)
	if err != nil {
		t.Fatal(err)
	}
	const slack = `  "slack":`
	cfg := strings.Replace(string(b), slack,
		`  "certificates": {"url": "https://hooks.lab.test/v1/issuances", "interval": "5s"},`+"\n"+slack, 1)
	if cfg == string(b) {
		t.Fatalf("no slack member in the config to put the certificates member before:\n%s", b)
	}
	expWrite(t, w.dir, "config.json", cfg)
}

var crtLabRunLine = `^checked certificates certificates corp\.test\. \S+ `

// crtLabRan matches a finished run of the certificates check whose line, after
// the start time, matches the pattern.
func crtLabRan(tail string) func(cliLabLog) bool {
	re := regexp.MustCompile(crtLabRunLine + tail + `$`)
	return func(l cliLabLog) bool { return l.Event == "checked" && re.MatchString(l.Text) }
}

func crtLabRuns(svc *cliLabService) int {
	n := 0
	for _, l := range svc.all() {
		if crtLabRan(`.*`)(l) {
			n++
		}
	}
	return n
}

// crtLabMoreRuns waits for n more finished runs of the certificates check.
func crtLabMoreRuns(t *testing.T, svc *cliLabService, n int) {
	t.Helper()
	want := crtLabRuns(svc) + n
	cliLabUntil(t, "more runs of the certificates check", time.Now().Add(time.Duration(n)*dngWindow(5*time.Second)), 100*time.Millisecond,
		func() bool { return crtLabRuns(svc) >= want })
}

// crtLabAlerts requires exactly these alert lines, in this order.
func crtLabAlerts(t *testing.T, svc *cliLabService, want ...string) {
	t.Helper()
	if got := regAlertLines(svc); !slices.Equal(got, want) {
		t.Fatalf("alert lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// crtLabSlack requires that the receiver holds exactly n Slack messages of the
// three certificate rules, an update included. Other notices, such as the
// ones that a restart or a changed file send, are not counted.
func crtLabSlack(t *testing.T, w *cliLabWorld, n int) {
	t.Helper()
	phrases := []string{crtLabHeadIssuer, crtLabHeadCertname, crtLabHeadHostnames,
		crtLabResolvedIssuer, crtLabResolvedCertname, crtLabResolvedHostname}
	var texts []string
	for _, s := range cliLabSlackTexts(t, w) {
		head, _, _ := strings.Cut(s, "\n")
		for _, p := range phrases {
			if _, phrase, _ := strings.Cut(p, " · "); strings.HasSuffix(head, " · "+phrase) {
				texts = append(texts, s)
				break
			}
		}
	}
	if len(texts) != n {
		t.Fatalf("the receiver holds %d Slack messages of the certificate rules, want %d:\n%s", len(texts), n, strings.Join(texts, "\n---\n"))
	}
}

// crtLabText waits for the one Slack message that starts with head. The
// messages of both services are in the receiver, so no index is used.
func crtLabText(t *testing.T, w *cliLabWorld, head string) string {
	t.Helper()
	cliLabUntil(t, "a Slack message that starts with "+head, time.Now().Add(10*time.Second), 100*time.Millisecond, func() bool {
		for _, s := range cliLabSlackTexts(t, w) {
			if strings.HasPrefix(s, head+"\n") {
				return true
			}
		}
		return false
	})
	return regTextWith(t, cliLabSlackTexts(t, w), head)
}

// Three certificate rules against a source in the lab: an authority that the
// file does not permit, a wildcard name and an unlisted host. A renewal sends
// nothing, a restart sends nothing twice, a file that lists the names and an
// expiry end the alerts, and a source that fails twice is no news.
func TestCertificateAlerts(t *testing.T) {
	const interval = 5 * time.Second
	window := dngWindow(interval)
	w := cliLabSetup(t, false, func(n string) string {
		return cliLabFile(n, `corp.test. CAA 0 issue "ca.test"`)
	}, nil)
	crtLabEnable(t, w)

	farOff := time.Now().Add(90 * 24 * time.Hour)
	apex := crtLabMake("1", []string{"corp.test", "www.corp.test"}, crtLabCA, farOff)
	wild := crtLabMake("2", []string{"corp.test", "*.corp.test"}, crtLabCA, farOff)
	dev := crtLabMake("3", []string{"dev.corp.test"}, crtLabCA, farOff)

	// A clean set: nothing is open.
	crtLabSet(t, apex)
	svc := cliLabStart(t, w)
	svc.wait(t, "the first run of the certificates check", time.Now().Add(60*time.Second), crtLabRan(`ok 1 valid`))
	crtLabMoreRuns(t, svc, 1)
	crtLabAlerts(t, svc)

	// A wildcard name that the file does not list.
	set := time.Now()
	crtLabSet(t, apex, wild)
	svc.wait(t, "the certname alert", set.Add(window), regIs(crtLabOpenCertname))
	crtLabAlerts(t, svc, crtLabOpenCertname)
	regExpect(t, crtLabText(t, w, crtLabHeadCertname), crtLabHeadCertname, []string{"now        *.corp.test."}, regOpenTimes, crtLabActionCertname)

	// A host that the file does not list.
	set = time.Now()
	crtLabSet(t, apex, wild, dev)
	svc.wait(t, "the hostnames alert", set.Add(window), regIs(crtLabOpenHostnames))
	crtLabAlerts(t, svc, crtLabOpenCertname, crtLabOpenHostnames)
	regExpect(t, crtLabText(t, w, crtLabHeadHostnames), crtLabHeadHostnames, []string{"now        dev.corp.test."}, regOpenTimes, crtLabActionHostnames)

	// A certificate from an authority that no line of the file permits. Both
	// issuances of it expire at one moment that is measured from here, so that
	// the speed of the machine does not decide whether the test can finish.
	added := time.Now()
	expiry := added.Add(120 * time.Second).Truncate(time.Second)
	other := crtLabMake("4", []string{"www.corp.test"}, crtLabOtherCA, expiry)
	crtLabSet(t, apex, wild, dev, other)
	svc.wait(t, "the issuer alert", added.Add(window), regIs(crtLabOpenIssuer))
	crtLabAlerts(t, svc, crtLabOpenCertname, crtLabOpenHostnames, crtLabOpenIssuer)
	regExpect(t, crtLabText(t, w, crtLabHeadIssuer), crtLabHeadIssuer, []string{
		`expected   corp.test. CAA 0 issue "ca.test"`,
		"",
		"now        www.corp.test. from evil.test",
	}, regOpenTimes, crtLabActionIssuer)

	// A renewal: the same name and authority under a new id, a new hash and
	// the same dates. It is no news.
	set = time.Now()
	renewal := crtLabMake("5", []string{"www.corp.test"}, crtLabOtherCA, expiry)
	crtLabSet(t, apex, wild, dev, other, renewal)
	svc.wait(t, "a run that reads the renewal", set.Add(window), crtLabRan(`ok 5 valid`))
	crtLabMoreRuns(t, svc, 2)
	crtLabAlerts(t, svc, crtLabOpenCertname, crtLabOpenHostnames, crtLabOpenIssuer)
	crtLabSlack(t, w, 3)

	// A restart with three alerts open: the new service reads the whole list
	// again and sends nothing.
	if left := time.Until(expiry); left < 30*time.Second {
		t.Fatalf("only %s are left before the issuances expire: this machine is too slow for the test to go on", left.Round(time.Second))
	}
	svc.stop(t)
	svc = cliLabStart(t, w)
	first := svc.wait(t, "the first run of the certificates check after the restart", time.Now().Add(60*time.Second), crtLabRan(`.*`))
	if !crtLabRan(`ok 5 valid`)(first) {
		t.Errorf("first run after the restart: %q, want it to end with ok 5 valid", first.Text)
	}
	crtLabMoreRuns(t, svc, 2)
	if time.Now().After(expiry) {
		t.Fatal("the issuances expired during the restart: this machine is too slow for the test to go on")
	}
	crtLabAlerts(t, svc)
	crtLabSlack(t, w, 3)

	// The file lists the names: two alerts end. The service takes a changed
	// file after two reads, 10 s apart.
	file, err := os.ReadFile(w.expect)
	if err != nil {
		t.Fatal(err)
	}
	set = time.Now()
	expWrite(t, w.dir, "corp.test.expect", string(file)+"certname *.corp.test.\ncertname dev.corp.test.\n")
	svc.wait(t, "the resolve of the certname alert", set.Add(10*time.Second+window), regIs(crtLabResolveCertnam))
	svc.wait(t, "the resolve of the hostnames alert", set.Add(10*time.Second+window), regIs(crtLabResolveHosts))
	regExpect(t, crtLabText(t, w, crtLabResolvedCertname), crtLabResolvedCertname, []string{crtLabNowNoWildcard}, regResolveTimes, regResolveAction)
	regExpect(t, crtLabText(t, w, crtLabResolvedHostname), crtLabResolvedHostname,
		[]string{"now        no unlisted host on a valid certificate"}, regResolveTimes, regResolveAction)

	// The two issuances expire: the alert of the authority ends.
	svc.wait(t, "the resolve of the issuer alert", expiry.Add(window+60*time.Second), regIs(crtLabResolveIssuer))
	regExpect(t, crtLabText(t, w, crtLabResolvedIssuer), crtLabResolvedIssuer, []string{crtLabNowNoIssuer}, regResolveTimes, regResolveAction)

	// Two failures of the source are no news: only a source that fails for
	// longer than the fail limit raises an alert.
	crtLabMoreRuns(t, svc, 1)
	alerts := regAlertLines(svc)
	expCtl(t, "certs", "fail", "503", "2")
	failed := crtLabRan(`failed status 503`)
	var lastFailure time.Time
	cliLabUntil(t, "two failed runs", time.Now().Add(2*window), 100*time.Millisecond, func() bool {
		n := 0
		for _, l := range svc.all() {
			if failed(l) {
				n++
				lastFailure = l.at
			}
		}
		return n >= 2
	})
	svc.wait(t, "a run that reads the source again", time.Now().Add(window), func(l cliLabLog) bool {
		return crtLabRan(`ok \d+ valid`)(l) && l.at.After(lastFailure)
	})
	if got := regAlertLines(svc); !slices.Equal(got, alerts) {
		t.Errorf("alert lines after two failed runs:\n%s\nwant those before them:\n%s", strings.Join(got, "\n"), strings.Join(alerts, "\n"))
	}

	svc.stop(t)
	crtLabSlack(t, w, 6)
}
