package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// regOpenAlert stores an open alert of rule on k, and ends it again when
// resolved.
func regOpenAlert(t *testing.T, s *store.Store, rule decide.Rule, k obs.Key, resolved bool) {
	t.Helper()
	opened := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	a := alert.Alert{Open: true, Rule: rule, Severity: decide.SeverityCritical, Peak: decide.SeverityCritical, Check: k,
		Expected: "x", Value: "x", Opened: opened, Noticed: opened}
	if err := s.Apply(k, false, opened, []store.Write{{Event: alert.Event{Kind: alert.EventOpen, Alert: a, Was: a.Severity, At: opened}}}); err != nil {
		t.Fatal(err)
	}
	if !resolved {
		return
	}
	open, err := s.OpenAlerts(k)
	if err != nil || len(open) != 1 {
		t.Fatalf("open alerts of %s: %+v, %v", k, open, err)
	}
	a = open[0]
	a.Open, a.Resolved = false, opened.Add(time.Minute)
	if err := s.Apply(k, false, a.Resolved, []store.Write{{Event: alert.Event{Kind: alert.EventResolve, Alert: a, Was: a.Severity, At: a.Resolved}}}); err != nil {
		t.Fatal(err)
	}
}

func regName(t *testing.T, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Only a ds check of a domain whose delegation check has an open
// nameservers alert is told so: not a check of another kind, not another
// domain, not another rule, and not an alert that has ended.
func TestNameServersOpenIsTrueOnlyForTheDSCheckOfTheSameDomain(t *testing.T) {
	corp, shop := regName(t, "corp.test."), regName(t, "shop.test.")
	for _, c := range []struct {
		name   string
		rule   decide.Rule
		on     obs.Key // where the alert is open; no alert when rule is 0
		ended  bool
		domain dnswire.Name // the domain judged
		judged obs.Key
		want   bool
	}{
		{"ds of the same domain", decide.RuleNameServers, obs.DelegationKey(corp), false, corp, obs.DSKey(corp), true},
		{"the delegation check itself", decide.RuleNameServers, obs.DelegationKey(corp), false, corp, obs.DelegationKey(corp), false},
		{"a records check", decide.RuleNameServers, obs.DelegationKey(corp), false, corp,
			obs.RecordsKey(corp, regName(t, "www.corp.test."), dnswire.TypeA), false},
		{"the serial check", decide.RuleNameServers, obs.DelegationKey(corp), false, corp, obs.SerialKey(corp), false},
		{"ds of another domain", decide.RuleNameServers, obs.DelegationKey(corp), false, shop, obs.DSKey(shop), false},
		{"another rule on the delegation", decide.RuleGone, obs.DelegationKey(corp), false, corp, obs.DSKey(corp), false},
		{"the alert has ended", decide.RuleNameServers, obs.DelegationKey(corp), true, corp, obs.DSKey(corp), false},
		{"the alert is on the ds key", decide.RuleNameServers, obs.DSKey(corp), false, corp, obs.DSKey(corp), false},
		{"no alert", 0, obs.DelegationKey(corp), false, corp, obs.DSKey(corp), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, err := store.Open(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			if c.rule != 0 {
				regOpenAlert(t, s, c.rule, c.on, c.ended)
			}
			m := &monitor{store: s}
			got, err := m.nameServersOpen(&watched{name: c.domain}, c.judged)
			if err != nil || got != c.want {
				t.Errorf("nameServersOpen = %t, %v; want %t, nil", got, err, c.want)
			}
		})
	}
}
