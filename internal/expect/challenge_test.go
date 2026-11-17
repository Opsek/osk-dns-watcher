package expect

import (
	"testing"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

func TestIsChallengeName(t *testing.T) {
	for _, c := range []struct {
		name string
		want bool
	}{
		{".", false},
		{"_acme-challenge.corp.test.", true},
		{"_ACME-Challenge.corp.test.", true},
		{"_acme-challenge.", true},
		{"www._acme-challenge.corp.test.", false},
		{"_acme-challenge2.corp.test.", false},
		{"x_acme-challenge.corp.test.", false},
		{"corp.test.", false},
	} {
		n, err := dnswire.ParseName(c.name)
		if err != nil {
			t.Fatalf("ParseName(%q): %v", c.name, err)
		}
		if got := IsChallengeName(n); got != c.want {
			t.Errorf("IsChallengeName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
