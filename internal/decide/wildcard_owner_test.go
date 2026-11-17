package decide

import (
	"testing"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

func TestIsWildcardOwner(t *testing.T) {
	for _, c := range []struct {
		name string
		want bool
	}{
		{".", false},
		{"*.corp.test.", true},
		{"*.", true},
		{"*.*.corp.test.", true},
		{"www.*.corp.test.", false},
		{"**.corp.test.", false},
		{"*a.corp.test.", false},
		{"corp.test.", false},
	} {
		n, err := dnswire.ParseName(c.name)
		if err != nil {
			t.Fatalf("ParseName(%q): %v", c.name, err)
		}
		if got := IsWildcardOwner(n); got != c.want {
			t.Errorf("IsWildcardOwner(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
