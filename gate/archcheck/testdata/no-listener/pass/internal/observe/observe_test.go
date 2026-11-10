package observe

import (
	"net/http/httptest"
	"testing"
)

// A test file is not linked into the tool, so it may start a server.
func TestDial(t *testing.T) {
	s := httptest.NewServer(nil)
	defer s.Close()
}
