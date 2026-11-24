package dnswire

import (
	"errors"
	"fmt"
)

// Every error of this package wraps one of these. Its text names the
// section, index or offset where the problem was found.
var (
	ErrMalformed    = errors.New("dnswire: malformed message")
	ErrInvalidName  = errors.New("dnswire: invalid name")
	ErrInvalidType  = errors.New("dnswire: invalid type")
	ErrInvalidQuery = errors.New("dnswire: invalid query")
	ErrMismatch     = errors.New("dnswire: answer does not match the query")
	ErrTSIG         = errors.New("dnswire: TSIG check failed")
	ErrNoRoute      = errors.New("dnswire: no route from this machine")
)

// malformed puts where in front of err and wraps ErrMalformed, unless err
// wraps it already, as an error from reading a name does.
func malformed(where string, err error) error {
	if errors.Is(err, ErrMalformed) {
		return fmt.Errorf("%s: %w", where, err)
	}
	return fmt.Errorf("%w: %s: %w", ErrMalformed, where, err)
}
