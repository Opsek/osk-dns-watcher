package b

import (
	"os/signal"
	. "syscall"
)

// Quiet names only an allowed signal, but after a dot import no use of
// syscall can be told from a name of the file.
func Quiet() {
	signal.Ignore(SIGPIPE)
}
