// Command osk watches the DNS of the domains of its operator.
package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/store"
)

// version is set by build/static.sh with -ldflags "-X main.version=...".
// It is a var because -X cannot set a constant.
var version = "unknown"

func main() {
	if len(os.Args) != 2 || os.Args[1] != "version" {
		fmt.Fprintln(os.Stderr, "usage: osk version")
		os.Exit(2)
	}
	sqlite, err := store.SQLiteVersion()
	if err != nil {
		fmt.Fprintln(os.Stderr, "osk:", err)
		os.Exit(1)
	}
	fmt.Println("osk", version)
	fmt.Println("go", strings.TrimPrefix(runtime.Version(), "go"))
	fmt.Println("sqlite", sqlite)
}
