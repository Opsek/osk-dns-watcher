package main

import (
	"osk/internal/a"
	"osk/internal/b"
)

func main() {
	a.Serve()
	_, _ = b.Socket()
}
