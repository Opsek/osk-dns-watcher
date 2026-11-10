package main

import (
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"osk/internal/decide"
	"osk/internal/observe"
)

func main() {
	fmt.Println(decide.Decide("192.0.2.1"), observe.Name())
}
