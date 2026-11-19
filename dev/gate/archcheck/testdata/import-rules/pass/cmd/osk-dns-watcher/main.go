package main

import (
	"fmt"

	"osk/internal/decide"
	"osk/internal/observe"
	"osk/internal/store"
)

func main() {
	fmt.Println(decide.Decide("192.0.2.1"), observe.Client, store.Name)
}
