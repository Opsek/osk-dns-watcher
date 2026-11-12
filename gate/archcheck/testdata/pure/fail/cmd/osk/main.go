package main

import (
	"fmt"

	"osk/internal/decide"
	"osk/internal/expect"
)

func main() {
	fmt.Println(decide.Decide(), expect.Server)
}
