package main

import (
	_ "osk/gate/tool"
	"osk/internal/a"
	_ "osk/internal/a/testdata/helper"
	_ "osk/internal/_old"
)

func main() {
	println(a.Name)
}
