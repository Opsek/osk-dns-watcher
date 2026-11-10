package a

import (
	"example.com/lib"
	"fmt"
)

// #include <stdio.h>
import "C"

// Y is a value.
var Y = len(fmt.Sprint(lib.X))
