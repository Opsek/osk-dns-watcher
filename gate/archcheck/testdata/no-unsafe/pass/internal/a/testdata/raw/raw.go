package raw

import "unsafe"

// Size is in a testdata folder that no checked package imports.
var Size = unsafe.Sizeof(0)
