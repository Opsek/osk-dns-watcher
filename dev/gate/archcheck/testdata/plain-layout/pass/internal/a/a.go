package a

import _ "embed"

// Name is read from a data file, which is not source code.
//
//go:embed name.txt
var Name string
