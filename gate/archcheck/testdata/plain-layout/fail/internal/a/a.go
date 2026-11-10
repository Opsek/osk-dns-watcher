package a

import "osk/internal/b"

// Name comes from package b, which cmd/osk reaches only through this one.
const Name = b.Name
