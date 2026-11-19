package observe

import (
	"net/http"

	"osk/internal/expect"
)

// Client makes requests.
var Client = http.Client{}

// Valid is the check of the expectations.
var Valid = expect.Valid
