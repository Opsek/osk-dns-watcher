package expect

import (
	"bytes"
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"osk/internal/dnswire"
)

// File gives each name the range that its address must lie in.
type File map[dnswire.Name]netip.Prefix

// String prints one numbered line for each name, sorted by name.
func (f File) String() string {
	names := slices.SortedFunc(maps.Keys(f), func(x, y dnswire.Name) int {
		return cmp.Compare(strings.ToLower(string(x)), strings.ToLower(string(y)))
	})
	var b bytes.Buffer
	for i, n := range names {
		b.WriteString(strconv.Itoa(i+1) + " " + string(n) + " in " + f[n].String() + "\n")
	}
	return b.String()
}
