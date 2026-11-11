package dnswire

import (
	"cmp"
	"fmt"
	"strings"
)

const (
	maxLabelLen = 63
	maxNameLen  = 255 // the wire form, final zero octet included
	maxPointers = 128
)

// Name is a domain name: its uncompressed wire form, with the case as received.
// The zero Name is the root. The blank field makes == and map keys a compile error:
// names compare with Equal (ASCII case-insensitive, RFC 4343) and key maps with Key.
type Name struct {
	_ [0]func()
	// The labels, each after its length octet, without the final zero octet.
	// Length octets are at most 63, below 'A', so folding the case of the
	// whole string changes only label octets.
	wire string
}

// ParseName reads a name in presentation form; the trailing dot is optional
// and "." is the root. \X is the octet X when X is not a digit, and \DDD is
// the octet of that decimal value.
func ParseName(s string) (Name, error) {
	if s == "" {
		return Name{}, fmt.Errorf("%w: empty text", ErrInvalidName)
	}
	if s == "." {
		return Name{}, nil
	}
	var labels []string
	var label []byte
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.':
			labels = append(labels, string(label))
			label = label[:0]
		case '\\':
			octet, n, ok := readEscape(s[i+1:])
			if !ok {
				return Name{}, fmt.Errorf("%w: bad escape at index %d of %q", ErrInvalidName, i, s)
			}
			label = append(label, octet)
			i += n
		default:
			label = append(label, s[i])
		}
	}
	if len(label) > 0 {
		labels = append(labels, string(label))
	}
	return NameFromLabels(labels)
}

// readEscape reads what follows a backslash and returns the octet and the
// number of characters it took.
func readEscape(s string) (octet byte, n int, ok bool) {
	if s == "" {
		return 0, 0, false
	}
	if !isDigit(s[0]) {
		return s[0], 1, true
	}
	if len(s) < 3 || !isDigit(s[1]) || !isDigit(s[2]) {
		return 0, 0, false
	}
	v := int(s[0]-'0')*100 + int(s[1]-'0')*10 + int(s[2]-'0')
	if v > 255 {
		return 0, 0, false
	}
	return byte(v), 3, true
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

// NameFromLabels builds a name from raw label octets, leftmost first. No
// labels give the root.
func NameFromLabels(labels []string) (Name, error) {
	var b strings.Builder
	for i, l := range labels {
		if l == "" {
			return Name{}, fmt.Errorf("%w: label %d is empty", ErrInvalidName, i)
		}
		if len(l) > maxLabelLen {
			return Name{}, fmt.Errorf("%w: label %d has %d octets, more than %d", ErrInvalidName, i, len(l), maxLabelLen)
		}
		if b.Len()+1+len(l)+1 > maxNameLen {
			return Name{}, fmt.Errorf("%w: longer than %d octets at label %d", ErrInvalidName, maxNameLen, i)
		}
		b.WriteByte(byte(len(l)))
		b.WriteString(l)
	}
	return Name{wire: b.String()}, nil
}

// String returns the presentation form, always with the trailing dot.
func (n Name) String() string {
	if n.wire == "" {
		return "."
	}
	var b []byte
	for _, l := range n.Labels() {
		for i := 0; i < len(l); i++ {
			b = appendEscaped(b, l[i])
		}
		b = append(b, '.')
	}
	return string(b)
}

// appendEscaped writes one label octet so that zone files and dig read it
// back as the same octet.
func appendEscaped(b []byte, c byte) []byte {
	switch {
	case strings.IndexByte(`.;\()"@$`, c) >= 0:
		return append(b, '\\', c)
	case 0x21 <= c && c <= 0x7E:
		return append(b, c)
	default:
		return append(b, '\\', '0'+c/100, '0'+c/10%10, '0'+c%10)
	}
}

// Labels returns the raw label octets, leftmost first; nil for the root.
func (n Name) Labels() []string {
	var labels []string
	for w := n.wire; w != ""; w = w[1+int(w[0]):] {
		labels = append(labels, w[1:1+int(w[0])])
	}
	return labels
}

// LabelCount returns the number of labels: 0 for the root. "*" counts like
// any other label.
func (n Name) LabelCount() int {
	count := 0
	for w := n.wire; w != ""; w = w[1+int(w[0]):] {
		count++
	}
	return count
}

// Parent returns the name without its leftmost label. The parent of the
// root is the root.
func (n Name) Parent() Name {
	if n.wire == "" {
		return n
	}
	return Name{wire: n.wire[1+int(n.wire[0]):]}
}

// Equal reports whether n and m are the same name, ignoring ASCII case.
func (n Name) Equal(m Name) bool {
	if len(n.wire) != len(m.wire) {
		return false
	}
	for i := 0; i < len(n.wire); i++ {
		if lowerByte(n.wire[i]) != lowerByte(m.wire[i]) {
			return false
		}
	}
	return true
}

// IsSubdomainOf reports whether n is p or lies under it. Every name lies
// under the root.
func (n Name) IsSubdomainOf(p Name) bool {
	w := n.wire
	for len(w) > len(p.wire) {
		w = w[1+int(w[0]):]
	}
	return Name{wire: w}.Equal(p)
}

// Lower returns the name with A-Z turned into a-z; other octets stay as
// they are.
func (n Name) Lower() Name {
	return Name{wire: lowerASCII(n.wire)}
}

// Key returns the lowercased wire form, final zero octet included: equal
// names have equal keys.
func (n Name) Key() string {
	return lowerASCII(n.wire) + "\x00"
}

// AppendWire appends the uncompressed wire form, with its case, to b.
func (n Name) AppendWire(b []byte) []byte {
	return append(append(b, n.wire...), 0)
}

// Compare orders names canonically (RFC 4034 section 6.1) and returns -1,
// 0 or +1.
func Compare(a, b Name) int {
	la, lb := a.Lower().Labels(), b.Lower().Labels()
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := strings.Compare(la[i], lb[j]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(la), len(lb))
}

// lowerASCII folds A-Z only: other octets of a name are not text and must
// stay as they are.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		b[i] = lowerByte(c)
	}
	return string(b)
}

func lowerByte(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// readName reads the name at off in msg, following compression pointers
// only when ptrOK. next is the offset after the name where it stands, before
// any pointer.
func readName(msg []byte, off int, ptrOK bool) (n Name, next int, err error) {
	var buf [maxNameLen]byte
	wire, next, err := appendName(buf[:0], msg, off, ptrOK)
	if err != nil {
		return Name{}, 0, err
	}
	return Name{wire: string(wire[:len(wire)-1])}, next, nil
}

// appendName appends the uncompressed wire form of the name at off in msg,
// final zero octet included, to dst. A pointer must lead back, strictly
// before itself and not into the header, so a chain of pointers always ends;
// the count of pointers and the length of the name bound the work for one
// name.
func appendName(dst, msg []byte, off int, ptrOK bool) (wire []byte, next int, err error) {
	start := len(dst)
	next = -1
	pointers := 0
	for pos := off; ; {
		if pos >= len(msg) {
			return nil, 0, fmt.Errorf("%w: name at offset %d runs past the end", ErrMalformed, off)
		}
		c := int(msg[pos])
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				if next < 0 {
					next = pos + 1
				}
				return append(dst, 0), next, nil
			}
			if len(dst)-start+1+c+1 > maxNameLen {
				return nil, 0, fmt.Errorf("%w: name at offset %d is longer than %d octets", ErrMalformed, off, maxNameLen)
			}
			if pos+1+c > len(msg) {
				return nil, 0, fmt.Errorf("%w: name at offset %d runs past the end", ErrMalformed, off)
			}
			dst = append(dst, msg[pos:pos+1+c]...)
			pos += 1 + c
		case 0xC0:
			if !ptrOK {
				return nil, 0, fmt.Errorf("%w: name at offset %d: compression pointer at offset %d where none is allowed", ErrMalformed, off, pos)
			}
			if pos+1 >= len(msg) {
				return nil, 0, fmt.Errorf("%w: name at offset %d runs past the end", ErrMalformed, off)
			}
			pointers++
			if pointers > maxPointers {
				return nil, 0, fmt.Errorf("%w: name at offset %d follows more than %d pointers", ErrMalformed, off, maxPointers)
			}
			target := (c&0x3F)<<8 | int(msg[pos+1])
			if target < headerLen || target >= pos {
				return nil, 0, fmt.Errorf("%w: name at offset %d: pointer at offset %d leads to offset %d", ErrMalformed, off, pos, target)
			}
			if next < 0 {
				next = pos + 2
			}
			pos = target
		default:
			return nil, 0, fmt.Errorf("%w: name at offset %d: label type %02b at offset %d", ErrMalformed, off, c>>6, pos)
		}
	}
}
