package dnswire

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// caatWire is the data of a CAA record: flags, tag length, tag, value.
func caatWire(tag, value string) []byte {
	return append([]byte{0, byte(len(tag))}, tag+value...)
}

// caatIsPlain says which tag octets the text form writes as they are. It is
// written out here, apart from the code under test.
func caatIsPlain(c int) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func caatEscaped(tag string) string {
	var b strings.Builder
	for i := 0; i < len(tag); i++ {
		if caatIsPlain(int(tag[i])) {
			b.WriteByte(tag[i])
		} else {
			fmt.Fprintf(&b, `\%03d`, tag[i])
		}
	}
	return b.String()
}

// caatRead reads a CAA record with the given tag from the wire and checks
// that the record keeps the tag and writes the same octets again.
func caatRead(t *testing.T, tag string) CAA {
	t.Helper()
	wire := caatWire(tag, "x")
	r, err := dataParse(TypeCAA, wire)
	if err != nil {
		t.Fatalf("tag %q: %v", tag, err)
	}
	d, ok := r.Data.(CAA)
	if !ok {
		t.Fatalf("tag %q: data is %T", tag, r.Data)
	}
	if d.Tag != tag || d.Value != "x" || d.Flags != 0 {
		t.Fatalf("tag %q: read %#v", tag, d)
	}
	if got := AppendRData(nil, d); !bytes.Equal(got, wire) {
		t.Fatalf("tag %q: written as %x, want %x", tag, got, wire)
	}
	return d
}

func TestCAATagReadRows(t *testing.T) {
	rows := []struct {
		name string
		tag  string
		text string
	}{
		{"a hyphen", "bad-tag", `0 bad\045tag "x"`},
		{"a hyphen inside", "a-b", `0 a\045b "x"`},
		{"a space", "a b", `0 a\032b "x"`},
		{"not ASCII", "\xc3\xa9", `0 \195\169 "x"`},
		{"upper case kept", "BAD-Tag", `0 BAD\045Tag "x"`},
		{"NUL", "\x00", `0 \000 "x"`},
		{"space", " ", `0 \032 "x"`},
		{"hyphen", "-", `0 \045 "x"`},
		{"slash, one below 0", "/", `0 \047 "x"`},
		{"zero", "0", `0 0 "x"`},
		{"nine", "9", `0 9 "x"`},
		{"colon, one above 9", ":", `0 \058 "x"`},
		{"at, one below A", "@", `0 \064 "x"`},
		{"A", "A", `0 A "x"`},
		{"Z", "Z", `0 Z "x"`},
		{"bracket, one above Z", "[", `0 \091 "x"`},
		{"backtick, one below a", "`", `0 \096 "x"`},
		{"a", "a", `0 a "x"`},
		{"z", "z", `0 z "x"`},
		{"brace, one above z", "{", `0 \123 "x"`},
		{"DEL", "\x7f", `0 \127 "x"`},
		{"255", "\xff", `0 \255 "x"`},
		{"quote", `"`, `0 \034 "x"`},
		{"semicolon", ";", `0 \059 "x"`},
		{"bar", "|", `0 \124 "x"`},
		{"backslash", `\`, `0 \092 "x"`},
		{"line feed", "\n", `0 \010 "x"`},
		{"a backslash before digits is escaped itself", `\065`, `0 \092065 "x"`},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			d := caatRead(t, r.tag)
			if got := d.String(); got != r.text {
				t.Errorf("String() = %q, want %q", got, r.text)
			}
			rec := Record{Name: dataName(t, "example."), Class: ClassINET, TTL: 3600, Data: d}
			if got, want := rec.String(), "example.\t3600\tIN\tCAA\t"+r.text; got != want {
				t.Errorf("record String() = %q, want %q", got, want)
			}
		})
	}
}

// Every octet value is read as a one-octet tag and inside a tag.
func TestCAATagEveryOctet(t *testing.T) {
	for c := 0; c < 256; c++ {
		for _, tag := range []string{string([]byte{byte(c)}), "a" + string([]byte{byte(c)}) + "z"} {
			d := caatRead(t, tag)
			want := fmt.Sprintf("0 %s \"x\"", caatEscaped(tag))
			if caatIsPlain(c) && strings.Contains(want, `\`) {
				t.Fatalf("octet %d: the test expects an escape for a plain octet", c)
			}
			if !caatIsPlain(c) && !strings.Contains(want, fmt.Sprintf(`\%03d`, c)) {
				t.Fatalf("octet %d: the test expects no escape for an odd octet", c)
			}
			text := d.String()
			if text != want {
				t.Errorf("tag %q: String() = %q, want %q", tag, text, want)
			}
			// The tag is the second of three fields: flags, tag, quoted value.
			field := strings.SplitN(text, " ", 3)[1]
			if strings.ContainsAny(field, " |\";\n") {
				t.Errorf("tag %q: text field %q holds a separator", tag, field)
			}
			for i := 0; i < len(field); i++ {
				if field[i] != '\\' {
					continue
				}
				if i+4 > len(field) || strings.Trim(field[i+1:i+4], "0123456789") != "" {
					t.Errorf("tag %q: backslash not followed by three digits in %q", tag, field)
					break
				}
				i += 3
			}
		}
	}
}

func TestCAATagLengthBounds(t *testing.T) {
	long := strings.Repeat("a", 255)
	d := caatRead(t, long)
	if d.String() != `0 `+long+` "x"` {
		t.Errorf("a tag of 255 octets: String() has length %d", len(d.String()))
	}
	odd := strings.Repeat("-", 255)
	d = caatRead(t, odd)
	if want := `0 ` + strings.Repeat(`\045`, 255) + ` "x"`; d.String() != want {
		t.Errorf("a tag of 255 hyphens: String() = %q", d.String())
	}
	// A tag with no value after it is read.
	if r, err := dataParse(TypeCAA, caatWire(long, "")); err != nil || r.Data.(CAA).Tag != long {
		t.Errorf("tag of 255 octets and no value: %v, %v", r, err)
	}
	if r, err := dataParse(TypeCAA, caatWire("-", "")); err != nil || r.Data.(CAA).Tag != "-" {
		t.Errorf("tag of 1 octet and no value: %v, %v", r, err)
	}

	refused := []struct {
		name string
		wire []byte
	}{
		{"no octet", nil},
		{"flags only", []byte{0}},
		{"length 0", []byte{0, 0}},
		{"length 0 and a value", []byte{0, 0, 'x'}},
		{"length 0 beside an odd value", []byte{128, 0, '-', '-'}},
		{"length 1, no tag", []byte{0, 1}},
		{"length 2, one octet", []byte{0, 2, '-'}},
		{"length 255, 254 octets", append([]byte{0, 255}, bytes.Repeat([]byte{'-'}, 254)...)},
		{"length 255, none", []byte{0, 255}},
		{"length 7, six octets", append([]byte{0, 7}, "bad-ta"...)},
	}
	for _, r := range refused {
		if got, err := dataParse(TypeCAA, r.wire); err == nil {
			t.Errorf("%s: read as %v, want a refusal", r.name, got)
		}
	}
}

// The text parser stays strict: a tag is letters and digits, so the escape
// form of String() does not read back.
func TestCAATagTextParserStaysStrict(t *testing.T) {
	for c := 0; c < 256; c++ {
		if caatIsPlain(c) {
			continue
		}
		raw := string([]byte{byte(c)})
		for _, text := range []string{
			`0 ` + raw + ` "x"`,
			`0 a` + raw + `b "x"`,
			`0 ` + caatEscaped(raw) + ` "x"`,
			`0 a` + caatEscaped(raw) + `b "x"`,
		} {
			if d, err := ParseRData(TypeCAA, text); err == nil {
				t.Errorf("ParseRData(CAA, %q) = %#v, want a refusal", text, d)
			}
		}
	}
	for _, text := range []string{
		`0 bad\045tag "x"`,
		`0 \097 "x"`,
		`0 iss\117e "x"`,
		`0 bad-tag "x"`,
		`0 "" "x"`,
		`0 ` + strings.Repeat("a", 256) + ` "x"`,
	} {
		if d, err := ParseRData(TypeCAA, text); err == nil {
			t.Errorf("ParseRData(CAA, %q) = %#v, want a refusal", text, d)
		}
	}
	// The boundary on the other side: the plain forms still read.
	for _, tag := range []string{"issue", "0", "9", "A", "Z", "a", "z", "Az09", strings.Repeat("a", 255)} {
		d, err := ParseRData(TypeCAA, `0 `+tag+` "x"`)
		if err != nil || d.(CAA).Tag != tag {
			t.Errorf("ParseRData(CAA, tag %q) = %#v, %v", tag, d, err)
		}
	}
	// A record with an odd tag, written as text, does not read back.
	d := caatRead(t, "bad-tag")
	if _, err := ParseRData(TypeCAA, d.String()); err == nil {
		t.Errorf("the text %q of an odd tag reads back", d.String())
	}
	// A record with a plain tag does.
	d = caatRead(t, "issue")
	if back, err := ParseRData(TypeCAA, d.String()); err != nil || back.(CAA) != d {
		t.Errorf("the text %q of a plain tag reads back as %#v, %v", d.String(), back, err)
	}
}

// Records that differ in one octet of the tag are different records, in the
// order of their wire forms.
func TestCAATagRecordsDiffer(t *testing.T) {
	base := "bad-tag"
	var set []CAA
	for c := 0; c < 256; c++ {
		tag := []byte(base)
		tag[3] = byte(c)
		set = append(set, caatRead(t, string(tag)))
	}
	for i := 1; i < len(set); i++ {
		a, b := set[i-1], set[i]
		if a == b {
			t.Fatalf("tags differing at octet 4 (%d and %d) are equal records", i-1, i)
		}
		if bytes.Equal(AppendRData(nil, a), AppendRData(nil, b)) {
			t.Fatalf("tags differing at octet 4 (%d and %d) have the same wire form", i-1, i)
		}
		if a.String() == b.String() && !(caatIsPlain(i-1) && caatIsPlain(i)) {
			t.Fatalf("octets %d and %d have the same text %q", i-1, i, a.String())
		}
		if bytes.Compare(AppendRData(nil, a), AppendRData(nil, b)) >= 0 {
			t.Errorf("octet %d does not sort before octet %d", i-1, i)
		}
	}

	// The order is fixed: any order of the input gives the same sorted set.
	want := slices.Clone(set)
	for _, shift := range []int{1, 7, 100, 255} {
		got := slices.Concat(set[shift:], set[:shift])
		slices.SortFunc(got, func(a, b CAA) int {
			return bytes.Compare(AppendRData(nil, a), AppendRData(nil, b))
		})
		if !slices.Equal(got, want) {
			t.Errorf("a rotation by %d does not sort to the same order", shift)
		}
	}

	// A tag that differs in case only, and a flag that differs, are different.
	x, y := CAA{0, "bad-tag", "x"}, CAA{0, "BAD-tag", "x"}
	if x == y || bytes.Equal(AppendRData(nil, x), AppendRData(nil, y)) {
		t.Error("tags that differ in case are the same record")
	}
	if z := (CAA{128, "bad-tag", "x"}); z == x || bytes.Equal(AppendRData(nil, z), AppendRData(nil, x)) {
		t.Error("the critical flag makes no difference")
	}
}

// The canonical form keeps the tag as it is, case included.
func TestCAATagCanonicalKeepsTag(t *testing.T) {
	for _, tag := range []string{"BAD-Tag", "\xff\x00A", "Issue"} {
		r := Record{Name: dataName(t, "Example."), Class: ClassINET, TTL: 1, Data: CAA{128, tag, "V"}}
		if got := Canonical(r).Data; got != (CAA{128, tag, "V"}) {
			t.Errorf("Canonical changed the data to %#v", got)
		}
	}
}
