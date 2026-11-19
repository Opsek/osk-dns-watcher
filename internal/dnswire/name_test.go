package dnswire_test

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

func wireMustName(t testing.TB, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

func wireTextName(lengths ...int) string {
	var labels []string
	for _, n := range lengths {
		labels = append(labels, strings.Repeat("a", n))
	}
	return strings.Join(labels, ".")
}

func TestParseNameReadsTheTextForm(t *testing.T) {
	cases := []struct {
		in, text string
		labels   []string
	}{
		{"example.test", "example.test.", []string{"example", "test"}},
		{"example.test.", "example.test.", []string{"example", "test"}},
		{".", ".", nil},
		{"Ex.TEST", "Ex.TEST.", []string{"Ex", "TEST"}},
		{"*.example.test", "*.example.test.", []string{"*", "example", "test"}},
		{`x\@y\$z\;w\(\)\"q.odd.test.`, `x\@y\$z\;w\(\)\"q.odd.test.`, []string{`x@y$z;w()"q`, "odd", "test"}},
		{`weird\032name`, `weird\032name.`, []string{"weird name"}},
		{`\000\255`, `\000\255.`, []string{"\x00\xff"}},
		{`a\.b`, `a\.b.`, []string{"a.b"}},
		{`\\`, `\\.`, []string{`\`}},
		{`\a\-`, `a-.`, []string{"a-"}},
		{`\065\126\033`, `A~!.`, []string{"A~!"}},
		{`\127\128\031`, `\127\128\031.`, []string{"\x7f\x80\x1f"}},
	}
	for _, c := range cases {
		n, err := dnswire.ParseName(c.in)
		if err != nil {
			t.Errorf("ParseName(%q): %v", c.in, err)
			continue
		}
		if got := n.String(); got != c.text {
			t.Errorf("ParseName(%q).String() = %q; want %q", c.in, got, c.text)
		}
		if got := n.Labels(); !slices.Equal(got, c.labels) || n.LabelCount() != len(c.labels) {
			t.Errorf("ParseName(%q) has labels %q, count %d; want %q", c.in, got, n.LabelCount(), c.labels)
		}
	}
}

func TestParseNameRejectsInvalidText(t *testing.T) {
	for _, s := range []string{"", "..", "a..b", ".a", "a..", `a\`, `\25`, `\25x`, `\256`, `\999`} {
		if n, err := dnswire.ParseName(s); !errors.Is(err, dnswire.ErrInvalidName) {
			t.Errorf("ParseName(%q) = %q, %v; want an error that wraps ErrInvalidName", s, n, err)
		}
	}
}

func TestParseNameEnforcesLabelAndNameLengths(t *testing.T) {
	ones := func(n int) []int { return slices.Repeat([]int{1}, n) }
	cases := []struct {
		name, in string
		ok       bool
	}{
		{"label of 63 octets", wireTextName(63), true},
		{"label of 64 octets", wireTextName(64), false},
		{"label of 63 escaped octets", strings.Repeat(`\000`, 63), true},
		{"label of 64 escaped octets", strings.Repeat(`\000`, 64), false},
		{"name of 255 octets", wireTextName(63, 63, 63, 61), true},
		{"name of 255 octets with the trailing dot", wireTextName(63, 63, 63, 61) + ".", true},
		{"name of 256 octets", wireTextName(63, 63, 63, 62), false},
		{"name of 256 octets with the trailing dot", wireTextName(63, 63, 63, 62) + ".", false},
		{"name of 255 octets in 127 labels", wireTextName(ones(127)...), true},
		{"name of 256 octets in 127 labels", wireTextName(append(ones(126), 2)...), false},
	}
	for _, c := range cases {
		_, err := dnswire.ParseName(c.in)
		if c.ok && err != nil {
			t.Errorf("%s: ParseName: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, dnswire.ErrInvalidName) {
			t.Errorf("%s: ParseName error = %v; want one that wraps ErrInvalidName", c.name, err)
		}
	}
}

func TestNameStringEscapesEveryOctetByTheRule(t *testing.T) {
	for c := range 256 {
		var want string
		switch {
		case strings.IndexByte(`.;\()"@$`, byte(c)) >= 0:
			want = `\` + string(rune(c))
		case c >= 0x21 && c <= 0x7E:
			want = string(rune(c))
		default:
			want = fmt.Sprintf(`\%03d`, c)
		}
		n, err := dnswire.NameFromLabels([]string{string([]byte{byte(c)})})
		if err != nil {
			t.Fatalf("NameFromLabels with octet %d: %v", c, err)
		}
		if got := n.String(); got != want+"." {
			t.Errorf("octet %d prints as %q; want %q", c, got, want+".")
		}
		back, err := dnswire.ParseName(n.String())
		if err != nil || !slices.Equal(back.Labels(), n.Labels()) {
			t.Errorf("octet %d: ParseName(%q) = %q, %v; want the same octet back", c, n.String(), back.Labels(), err)
		}
	}
}

func TestNameOfTheLongestFormPrintsAndParsesBack(t *testing.T) {
	var labels []string
	octet := 0
	for _, size := range []int{63, 63, 63, 61} {
		var l []byte
		for range size {
			l = append(l, byte(octet))
			octet += 7
		}
		labels = append(labels, string(l))
	}
	n, err := dnswire.NameFromLabels(labels)
	if err != nil {
		t.Fatalf("NameFromLabels: %v", err)
	}
	if got := len(n.AppendWire(nil)); got != 255 {
		t.Fatalf("wire form of %d octets; want 255", got)
	}
	back, err := dnswire.ParseName(n.String())
	if err != nil {
		t.Fatalf("ParseName(%q): %v", n.String(), err)
	}
	if !back.Equal(n) || back.String() != n.String() || !slices.Equal(back.Labels(), labels) {
		t.Errorf("ParseName(%q) gave %q; want the same name", n.String(), back.String())
	}
}

func TestZeroNameIsTheRoot(t *testing.T) {
	var n dnswire.Name
	if n.String() != "." || n.LabelCount() != 0 || len(n.Labels()) != 0 {
		t.Errorf("zero Name = %q with %d labels %q; want the root", n.String(), n.LabelCount(), n.Labels())
	}
	if !n.Equal(wireMustName(t, ".")) || n.Key() != "\x00" || !bytes.Equal(n.AppendWire(nil), []byte{0}) {
		t.Errorf("zero Name has key %q and wire % X; want the root", n.Key(), n.AppendWire(nil))
	}
	if p := n.Parent(); p.String() != "." {
		t.Errorf("parent of the root = %q; want the root", p.String())
	}
}

func TestNameParentDropsTheLeftmostLabel(t *testing.T) {
	cases := map[string]string{"a.b.c.": "b.c.", "A.B.C": "B.C.", "c.": ".", ".": ".", `x\.y.z`: "z."}
	for in, want := range cases {
		if got := wireMustName(t, in).Parent().String(); got != want {
			t.Errorf("parent of %q = %q; want %q", in, got, want)
		}
	}
}

func TestNameEqualFoldsOnlyASCIILetters(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"Example.TEST", "example.test.", true},
		{`\065`, "a", true},
		{".", ".", true},
		{"example.test", "example.net", false},
		{"a.bc", "ab.c", false},
		{"a.", ".", false},
		{`\195`, `\227`, false},
		{"[", "{", false},
		{`\@`, "`", false},
		{"^", "~", false},
	}
	for _, c := range cases {
		a, b := wireMustName(t, c.a), wireMustName(t, c.b)
		if a.Equal(b) != c.want || b.Equal(a) != c.want {
			t.Errorf("%q equal to %q: %v; want %v", c.a, c.b, a.Equal(b), c.want)
		}
		if (a.Key() == b.Key()) != c.want {
			t.Errorf("%q and %q: same key %v; want %v", c.a, c.b, a.Key() == b.Key(), c.want)
		}
	}
}

func TestNameIsSubdomainOfComparesWholeLabels(t *testing.T) {
	cases := []struct {
		n, p string
		want bool
	}{
		{"www.example.test", "example.test", true},
		{"example.test", "example.test", true},
		{"WWW.EXAMPLE.test", "Example.TEST", true},
		{"example.test", ".", true},
		{".", ".", true},
		{"example.test", "www.example.test", false},
		{"wwwexample.test", "example.test", false},
		// The label "x\007example" ends with the wire form of "example.test.".
		{`x\007example.test`, "example.test", false},
		{".", "test", false},
		{"example.net", "example.test", false},
	}
	for _, c := range cases {
		if got := wireMustName(t, c.n).IsSubdomainOf(wireMustName(t, c.p)); got != c.want {
			t.Errorf("%q under %q: %v; want %v", c.n, c.p, got, c.want)
		}
	}
}

func TestNameLowerChangesOnlyASCIILetters(t *testing.T) {
	cases := map[string]string{
		"ExAmple.TEST": "example.test.",
		`A\@B[Z`:       `a\@b[z.`,
		`\195X`:        `\195x.`,
		".":            ".",
	}
	for in, want := range cases {
		if got := wireMustName(t, in).Lower().String(); got != want {
			t.Errorf("Lower of %q = %q; want %q", in, got, want)
		}
	}
}

func TestNameKeyIsTheLowercasedWireForm(t *testing.T) {
	cases := map[string]string{
		"Example.TEST": "\x07example\x04test\x00",
		".":            "\x00",
		`A\.B`:         "\x03a.b\x00",
		`\195Z`:        "\x02\xc3z\x00",
	}
	for in, want := range cases {
		if got := wireMustName(t, in).Key(); got != want {
			t.Errorf("Key of %q = %q; want %q", in, got, want)
		}
	}
}

func TestNameAppendWireKeepsCaseAndPrefix(t *testing.T) {
	got := wireMustName(t, "Ex.TEST").AppendWire([]byte{0xAA})
	want := []byte{0xAA, 2, 'E', 'x', 4, 'T', 'E', 'S', 'T', 0}
	if !bytes.Equal(got, want) {
		t.Errorf("AppendWire = % X; want % X", got, want)
	}
}

func TestNameFromLabelsTakesRawOctets(t *testing.T) {
	l63 := strings.Repeat("a", 63)
	cases := []struct {
		name   string
		labels []string
		text   string
	}{
		{"nil is the root", nil, "."},
		{"case is kept", []string{"Ex", "TEST"}, "Ex.TEST."},
		{"a dot is an octet", []string{"a.b"}, `a\.b.`},
		{"any octet", []string{"\x00\xff"}, `\000\255.`},
		{"label of 63 octets", []string{l63}, l63 + "."},
		{"name of 255 octets", []string{l63, l63, l63, l63[:61]}, strings.Join([]string{l63, l63, l63, l63[:61]}, ".") + "."},
	}
	for _, c := range cases {
		n, err := dnswire.NameFromLabels(c.labels)
		if err != nil {
			t.Errorf("%s: NameFromLabels: %v", c.name, err)
			continue
		}
		if n.String() != c.text || !slices.Equal(n.Labels(), c.labels) {
			t.Errorf("%s: name %q with labels %q; want %q", c.name, n.String(), n.Labels(), c.text)
		}
	}
	bad := map[string][]string{
		"empty label":        {"a", ""},
		"label of 64 octets": {l63 + "a"},
		"name of 256 octets": {l63, l63, l63, l63[:62]},
	}
	for name, labels := range bad {
		if _, err := dnswire.NameFromLabels(labels); !errors.Is(err, dnswire.ErrInvalidName) {
			t.Errorf("%s: NameFromLabels error = %v; want one that wraps ErrInvalidName", name, err)
		}
	}
}

func TestCompareFollowsTheCanonicalOrderOfRFC4034(t *testing.T) {
	// The example of RFC 4034 section 6.1, in order, after the root.
	ordered := []string{
		".",
		"example",
		"a.example",
		"yljkjljk.a.example",
		"Z.a.example",
		"zABC.a.EXAMPLE",
		"z.example",
		`\001.z.example`,
		"*.z.example",
		`\200.z.example`,
	}
	for i, a := range ordered {
		for j, b := range ordered {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := dnswire.Compare(wireMustName(t, a), wireMustName(t, b)); got != want {
				t.Errorf("Compare(%q, %q) = %d; want %d", a, b, got, want)
			}
		}
	}
	if got := dnswire.Compare(wireMustName(t, "Z.a.example"), wireMustName(t, "z.A.EXAMPLE")); got != 0 {
		t.Errorf("Compare of names that differ only in case = %d; want 0", got)
	}
}
