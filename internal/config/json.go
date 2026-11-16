package config

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// maxProblems keeps the report of a badly broken file readable.
const maxProblems = 100

// walker reads a config token by token. Unlike json.Unmarshal into a
// struct, it knows where each key and value starts, refuses a key in
// another letter case or given twice, and goes on after a problem.
type walker struct {
	file     string // the config file as given, for the problems
	dir      string // the absolute folder of the config file
	data     []byte
	lines    lines
	dec      *json.Decoder
	problems []Problem
	stopped  bool
}

func newWalker(file, dir string, data []byte) *walker {
	dec := json.NewDecoder(bytes.NewReader(data))
	// A number stays as written, so that 90.0 and 9e1 can be refused where
	// an integer is wanted.
	dec.UseNumber()
	return &walker{file: file, dir: dir, data: data, lines: newLines(data), dec: dec}
}

// lines holds the offsets of the LF octets of a file. The line of an
// offset is a binary search, so that a file of many entries is not counted
// again for each one.
type lines []int64

func newLines(data []byte) lines {
	var l lines
	for i, c := range data {
		if c == '\n' {
			l = append(l, int64(i))
		}
	}
	return l
}

// at gives the line of an offset: 1 + the LF octets before it.
func (l lines) at(off int64) int {
	n, _ := slices.BinarySearch(l, off)
	return 1 + n
}

// maxShown bounds a value of the config that a problem repeats: a secret
// pasted into the wrong field, or a huge key, must not reach a log whole.
const maxShown = 40

// shown gives v, or its first maxShown octets and … when it is longer. The
// cut falls at the start of a character, so the text stays valid UTF-8.
func shown(v string) string {
	if len(v) <= maxShown {
		return v
	}
	cut := maxShown
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + "…"
}

func (w *walker) add(at int64, path, text string) {
	if w.stopped || len(w.problems) >= maxProblems {
		return
	}
	w.problems = append(w.problems, Problem{File: w.file, Line: w.lines.at(at), Path: path, Text: text})
}

// next reads one token and gives the offset where it starts. A nil token
// with no problem is a JSON null.
func (w *walker) next() (json.Token, int64) {
	// The decoder's offset is the end of the last token; blanks and the
	// separators : and , may stand before the next one.
	at := w.dec.InputOffset()
	for at < int64(len(w.data)) && strings.IndexByte(" \t\r\n:,", w.data[at]) >= 0 {
		at++
	}
	t, err := w.dec.Token()
	// Parse checked the syntax of the whole file first, so this cannot
	// happen; if it does, the walk ends and the config is refused.
	if err != nil && !w.stopped {
		w.add(at, "", "not valid JSON: "+err.Error())
		w.stopped = true
	}
	return t, at
}

// more ends every loop of a stopped walk: a token that the decoder cannot
// read is never consumed, so More could report it forever.
func (w *walker) more() bool {
	return !w.stopped && w.dec.More()
}

func (w *walker) skip() {
	t, _ := w.next()
	w.skipRest(t)
}

// skipRest passes over the rest of a value whose first token was t.
func (w *walker) skipRest(t json.Token) {
	if t != json.Delim('{') && t != json.Delim('[') {
		return
	}
	for depth := 1; depth > 0 && !w.stopped; {
		switch t, _ := w.next(); t {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
}

// refuse reports a value of the wrong type and passes over it.
func (w *walker) refuse(t json.Token, at int64, path, text string) {
	w.add(at, path, text)
	w.skipRest(t)
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// fields gives the reader of each key that an object may hold. A reader
// gets the path of the value and the offset of its key.
type fields map[string]func(path string, keyAt int64)

// object reads an object value. It gives the keys that it read and where
// the object starts; the keys are nil when the value is not an object.
func (w *walker) object(path string, f fields, required ...string) (map[string]bool, int64) {
	t, at := w.next()
	if t != json.Delim('{') {
		w.refuse(t, at, path, "want an object")
		return nil, at
	}
	return w.members(path, at, f, required), at
}

// members reads the keys of an object whose { starts at open. Keys match
// exactly: "State" is an unknown key, never the key state.
func (w *walker) members(path string, open int64, f fields, required []string) map[string]bool {
	seen := map[string]bool{}
	for w.more() {
		t, at := w.next()
		key, _ := t.(string)
		read, known := f[key]
		switch {
		case !known:
			w.add(at, path, fmt.Sprintf("unknown key %q", shown(key)))
			w.skip()
		case seen[key]:
			w.add(at, path, fmt.Sprintf("key %q is given twice", shown(key)))
			w.skip()
		default:
			seen[key] = true
			read(join(path, key), at)
		}
	}
	w.next() // the closing }
	for _, key := range required {
		if !seen[key] {
			w.add(open, join(path, key), "is required")
		}
	}
	return seen
}

// list reads a list value and hands the path of each item to read. It
// gives the number of items and where the list starts; ok is false when
// the value is not a list.
func (w *walker) list(path string, read func(path string)) (n int, at int64, ok bool) {
	t, at := w.next()
	if t != json.Delim('[') {
		w.refuse(t, at, path, "want a list")
		return 0, at, false
	}
	for ; w.more(); n++ {
		read(fmt.Sprintf("%s[%d]", path, n))
	}
	w.next() // the closing ]
	return n, at, true
}

func (w *walker) str(path string) (string, int64, bool) {
	t, at := w.next()
	s, ok := t.(string)
	if !ok {
		w.refuse(t, at, path, "want a string")
	}
	return s, at, ok
}

// integer reads a number without a fraction or an exponent and gives its
// text.
func (w *walker) integer(path string) (string, int64, bool) {
	t, at := w.next()
	n, ok := t.(json.Number)
	if !ok || strings.ContainsAny(string(n), ".eE") {
		w.refuse(t, at, path, "want an integer")
		return "", at, false
	}
	return string(n), at, true
}

// sortProblems puts the problems in line order: a missing key is found at
// the end of its object but reported at its {.
func sortProblems(problems []Problem) {
	slices.SortStableFunc(problems, func(a, b Problem) int { return cmp.Compare(a.Line, b.Line) })
}
