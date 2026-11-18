package expect

import (
	"cmp"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// dkimLong names a record that osk does not read.
const dkimLong = "a DKIM record longer than 4096 octets"

// dkimSpace is the white space that may stand around a tag of a key record
// and inside its p (RFC 6376 section 3.2).
const dkimSpace = " \t\r\n"

// dkimID names a key that signs mail. Two keys are one only when their whole
// key text is: whoever holds the private key of a key whose printed tail
// merely matches can sign as the domain too.
type dkimID struct {
	shown string // how a word names the key
	key   string // k and the whole p, the CNAME target, or the text of a record that osk does not read
}

type dkimFlags struct{ testing, strict bool }

// dkimWeaker names each key of now that was does not list, and each key of
// both that leaves t=y or t=s. A key that is gone signs nothing, so it is
// never weaker.
func dkimWeaker(was, now map[dkimID]dkimFlags) []string {
	ids := slices.SortedFunc(maps.Keys(now), func(a, b dkimID) int {
		return cmp.Or(strings.Compare(a.shown, b.shown), strings.Compare(a.key, b.key))
	})
	var words []string
	for _, id := range ids {
		w, listed := was[id]
		if !listed {
			word := "a key that the file does not list: " + id.shown
			if id.shown == dkimLong {
				word = dkimLong + ": osk does not read it and counts it as a key that the file does not list"
			}
			words = append(words, word)
			continue
		}
		if w.testing && !now[id].testing {
			words = append(words, "the key "+id.shown+" leaves testing mode: t=y is gone")
		}
		if w.strict && !now[id].strict {
			words = append(words, "the key "+id.shown+" no longer has t=s")
		}
	}
	return words
}

// readDKIM gives the keys that sign mail for the selector of set. A key found
// twice is testing, or strict, only when every copy is.
func readDKIM(set []dnswire.RData) map[dkimID]dkimFlags {
	keys := map[dkimID]dkimFlags{}
	for _, d := range set {
		id, f, ok := dkimSigner(d)
		if !ok {
			continue
		}
		if g, twice := keys[id]; twice {
			f = dkimFlags{testing: f.testing && g.testing, strict: f.strict && g.strict}
		}
		keys[id] = f
	}
	return keys
}

// dkimSigner gives the key that d makes sign mail. A CNAME hands the key to
// another zone, whose owner can change it at will.
func dkimSigner(d dnswire.RData) (dkimID, dkimFlags, bool) {
	switch d := d.(type) {
	case dnswire.TXT:
		return dkimKey(strings.Join(d.Strings, ""))
	case dnswire.CNAME:
		name := "CNAME " + d.Target.Lower().String()
		return dkimID{shown: name, key: name}, dkimFlags{}, true
	}
	return dkimID{}, dkimFlags{}, false
}

// dkimKey reads a key record (RFC 6376 section 3.6.1). ok is false when it
// signs no mail: its tag-list does not read, its key is revoked, or its
// service types leave out email.
func dkimKey(text string) (dkimID, dkimFlags, bool) {
	if len(text) > maxText {
		// osk does not read it, so it may hold any key: it is listed only
		// when the file holds the same text.
		return dkimID{shown: dkimLong, key: text}, dkimFlags{}, true
	}
	tags, first := dkimTags(text)
	v, hasV := tags["v"]
	if hasV && (first != "v" || v != "DKIM1") {
		return dkimID{}, dkimFlags{}, false
	}
	// A missing p, an empty one, which revokes the key, and a tag-list that
	// does not read sign nothing.
	p := strings.Join(strings.FieldsFunc(tags["p"], func(r rune) bool { return strings.ContainsRune(dkimSpace, r) }), "")
	if p == "" || !onlyOf(p, alnum+"+/=") {
		return dkimID{}, dkimFlags{}, false
	}
	k, hasK := tags["k"]
	if !hasK {
		k = "rsa"
	}
	if !isWord(k, alpha, alnum) {
		return dkimID{}, dkimFlags{}, false
	}
	if s, hasS := tags["s"]; hasS && !slices.Contains(dkimList(s), "*") && !slices.Contains(dkimList(s), "email") {
		return dkimID{}, dkimFlags{}, false
	}
	flags := dkimList(tags["t"])
	id := dkimID{
		shown: "k=" + k + ", " + strconv.Itoa(len(p)) + ` characters, ending "` + p[max(0, len(p)-12):] + `"`,
		key:   "k=" + k + "; p=" + p,
	}
	return id, dkimFlags{testing: slices.Contains(flags, "y"), strict: slices.Contains(flags, "s")}, true
}

// dkimTags reads a tag-list (RFC 6376 section 3.2) and the name of its first
// tag. The tags are nil when a part is not name=value, a name is not ALPHA
// *(ALPHA / DIGIT / "_"), or a name is given twice.
func dkimTags(text string) (tags map[string]string, first string) {
	tags = map[string]string{}
	for _, part := range strings.Split(text, ";") {
		part = strings.Trim(part, dkimSpace)
		if part == "" {
			continue
		}
		name, value, found := strings.Cut(part, "=")
		name = strings.Trim(name, dkimSpace)
		if _, twice := tags[name]; !found || twice || !isWord(name, alpha, alnum+"_") {
			return nil, ""
		}
		if first == "" {
			first = name
		}
		tags[name] = strings.Trim(value, dkimSpace)
	}
	return tags, first
}

// dkimList splits a list value of a key record at ":".
func dkimList(v string) []string {
	items := strings.Split(v, ":")
	for i, item := range items {
		items[i] = strings.Trim(item, dkimSpace)
	}
	return items
}
