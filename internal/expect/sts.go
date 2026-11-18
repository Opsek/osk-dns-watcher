package expect

import (
	"slices"
	"strconv"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

var stsPick = recordProblems{
	none: "no MTA-STS record",
	many: "two or more MTA-STS records",
	long: "an MTA-STS record longer than 4096 octets",
}

// stsWeaker names a record that is gone or cannot be read where was had
// one. The record holds no policy, only its id: senders that find no
// record and have not cached the policy send mail without it (RFC 8461
// sections 3.3 and 10.2).
func stsWeaker(was, now string) []string {
	if was != "" || now == "" {
		return nil
	}
	return []string{now + ": senders that have not cached the policy send mail without it"}
}

// STSOn reports whether set holds exactly one MTA-STS record that reads.
func STSOn(set []dnswire.RData) bool {
	return readSTS(set) == ""
}

// readSTS gives the problem of the MTA-STS record of set; "" when set has
// one record and it reads.
func readSTS(set []dnswire.RData) string {
	rest, problem := oneRecord(set, stsVersion, stsPick)
	if problem == "" && !stsFields(rest) {
		return "an MTA-STS record that cannot be read"
	}
	return problem
}

// stsVersion accepts the text of an MTA-STS record (RFC 8461 section 3.1):
// "v=STSv1" in this case, then the end, a space, a tab or ";". It gives the
// text after the version.
func stsVersion(text string) (string, bool) {
	rest, ok := strings.CutPrefix(text, "v=STSv1")
	return rest, ok && (rest == "" || strings.ContainsAny(rest[:1], wsp+";"))
}

// stsFields reports whether the text after the version reads (RFC 8461
// section 3.1): ";", then fields name=value split at ";", at least one of
// them an id and each id valid, and at most one ";" at the end.
func stsFields(rest string) bool {
	rest, ok := strings.CutPrefix(strings.TrimLeft(rest, wsp), ";")
	if !ok {
		return false
	}
	rest, _ = strings.CutSuffix(strings.TrimRight(rest, wsp), ";")
	id := false
	for _, field := range strings.Split(rest, ";") {
		// A value holds no ";", since the fields are split there.
		name, value, found := strings.Cut(strings.Trim(field, wsp), "=")
		if !found || len(name) > 32 || !isWord(name, alnum, alnum+"_-.") || !visible(value) || strings.Contains(value, "=") {
			return false
		}
		if name == "id" {
			if len(value) > 32 || !onlyOf(value, alnum) {
				return false
			}
			id = true
		}
	}
	return id
}

// STSMode is what a policy asks of senders (RFC 8461 section 5).
type STSMode uint8

const (
	STSNone    STSMode = iota + 1 // act as if there were no policy
	STSTesting                    // report a host that fails the check, but deliver to it
	STSEnforce                    // deliver only to a host that passes the check
)

// stsModeWords are the modes as the policy file and the expectations file
// write them. A map, so that a mode of no word prints as "" and never
// panics.
var stsModeWords = map[STSMode]string{STSNone: "none", STSTesting: "testing", STSEnforce: "enforce"}

const (
	maxPolicySize = 65536    // RFC 8461 section 3.3 suggests 64 kilobytes
	maxSTSAge     = 31557600 // RFC 8461 section 3.2: one year
	maxMXLines    = 64
)

// STSPolicy is an MTA-STS policy (RFC 8461 section 3.2): the mta-sts line
// of a file, or what a policy file says. It holds no text of the policy
// file, so that the file can reach a message only through String.
type STSPolicy struct {
	Line   int            // its line in the file; 0 when read from a policy file
	Mode   STSMode        // what senders do when a host fails the check
	MaxAge uint32         // seconds, at most 31557600
	MX     []dnswire.Name // patterns; a first label "*" matches one label; lower case, dnswire.Compare order, each once, at most 64
}

// String gives the policy as its line in the file: "mta-sts <mode>
// <max_age> <mx>...".
func (p STSPolicy) String() string {
	words := []string{"mta-sts", stsModeWords[p.Mode], strconv.FormatUint(uint64(p.MaxAge), 10)}
	for _, n := range p.MX {
		words = append(words, n.String())
	}
	return strings.Join(words, " ")
}

// ParseSTSPolicy reads a policy file (RFC 8461 section 3.2). problem is ""
// when it reads, else one of the fixed texts below, which hold nothing of
// the file.
func ParseSTSPolicy(body []byte) (p STSPolicy, problem string) {
	if len(body) > maxPolicySize {
		return STSPolicy{}, "longer than 65536 octets"
	}
	first := map[string]string{} // the value of the first line of each key
	var mx []string
	for line := range strings.SplitSeq(string(body), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if ok && stsExtension(key) {
			if !stsExtValue(value) {
				return STSPolicy{}, "a line that is not printable ASCII"
			}
			continue
		}
		if checkOctets(line) != "" {
			return STSPolicy{}, "a line that is not printable ASCII"
		}
		if !ok {
			return STSPolicy{}, "a line without a colon"
		}
		value = strings.Trim(value, wsp)
		if key == "mx" {
			mx = append(mx, value)
		} else if _, given := first[key]; !given {
			// RFC 8461 section 3.2: of a key that is given twice, other than
			// mx, the first line counts.
			first[key] = value
		}
	}
	return stsPolicyOf(first, mx)
}

// stsExtension reports whether key names an extension field of a policy file
// (RFC 8461 section 3.2): a key of that form that osk does not read. Senders
// ignore such a field, so its line is skipped whole.
func stsExtension(key string) bool {
	switch key {
	case "version", "mode", "max_age", "mx":
		return false
	}
	return len(key) <= 32 && isWord(key, alnum, alnum+"_-.")
}

// stsExtValue reports whether v may stand after the key of an extension
// field: valid UTF-8 (RFC 8461 section 3.2), with no control character other
// than tab and no Unicode line or paragraph separator. A reader may end a
// line, or the text, at one of those, and then read what follows as a key
// that osk skips. The range loop gives U+FFFD for each octet that is not
// valid UTF-8, so invalid UTF-8 is refused with it; so is a written U+FFFD.
func stsExtValue(v string) bool {
	for _, r := range v {
		switch {
		case r == '\t':
		case r < 0x20, r >= 0x7F && r <= 0x9F, r == 0x2028, r == 0x2029, r == 0xFFFD:
			return false
		}
	}
	return true
}

// stsPolicyOf reads the values of a policy file: the first value of each key,
// and every mx value. Unknown keys are left out (RFC 8461 section 3.2).
func stsPolicyOf(first map[string]string, mx []string) (STSPolicy, string) {
	version, hasVersion := first["version"]
	modeText, hasMode := first["mode"]
	ageText, hasAge := first["max_age"]
	mode, modeOK := stsModeOf(modeText)
	maxAge, ageOK := stsMaxAge(ageText)
	switch {
	case !hasVersion:
		return STSPolicy{}, "no version line"
	case version != "STSv1":
		return STSPolicy{}, "the version is not STSv1"
	case !hasMode:
		return STSPolicy{}, "no mode line"
	case !modeOK:
		return STSPolicy{}, "the mode is not enforce, testing or none"
	case !hasAge:
		return STSPolicy{}, "no max_age line"
	case !ageOK:
		return STSPolicy{}, "max_age is not a whole number from 0 to 31557600"
	case mode != STSNone && len(mx) == 0:
		return STSPolicy{}, "no mx line"
	case len(mx) > maxMXLines:
		return STSPolicy{}, "more than 64 mx lines"
	}
	var names []dnswire.Name
	for _, v := range mx {
		n, ok := stsPattern(v)
		if !ok {
			return STSPolicy{}, "an mx line that cannot be read"
		}
		names = append(names, n)
	}
	return STSPolicy{Mode: mode, MaxAge: maxAge, MX: stsPatterns(names)}, ""
}

// stsModeOf reads a mode, in lower case only (RFC 8461 section 3.2).
func stsModeOf(s string) (STSMode, bool) {
	for m, w := range stsModeWords {
		if w == s {
			return m, true
		}
	}
	return 0, false
}

// stsMaxAge reads a max_age: 1 to 10 digits (RFC 8461 section 3.2), at most
// one year. The count of digits counts too: a sender may refuse a value
// padded with zeros.
func stsMaxAge(s string) (uint32, bool) {
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil && len(s) <= 10 && n <= maxSTSAge
}

// stsPattern reads an mx pattern (RFC 8461 section 3.2): an optional "*."
// and a Domain of RFC 5321 section 4.1.2, labels of letters, digits and
// hyphens, then one trailing dot or none. The name is in lower case. Other
// octets are refused, not escaped: a sender would compare the text, not the
// name that the escapes stand for.
func stsPattern(s string) (dnswire.Name, bool) {
	if !isHostName(strings.TrimPrefix(strings.TrimSuffix(s, "."), "*.")) {
		return dnswire.Name{}, false
	}
	n, err := dnswire.ParseName(s)
	return n.Lower(), err == nil
}

// stsPatterns puts patterns in dnswire.Compare order and keeps each once.
func stsPatterns(names []dnswire.Name) []dnswire.Name {
	slices.SortFunc(names, dnswire.Compare)
	return slices.CompactFunc(names, dnswire.Name.Equal)
}

// STSPolicyWeaker gives each way in which the policy now protects mail in
// transit less than the policy was, in words; nil when it protects as
// much. The words are bounded as those of Weaker.
func STSPolicyWeaker(was, now STSPolicy) []string {
	var words []string
	// RFC 8461 section 5: none < testing < enforce.
	if now.Mode < was.Mode {
		if now.Mode == STSTesting {
			words = append(words, "mode testing in place of enforce: senders deliver mail even when the TLS check fails")
		} else {
			words = append(words, "mode none in place of "+stsModeWords[was.Mode]+": senders act as if there were no policy")
		}
	}
	if now.MaxAge < was.MaxAge {
		words = append(words, "max_age "+strconv.FormatUint(uint64(now.MaxAge), 10)+" in place of "+
			strconv.FormatUint(uint64(was.MaxAge), 10)+": senders keep the policy for less time")
	}
	for _, q := range now.MX {
		if !slices.ContainsFunc(was.MX, func(p dnswire.Name) bool { return stsCovers(p, q) }) {
			words = append(words, "mx "+q.String()+" is not allowed by the file")
		}
	}
	return MergeWords(words)
}

// stsCovers reports whether pattern p matches every host that pattern q
// matches. A first label "*" matches exactly one label (RFC 8461 section
// 4.1).
func stsCovers(p, q dnswire.Name) bool {
	return p.Equal(q) || strings.HasPrefix(p.String(), "*.") && q.Parent().Equal(p.Parent())
}
