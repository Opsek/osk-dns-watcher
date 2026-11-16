package deliver

// Clean makes text from DNS safe inside Slack inline code or a code block,
// where Slack shows text as it is. The result holds only octets 0x20-0x7E,
// no backtick, so it cannot end the code or start a line, and no < or >, so
// it cannot form a link or a mention. It has at most max(max, 16) octets.
//
// Each input octet becomes one unit. An octet outside 0x20-0x7E and the
// backtick become \DDD, the escape of DNS presentation format (RFC 1035
// section 5.1); &, < and > become the three entities that Slack decodes. When
// the units do not fit, the longest run of whole units that leaves room for
// " [cut]" is kept, so the cut never splits an escape.
func Clean(s string, max int) string {
	limit := 16
	if max > limit {
		limit = max
	}
	var out []byte
	keep := 0
	for i := 0; i < len(s); i++ {
		out = appendUnit(out, s[i])
		if len(out) <= limit-len(" [cut]") {
			keep = len(out)
		}
		if len(out) > limit {
			return string(out[:keep]) + " [cut]"
		}
	}
	return string(out)
}

func appendUnit(b []byte, c byte) []byte {
	switch {
	case c < 0x20 || c > 0x7e || c == '`':
		return append(b, '\\', '0'+c/100, '0'+c/10%10, '0'+c%10)
	case c == '&':
		return append(b, "&amp;"...)
	case c == '<':
		return append(b, "&lt;"...)
	case c == '>':
		return append(b, "&gt;"...)
	}
	return append(b, c)
}
