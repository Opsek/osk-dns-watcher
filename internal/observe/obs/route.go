package obs

// NoRoute reports whether a failed because this machine has no route to the
// address of its server. Nothing was sent, so the answer tells nothing of the
// server or of the path to it, and only this machine can cause it.
func NoRoute(a Answer) bool {
	return Match(a.Result,
		func(Records) bool { return false },
		func(NoData) bool { return false },
		func(NoName) bool { return false },
		func(f Failure) bool { return f.Reason == ReasonNoRoute })
}

// Routed splits answers into those that show what the servers hold and the
// no-route failures that it leaves out. On a machine without IPv6, every IPv6
// address of every server gives such a failure, and no check would ever see
// all its servers. So such a failure is left out when another answer is
// usable. When no answer is usable, every answer stays: the check saw
// nothing. Every other failure always stays, whatever its address.
func Routed(answers []Answer) (routed, unrouted []Answer) {
	usable := false
	for _, a := range answers {
		if NoRoute(a) {
			unrouted = append(unrouted, a)
			continue
		}
		routed = append(routed, a)
		usable = usable || Match(a.Result,
			func(Records) bool { return true },
			func(NoData) bool { return true },
			func(NoName) bool { return true },
			func(Failure) bool { return false })
	}
	if !usable {
		return answers, nil
	}
	return routed, unrouted
}
