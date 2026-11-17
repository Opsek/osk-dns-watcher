package zz

type Counter struct{ n int }

func (c *Counter) inc() { c.n++ }

func Pair(a, b *Counter) {
	a.inc()
	b.inc()
}

func Must(fail bool) {
	if fail {
		panic("must")
	}
}
