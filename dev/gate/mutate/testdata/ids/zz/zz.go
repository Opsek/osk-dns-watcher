package zz

var Verbose = false

type Gauge struct{ max int }

func (g Gauge) Full(n int) bool { return n == g.max }

func Pick(x int) (r, s int) {
	if x == 1 {
		r = 1
	}
	if x == 1 {
		s = 1
	}
	return
}
