package zz

func Countdown(n int) int {
	steps := 0
	for n != 0 {
		n = n - 1
		steps = steps + 1
	}
	return steps
}
