package zz

type Record struct{ PreviousName, CurrentNameValue string }

func Changed(candidateRecord Record) bool {
	return candidateRecord.PreviousName == candidateRecord.CurrentNameValue
}

func IsZero(x int) bool { return x == 0 }
