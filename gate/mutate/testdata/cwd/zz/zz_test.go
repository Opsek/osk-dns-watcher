package zz

import (
	"os"
	"strings"
	"testing"
)

func TestReadsFileNextToPackage(t *testing.T) {
	b, err := os.ReadFile("testdata/in.txt")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != "5" || IsZero(5) || !IsSet(5) || !IsZero(0) || IsSet(0) {
		t.Error("wrong result")
	}
}
