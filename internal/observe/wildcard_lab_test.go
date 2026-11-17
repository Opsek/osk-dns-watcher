//go:build lab

package observe

import (
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// TestWildcardFromLab: the random name under corp.test. does not exist at
// either server, until a wildcard is set; then both answer it with records.
func TestWildcardFromLab(t *testing.T) {
	walkLabStart(t)
	o := walkLabObserver(t, 0)
	key := dngKey(t, "corp.test.", "corp.test.")

	ob := walkRun(t, o, key, time.Minute)
	if !ob.Zone.Equal(walkName(t, "corp.test.")) {
		t.Errorf("Zone = %v, want corp.test.", ob.Zone)
	}
	walkLabWant(t, "no wildcard", walkAnswers(ob.Answers),
		"ns1.corp.test. @11:53 noname corp.test.", "ns2.corp.test. @12:53 noname corp.test.")
	label := dngFirst(ob.Answers[0].Question.Name)
	if !dngInAlphabet(label) {
		t.Errorf("the label %q is not 26 octets of a-z and 2-7", label)
	}
	for _, a := range ob.Answers {
		if q := a.Question; !q.Name.Equal(walkName(t, label+".corp.test.")) || q.Type != dnswire.TypeA {
			t.Errorf("answer of %v asks %v %v, want the same random name, type A", a.Server.Addr, q.Name, q.Type)
		}
	}
	for _, e := range ob.Walk {
		if q := e.Question; !q.Name.Equal(walkName(t, "corp.test.")) || q.Type != dnswire.TypeNS {
			t.Errorf("walk asked %v %v, want corp.test. NS", q.Name, q.Type)
		}
	}

	walkLabctl(t, "set", "both", "*.corp.test.", "300", "A", walkLab(t)+"66")
	ob = walkRun(t, o, key, time.Minute)
	label2 := dngFirst(ob.Answers[0].Question.Name)
	if label2 == label {
		t.Errorf("a second run asked the label %q again", label)
	}
	want := "records " + label2 + ".corp.test. 300 IN A @66"
	walkLabWant(t, "wildcard set", walkAnswers(ob.Answers),
		"ns1.corp.test. @11:53 "+want, "ns2.corp.test. @12:53 "+want)
}
