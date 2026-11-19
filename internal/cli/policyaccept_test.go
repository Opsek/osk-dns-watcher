package cli

import (
	"strconv"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

const (
	pcaWas  = "mta-sts enforce 604800 mail.corp.test."
	pcaSeen = "mta-sts testing 86400 mail.corp.test. *.evil.test."
)

// pcaFile is the expectations file of corp.test. whose mta-sts line is line,
// on line 2.
func pcaFile(line string) string {
	return "domain corp.test.\n" + line + "\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\ncorp.test. DS none\nwww.corp.test. A 10.53.0.81\n"
}

// pcaOpen stores an open alert of the policy check of corp.test. that read
// the policy texts, one server line each, in place of expected.
func pcaOpen(t *testing.T, w *cliWorld, expected string, texts ...string) int64 {
	t.Helper()
	key, ok := obs.PolicyKey(cliName("corp.test."))
	if !ok {
		t.Fatal("no policy key for corp.test.")
	}
	a := cliAlert(decide.RuleMTASTS, decide.SeverityMedium, key, expected, cliT0, texts...)
	a.Value += "\nweaker a word of the rule"
	var id int64
	cliStore(t, w.state, func(s *store.Store) { id = cliOpen(t, s, cliT0, a)[0].ID })
	return id
}

func TestPcaAcceptEditsTheMTASTSLineOfAPolicyAlert(t *testing.T) {
	file := pcaFile(pcaWas)
	w := cliNewWorld(t, false)
	cliWriteFile(t, w.corp, file)
	id := pcaOpen(t, w, pcaWas, pcaSeen, pcaSeen)
	idText := strconv.FormatInt(id, 10)

	code, out, errOut := cliAccept(w, idText)
	if code != 0 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 0 and none", code, errOut)
	}
	cliSame(t, "accept", out, w.corp+":2", "- "+pcaWas, "+ "+pcaSeen, cliToWrite(w, id, w.corp, pcaWas, pcaSeen))
	if cliRead(t, w.corp) != file {
		t.Error("accept without --write changed the file")
	}

	code, out, errOut = cliAccept(w, "--write", cliChangeCode(id, w.corp, pcaWas, pcaSeen), idText)
	if code != 0 || errOut != "" {
		t.Errorf("--write: exit code %d, errors %q; want 0 and none", code, errOut)
	}
	cliSame(t, "accept --write", out, w.corp+":2", "- "+pcaWas, "+ "+pcaSeen, "written")
	got := cliRead(t, w.corp)
	if want := cliReplaced(file, 2, pcaSeen); got != want {
		t.Errorf("the file after accept --write:\n%s\nwant:\n%s", got, want)
	}
	f, err := expect.Parse([]byte(got))
	if err != nil {
		t.Fatalf("the file after accept is not valid: %v\n%s", err, got)
	}
	if f.Policy == nil || f.Policy.String() != pcaSeen || f.Policy.Line != 2 {
		t.Errorf("the policy of the file after accept: %+v; want %q on line 2", f.Policy, pcaSeen)
	}
}

func TestPcaAcceptRefusesAPolicyAlertThatItCannotApply(t *testing.T) {
	const unreadable = "mta-sts policy cannot be read: no version line"
	for _, c := range []struct {
		name  string
		file  string
		seen  []string
		error string
	}{
		{"a text that does not read", pcaFile(pcaWas), []string{unreadable},
			"the new line is not valid: line 2: mode must be enforce, testing or none; edit the file by hand"},
		{"the file holds the new line already", pcaFile(pcaSeen), []string{pcaSeen},
			"the file changed since this alert: the mta-sts line is now " + pcaSeen},
		{"the line is another one now", pcaFile("mta-sts none 0"), []string{pcaSeen},
			"the file changed since this alert: the mta-sts line is now mta-sts none 0"},
		{"the line is gone", cliCorpFile, []string{pcaSeen}, "the file has no mta-sts line now"},
		{"the servers read different files", pcaFile(pcaWas), []string{pcaSeen, "mta-sts none 0"},
			"the servers disagree: " + pcaSeen + "; mta-sts none 0; edit the file by hand"},
		{"no server gave a text", pcaFile(pcaWas), nil, "no server gave a set for this alert; edit the file by hand"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := cliNewWorld(t, false)
			cliWriteFile(t, w.corp, c.file)
			id := pcaOpen(t, w, pcaWas, c.seen...)
			for _, args := range [][]string{{}, {"--write", cliAnyCode}} {
				code, out, errOut := cliAccept(w, append(args, strconv.FormatInt(id, 10))...)
				if want := "osk-dns-watcher: " + c.error + "\n"; code != 1 || out != "" || errOut != want {
					t.Errorf("accept %q: exit code %d, output %q, errors %q; want 1, nothing and %q", args, code, out, errOut, want)
				}
			}
			if cliRead(t, w.corp) != c.file {
				t.Error("a refused accept changed the file")
			}
		})
	}
}
