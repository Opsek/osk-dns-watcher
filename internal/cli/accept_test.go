package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// cliAcceptCorp has comments, a blank line, columns of blanks and tabs and
// an owner in capitals: accept must keep every octet but those of one line.
const cliAcceptCorp = "# corp.test. as it should be\n" +
	"domain corp.test.\n" +
	"\n" +
	"corp.test.   NS   ns1.corp.test. | ns2.corp.test.\n" +
	"corp.test. DS none\n" +
	"\t# web\n" +
	"WWW.Corp.Test.\tA\t10.53.0.81\n" +
	"corp.test. TXT \"v=spf1 mx -all\"\n" +
	"ftp.corp.test. A 10.53.0.85\n"

// cliAcceptShop does not end in LF.
const cliAcceptShop = "domain shop.test.\nshop.test. NS ns1.dnshost.test. | ns2.dnshost.test."

// cliToWrite is the last line of a dry run of accept for the alert id whose
// change of file replaces old (none: "") by line.
func cliToWrite(w *cliWorld, id int64, file, old, line string) string {
	return "To write this change: osk accept --config " + w.config + " --write " + cliChangeCode(id, file, old, line) + " " + strconv.FormatInt(id, 10)
}

// cliAnyCode is a value of --write for a refusal, which comes before the
// code is compared.
const cliAnyCode = "00000000"

// cliAcceptWorld stores one open alert for each case of the accept tests
// and gives their ids by name.
func cliAcceptWorld(t *testing.T) (*cliWorld, map[string]int64) {
	t.Helper()
	w := cliNewWorld(t, false)
	cliWriteFile(t, w.corp, cliAcceptCorp)
	cliWriteFile(t, w.shop, cliAcceptShop)
	corp, shop := cliName("corp.test."), cliName("shop.test.")
	rec := func(name string, typ dnswire.Type) obs.Key { return cliRecordsKey("corp.test.", name, typ) }
	type c struct {
		name string
		a    alert.Alert
	}
	high, medium := decide.SeverityHigh, decide.SeverityMedium
	cases := []c{
		{"www", cliAlert(decide.RuleRecordSet, high, rec("www.corp.test.", dnswire.TypeA), "10.53.0.81", cliT0, "10.53.0.99", "10.53.0.99")},
		{"ns", cliAlert(decide.RuleNameServers, decide.SeverityCritical, obs.DelegationKey(corp), "ns1.corp.test. | ns2.corp.test.", cliT0,
			"ns1.dnshost.test. | ns2.dnshost.test.")},
		{"mail", cliAlert(decide.RuleNotCovered, medium, rec("mail.corp.test.", dnswire.TypeA), "", cliT0, "10.53.0.82")},
		{"shop-ds", cliAlert(decide.RuleNotCovered, medium, obs.DSKey(shop), "", cliT0, "none")},
		{"ns-covered", cliAlert(decide.RuleNotCovered, medium, obs.DelegationKey(corp), "", cliT0, "ns1.corp.test. | ns2.corp.test.")},
		{"zone", cliAlert(decide.RuleZone, high, rec("sub.corp.test.", dnswire.TypeA), "", cliT0, "sub.corp.test.")},
		{"invalid-file", cliAlert(decide.RuleInvalidFile, medium, cliScopeKey("corp.test."), "", cliT0)},
		{"check-failing", cliAlert(decide.RuleCheckFailing, medium, rec("corp.test.", dnswire.TypeA), "10.53.0.80", cliT0)},
		{"zone-changed", cliAlert(decide.RuleZoneChanged, decide.SeverityLow, cliScopeKey("corp.test."), "", cliT0)},
		{"disagree", cliAlert(decide.RuleRecordSet, high, rec("mail2.corp.test.", dnswire.TypeA), "10.53.0.97", cliT0, "10.53.0.98", "10.53.0.99")},
		{"txt", cliAlert(decide.RuleRecordSet, medium, rec("corp.test.", dnswire.TypeTXT), `"v=spf1 -all"`, cliT0, `"v=spf1 +all"`)},
		{"ftp", cliAlert(decide.RuleRecordSet, high, rec("ftp.corp.test.", dnswire.TypeA), "10.53.0.85", cliT0, "CNAME edge.dnshost.test.")},
		{"resolved", cliAlert(decide.RuleRecordSet, high, rec("old.corp.test.", dnswire.TypeA), "10.53.0.86", cliT0, "10.53.0.87")},
		{"no-lines", cliAlert(decide.RuleRecordSet, high, rec("nolines.corp.test.", dnswire.TypeA), "10.53.0.1", cliT0)},
		{"gone", cliAlert(decide.RuleRecordSet, high, rec("gone.corp.test.", dnswire.TypeA), "10.53.0.2", cliT0, "10.53.0.3")},
		{"other", cliAlert(decide.RuleRecordSet, high, cliRecordsKey("other.test.", "www.other.test.", dnswire.TypeA), "10.0.0.1", cliT0, "10.0.0.2")},
		{"hash", cliAlert(decide.RuleNotCovered, medium, rec("#hash.corp.test.", dnswire.TypeTXT), "", cliT0, `"x"`)},
	}
	ids := map[string]int64{}
	cliStore(t, w.state, func(s *store.Store) {
		for _, x := range cases {
			a := cliOpen(t, s, cliT0, x.a)[0]
			ids[x.name] = a.ID
			if x.name == "resolved" {
				a.Open, a.Resolved = false, cliT0.Add(time.Minute)
				cliApply(t, s, cliT0, cliEvent(alert.EventResolve, a, a.Severity, a.Resolved))
			}
		}
	})
	return w, ids
}

func cliAccept(w *cliWorld, args ...string) (int, string, string) {
	return cliRun(10*time.Second, "accept", append([]string{"--config", w.config}, args...)...)
}

// cliReplaced is text with its line n (from 1) replaced by line.
func cliReplaced(text string, n int, line string) string {
	lines := strings.Split(text, "\n")
	lines[n-1] = line
	return strings.Join(lines, "\n")
}

func cliRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func cliStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func cliEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// cliFinds checks that text is a valid file whose set name/typ has the
// form text form.
func cliFinds(t *testing.T, text, name string, typ dnswire.Type, form string) {
	t.Helper()
	f, err := expect.Parse([]byte(text))
	if err != nil {
		t.Errorf("the file after accept is not valid: %v\n%s", err, text)
		return
	}
	if e, ok := f.Find(cliName(name), typ); !ok || e.FormText() != form {
		t.Errorf("the file after accept has %s %s %q (found %t), want %q", name, typ, e.FormText(), ok, form)
	}
}

func TestAcceptPrintsTheChangeOfOneLineAndWritesNothingWithoutWrite(t *testing.T) {
	w, ids := cliAcceptWorld(t)
	before := cliEntries(t, w.dir)
	corpInfo, shopInfo := cliStat(t, w.corp), cliStat(t, w.shop)
	for _, c := range []struct {
		name string
		want []string
	}{
		{"www", []string{w.corp + ":7", "- WWW.Corp.Test.\tA\t10.53.0.81", "+ www.corp.test. A 10.53.0.99"}},
		{"ns", []string{w.corp + ":4", "- corp.test.   NS   ns1.corp.test. | ns2.corp.test.", "+ corp.test. NS ns1.dnshost.test. | ns2.dnshost.test."}},
		{"mail", []string{w.corp + ":10", "+ mail.corp.test. A 10.53.0.82"}},
		{"shop-ds", []string{w.shop + ":3", "+ shop.test. DS none"}},
		{"hash", []string{w.corp + ":10", `+ \#hash.corp.test. TXT "x"`}},
	} {
		code, out, errOut := cliAccept(w, strconv.FormatInt(ids[c.name], 10))
		if code != 0 || errOut != "" {
			t.Errorf("accept of %s: exit code %d, errors %q; want 0 and none", c.name, code, errOut)
		}
		file, old := c.want[0][:strings.LastIndex(c.want[0], ":")], ""
		if len(c.want) == 3 {
			old = strings.TrimPrefix(c.want[1], "- ")
		}
		toWrite := cliToWrite(w, ids[c.name], file, old, strings.TrimPrefix(c.want[len(c.want)-1], "+ "))
		cliSame(t, "accept of "+c.name, out, append(c.want, toWrite)...)
	}
	if cliRead(t, w.corp) != cliAcceptCorp || cliRead(t, w.shop) != cliAcceptShop {
		t.Error("accept without --write changed a file")
	}
	if !os.SameFile(corpInfo, cliStat(t, w.corp)) || !os.SameFile(shopInfo, cliStat(t, w.shop)) {
		t.Error("accept without --write replaced a file")
	}
	if after := cliEntries(t, w.dir); !slices.Equal(after, before) {
		t.Errorf("the folder of the files holds %q, want %q", after, before)
	}
}

// The new file comes in place of the old by a rename: a hard link to the
// old file keeps the old bytes, the mode stays, and no other file is left.
func TestAcceptWriteReplacesTheLineAtomicallyAndKeepsTheMode(t *testing.T) {
	w, ids := cliAcceptWorld(t)
	if err := os.Chmod(w.corp, 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(w.dir, "corp.link")
	if err := os.Link(w.corp, link); err != nil {
		t.Fatal(err)
	}
	before := cliEntries(t, w.dir)
	old := cliStat(t, w.corp)

	code, out, errOut := cliAccept(w, "--write", cliChangeCode(ids["www"], w.corp, "WWW.Corp.Test.\tA\t10.53.0.81", "www.corp.test. A 10.53.0.99"),
		strconv.FormatInt(ids["www"], 10))
	if code != 0 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 0 and none", code, errOut)
	}
	cliSame(t, "accept --write", out, w.corp+":7", "- WWW.Corp.Test.\tA\t10.53.0.81", "+ www.corp.test. A 10.53.0.99", "written")
	want := cliReplaced(cliAcceptCorp, 7, "www.corp.test. A 10.53.0.99")
	if got := cliRead(t, w.corp); got != want {
		t.Errorf("the file after accept --write:\n%s\nwant:\n%s", got, want)
	}
	cliFinds(t, cliRead(t, w.corp), "www.corp.test.", dnswire.TypeA, "10.53.0.99")
	info := cliStat(t, w.corp)
	if info.Mode().Perm() != 0o640 || os.SameFile(old, info) {
		t.Errorf("the file has mode %04o and is the old file: %t; want 0640 and a new file", info.Mode().Perm(), os.SameFile(old, info))
	}
	if cliRead(t, link) != cliAcceptCorp {
		t.Error("the old file was written in place")
	}
	if after := cliEntries(t, w.dir); !slices.Equal(after, before) {
		t.Errorf("the folder holds %q, want %q", after, before)
	}

	// The alert is still open, but the file no longer holds what it expected.
	code, out, errOut = cliAccept(w, strconv.FormatInt(ids["www"], 10))
	if want := "osk: the file changed since this alert: www.corp.test. A is now 10.53.0.99\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("accept again: exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, want)
	}

	code, out, errOut = cliAccept(w, "--write", cliChangeCode(ids["ns"], w.corp, "corp.test.   NS   ns1.corp.test. | ns2.corp.test.",
		"corp.test. NS ns1.dnshost.test. | ns2.dnshost.test."), strconv.FormatInt(ids["ns"], 10))
	if code != 0 || errOut != "" {
		t.Errorf("accept --write of ns: exit code %d, errors %q; want 0 and none", code, errOut)
	}
	cliSame(t, "accept --write of ns", out, w.corp+":4", "- corp.test.   NS   ns1.corp.test. | ns2.corp.test.",
		"+ corp.test. NS ns1.dnshost.test. | ns2.dnshost.test.", "written")
	if got, want := cliRead(t, w.corp), cliReplaced(want, 4, "corp.test. NS ns1.dnshost.test. | ns2.dnshost.test."); got != want {
		t.Errorf("the file after the second accept --write:\n%s\nwant:\n%s", got, want)
	}
}

func TestAcceptWriteAppendsTheLineOfASetThatIsNotCovered(t *testing.T) {
	w, ids := cliAcceptWorld(t)
	for _, c := range []struct {
		name, file, line, owner string
		typ                     dnswire.Type
		form, text              string
		n                       int
	}{
		{"mail", w.corp, "mail.corp.test. A 10.53.0.82", "mail.corp.test.", dnswire.TypeA, "10.53.0.82", cliAcceptCorp, 10},
		// The file does not end in LF, so one comes first.
		{"shop-ds", w.shop, "shop.test. DS none", "shop.test.", dnswire.TypeDS, "none", cliAcceptShop + "\n", 3},
		{"hash", w.corp, `\#hash.corp.test. TXT "x"`, "#hash.corp.test.", dnswire.TypeTXT, `"x"`, cliAcceptCorp, 10},
	} {
		cliWriteFile(t, w.corp, cliAcceptCorp)
		cliWriteFile(t, w.shop, cliAcceptShop)
		code, out, errOut := cliAccept(w, "--write", cliChangeCode(ids[c.name], c.file, "", c.line), strconv.FormatInt(ids[c.name], 10))
		if code != 0 || errOut != "" {
			t.Errorf("accept --write of %s: exit code %d, errors %q; want 0 and none", c.name, code, errOut)
		}
		cliSame(t, "accept --write of "+c.name, out, c.file+":"+strconv.Itoa(c.n), "+ "+c.line, "written")
		got := cliRead(t, c.file)
		if want := c.text + c.line + "\n"; got != want {
			t.Errorf("the file after accept --write of %s:\n%q\nwant:\n%q", c.name, got, want)
		}
		cliFinds(t, got, c.owner, c.typ, c.form)
	}
}

func TestAcceptJSONGivesTheChange(t *testing.T) {
	w, ids := cliAcceptWorld(t)
	type change struct {
		Type    string `json:"type"`
		File    string `json:"file"`
		Line    int    `json:"line"`
		Old     string `json:"old"`
		New     string `json:"new"`
		Written bool   `json:"written"`
		Code    string `json:"code"`
	}
	code, out, errOut := cliAccept(w, "--json", strconv.FormatInt(ids["www"], 10))
	if code != 0 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 0 and none", code, errOut)
	}
	www := "www.corp.test. A 10.53.0.99"
	old := "WWW.Corp.Test.\tA\t10.53.0.81"
	cliSame(t, "accept --json", out, cliMarshal(t, change{"change", w.corp, 7, old, www, false, cliChangeCode(ids["www"], w.corp, old, www)}))
	if cliRead(t, w.corp) != cliAcceptCorp {
		t.Error("accept --json without --write changed the file")
	}

	mail := "mail.corp.test. A 10.53.0.82"
	code, out, errOut = cliAccept(w, "--write", cliChangeCode(ids["mail"], w.corp, "", mail), "--json", strconv.FormatInt(ids["mail"], 10))
	if code != 0 || errOut != "" {
		t.Errorf("--write: exit code %d, errors %q; want 0 and none", code, errOut)
	}
	cliSame(t, "accept --write --json", out, cliMarshal(t, change{"change", w.corp, 10, "", mail, true, cliChangeCode(ids["mail"], w.corp, "", mail)}))
	if got, want := cliRead(t, w.corp), cliAcceptCorp+"mail.corp.test. A 10.53.0.82\n"; got != want {
		t.Errorf("the file after accept --write --json:\n%s\nwant:\n%s", got, want)
	}
}

// Each refusal is an error with exit 1, also with --write, and no file
// changes.
func TestAcceptRefusesWhatItCannotAcceptAndChangesNothing(t *testing.T) {
	w, ids := cliAcceptWorld(t)
	newFTP := cliReplaced(cliAcceptCorp, 9, "ftp.corp.test. A CNAME edge.dnshost.test.")
	var bad *expect.Error
	if _, err := expect.Parse([]byte(newFTP)); !errors.As(err, &bad) {
		t.Fatalf("the new line of ftp parses: %v", err)
	}
	cannot := "accept cannot change the file for a "
	for _, c := range []struct{ name, want string }{
		{"ns-covered", "the file has a line for corp.test. NS now"},
		{"zone", cannot + "zone alert: add or remove the NS pair of the subzone by hand"},
		{"invalid-file", "accept cannot change the file for an invalid-file alert: fix the file"},
		{"check-failing", cannot + "check-failing alert: nothing to accept: no server answers"},
		{"zone-changed", cannot + "zone-changed alert: nothing to accept: no watched record differs"},
		{"disagree", "the servers disagree: 10.53.0.98; 10.53.0.99; edit the file by hand"},
		{"txt", `the file changed since this alert: corp.test. TXT is now "v=spf1 mx -all"`},
		{"ftp", fmt.Sprintf("the new line is not valid: line %d: %s; edit the file by hand", bad.Problems[0].Line, bad.Problems[0].Text)},
		{"resolved", fmt.Sprintf("alert %d is not open", ids["resolved"])},
		{"no-lines", "no server gave a set for this alert; edit the file by hand"},
		{"gone", "the file changed since this alert: it has no line for gone.corp.test. A"},
		{"other", "other.test. is not a domain of the config"},
	} {
		for _, args := range [][]string{{}, {"--write", cliAnyCode}} {
			code, out, errOut := cliAccept(w, append(args, strconv.FormatInt(ids[c.name], 10))...)
			if want := "osk: " + c.want + "\n"; code != 1 || out != "" || errOut != want {
				t.Errorf("accept %q of %s: exit code %d, output %q, errors %q; want 1, nothing and %q", args, c.name, code, out, errOut, want)
			}
		}
	}
	code, out, errOut := cliAccept(w, "--write", cliAnyCode, "999")
	if want := "osk: store: no alert 999\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("accept of an unknown id: exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, want)
	}
	if cliRead(t, w.corp) != cliAcceptCorp || cliRead(t, w.shop) != cliAcceptShop {
		t.Error("a refused accept changed a file")
	}
}

func TestAcceptPrintsTheProblemsOfAnExpectationsFileThatIsNotValid(t *testing.T) {
	w, ids := cliAcceptWorld(t)
	broken := cliAcceptCorp + "bad.corp.test A 10.53.0.1\nworse.corp.test. A 300.1.1.1\n"
	cliWriteFile(t, w.corp, broken)
	var bad *expect.Error
	if _, err := expect.Parse([]byte(broken)); !errors.As(err, &bad) || len(bad.Problems) != 2 {
		t.Fatalf("the broken file: %v, want two problems", err)
	}
	var want []string
	for _, p := range bad.Problems {
		want = append(want, fmt.Sprintf("osk: %s:%d: %s", w.corp, p.Line, p.Text))
	}
	code, out, errOut := cliAccept(w, "--write", cliAnyCode, strconv.FormatInt(ids["www"], 10))
	if code != 1 || out != "" || errOut != cliLines(want...) {
		t.Errorf("exit code %d, output %q, errors:\n%s\nwant 1, nothing and:\n%s", code, out, errOut, cliLines(want...))
	}
	if cliRead(t, w.corp) != broken {
		t.Error("accept changed the broken file")
	}
}

// An expectations file that is not a regular file is refused before it is
// opened: a FIFO would hold the open until a writer came.
func TestAcceptRefusesAnExpectationsFileThatIsNotRegular(t *testing.T) {
	w, ids := cliAcceptWorld(t)
	if err := os.Remove(w.corp); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(w.corp, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f, err := os.OpenFile(w.corp, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	type outcome struct {
		code        int
		out, errOut string
	}
	done := make(chan outcome, 1)
	go func() {
		code, out, errOut := cliAccept(w, "--write", cliAnyCode, strconv.FormatInt(ids["www"], 10))
		done <- outcome{code, out, errOut}
	}()
	select {
	case o := <-done:
		if want := "osk: " + w.corp + ": is not a regular file\n"; o.code != 1 || o.out != "" || o.errOut != want {
			t.Errorf("exit code %d, output %q, errors %q; want 1, nothing and %q", o.code, o.out, o.errOut, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("accept did not return within 2s")
	}
}

// A case of the property: an alert of one set with one text, and a file
// that holds that set (record-set) or not (not-covered).
type cliAcceptCase struct {
	owner string // lower case
	typ   dnswire.Type
	text  string
	file  string
	a     alert.Alert
}

func cliPick[T any](r *rand.Rand, list ...T) T { return list[r.IntN(len(list))] }

// cliData gives the data of one record of each type of cliTypes.
var cliData = map[dnswire.Type]func(r *rand.Rand) string{
	dnswire.TypeA: func(r *rand.Rand) string {
		return fmt.Sprintf("10.%d.%d.%d", r.IntN(256), r.IntN(256), r.IntN(256))
	},
	dnswire.TypeAAAA:  func(r *rand.Rand) string { return fmt.Sprintf("fd53::%x", r.IntN(65536)) },
	dnswire.TypeTXT:   func(r *rand.Rand) string { return fmt.Sprintf(`"w%d w%d"`, r.IntN(100), r.IntN(100)) },
	dnswire.TypeMX:    func(r *rand.Rand) string { return fmt.Sprintf("%d mail%d.corp.test.", r.IntN(50), r.IntN(100)) },
	dnswire.TypeCNAME: func(r *rand.Rand) string { return fmt.Sprintf("edge%d.dnshost.test.", r.IntN(100)) },
}

var cliTypes = []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeTXT, dnswire.TypeMX, dnswire.TypeCNAME}

func cliSet(r *rand.Rand, typ dnswire.Type) string {
	n := 1 + r.IntN(3)
	if typ == dnswire.TypeCNAME {
		n = 1
	}
	var data []string
	for range n {
		data = append(data, cliData[typ](r))
	}
	return strings.Join(data, " | ")
}

// cliCase writes names in any case, fields apart by any blanks, comments
// with blanks before them, blank lines, and sometimes no LF at the end.
func cliCase(r *rand.Rand, i int) cliAcceptCase {
	c := cliAcceptCase{owner: fmt.Sprintf("h%d.corp.test.", i)}
	c.typ = cliPick(r, cliTypes...)
	c.text = cliSet(r, c.typ)
	sep := func() string { return cliPick(r, " ", "  ", "\t", " \t ") }
	mixed := func(s string) string {
		b := []byte(s)
		for j := range b {
			if r.IntN(2) == 0 && b[j] >= 'a' && b[j] <= 'z' {
				b[j] -= 'a' - 'A'
			}
		}
		return string(b)
	}
	filler := func() string {
		return cliPick(r, "", " ", "\t ", cliPick(r, "", " ", "\t")+fmt.Sprintf("# note %d | x", r.IntN(100)))
	}
	var head []string
	for range r.IntN(3) {
		head = append(head, filler())
	}
	head = append(head, "domain"+sep()+"corp.test.")
	var body []string
	for j := range r.IntN(5) {
		owner := mixed(fmt.Sprintf("o%d.corp.test.", j))
		body = append(body, cliPick(r, owner+sep()+"A"+sep()+fmt.Sprintf("10.53.%d.1", j), owner+sep()+"TXT"+sep()+`"a b"`))
	}
	for range r.IntN(4) {
		body = append(body, filler())
	}
	covered := r.IntN(5) < 3
	expected := ""
	if covered {
		expected = cliSet(r, c.typ)
		body = append(body, mixed(c.owner)+sep()+c.typ.String()+sep()+expected)
	}
	r.Shuffle(len(body), func(a, b int) { body[a], body[b] = body[b], body[a] })
	c.file = strings.Join(append(head, body...), "\n")
	if r.IntN(5) > 0 {
		c.file += "\n"
	}
	texts := make([]string, 1+r.IntN(3))
	for j := range texts {
		texts[j] = c.text
	}
	rule := decide.RuleNotCovered
	if covered {
		rule = decide.RuleRecordSet
		f, err := expect.Parse([]byte(c.file))
		if err != nil {
			panic(fmt.Sprintf("case %d: the file is not valid: %v\n%s", i, err, c.file))
		}
		e, _ := f.Find(cliName(c.owner), c.typ)
		expected = e.FormText()
	}
	c.a = cliAlert(rule, decide.SeverityHigh, cliRecordsKey("corp.test.", c.owner, c.typ), expected, cliT0, texts...)
	return c
}

// For random files and alerts of one set with one text, accept --write
// changes only the line of the set, or appends one line; the new file is
// valid and expects the canonical form of the text.
func TestAcceptProperty(t *testing.T) {
	const seed, n = 20261115, 1000
	r := rand.New(rand.NewPCG(seed, seed))
	w := cliNewWorld(t, false)
	cases := make([]cliAcceptCase, n)
	writes := make([]store.Write, n)
	for i := range cases {
		cases[i] = cliCase(r, i)
		writes[i] = cliEvent(alert.EventOpen, cases[i].a, decide.SeverityHigh, cliT0)
	}
	ids := make([]int64, n)
	cliStore(t, w.state, func(s *store.Store) {
		cliApply(t, s, cliT0, writes...)
		for i, c := range cases {
			ids[i] = cliStored(t, s, c.a).ID
		}
	})
	failures := 0
	for i, c := range cases {
		cliWriteFile(t, w.corp, c.file)
		line := c.owner + " " + c.typ.String() + " " + c.text
		old := ""
		if f, err := expect.Parse([]byte(c.file)); err == nil && c.a.Rule == decide.RuleRecordSet {
			e, _ := f.Find(cliName(c.owner), c.typ)
			old = strings.Split(c.file, "\n")[e.Line-1]
		}
		code, out, errOut := cliAccept(w, "--write", cliChangeCode(ids[i], w.corp, old, line), strconv.FormatInt(ids[i], 10))
		got := cliRead(t, w.corp)
		var want, wantOut string
		if c.a.Rule == decide.RuleRecordSet {
			f, err := expect.Parse([]byte(c.file))
			if err != nil {
				t.Fatal(err)
			}
			e, _ := f.Find(cliName(c.owner), c.typ)
			want = cliReplaced(c.file, e.Line, line)
			wantOut = cliLines(w.corp+":"+strconv.Itoa(e.Line), "- "+strings.Split(c.file, "\n")[e.Line-1], "+ "+line, "written")
		} else {
			want = c.file
			if !strings.HasSuffix(want, "\n") {
				want += "\n"
			}
			want += line + "\n"
			wantOut = cliLines(w.corp+":"+strconv.Itoa(strings.Count(want, "\n")), "+ "+line, "written")
		}
		canon, err := expect.Parse([]byte("domain corp.test.\n" + line + "\n"))
		if err != nil {
			t.Fatalf("seed %d, case %d: the line %q is not valid: %v", seed, i, line, err)
		}
		form, _ := canon.Find(cliName(c.owner), c.typ)
		var found string
		if f, err := expect.Parse([]byte(got)); err == nil {
			e, _ := f.Find(cliName(c.owner), c.typ)
			found = e.FormText()
		}
		if code != 0 || errOut != "" || out != wantOut || got != want || found != form.FormText() {
			t.Errorf("seed %d, case %d (%s): exit code %d, errors %q, output:\n%s\nwant 0, none and:\n%s\nthe file was:\n%q\nis:\n%q\nwant:\n%q\nexpects %q, want %q",
				seed, i, c.a.Rule, code, errOut, out, wantOut, c.file, got, want, found, form.FormText())
			if failures++; failures == 5 {
				t.Fatal("five cases failed")
			}
		}
	}
}

// accept --write writes only the change that the operator saw: the dry run
// ends with the command that writes it, whose code is that of its new line,
// and an alert that changed since then gives another code, so nothing is
// written.
func TestAcceptWritesOnlyTheChangeThatTheDryRunPrinted(t *testing.T) {
	w, ids := cliAcceptWorld(t)
	id := strconv.FormatInt(ids["www"], 10)
	const old = "WWW.Corp.Test.\tA\t10.53.0.81"
	seen := cliChangeCode(ids["www"], w.corp, old, "www.corp.test. A 10.53.0.99")
	code, out, errOut := cliAccept(w, id)
	if want := "To write this change: osk accept --config " + w.config + " --write " + seen + " " + id; code != 0 || errOut != "" ||
		!strings.HasSuffix(out, "\n"+want+"\n") {
		t.Fatalf("accept %s: exit code %d, output:\n%s\nerrors %q; want 0, the change and the line %q", id, code, out, errOut, want)
	}

	// The servers now show another set, and the alert says so.
	cliStore(t, w.state, func(s *store.Store) {
		a := cliStored(t, s, alert.Alert{Rule: decide.RuleRecordSet, Check: cliRecordsKey("corp.test.", "www.corp.test.", dnswire.TypeA)})
		for i := range a.Lines {
			a.Lines[i].Text = "10.53.0.77"
		}
		cliApply(t, s, cliT0.Add(time.Minute), cliEvent(alert.EventUpdate, a, a.Severity, cliT0.Add(time.Minute)))
	})
	code, out, errOut = cliAccept(w, "--write", seen, id)
	if want := "osk: the alert changed since you looked; run osk accept " + id + " again\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("accept --write with the code of the old set: exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, want)
	}
	if cliRead(t, w.corp) != cliAcceptCorp {
		t.Fatal("accept --write with the code of the old set changed the file")
	}

	code, out, errOut = cliAccept(w, "--write", cliChangeCode(ids["www"], w.corp, old, "www.corp.test. A 10.53.0.77"), id)
	cliSame(t, "accept --write with the code of the new set", out, w.corp+":7", "- WWW.Corp.Test.\tA\t10.53.0.81", "+ www.corp.test. A 10.53.0.77", "written")
	if code != 0 || errOut != "" || cliRead(t, w.corp) != cliReplaced(cliAcceptCorp, 7, "www.corp.test. A 10.53.0.77") {
		t.Errorf("exit code %d, errors %q, file:\n%s\nwant 0, none and line 7 written", code, errOut, cliRead(t, w.corp))
	}

	// --write takes the code; without it the use is wrong.
	if code, out, errOut := cliAccept(w, id, "--write"); code != 2 || out != "" || !strings.HasPrefix(errOut, "osk accept: ") {
		t.Errorf("accept %s --write: exit code %d, output %q, errors %q; want 2, nothing and the wrong use", id, code, out, errOut)
	}
	if code, out, errOut := cliAccept(w, "--write"); code != 2 || out != "" || !strings.HasPrefix(errOut, "osk accept: ") {
		t.Errorf("accept --write: exit code %d, output %q, errors %q; want 2, nothing and the wrong use", code, out, errOut)
	}
}

// accept --write through a symbolic link changes the file that the link
// names, in that file's own folder; the link stays a link.
func TestAcceptWriteKeepsASymbolicLink(t *testing.T) {
	w, ids := cliAcceptWorld(t)
	target := filepath.Join(t.TempDir(), "corp.test.expect")
	cliWriteFile(t, target, cliAcceptCorp)
	if err := errors.Join(os.Remove(w.corp), os.Symlink(target, w.corp)); err != nil {
		t.Fatal(err)
	}
	line := "www.corp.test. A 10.53.0.99"
	code, out, errOut := cliAccept(w, "--write", cliChangeCode(ids["www"], w.corp, "WWW.Corp.Test.\tA\t10.53.0.81", line), strconv.FormatInt(ids["www"], 10))
	if code != 0 || errOut != "" || !strings.HasSuffix(out, "\nwritten\n") {
		t.Fatalf("accept --write: exit code %d, output %q, errors %q; want 0, the change and written", code, out, errOut)
	}
	if info, err := os.Lstat(w.corp); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("after accept --write the link is %v (%v); want a symbolic link", info, err)
	}
	if got, want := cliRead(t, target), cliReplaced(cliAcceptCorp, 7, line); got != want {
		t.Errorf("the file that the link names:\n%s\nwant:\n%s", got, want)
	}
	if entries := cliEntries(t, filepath.Dir(target)); !slices.Equal(entries, []string{"corp.test.expect"}) {
		t.Errorf("the folder of the file holds %q, want only the file", entries)
	}
}

// cliChangeCode is the code that accept prints for the change of alert id
// in file: the first 32 hex digits of the SHA-256 of the id, the file, the
// old line (none for an appended line), "--" and the new line, each followed
// by LF.
func cliChangeCode(id int64, file, old, line string) string {
	lines := []string{strconv.FormatInt(id, 10), file}
	if old != "" {
		lines = append(lines, old)
	}
	lines = append(lines, "--", line)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n") + "\n"))
	return hex.EncodeToString(sum[:])[:32]
}

// The code of a change covers the alert, the file, the line it removes and
// the line it writes, with 128 bits. Two new lines whose SHA-256 share the
// first 8 hex digits, found by trying sets that a server can give, get
// different codes; a code of 8 digits, and a change of the file's line since
// the dry run, are refused.
func TestAcceptCodeCoversTheWholeChange(t *testing.T) {
	const seen = "www.corp.test. A 192.0.2.66"
	const forged = "www.corp.test. A 192.0.2.77 | 201.142.3.60 | 223.0.0.5"
	short := func(line string) string {
		sum := sha256.Sum256([]byte(line))
		return hex.EncodeToString(sum[:])[:8]
	}
	if short(seen) != short(forged) {
		t.Fatalf("the fixed case lost its point: %s and %s differ", short(seen), short(forged))
	}
	w, ids := cliAcceptWorld(t)
	id := strconv.FormatInt(ids["www"], 10)
	const old = "WWW.Corp.Test.\tA\t10.53.0.81"
	show := func(text string, at time.Time) string {
		cliStore(t, w.state, func(s *store.Store) {
			a := cliStored(t, s, alert.Alert{Rule: decide.RuleRecordSet, Check: cliRecordsKey("corp.test.", "www.corp.test.", dnswire.TypeA)})
			for i := range a.Lines {
				a.Lines[i].Text = text
			}
			cliApply(t, s, at, cliEvent(alert.EventUpdate, a, a.Severity, at))
		})
		code, out, errOut := cliAccept(w, id)
		if code != 0 || errOut != "" {
			t.Fatalf("accept %s: exit code %d, errors %q", id, code, errOut)
		}
		return out
	}
	seenCode, forgedCode := cliChangeCode(ids["www"], w.corp, old, seen), cliChangeCode(ids["www"], w.corp, old, forged)
	if seenCode == forgedCode {
		t.Fatal("the two lines have one code")
	}
	if out := show("192.0.2.66", cliT0.Add(time.Minute)); !strings.HasSuffix(out, " --write "+seenCode+" "+id+"\n") {
		t.Errorf("the dry run of %s gave:\n%s\nwant the code %s", seen, out, seenCode)
	}
	if out := show("192.0.2.77 | 201.142.3.60 | 223.0.0.5", cliT0.Add(2*time.Minute)); !strings.HasSuffix(out, " --write "+forgedCode+" "+id+"\n") {
		t.Errorf("the dry run of %s gave:\n%s\nwant the code %s", forged, out, forgedCode)
	}
	refused := "osk: the alert changed since you looked; run osk accept " + id + " again\n"
	for _, c := range []string{seenCode, short(seen)} {
		if code, out, errOut := cliAccept(w, "--write", c, id); code != 1 || out != "" || errOut != refused {
			t.Errorf("accept --write %s: exit code %d, output %q, errors %q; want 1, nothing and %q", c, code, out, errOut, refused)
		}
	}
	// The line keeps its set but not its octets, so the change is not the one
	// the dry run printed.
	respaced := cliReplaced(cliAcceptCorp, 7, "www.corp.test.  A  10.53.0.81")
	cliWriteFile(t, w.corp, respaced)
	if code, out, errOut := cliAccept(w, "--write", forgedCode, id); code != 1 || out != "" || errOut != refused {
		t.Errorf("accept --write after the line changed: exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, refused)
	}
	if cliRead(t, w.corp) != respaced {
		t.Error("a refused accept --write changed the file")
	}
}

const cliDSData = "11111 13 2 ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"

// The ds key names the DS line, so accept edits that line: the line that
// holds the records becomes none when the servers show none, and the other
// way round.
func TestAcceptEditsTheDSLineOfADSAlert(t *testing.T) {
	for _, c := range []struct {
		name, file, expected, seen string
		old, line                  string
	}{
		{"records to none", "domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\ncorp.test. DS " + cliDSData + "\nwww.corp.test. A 10.53.0.81\n",
			cliDSData, "none", "corp.test. DS " + cliDSData, "corp.test. DS none"},
		{"none to records", cliCorpFile, "none", cliDSData, "corp.test. DS none", "corp.test. DS " + cliDSData},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := cliNewWorld(t, false)
			cliWriteFile(t, w.corp, c.file)
			var id int64
			cliStore(t, w.state, func(s *store.Store) {
				id = cliOpen(t, s, cliT0, cliAlert(decide.RuleDS, decide.SeverityHigh, obs.DSKey(cliName("corp.test.")), c.expected, cliT0, c.seen))[0].ID
			})
			code, out, errOut := cliAccept(w, strconv.FormatInt(id, 10))
			if code != 0 || errOut != "" {
				t.Errorf("exit code %d, errors %q; want 0 and none", code, errOut)
			}
			cliSame(t, "accept of a ds alert", out, w.corp+":3", "- "+c.old, "+ "+c.line, cliToWrite(w, id, w.corp, c.old, c.line))
			if cliRead(t, w.corp) != c.file {
				t.Error("accept without --write changed the file")
			}

			code, out, errOut = cliAccept(w, "--write", cliChangeCode(id, w.corp, c.old, c.line), strconv.FormatInt(id, 10))
			if code != 0 || errOut != "" {
				t.Errorf("accept --write: exit code %d, errors %q; want 0 and none", code, errOut)
			}
			cliSame(t, "accept --write of a ds alert", out, w.corp+":3", "- "+c.old, "+ "+c.line, "written")
			if got, want := cliRead(t, w.corp), cliReplaced(c.file, 3, c.line); got != want {
				t.Errorf("the file after accept --write:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

// A glue alert has the key of the delegation but its lines are those of the
// hosts, and a gone alert has nothing to accept: both are refused, with and
// without --write, and the file stays.
func TestAcceptRefusesGlueAndGoneAlerts(t *testing.T) {
	w := cliNewWorld(t, false)
	corp := obs.DelegationKey(cliName("corp.test."))
	var glue, gone int64
	cliStore(t, w.state, func(s *store.Store) {
		glue = cliOpen(t, s, cliT0, cliAlert(decide.RuleGlue, decide.SeverityCritical, corp, "ns2.corp.test. A 10.53.0.12", cliT0, "ns2.corp.test. A 10.53.0.11"))[0].ID
		gone = cliOpen(t, s, cliT0, cliAlert(decide.RuleGone, decide.SeverityCritical, corp, "", cliT0, "no such name"))[0].ID
	})
	for _, c := range []struct {
		name string
		id   int64
		want string
	}{
		{"glue", glue, "osk: accept cannot change the file for a glue alert: edit the address line of each nameserver host that differs\n"},
		{"gone", gone, "osk: accept cannot change the file for a gone alert: nothing to accept: the domain must exist at the parent zone\n"},
	} {
		for _, args := range [][]string{{}, {"--write", cliAnyCode}} {
			code, out, errOut := cliAccept(w, append(args, strconv.FormatInt(c.id, 10))...)
			if code != 1 || out != "" || errOut != c.want {
				t.Errorf("accept %q of %s: exit code %d, output %q, errors %q; want 1, nothing and %q", args, c.name, code, out, errOut, c.want)
			}
		}
	}
	if cliRead(t, w.corp) != cliCorpFile {
		t.Error("a refused accept changed the file")
	}
}

// The rules of the probes, the wildcard check and the series of answers
// name no line that accept could write: each is refused, with and without
// --write, and the file stays.
func TestAcceptRefusesTheDanglingRules(t *testing.T) {
	w := cliNewWorld(t, false)
	rec := func(name string, typ dnswire.Type) obs.Key { return cliRecordsKey("corp.test.", name, typ) }
	cases := []struct {
		rule     decide.Rule
		sev      decide.Severity
		key      obs.Key
		expected string
		text     string
		want     string
	}{
		{decide.RuleDisagree, decide.SeverityMedium, rec("www.corp.test.", dnswire.TypeA), "in 10.53.0.0/24", "10.53.0.81",
			"osk: accept cannot change the file for a disagree alert: nothing to accept: the servers give different sets; find the server that is wrong\n"},
		{decide.RuleAliasTarget, decide.SeverityHigh, rec("edge.dnshost.test.", dnswire.TypeA), "cdn.corp.test. CNAME edge.dnshost.test.", "no such name",
			"osk: accept cannot change the file for an alias-target alert: nothing to accept: the name does not exist; change or remove the line that points at it\n"},
		{decide.RuleNameServerHost, decide.SeverityCritical, rec("ns3.dnshost.test.", dnswire.TypeA), "corp.test. NS ns3.dnshost.test.", "no such name",
			"osk: accept cannot change the file for a nameserver-host alert: nothing to accept: the nameserver does not exist; change the delegation and the NS line\n"},
		{decide.RuleMailTarget, decide.SeverityHigh, rec("mx.dnshost.test.", dnswire.TypeA), "corp.test. MX mx.dnshost.test.", "no such name",
			"osk: accept cannot change the file for a mail-target alert: nothing to accept: the name does not exist; change or remove the line that points at it\n"},
		{decide.RuleChallenge, decide.SeverityHigh, rec("_acme-challenge.corp.test.", dnswire.TypeTXT), "none", `"t0ken1"`,
			"osk: accept cannot change the file for a challenge alert: a challenge record changes with each certificate request; remove the line by hand if you use DNS challenges\n"},
		{decide.RuleWildcard, decide.SeverityMedium, rec("corp.test.", dnswire.TypeA), "none", "10.53.0.66",
			"osk: accept cannot change the file for a wildcard alert: write the lines of the wildcard by hand\n"},
	}
	ids := make([]int64, len(cases))
	cliStore(t, w.state, func(s *store.Store) {
		for i, c := range cases {
			ids[i] = cliOpen(t, s, cliT0, cliAlert(c.rule, c.sev, c.key, c.expected, cliT0, c.text))[0].ID
		}
	})
	for i, c := range cases {
		for _, args := range [][]string{{}, {"--write", cliAnyCode}} {
			code, out, errOut := cliAccept(w, append(args, strconv.FormatInt(ids[i], 10))...)
			if code != 1 || out != "" || errOut != c.want {
				t.Errorf("accept %q of %s: exit code %d, output %q, errors %q; want 1, nothing and %q", args, c.rule, code, out, errOut, c.want)
			}
		}
	}
	if cliRead(t, w.corp) != cliCorpFile {
		t.Error("a refused accept changed the file")
	}
}
