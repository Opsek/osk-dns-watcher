//go:build lab

package installtest

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// These tests drive deploy/start.sh and release/verify.sh with throwaway
// keys, temporary git repositories and a stand-in docker that only logs its
// commands, so they need git, ssh-keygen and a shell, but no lab and no
// Docker. The quickstart phase runs them in its clean container, the only
// container of the gate with git and OpenSSH. Their git config asks for
// OpenPGP signing of every commit and tag, to show that a user's config
// neither helps nor harms the checks.

// sgDocker is the stand-in docker. It logs each command, with the folder of
// the Compose file that start.sh names as <export>, and at a build it writes
// the list of the files of that folder, the build context, to $LOG.context.
const sgDocker = `#!/bin/sh
tree= prev=
for a; do
	[ "$prev" != -f ] || [ -n "$tree" ] || tree=${a%/deploy/compose.yaml}
	prev=$a
done
line="docker $*"
if [ -n "$tree" ]; then
	line=$(printf '%s\n' "$line" | sed "s|$tree/|<export>/|g")
	case " $* " in
	*" build "*) (cd "$tree" && find . -type f | sed 's|^\./||' | LC_ALL=C sort) >"$LOG.context" ;;
	esac
fi
echo "$line OSK_VERSION=${OSK_VERSION-}" >>"$LOG"
`

// sgFix is an owner's repository work, its remote remote.git and a user's
// copy of it, at the release v0.1.0 that the key owner signed.
type sgFix struct {
	dir  string
	env  []string
	work string
	copy string
	log  string
}

// sgSrc is the tree under test.
func sgSrc(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(filepath.Dir(wd))
}

// sgCopyFile copies a file of the tree under test into a tree of the test.
func sgCopyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

// sgEnviron is the environment of every command of a test: its own home,
// git config and stand-in docker.
func sgEnviron(dir string) []string {
	return append(os.Environ(),
		"HOME="+dir+"/home",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+dir+"/gitconfig",
		"PATH="+dir+"/bin:"+os.Getenv("PATH"),
		"LOG="+dir+"/docker.log",
		"OSK_UNVERIFIED=")
}

// sgKeys makes the throwaway keys owner and other in dir, and an
// allowed-signers file for each.
func sgKeys(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{"owner", "other"} {
		path := filepath.Join(dir, name)
		qsMust(t, qsRun(qsBound, dir, sgEnviron(dir), "", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", path))
		pub, err := os.ReadFile(path + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		qsWrite(t, path+".allowed", `osk-dns-watcher-release namespaces="file,git" `+strings.TrimSpace(string(pub))+"\n")
	}
}

func sgSetup(t *testing.T) *sgFix {
	t.Helper()
	dir := t.TempDir()
	f := &sgFix{dir: dir, env: sgEnviron(dir), work: dir + "/work", copy: dir + "/copy", log: dir + "/docker.log"}
	for _, d := range []string{dir + "/home", dir + "/bin", f.work} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A user who asks for OpenPGP signatures; no maintenance in the background,
	// which would hold the output of a command open after its end.
	qsWrite(t, dir+"/gitconfig", "[gpg]\n\tformat = openpgp\n[commit]\n\tgpgsign = true\n[tag]\n\tgpgSign = true\n"+
		"[maintenance]\n\tauto = false\n[gc]\n\tauto = 0\n")
	if err := os.WriteFile(dir+"/bin/docker", []byte(sgDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	sgKeys(t, dir)
	src := sgSrc(t)
	for _, name := range []string{"deploy/start.sh", "build/version.sh", "release/verify-tag.sh", "release/export.sh", "release/commit.sh"} {
		sgCopyFile(t, src+"/"+name, f.work+"/"+name)
	}
	sgCopyFile(t, dir+"/owner.allowed", f.work+"/release/allowed_signers")
	f.git(t, f.work, "init", "-q", "-b", "main")
	f.git(t, f.work, "add", "-A")
	f.git(t, f.work, "commit", "-qm", "one")
	f.tag(t, "owner", "v0.1.0")
	f.git(t, dir, "clone", "-q", "--bare", f.work, dir+"/remote.git")
	f.git(t, f.work, "remote", "add", "origin", dir+"/remote.git")
	f.git(t, dir, "clone", "-q", dir+"/remote.git", f.copy)
	return f
}

// git runs git in dir, with no signature unless tag asks for one.
func (f *sgFix) git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return qsMust(t, qsRun(qsBound, dir, f.env, "", "git", append([]string{
		"-c", "user.name=osk-dns-watcher test", "-c", "user.email=test@lab.test",
		"-c", "commit.gpgsign=false", "-c", "tag.gpgSign=false"}, args...)...))
}

// tag makes in work a tag signed by the key of that name.
func (f *sgFix) tag(t *testing.T, key, name string) {
	t.Helper()
	f.git(t, f.work, "-c", "gpg.format=ssh", "-c", "user.signingkey="+f.dir+"/"+key, "tag", "-s", "-m", "osk-dns-watcher "+strings.TrimPrefix(name, "v"), name)
}

// release commits a new file in work, and the change if there is one, tags
// it with a tag signed by the key, and pushes both.
func (f *sgFix) release(t *testing.T, key, name string, change func()) {
	t.Helper()
	f.commit(t, name, change)
	f.tag(t, key, name)
	f.git(t, f.work, "push", "-q", "origin", "main", name)
}

func (f *sgFix) commit(t *testing.T, name string, change func()) {
	t.Helper()
	qsWrite(t, f.work+"/"+name, name+"\n")
	if change != nil {
		change()
	}
	f.git(t, f.work, "add", "-A")
	f.git(t, f.work, "commit", "-qm", name)
}

// start runs start.sh of the copy with the arguments, and the variables of
// env in addition.
func (f *sgFix) start(t *testing.T, env []string, args ...string) qsResult {
	t.Helper()
	if err := os.WriteFile(f.log, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return qsRun(qsBound, f.copy+"/deploy", append(f.env, env...), "", "sh", append([]string{"start.sh"}, args...)...)
}

func (f *sgFix) calls(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (f *sgFix) head(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(f.git(t, f.copy, "rev-parse", "HEAD"))
}

func (f *sgFix) commitOf(t *testing.T, tag string) string {
	t.Helper()
	return strings.TrimSpace(f.git(t, f.work, "rev-parse", tag+"^{commit}"))
}

// sgBuilt is what the stand-in docker logs for a whole run of start.sh.
func sgBuilt(version string) string {
	b := "docker compose version OSK_VERSION=" + version + "\n"
	for _, c := range []string{"--profile setup build", "run --rm init", "up --detach --wait",
		"exec -T watcher osk-dns-watcher test-alert --config /data/config.json"} {
		b += "docker compose -f <export>/deploy/compose.yaml " + c + " OSK_VERSION=" + version + "\n"
	}
	return b
}

// refused runs start.sh update and requires that it stops with text, runs
// no docker command and leaves the copy where it was.
func (f *sgFix) refused(t *testing.T, text string) {
	t.Helper()
	before := f.head(t)
	r := f.start(t, nil, "update")
	if r.code != 1 || !strings.Contains(r.stderr, text) {
		t.Errorf("start.sh update: exit %d; want 1 and %q:\n%s", r.code, text, r)
	}
	if got := f.head(t); got != before {
		t.Errorf("the copy moved from %s to %s", before, got)
	}
	if got := f.calls(t); got != "" {
		t.Errorf("start.sh ran docker:\n%s", got)
	}
}

func TestStartInstallsSignedRelease(t *testing.T) {
	f := sgSetup(t)
	r := f.start(t, nil)
	if r.code != 0 {
		t.Fatal(r)
	}
	if got := f.calls(t); got != sgBuilt("0.1.0") {
		t.Errorf("docker got:\n%s\nwant:\n%s", got, sgBuilt("0.1.0"))
	}
}

func TestStartRefusesCopyNotAtRelease(t *testing.T) {
	f := sgSetup(t)
	f.commit(t, "two", nil)
	f.git(t, f.work, "push", "-q", "origin", "main")
	f.git(t, f.copy, "pull", "-q", "--ff-only")
	r := f.start(t, nil)
	if r.code != 1 || !strings.Contains(r.stderr, "This copy is not at a signed release. Check out the newest signed release here, 0.1.0, with: git checkout "+f.commitOf(t, "v0.1.0")+"\n") {
		t.Errorf("start.sh: exit %d; want 1 and the tag to check out:\n%s", r.code, r)
	}
	if got := f.calls(t); got != "" {
		t.Errorf("start.sh ran docker:\n%s", got)
	}

	t.Run("OSK_UNVERIFIED=1 builds the copy as it is", func(t *testing.T) {
		r := f.start(t, []string{"OSK_UNVERIFIED=1"})
		if r.code != 0 || !strings.HasPrefix(r.stdout, "OSK_UNVERIFIED=1: the signature of this copy is not checked") {
			t.Fatalf("start.sh with OSK_UNVERIFIED=1: exit %d; want 0 and its line first:\n%s", r.code, r)
		}
		if got := f.calls(t); got != sgBuilt("0.0.0-dev") {
			t.Errorf("docker got:\n%s\nwant:\n%s", got, sgBuilt("0.0.0-dev"))
		}
	})
}

func TestStartRefusesCopyWithoutTags(t *testing.T) {
	f := sgSetup(t)
	f.git(t, f.copy, "tag", "-d", "v0.1.0")
	for _, args := range [][]string{nil, {"update"}} {
		r := f.start(t, nil, args...)
		if r.code != 1 || !strings.Contains(r.stderr, "no such release is here. Fetch the tags with: git fetch --tags") {
			t.Errorf("start.sh %v: exit %d; want 1 and the advice to fetch the tags:\n%s", args, r.code, r)
		}
	}
}

func TestStartRefusesOldGit(t *testing.T) {
	f := sgSetup(t)
	if err := os.WriteFile(f.dir+"/bin/git", []byte("#!/bin/sh\necho 'git version 2.33.1'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := f.start(t, nil)
	if r.code != 1 || !strings.Contains(r.stderr, "start.sh needs git 2.34 or later to check the signature of a release; this is git 2.33.1.") {
		t.Errorf("start.sh with git 2.33.1: exit %d; want 1 and the version:\n%s", r.code, r)
	}
}

func TestStartUpdateMovesToSignedRelease(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", nil)
	r := f.start(t, nil, "update")
	if r.code != 0 {
		t.Fatal(r)
	}
	if got, want := f.head(t), f.commitOf(t, "v0.2.0"); got != want {
		t.Errorf("the copy is at %s, want v0.2.0 at %s", got, want)
	}
	if got := f.calls(t); got != sgBuilt("0.2.0") {
		t.Errorf("docker got:\n%s\nwant:\n%s", got, sgBuilt("0.2.0"))
	}

	t.Run("a second update has nothing to do", func(t *testing.T) {
		r := f.start(t, nil, "update")
		if r.code != 0 || !strings.Contains(r.stdout, "No newer signed release was found; v0.2.0 keeps running.") {
			t.Errorf("start.sh update: exit %d; want 0 and nothing to do:\n%s", r.code, r)
		}
	})
}

func TestStartUpdateRefusesUnverifiedTag(t *testing.T) {
	const notSigned = "The newest release tag, v0.2.0, is not signed by a key of release/allowed_signers of v0.1.0"
	t.Run("signed by another key", func(t *testing.T) {
		f := sgSetup(t)
		f.release(t, "other", "v0.2.0", nil)
		f.refused(t, notSigned)
	})
	t.Run("with no signature", func(t *testing.T) {
		f := sgSetup(t)
		f.commit(t, "v0.2.0", nil)
		f.git(t, f.work, "tag", "-a", "-m", "osk-dns-watcher v0.2.0", "v0.2.0")
		f.git(t, f.work, "push", "-q", "origin", "main", "v0.2.0")
		f.refused(t, notSigned)
	})
	t.Run("a lightweight tag", func(t *testing.T) {
		f := sgSetup(t)
		f.commit(t, "v0.2.0", nil)
		f.git(t, f.work, "tag", "v0.2.0")
		f.git(t, f.work, "push", "-q", "origin", "main", "v0.2.0")
		f.refused(t, notSigned)
	})
	t.Run("the fetch brings a new key on the branch; the old key decides", func(t *testing.T) {
		f := sgSetup(t)
		f.release(t, "other", "v0.2.0", func() { sgCopyFile(t, f.dir+"/other.allowed", f.work+"/release/allowed_signers") })
		f.refused(t, notSigned)
	})
	t.Run("an old signed release under a newer name", func(t *testing.T) {
		f := sgSetup(t)
		f.git(t, f.work, "update-ref", "refs/tags/v0.2.0", strings.TrimSpace(f.git(t, f.work, "rev-parse", "refs/tags/v0.1.0")))
		f.git(t, f.work, "push", "-q", "origin", "v0.2.0")
		f.refused(t, notSigned)
	})
}

// The remote loses the newest release and its branch goes back: an update
// never moves to an older release than the installed one.
func TestStartUpdateNeverGoesBack(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", nil)
	if r := f.start(t, nil, "update"); r.code != 0 {
		t.Fatal(r)
	}
	f.git(t, f.work, "push", "-q", "--force", "origin", "v0.1.0^{commit}:refs/heads/main", ":refs/tags/v0.2.0")
	before := f.head(t)
	r := f.start(t, nil, "update")
	if r.code != 0 || !strings.Contains(r.stdout, "No newer signed release was found; v0.2.0 keeps running.") {
		t.Errorf("start.sh update: exit %d; want 0 and nothing to do:\n%s", r.code, r)
	}
	if got := f.head(t); got != before {
		t.Errorf("the copy moved from %s to %s", before, got)
	}
}

// Tags of another form, and names that a shell would run, are not releases.
func TestStartUpdateIgnoresOtherTags(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", nil)
	for _, name := range []string{"v9.9.9;touch${IFS}pwned", "v9.9.9`touch${IFS}pwned`", "v9.9", "v09.0.0", "latest", "v9.9.9-"} {
		f.git(t, f.work, "tag", name)
	}
	f.git(t, f.work, "push", "-q", "origin", "--tags")
	r := f.start(t, nil, "update")
	if r.code != 0 {
		t.Fatal(r)
	}
	if got, want := f.head(t), f.commitOf(t, "v0.2.0"); got != want {
		t.Errorf("the copy is at %s, want v0.2.0 at %s", got, want)
	}
	err := filepath.WalkDir(f.dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.Name() == "pwned" {
			t.Errorf("a tag name ran a command: %s exists", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The build context holds the files of the verified commit and nothing else.
func TestStartBuildsTheCommit(t *testing.T) {
	f := sgSetup(t)
	qsWrite(t, f.copy+"/stray.go", "package main\n")
	if err := os.MkdirAll(f.copy+"/cmd", 0o700); err != nil {
		t.Fatal(err)
	}
	qsWrite(t, f.copy+"/cmd/stray.go", "package main\n")
	if r := f.start(t, nil); r.code != 0 {
		t.Fatal(r)
	}
	data, err := os.ReadFile(f.log + ".context")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(data))
	want := strings.Fields(f.git(t, f.copy, "ls-tree", "-r", "--name-only", "HEAD"))
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the build context holds %v, want the files of the commit %v", got, want)
	}
}

// A start.sh in another folder of a signed release, tracked, is not
// deploy/start.sh of the checkout, so it builds nothing.
func TestStartRefusesFolderInsideCheckout(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", func() {
		sgCopyFile(t, f.work+"/deploy/start.sh", f.work+"/nested/deploy/start.sh")
	})
	f.git(t, f.copy, "fetch", "-q", "--tags")
	f.git(t, f.copy, "checkout", "-q", "v0.2.0")
	if err := os.WriteFile(f.log, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r := qsRun(qsBound, f.copy+"/nested/deploy", f.env, "", "sh", "start.sh")
	if r.code != 1 || !strings.Contains(r.stderr, "start.sh must be deploy/start.sh of the git checkout that it checks") {
		t.Errorf("nested/deploy/start.sh: exit %d; want 1:\n%s", r.code, r)
	}
	if got := f.calls(t); got != "" {
		t.Errorf("start.sh ran docker:\n%s", got)
	}
}

func TestStartRefusesInstalledTagOfOtherKey(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "other", "v0.1.1", nil)
	f.git(t, f.copy, "fetch", "-q", "--tags")
	f.git(t, f.copy, "checkout", "-q", "v0.1.1")
	r := f.start(t, nil)
	if r.code != 1 || !strings.Contains(r.stderr, "This copy is not at a signed release. Check out the newest signed release here, 0.1.0, with: git checkout "+f.commitOf(t, "v0.1.0")+"\n") {
		t.Errorf("start.sh at v0.1.1 signed by another key: exit %d; want 1 and the signed tag:\n%s", r.code, r)
	}
	if got := f.calls(t); got != "" {
		t.Errorf("start.sh ran docker:\n%s", got)
	}
}

func TestStartRefusesChangedTrackedFile(t *testing.T) {
	f := sgSetup(t)
	qsWrite(t, f.copy+"/build/version.sh", "exit 0\n")
	r := f.start(t, nil)
	if r.code != 1 || !strings.Contains(r.stderr, "Files of this copy differ from its commit") {
		t.Errorf("start.sh with a changed tracked file: exit %d; want 1:\n%s", r.code, r)
	}
	if got := f.calls(t); got != "" {
		t.Errorf("start.sh ran docker:\n%s", got)
	}
}

func TestStartUpdateStopsWhenFetchFails(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", nil)
	f.git(t, f.copy, "remote", "set-url", "origin", f.dir+"/missing.git")
	f.refused(t, "git fetch failed (see above), so osk-dns-watcher was not updated; v0.1.0 keeps running.")
}

// Versions order as numbers of any length, and a pre-release is below its
// release.
func TestStartUpdateOrdersVersions(t *testing.T) {
	for _, c := range []struct {
		name string
		tags []string
		want string
	}{
		{"0.10 above 0.9, a release above its pre-releases", []string{"v0.9.0", "v0.10.0-rc.9", "v0.10.0", "v0.10.0-rc.10"}, "v0.10.0"},
		{"rc.10 above rc.9", []string{"v0.10.0-rc.10", "v0.10.0-rc.9", "v0.9.0"}, "v0.10.0-rc.10"},
		{"numbers of any length", []string{"v0.100000000000000000000.0", "v0.99999999999999999999.0"}, "v0.100000000000000000000.0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := sgSetup(t)
			for _, tag := range c.tags {
				f.release(t, "owner", tag, nil)
			}
			if r := f.start(t, nil, "update"); r.code != 0 {
				t.Fatal(r)
			}
			if got, want := f.head(t), f.commitOf(t, c.want); got != want {
				t.Errorf("the copy is at %s, want %s at %s", got, c.want, want)
			}
		})
	}
}

// OSK_UNVERIFIED=1 does not let an update start from a copy that is not at
// a signed release.
func TestStartUpdateIgnoresSwitch(t *testing.T) {
	f := sgSetup(t)
	f.commit(t, "two", nil)
	f.git(t, f.work, "push", "-q", "origin", "main")
	f.git(t, f.copy, "pull", "-q", "--ff-only")
	r := f.start(t, []string{"OSK_UNVERIFIED=1"}, "update")
	if r.code != 1 || !strings.Contains(r.stderr, "This copy is not at a signed release") {
		t.Errorf("OSK_UNVERIFIED=1 start.sh update: exit %d; want 1:\n%s", r.code, r)
	}
	if got := f.calls(t); got != "" {
		t.Errorf("start.sh ran docker:\n%s", got)
	}
}

func TestStartUpdateRefusesTagNotOnCommit(t *testing.T) {
	f := sgSetup(t)
	blob := strings.TrimSpace(qsMust(t, qsRun(qsBound, f.work, f.env, "a blob\n", "git", "hash-object", "-w", "--stdin")))
	f.git(t, f.work, "-c", "gpg.format=ssh", "-c", "user.signingkey="+f.dir+"/owner", "tag", "-s", "-m", "osk-dns-watcher v0.2.0", "v0.2.0", blob)
	f.git(t, f.work, "push", "-q", "origin", "v0.2.0")
	f.refused(t, "the tag v0.2.0 is not on a commit")
}

// installed gives the object id that refs/osk-dns-watcher/installed of the copy holds.
func (f *sgFix) installed(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(f.git(t, f.copy, "rev-parse", "refs/osk-dns-watcher/installed"))
}

func (f *sgFix) tagObject(t *testing.T, tag string) string {
	t.Helper()
	return strings.TrimSpace(f.git(t, f.work, "rev-parse", "refs/tags/"+tag))
}

// The copy keeps the tag object of its release under a ref of its own, so a
// tag that someone moves on the remote changes nothing for it.
func TestStartKeepsRecordOfInstalledRelease(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", nil)
	genuine := f.tagObject(t, "v0.2.0")
	if r := f.start(t, nil, "update"); r.code != 0 {
		t.Fatal(r)
	}
	if got := f.installed(t); got != genuine {
		t.Errorf("refs/osk-dns-watcher/installed is %s, want the tag object of v0.2.0, %s", got, genuine)
	}
	f.commit(t, "junk", nil)
	f.git(t, f.work, "tag", "-f", "v0.2.0")
	f.git(t, f.work, "push", "-q", "--force", "origin", "main", "v0.2.0")
	if r := f.start(t, nil, "update"); r.code != 0 {
		t.Fatal(r)
	}
	r := f.start(t, nil)
	if got := f.calls(t); r.code != 0 || got != sgBuilt("0.2.0") || f.installed(t) != genuine {
		t.Errorf("start.sh after a moved tag: exit %d, record %s; want the build of 0.2.0 and the record %s; docker got:\n%s\n%s",
			r.code, f.installed(t), genuine, got, r)
	}
}

// A copy with fetched release refs and no record updates, and gets its
// record.
func TestStartUpdatesCopyWithoutRecord(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", nil)
	f.git(t, f.copy, "fetch", "-q", "--no-tags", "origin", "+refs/tags/*:refs/osk-dns-watcher/fetched/*")
	f.git(t, f.copy, "checkout", "-q", "--detach", f.commitOf(t, "v0.2.0"))
	f.release(t, "owner", "v0.3.0", nil)
	r := f.start(t, nil, "update")
	if got, want := f.head(t), f.commitOf(t, "v0.3.0"); r.code != 0 || got != want {
		t.Fatalf("start.sh update: exit %d, copy at %s; want v0.3.0 at %s:\n%s", r.code, got, want, r)
	}
	if got, want := f.installed(t), f.tagObject(t, "v0.3.0"); got != want {
		t.Errorf("refs/osk-dns-watcher/installed is %s, want the tag object of v0.3.0, %s", got, want)
	}
}

// A tag that the key signed with a message that is not "osk-dns-watcher <version>" of
// its own name is not a release.
func TestStartUpdateRefusesTagWithOtherMessage(t *testing.T) {
	for _, message := range []string{"other 0.2.0", "osk-dns-watcher 0.3.0", "osk-dns-watcher v0.2.0"} {
		t.Run(message, func(t *testing.T) {
			f := sgSetup(t)
			f.commit(t, "two", nil)
			f.git(t, f.work, "-c", "gpg.format=ssh", "-c", "user.signingkey="+f.dir+"/owner", "tag", "-s", "-m", message, "v0.2.0")
			f.git(t, f.work, "push", "-q", "origin", "main", "v0.2.0")
			f.refused(t, "does not begin with the line \"osk-dns-watcher 0.2.0\"")
		})
	}
}

// The advice names the commit that was verified, so a local tag of the same
// name that points elsewhere cannot divert it.
func TestStartAdviceNamesTheVerifiedCommit(t *testing.T) {
	f := sgSetup(t)
	verified := f.commitOf(t, "v0.1.0")
	f.commit(t, "two", nil)
	f.git(t, f.work, "push", "-q", "origin", "main")
	f.git(t, f.copy, "pull", "-q", "--ff-only")
	f.git(t, f.copy, "branch", "v0.1.0", "HEAD")
	r := f.start(t, nil)
	if r.code != 1 || !strings.HasSuffix(strings.TrimSpace(r.stderr), "git checkout "+verified) {
		t.Errorf("start.sh off a release: exit %d; want 1 and git checkout %s last:\n%s", r.code, verified, r)
	}
}

// Each update fetches into an empty namespace: a ref that the remote has
// removed does not stay.
func TestStartUpdateEmptiesFetchedTags(t *testing.T) {
	f := sgSetup(t)
	f.git(t, f.work, "tag", "zz", "v0.1.0^{commit}")
	f.git(t, f.work, "push", "-q", "origin", "zz")
	if r := f.start(t, nil, "update"); r.code != 0 {
		t.Fatal(r)
	}
	f.git(t, f.work, "push", "-q", "origin", ":refs/tags/zz")
	if r := f.start(t, nil, "update"); r.code != 0 {
		t.Fatal(r)
	}
	if refs := f.git(t, f.copy, "for-each-ref", "refs/osk-dns-watcher/fetched/zz"); refs != "" {
		t.Errorf("after an update, refs/osk-dns-watcher/fetched still holds the removed tag:\n%s", refs)
	}
}

// start.sh removes its temporary folder, and nothing else, also when TMPDIR
// holds a space.
func TestStartRemovesOnlyItsTemporaryFolder(t *testing.T) {
	f := sgSetup(t)
	tmp := f.dir + "/a tmp"
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	sgCopyText(t, f.dir+"/a/keep", "keep\n")
	if r := f.start(t, []string{"TMPDIR=" + tmp}); r.code != 0 {
		t.Fatal(r)
	}
	if _, err := os.Stat(f.dir + "/a/keep"); err != nil {
		t.Errorf("start.sh removed %s: %v", f.dir+"/a", err)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("start.sh left %d entries in TMPDIR, the first %s", len(left), left[0].Name())
	}
}

// A git command that fails inside the export stops start.sh with its own
// text, before any docker command.
func TestStartStopsWhenGitFailsInExport(t *testing.T) {
	f := sgSetup(t)
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\ncase \" $* \" in *\" archive \"*) echo 'fatal: planted' >&2; exit 128 ;; esac\nexec '" + gitPath + "' \"$@\"\n"
	if err := os.WriteFile(f.dir+"/bin/git", []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	r := f.start(t, nil)
	if got := f.calls(t); r.code != 1 || !strings.Contains(r.stderr, "git archive of") || got != "" {
		t.Errorf("start.sh with a failing git archive: exit %d; want 1, the reason and no docker command; docker got:\n%s\n%s", r.code, got, r)
	}
}

// start.sh accepts git 2.34, so its scripts use nothing that came later,
// such as git ls-tree --format of 2.36.
func TestStartBuildsWithGit234(t *testing.T) {
	f := sgSetup(t)
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\n[ \"$1\" != --version ] || { echo 'git version 2.34.1'; exit 0; }\n" +
		"case \" $* \" in *\" ls-tree \"*\" --format\"*) echo 'error: unknown option format' >&2; exit 129 ;; esac\n" +
		"exec '" + gitPath + "' \"$@\"\n"
	if err := os.WriteFile(f.dir+"/bin/git", []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	if r := f.start(t, nil); r.code != 0 || f.calls(t) != sgBuilt("0.1.0") {
		t.Errorf("start.sh with a git that has no ls-tree --format: exit %d; want the build of 0.1.0:\n%s", r.code, r)
	}
}

func TestStartShowsComposeExtra(t *testing.T) {
	f := sgSetup(t)
	extra := f.dir + "/extra.yaml"
	qsWrite(t, extra, "services: {}\n")
	r := f.start(t, []string{"OSK_COMPOSE_EXTRA=" + extra})
	if r.code != 0 || !strings.HasPrefix(r.stdout, "OSK_COMPOSE_EXTRA="+extra+": this Compose file is added to the release") {
		t.Errorf("start.sh with OSK_COMPOSE_EXTRA: exit %d; want 0 and its line first:\n%s", r.code, r)
	}
	if got := f.calls(t); !strings.Contains(got, "-f "+extra+" --profile setup build") {
		t.Errorf("docker got:\n%s\nwant the extra file after the release's", got)
	}
}

// A label number with a leading zero is not of the form of a version, so such
// a tag is no release.
func TestStartUpdateIgnoresLeadingZero(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0-rc.01", nil)
	r := f.start(t, nil, "update")
	if r.code != 0 || !strings.Contains(r.stdout, "No newer signed release was found; v0.1.0 keeps running.") {
		t.Errorf("start.sh update with only v0.2.0-rc.01: exit %d; want 0 and nothing to do:\n%s", r.code, r)
	}
}

// Tags that did not verify are named and counted, and the exit code is 1.
func TestStartUpdateNamesSkippedTags(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "other", "v0.2.0", nil)
	f.release(t, "other", "v0.3.0", nil)
	f.refused(t, "tags that did not verify were skipped (2): v0.3.0 v0.2.0. v0.1.0 keeps running.")
}

// A plain first start records the release that it checked.
func TestStartRecordsFirstStart(t *testing.T) {
	f := sgSetup(t)
	if r := f.start(t, nil); r.code != 0 {
		t.Fatal(r)
	}
	if got, want := f.installed(t), f.tagObject(t, "v0.1.0"); got != want {
		t.Errorf("refs/osk-dns-watcher/installed is %s, want the tag object of v0.1.0, %s", got, want)
	}
}

// The record is checked by its signature on every run: a record that names
// a tag object that another key signed starts nothing.
func TestStartChecksRecordBySignature(t *testing.T) {
	f := sgSetup(t)
	if r := f.start(t, nil); r.code != 0 {
		t.Fatal(r)
	}
	f.git(t, f.copy, "-c", "gpg.format=ssh", "-c", "user.signingkey="+f.dir+"/other", "tag", "-f", "-s", "-m", "osk-dns-watcher 0.1.0", "v0.1.0")
	f.git(t, f.copy, "update-ref", "refs/osk-dns-watcher/installed", "refs/tags/v0.1.0")
	r := f.start(t, nil)
	if got := f.calls(t); r.code != 1 || got != "" {
		t.Errorf("start.sh with a record signed by another key: exit %d; want 1 and no docker command; docker got:\n%s\n%s", r.code, got, r)
	}
}

// With a record, the advice names the recorded release, never a lower one.
func TestStartAdviceNeverBelowRecord(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", nil)
	if r := f.start(t, nil, "update"); r.code != 0 {
		t.Fatal(r)
	}
	// The only signed tag left in the copy is v0.1.0, below the record.
	f.git(t, f.copy, "update-ref", "-d", "refs/osk-dns-watcher/fetched/v0.2.0")
	f.commit(t, "three", nil)
	f.git(t, f.work, "push", "-q", "origin", "main")
	f.git(t, f.copy, "fetch", "-q", "--no-tags", "origin")
	f.git(t, f.copy, "checkout", "-q", "--detach", "origin/main")
	r := f.start(t, nil)
	if r.code != 1 || !strings.HasSuffix(strings.TrimSpace(r.stderr), "git checkout "+f.commitOf(t, "v0.2.0")) ||
		strings.Contains(r.stderr, f.commitOf(t, "v0.1.0")) {
		t.Errorf("start.sh off its release 0.2.0: exit %d; want the commit of v0.2.0 and not the lower v0.1.0:\n%s", r.code, r)
	}
}

// A higher release that the user checked out by hand counts when the key of
// the recorded release signed it; one that another key signed does not.
func TestStartAcceptsHigherReleaseByHand(t *testing.T) {
	t.Run("signed by the recorded release's key", func(t *testing.T) {
		f := sgSetup(t)
		if r := f.start(t, nil); r.code != 0 {
			t.Fatal(r)
		}
		f.release(t, "owner", "v0.2.0", nil)
		f.git(t, f.copy, "fetch", "-q", "--tags")
		f.git(t, f.copy, "checkout", "-q", "v0.2.0")
		r := f.start(t, nil)
		if got := f.calls(t); r.code != 0 || got != sgBuilt("0.2.0") || f.installed(t) != f.tagObject(t, "v0.2.0") {
			t.Errorf("start.sh at v0.2.0 checked out by hand: exit %d; want the build of 0.2.0 and its record; docker got:\n%s\n%s", r.code, got, r)
		}
	})
	t.Run("signed by another key that its own key file names", func(t *testing.T) {
		f := sgSetup(t)
		if r := f.start(t, nil); r.code != 0 {
			t.Fatal(r)
		}
		f.release(t, "other", "v0.2.0", func() { sgCopyFile(t, f.dir+"/other.allowed", f.work+"/release/allowed_signers") })
		f.git(t, f.copy, "fetch", "-q", "--tags")
		f.git(t, f.copy, "checkout", "-q", "v0.2.0")
		r := f.start(t, nil)
		if got := f.calls(t); r.code != 1 || got != "" || !strings.HasSuffix(strings.TrimSpace(r.stderr), "git checkout "+f.commitOf(t, "v0.1.0")) {
			t.Errorf("start.sh at a v0.2.0 of another key: exit %d; want 1 and the commit of v0.1.0; docker got:\n%s\n%s", r.code, got, r)
		}
	})
	t.Run("a lower release does not count", func(t *testing.T) {
		f := sgSetup(t)
		f.release(t, "owner", "v0.2.0", nil)
		if r := f.start(t, nil, "update"); r.code != 0 {
			t.Fatal(r)
		}
		record := f.installed(t)
		f.git(t, f.copy, "checkout", "-q", "v0.1.0")
		r := f.start(t, nil)
		if got := f.calls(t); r.code != 1 || got != "" || f.installed(t) != record ||
			!strings.HasSuffix(strings.TrimSpace(r.stderr), "git checkout "+f.commitOf(t, "v0.2.0")) {
			t.Errorf("start.sh at v0.1.0 after 0.2.0: exit %d; want 1, the record kept and the commit of v0.2.0; docker got:\n%s\n%s", r.code, got, r)
		}
	})
}

// An update leaves no temporary folder behind, also the one of the start.sh
// that it replaces with the new one.
func TestStartUpdateLeavesNoTemporaryFolder(t *testing.T) {
	f := sgSetup(t)
	tmp := f.dir + "/tmp"
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	f.release(t, "owner", "v0.2.0", nil)
	if r := f.start(t, []string{"TMPDIR=" + tmp}, "update"); r.code != 0 {
		t.Fatal(r)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("the update left %d entries in TMPDIR, the first %s", len(left), left[0].Name())
	}
}

// The removal takes only a folder of the form that mktemp gives: when the
// temporary folder has another name, nothing is removed.
func TestStartCleanupRemovesOnlyItsForm(t *testing.T) {
	f := sgSetup(t)
	mktemp, err := exec.LookPath("mktemp")
	if err != nil {
		t.Fatal(err)
	}
	// This mktemp gives each caller a folder of another name, and logs it.
	stub := "#!/bin/sh\nd=$('" + mktemp + "' -d '" + f.dir + "/precious.XXXXXXXX') || exit 1\necho \"$d\" >>'" + f.dir + "/made'\necho \"$d\"\n"
	if err := os.WriteFile(f.dir+"/bin/mktemp", []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	if r := f.start(t, nil); r.code != 0 {
		t.Fatal(r)
	}
	made, err := os.ReadFile(f.dir + "/made")
	if err != nil {
		t.Fatal(err)
	}
	dirs := strings.Fields(string(made))
	if len(dirs) != 2 {
		t.Fatalf("mktemp made %d folders, want 2, one for start.sh and one for release/export.sh", len(dirs))
	}
	for _, d := range dirs {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("start.sh removed %s, a folder of another form than its own: %v", d, err)
		}
	}
}

// The export takes file names with a space, a quote, a backslash, a tab and
// a byte above ASCII, and refuses a name with a line end in plain words.
func TestStartExportsAnyFileName(t *testing.T) {
	t.Run("names that git would quote", func(t *testing.T) {
		f := sgSetup(t)
		names := []string{"a b.txt", "q\"uote.txt", "back\\slash.txt", "tab\tname.txt", "caf\u00e9.txt"}
		f.release(t, "owner", "v0.2.0", func() {
			for _, name := range names {
				qsWrite(t, f.work+"/"+name, "x\n")
			}
		})
		if r := f.start(t, nil, "update"); r.code != 0 || f.calls(t) != sgBuilt("0.2.0") {
			t.Fatalf("start.sh update: exit %d; want the build of 0.2.0:\n%s", r.code, r)
		}
		data, err := os.ReadFile(f.log + ".context")
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			if !strings.Contains(string(data), name+"\n") {
				t.Errorf("the build context has no %q:\n%s", name, data)
			}
		}
	})
	t.Run("a name with a line end", func(t *testing.T) {
		f := sgSetup(t)
		f.release(t, "owner", "v0.2.0", func() { qsWrite(t, f.work+"/line\nend.txt", "x\n") })
		r := f.start(t, nil, "update")
		if r.code != 1 || !strings.Contains(r.stderr, "holds a file whose name has a line end") || f.calls(t) != "" {
			t.Errorf("start.sh update to a release with a line end in a file name: exit %d; want 1 and the reason:\n%s", r.code, r)
		}
	})
}

// The block of "A first copy" starts a signed release, and nothing else, with
// the fingerprint of the owner's key filled in.
func TestVerifyFirstCopyBlock(t *testing.T) {
	data, err := os.ReadFile(sgSrc(t) + "/release/README.md")
	if err != nil {
		t.Fatal(err)
	}
	const clone = "git clone --no-checkout "
	var block string
	for i, part := range strings.Split(string(data), "```") {
		if i%2 == 1 && strings.Contains(part, clone) {
			block = part[strings.Index(part, "\n")+1:]
		}
	}
	const placeholder = "SHA256:<the published fingerprint>"
	if !strings.Contains(block, placeholder) {
		t.Fatalf("release/README.md has no block with %q and %q", clone, placeholder)
	}
	url := strings.Fields(block[strings.Index(block, clone)+len(clone):])[0]
	paste := func(t *testing.T, f *sgFix) qsResult {
		fields := strings.Fields(qsMust(t, qsRun(qsBound, f.dir, f.env, "", "ssh-keygen", "-lf", f.dir+"/owner.pub")))
		block := strings.Replace(block, placeholder, fields[1], 1)
		config, err := os.ReadFile(f.dir + "/gitconfig")
		if err != nil {
			t.Fatal(err)
		}
		qsWrite(t, f.dir+"/gitconfig", string(config)+"[url \"file://"+f.dir+"/remote.git\"]\n\tinsteadOf = "+url+"\n")
		sgCopyText(t, f.dir+"/stranger/first.sh", block)
		if err := os.WriteFile(f.log, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return qsRun(qsBound, f.dir+"/stranger", f.env, "", "sh", "-e", "first.sh")
	}
	t.Run("a signed release starts", func(t *testing.T) {
		f := sgSetup(t)
		if r := paste(t, f); r.code != 0 || f.calls(t) != sgBuilt("0.1.0") {
			t.Errorf("the first-copy block: exit %d; want the build of 0.1.0; docker got:\n%s\n%s", r.code, f.calls(t), r)
		}
	})
	t.Run("a tag that another key signed, on a commit with the owner's key file, runs nothing of it", func(t *testing.T) {
		f := sgSetup(t)
		f.git(t, f.work, "checkout", "-q", "-b", "evil")
		f.commit(t, "evil", func() { sgCopyText(t, f.work+"/deploy/start.sh", "#!/bin/sh\necho planted-start-ran\n") })
		f.git(t, f.work, "tag", "-d", "v0.1.0")
		f.tag(t, "other", "v0.1.0")
		f.git(t, f.work, "push", "-q", "--force", "origin", "v0.1.0")
		if r := paste(t, f); r.code == 0 || strings.Contains(r.stdout+r.stderr, "planted-start-ran") {
			t.Errorf("the first-copy block on a tag of another key: exit %d; want a stop before its start.sh:\n%s", r.code, r)
		}
	})
	t.Run("a key file with the owner's key and a second key in a quoted option runs nothing of it", func(t *testing.T) {
		f := sgSetup(t)
		owner, err := os.ReadFile(f.dir + "/owner.allowed")
		if err != nil {
			t.Fatal(err)
		}
		other, err := os.ReadFile(f.dir + "/other.pub")
		if err != nil {
			t.Fatal(err)
		}
		f.git(t, f.work, "checkout", "-q", "-b", "evil")
		f.commit(t, "evil", func() {
			sgCopyText(t, f.work+"/release/allowed_signers", string(owner)+`x namespaces="git,y ssh-ed25519 z" `+string(other))
			sgCopyText(t, f.work+"/deploy/start.sh", "#!/bin/sh\necho planted-start-ran\n")
		})
		f.git(t, f.work, "tag", "-d", "v0.1.0")
		f.tag(t, "other", "v0.1.0")
		f.git(t, f.work, "push", "-q", "--force", "origin", "v0.1.0")
		if r := paste(t, f); r.code == 0 || strings.Contains(r.stdout+r.stderr, "planted-start-ran") {
			t.Errorf("the first-copy block on a tag of a key that the key file hides: exit %d; want a stop before its start.sh:\n%s", r.code, r)
		}
	})
}

// release/commit.sh checks a tag with release/verify-tag.sh: the name inside
// the tag, and the settings that a git config cannot change.
func TestVerifyTagInCommitScript(t *testing.T) {
	commitScript := func(t *testing.T, f *sgFix) qsResult {
		head := strings.TrimSpace(f.git(t, f.work, "rev-parse", "HEAD"))
		sgCopyText(t, f.work+"/out/release/0.1.0/CONTENTS", "version 0.1.0\ncommit "+head+"\n")
		return qsRun(qsBound, f.work, f.env, "", "sh", "release/commit.sh", "0.1.0")
	}
	retag := func(t *testing.T, f *sgFix, key string) {
		f.git(t, f.work, "tag", "-d", "v0.1.0")
		f.tag(t, key, "v0.1.0")
	}
	for _, c := range []struct {
		name, want string
		fault      func(t *testing.T, f *sgFix)
	}{
		{"the release tag passes", "", func(t *testing.T, f *sgFix) {}},
		{"a tag object of another name", "holds another name", func(t *testing.T, f *sgFix) {
			f.tag(t, "owner", "v0.0.9")
			oid := strings.TrimSpace(f.git(t, f.work, "rev-parse", "refs/tags/v0.0.9"))
			f.git(t, f.work, "update-ref", "refs/tags/v0.1.0", oid)
		}},
		{"a git config that names another key file", "does not verify", func(t *testing.T, f *sgFix) {
			retag(t, f, "other")
			sgCopyText(t, f.dir+"/gitconfig", "[gpg \"ssh\"]\n\tallowedSignersFile = "+f.dir+"/other.allowed\n\tprogram = true\n")
		}},
		{"an OpenPGP signature that the user's gpg accepts", "exactly one signature, an SSH signature", func(t *testing.T, f *sgFix) {
			gpg := "#!/bin/sh\ncat >/dev/null\nprintf '[GNUPG:] NEWSIG\\n[GNUPG:] GOODSIG 0123456789ABCDEF someone <someone@example.test>\\n'\n"
			if err := os.WriteFile(f.dir+"/bin/gpg", []byte(gpg), 0o755); err != nil {
				t.Fatal(err)
			}
			head := strings.TrimSpace(f.git(t, f.work, "rev-parse", "HEAD"))
			body := "object " + head + "\ntype commit\ntag v0.1.0\ntagger someone <someone@example.test> 1700000000 +0000\n\n" +
				"osk-dns-watcher 0.1.0\n-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEE\n=abcd\n-----END PGP SIGNATURE-----\n"
			oid := strings.TrimSpace(qsMust(t, qsRun(qsBound, f.work, f.env, body, "git", "mktag")))
			f.git(t, f.work, "update-ref", "refs/tags/v0.1.0", oid)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := sgSetup(t)
			c.fault(t, f)
			r := commitScript(t, f)
			if c.want == "" && r.code != 0 || c.want != "" && (r.code != 1 || !strings.Contains(r.stdout, c.want)) {
				t.Errorf("release/commit.sh: exit %d; want %q (none: exit 0):\n%s", r.code, c.want, r)
			}
		})
	}
}

// sgSignedRelease makes a tree with release/verify.sh and the release
// 0.0.1 whose SHA256SUMS the key owner signed, and gives its folder.
func sgSignedRelease(t *testing.T) (tree, release string) {
	t.Helper()
	tree = t.TempDir()
	sgKeys(t, tree)
	src := sgSrc(t)
	sgCopyFile(t, src+"/release/verify.sh", tree+"/release/verify.sh")
	sgCopyFile(t, src+"/build/version.sh", tree+"/build/version.sh")
	sgCopyFile(t, tree+"/owner.allowed", tree+"/release/allowed_signers")
	release = tree + "/out/release/0.0.1"
	files := map[string]string{
		"osk-dns-watcher-linux-amd64": "amd64\n",
		"osk-dns-watcher-linux-arm64": "arm64\n",
		"CONTENTS":                    "version 0.0.1\nimage ghcr.io/zz/osk-dns-watcher\nimage-digest index sha256:" + strings.Repeat("a", 64) + "\n",
	}
	var sums strings.Builder
	for _, name := range []string{"osk-dns-watcher-linux-amd64", "osk-dns-watcher-linux-arm64", "CONTENTS"} {
		sgCopyText(t, release+"/"+name, files[name])
		sum := sha256.Sum256([]byte(files[name]))
		sums.WriteString(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	}
	sgCopyText(t, release+"/SHA256SUMS", sums.String())
	sgSign(t, tree, "owner", "file", release+"/SHA256SUMS")
	return tree, release
}

func sgCopyText(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	qsWrite(t, path, text)
}

// sgSign writes path.sig, the signature of path by the key in the namespace.
func sgSign(t *testing.T, tree, key, namespace, path string) {
	t.Helper()
	_ = os.Remove(path + ".sig")
	qsMust(t, qsRun(qsBound, tree, sgEnviron(tree), "", "ssh-keygen", "-q", "-Y", "sign", "-f", tree+"/"+key, "-n", namespace, path))
}

func TestVerifyRelease(t *testing.T) {
	verify := func(tree string) qsResult {
		return qsRun(qsBound, tree, sgEnviron(tree), "", "sh", "release/verify.sh", "0.0.1")
	}
	t.Run("a good signature passes and names the image", func(t *testing.T) {
		tree, _ := sgSignedRelease(t)
		r := verify(tree)
		if r.code != 0 || !strings.Contains(r.stdout, "image: ghcr.io/zz/osk-dns-watcher@sha256:"+strings.Repeat("a", 64)+"\n") {
			t.Errorf("verify.sh: exit %d; want 0 and the image by digest:\n%s", r.code, r)
		}
	})
	for _, c := range []struct {
		name, want string
		fault      func(t *testing.T, tree, release string)
	}{
		{"no signature", "SHA256SUMS.sig is missing: this release is not signed", func(t *testing.T, tree, release string) {
			if err := os.Remove(release + "/SHA256SUMS.sig"); err != nil {
				t.Fatal(err)
			}
		}},
		{"a signature by another key", "does not verify with release/allowed_signers", func(t *testing.T, tree, release string) {
			sgSign(t, tree, "other", "file", release+"/SHA256SUMS")
		}},
		{"a signature over other bytes", "does not verify with release/allowed_signers", func(t *testing.T, tree, release string) {
			sgCopyText(t, release+"/SHA256SUMS", "0000  CONTENTS\n")
		}},
		{"a signature in the namespace git", "does not verify with release/allowed_signers", func(t *testing.T, tree, release string) {
			sgSign(t, tree, "owner", "git", release+"/SHA256SUMS")
		}},
		{"an empty allowed_signers", "release/allowed_signers has no key for osk-dns-watcher-release", func(t *testing.T, tree, release string) {
			sgCopyText(t, tree+"/release/allowed_signers", "")
		}},
		{"a changed binary", "do not match SHA256SUMS", func(t *testing.T, tree, release string) {
			sgCopyText(t, release+"/osk-dns-watcher-linux-amd64", "changed\n")
		}},
		{"a signed SHA256SUMS that leaves out a binary", "must list CONTENTS, osk-dns-watcher-linux-amd64 and osk-dns-watcher-linux-arm64", func(t *testing.T, tree, release string) {
			data, err := os.ReadFile(release + "/SHA256SUMS")
			if err != nil {
				t.Fatal(err)
			}
			var kept []string
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if !strings.HasSuffix(line, "osk-dns-watcher-linux-arm64") {
					kept = append(kept, line)
				}
			}
			sgCopyText(t, release+"/SHA256SUMS", strings.Join(kept, "\n")+"\n")
			sgSign(t, tree, "owner", "file", release+"/SHA256SUMS")
		}},
		{"the signed files of another version", "is the CONTENTS of another version than 0.0.1", func(t *testing.T, tree, release string) {
			sgCopyText(t, release+"/CONTENTS", "version 0.0.2\n")
			sum := sha256.Sum256([]byte("version 0.0.2\n"))
			data, err := os.ReadFile(release + "/SHA256SUMS")
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			lines[len(lines)-1] = hex.EncodeToString(sum[:]) + "  CONTENTS"
			sgCopyText(t, release+"/SHA256SUMS", strings.Join(lines, "\n")+"\n")
			sgSign(t, tree, "owner", "file", release+"/SHA256SUMS")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tree, release := sgSignedRelease(t)
			c.fault(t, tree, release)
			r := verify(tree)
			if r.code != 1 || !strings.Contains(r.stderr, c.want) {
				t.Errorf("verify.sh: exit %d; want 1 and %q:\n%s", r.code, c.want, r)
			}
		})
	}
}
