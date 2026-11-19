//go:build lab

package installtest

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// More tests of the update and verification path, each against one fault
// or one attack. They
// reuse the fixture of start_lab_test.go: no lab, no Docker, git and
// ssh-keygen only.

// Correct: start.sh update accepts only an SSH signature by a key of allowed_signers; an OpenPGP-signed tag is refused.
func TestStartUpdateRefusesOpenPGPSignedTag(t *testing.T) {
	f := sgSetup(t)
	// The user's gpg, whose keyring holds a key that the attacker can sign
	// with (or that gpg fetched by itself): it reports a good signature.
	// git picks the program from the armor of the signature, not from
	// gpg.format, so this gpg decides.
	stub := "#!/bin/sh\ncat >/dev/null\n" +
		"printf '[GNUPG:] NEWSIG\\n[GNUPG:] GOODSIG 0123456789ABCDEF someone <someone@example.test>\\n'\n"
	if err := os.WriteFile(f.dir+"/bin/gpg", []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	// Someone who can push, but holds no key of allowed_signers, adds a
	// commit and an annotated tag of its own name with an OpenPGP signature.
	// Its message is that of a release, so only the signature rule stops it.
	f.commit(t, "evil", nil)
	commit := strings.TrimSpace(f.git(t, f.work, "rev-parse", "HEAD"))
	body := "object " + commit + "\ntype commit\ntag v0.2.0\ntagger someone <someone@example.test> 1700000000 +0000\n\n" +
		"osk-dns-watcher 0.2.0\n-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEE\n=abcd\n-----END PGP SIGNATURE-----\n"
	oid := strings.TrimSpace(qsMust(t, qsRun(qsBound, f.work, f.env, body, "git", "mktag")))
	f.git(t, f.work, "update-ref", "refs/tags/v0.2.0", oid)
	f.git(t, f.work, "push", "-q", "origin", "main", "v0.2.0")
	f.refused(t, "The newest release tag, v0.2.0, is not signed by a key of release/allowed_signers of v0.1.0")
}

// Correct: start.sh update never moves to a release older than the installed one, also when the fetch prunes tags.
func TestStartUpdateNeverGoesBackWhenFetchPrunesTags(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", nil)
	if r := f.start(t, nil, "update"); r.code != 0 {
		t.Fatal(r)
	}
	// Ordinary settings of a user (or of anyone who can write ~/.gitconfig).
	f.git(t, f.copy, "config", "fetch.prune", "true")
	f.git(t, f.copy, "config", "fetch.pruneTags", "true")
	// Someone who can push, but has no key, removes the newest release and
	// puts the branch back on v0.1.0, an old signed release with a fault.
	f.git(t, f.work, "push", "-q", "--force", "origin", "v0.1.0^{commit}:refs/heads/main", ":refs/tags/v0.2.0")
	before := f.head(t)
	r := f.start(t, nil, "update")
	if got := f.head(t); got != before {
		t.Errorf("the copy went back from v0.2.0 (%s) to %s:\n%s", before, got, r)
	}
	if calls := f.calls(t); strings.Contains(calls, "OSK_VERSION=0.1.0") {
		t.Errorf("start.sh update built the older release 0.1.0:\n%s", calls)
	}
}

// Correct: verify.sh <version> fails, and names no image, when the verified CONTENTS names another version.
func TestVerifyReleaseRefusesFilesOfAnotherVersion(t *testing.T) {
	tree, release := sgSignedRelease(t)
	// The signed files of 0.0.1, offered as the release 0.0.2.
	if err := os.Rename(release, tree+"/out/release/0.0.2"); err != nil {
		t.Fatal(err)
	}
	r := qsRun(qsBound, tree, sgEnviron(tree), "", "sh", "release/verify.sh", "0.0.2")
	if r.code != 1 || strings.Contains(r.stdout, "image: ") {
		t.Errorf("verify.sh 0.0.2 on the signed files of 0.0.1: exit %d; want 1 and no image line:\n%s", r.code, r)
	}
}

// rvFingerprintCommand gives the one sh block of release/README.md that
// prints the fingerprints of release/allowed_signers, as the document has it.
func rvFingerprintCommand(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(sgSrc(t) + "/release/README.md")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "```sh") {
			continue
		}
		j := i + 1
		for j < len(lines) && !strings.HasPrefix(lines[j], "```") {
			j++
		}
		block := strings.Join(lines[i+1:j], "\n")
		if strings.Contains(block, "ssh-keygen -l") && strings.Contains(block, "release/allowed_signers") {
			found = append(found, block)
		}
		i = j
	}
	if len(found) != 1 {
		t.Fatalf("release/README.md has %d sh blocks that print the fingerprints of release/allowed_signers, want 1", len(found))
	}
	return found[0]
}

// Correct: the command that release/README.md gives a new user prints the right fingerprint of each key of release/allowed_signers.
func TestVerifyFingerprintCommandOfReleaseReadmeWorks(t *testing.T) {
	command := rvFingerprintCommand(t)
	src := sgSrc(t)
	dir := t.TempDir()
	// The file of the tree: one fingerprint for each key line.
	data, err := os.ReadFile(src + "/release/allowed_signers")
	if err != nil {
		t.Fatal(err)
	}
	keys := 0
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			keys++
		}
	}
	r := qsRun(qsBound, src, sgEnviron(dir), "", "sh", "-c", command)
	if r.code != 0 || keys == 0 || strings.Count(r.stdout, "SHA256:") != keys {
		t.Errorf("the command of the document on release/allowed_signers: exit %d; want 0 and %d fingerprints:\n%s", r.code, keys, r)
	}
	// A file of the same form with two keys whose fingerprints are known.
	sgKeys(t, dir)
	var both strings.Builder
	for _, key := range []string{"owner", "other"} {
		line, err := os.ReadFile(dir + "/" + key + ".allowed")
		if err != nil {
			t.Fatal(err)
		}
		both.Write(line)
	}
	sgCopyText(t, dir+"/tree/release/allowed_signers", both.String())
	r = qsRun(qsBound, dir+"/tree", sgEnviron(dir), "", "sh", "-c", command)
	for _, key := range []string{"owner", "other"} {
		want := strings.Fields(qsMust(t, qsRun(qsBound, dir, sgEnviron(dir), "", "ssh-keygen", "-lf", dir+"/"+key+".pub")))
		if r.code != 0 || len(want) < 2 || !strings.Contains(r.stdout, want[1]) {
			t.Errorf("the command of the document: exit %d; want 0 and the fingerprint %v of the key %s:\n%s", r.code, want, key, r)
		}
	}
}

// Correct: when the copy is not at a release, start.sh names only a tag that a key of the copy signed.
func TestStartNotAtReleaseAdviceNamesOnlySignedTags(t *testing.T) {
	f := sgSetup(t)
	// Someone who can push, but has no key, tags a commit of their own with
	// a newer version.
	f.git(t, f.work, "checkout", "-q", "-b", "other")
	f.commit(t, "other", nil)
	f.git(t, f.work, "tag", "v0.2.0")
	f.git(t, f.work, "push", "-q", "origin", "v0.2.0")
	// The owner's branch is ahead of the release, and the copy follows it.
	f.git(t, f.work, "checkout", "-q", "main")
	f.commit(t, "two", nil)
	f.git(t, f.work, "push", "-q", "origin", "main")
	f.git(t, f.copy, "pull", "-q", "--ff-only")
	f.git(t, f.copy, "fetch", "-q", "--tags")
	r := f.start(t, nil)
	if r.code != 1 || strings.Contains(r.stderr, "git checkout v0.2.0") {
		t.Errorf("start.sh: exit %d; want 1 and no advice to check out the unsigned v0.2.0:\n%s", r.code, r)
	}
}

// Correct: an unsigned tag of a higher version does not stop the update to the newest signed release.
func TestStartUnsignedHigherTagDoesNotFreezeUpdates(t *testing.T) {
	f := sgSetup(t)
	f.git(t, f.work, "tag", "v9.0.0", "v0.1.0^{commit}")
	f.git(t, f.work, "push", "-q", "origin", "v9.0.0")
	f.release(t, "owner", "v0.2.0", nil)
	r := f.start(t, nil, "update")
	if got, want := f.head(t), f.commitOf(t, "v0.2.0"); r.code != 0 || got != want {
		t.Errorf("start.sh update: exit %d, copy at %s; want 0 and v0.2.0 at %s:\n%s", r.code, got, want, r)
	}
}

// Correct: an old tag that someone moved on the remote does not stop the update to a newer signed release.
func TestStartMovedOldTagDoesNotFreezeUpdates(t *testing.T) {
	f := sgSetup(t)
	f.commit(t, "junk", nil)
	f.git(t, f.work, "tag", "-f", "v0.1.0")
	f.git(t, f.work, "push", "-q", "--force", "origin", "main", "v0.1.0")
	f.release(t, "owner", "v0.2.0", nil)
	r := f.start(t, nil, "update")
	if got, want := f.head(t), f.commitOf(t, "v0.2.0"); r.code != 0 || got != want {
		t.Errorf("start.sh update: exit %d, copy at %s; want 0 and v0.2.0 at %s:\n%s", r.code, got, want, r)
	}
}

// Correct: start.sh starts a signed release although an unsigned tag of a higher version is on the same commit.
func TestStartUnsignedTagAtInstalledCommitDoesNotStopStart(t *testing.T) {
	f := sgSetup(t)
	f.git(t, f.work, "tag", "v9.0.0", "v0.1.0^{commit}")
	f.git(t, f.work, "push", "-q", "origin", "v9.0.0")
	f.git(t, f.copy, "fetch", "-q", "--tags")
	r := f.start(t, nil)
	if got := f.calls(t); r.code != 0 || got != sgBuilt("0.1.0") {
		t.Errorf("start.sh: exit %d; want 0 and the build of 0.1.0; docker got:\n%s\n%s", r.code, got, r)
	}
}

// Correct: start.sh refuses a copy with a file outside the release that Compose or the build reads.
func TestStartRefusesUntrackedFileThatComposeReads(t *testing.T) {
	f := sgSetup(t)
	// docker compose merges compose.override.yaml with compose.yaml by default.
	qsWrite(t, f.copy+"/deploy/compose.override.yaml", "services:\n  watcher:\n    privileged: true\n")
	r := f.start(t, nil)
	if got := f.calls(t); r.code != 1 || got != "" {
		t.Errorf("start.sh with an untracked deploy/compose.override.yaml: exit %d; want 1 and no docker command; docker got:\n%s\n%s", r.code, got, r)
	}
}

// Correct: start.sh refuses a folder that is not itself the checkout whose signed tag it checked.
func TestStartRefusesFolderThatIsNotTheVerifiedCheckout(t *testing.T) {
	f := sgSetup(t)
	src := sgSrc(t)
	// A copy without .git (a downloaded archive) inside a signed checkout.
	nested := f.copy + "/nested"
	sgCopyFile(t, src+"/deploy/start.sh", nested+"/deploy/start.sh")
	sgCopyFile(t, src+"/build/version.sh", nested+"/build/version.sh")
	if err := os.WriteFile(f.log, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r := qsRun(qsBound, nested+"/deploy", f.env, "", "sh", "start.sh")
	if got := f.calls(t); r.code != 1 || got != "" {
		t.Errorf("start.sh of a folder inside the checkout: exit %d; want 1 and no docker command; docker got:\n%s\n%s", r.code, got, r)
	}
}

// Correct: OSK_UNVERIFIED does not reach the start.sh that an update runs, so the verified release builds as its version.
func TestStartUpdateDoesNotPassOnUnverifiedSwitch(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", nil)
	r := f.start(t, []string{"OSK_UNVERIFIED=1"}, "update")
	if got := f.calls(t); r.code != 0 || got != sgBuilt("0.2.0") {
		t.Errorf("OSK_UNVERIFIED=1 start.sh update: exit %d; docker got:\n%s\nwant:\n%s\n%s", r.code, got, sgBuilt("0.2.0"), r)
	}
}

// Correct: a tag that someone moves on the remote cannot erase the record of the installed release; a later update still moves to a newer signed release, and start.sh never advises an older one.
func TestStartMovedInstalledTagDoesNotStrandCopy(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", nil)
	if r := f.start(t, nil, "update"); r.code != 0 {
		t.Fatal(r)
	}
	// Someone who can push, but has no key, moves the tag of the installed
	// release; the next update brings it, forced, into refs/osk-dns-watcher/fetched.
	f.commit(t, "junk", nil)
	f.git(t, f.work, "tag", "-f", "v0.2.0")
	f.git(t, f.work, "push", "-q", "--force", "origin", "main", "v0.2.0")
	if r := f.start(t, nil, "update"); r.code != 0 {
		t.Fatal(r)
	}
	f.release(t, "owner", "v0.3.0", nil)
	r := f.start(t, nil, "update")
	if got, want := f.head(t), f.commitOf(t, "v0.3.0"); r.code != 0 || got != want {
		t.Errorf("start.sh update: exit %d, copy at %s; want 0 and v0.3.0 at %s:\n%s", r.code, got, want, r)
	}
	if old := f.commitOf(t, "v0.1.0"); strings.Contains(r.stderr, "git checkout v0.1.0") || strings.Contains(r.stderr, "git checkout "+old) {
		t.Errorf("start.sh advises the older release v0.1.0 to a copy that runs v0.2.0:\n%s", r)
	}
}

// Correct: a tag that the owner's key signed for another project is not an osk-dns-watcher release, so the update does not check it out.
func TestStartUpdateRefusesSignedTagOfAnotherProject(t *testing.T) {
	f := sgSetup(t)
	// Another project of the owner, whose tags the same key signs.
	foreign := f.dir + "/foreign"
	sgCopyText(t, foreign+"/deploy/start.sh", "echo foreign-code-ran\n")
	f.git(t, foreign, "init", "-q", "-b", "main")
	f.git(t, foreign, "add", "-A")
	f.git(t, foreign, "commit", "-qm", "another project")
	f.git(t, foreign, "-c", "gpg.format=ssh", "-c", "user.signingkey="+f.dir+"/owner", "tag", "-s", "-m", "other 2.0.0", "v2.0.0")
	// Someone who can push copies that tag, and its commit, to the remote of osk-dns-watcher.
	f.git(t, foreign, "push", "-q", f.dir+"/remote.git", "v2.0.0")
	before := f.head(t)
	r := f.start(t, nil, "update")
	if got := f.head(t); got != before || strings.Contains(r.stdout+r.stderr, "foreign-code-ran") {
		t.Errorf("start.sh update moved the copy from %s to %s, the commit of another project:\n%s", before, got, r)
	}
}

// Correct: following the advice of start.sh reaches the commit that it verified, whatever refs of that name the copy holds.
func TestStartNotAtReleaseAdviceLeadsToVerifiedCommit(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", nil)
	verified := f.commitOf(t, "v0.2.0")
	if r := f.start(t, nil, "update"); r.code != 0 {
		t.Fatal(r)
	}
	// The owner's branch goes on past the release.
	f.commit(t, "three", nil)
	f.git(t, f.work, "push", "-q", "origin", "main")
	// Someone who can push, but has no key, moves the tag v0.2.0 to a commit of theirs.
	f.git(t, f.work, "checkout", "-q", "-b", "side", verified)
	f.commit(t, "evil", nil)
	evil := strings.TrimSpace(f.git(t, f.work, "rev-parse", "HEAD"))
	f.git(t, f.work, "tag", "-f", "v0.2.0")
	f.git(t, f.work, "push", "-q", "--force", "origin", "side", "v0.2.0")
	f.git(t, f.work, "checkout", "-q", "main")
	// The user fetches the tags (as start.sh advises in another case) and
	// is on the branch, off a release.
	f.git(t, f.copy, "fetch", "-q", "--tags")
	f.git(t, f.copy, "checkout", "-q", "--detach", "origin/main")
	r := f.start(t, nil)
	i := strings.Index(r.stderr, "git checkout ")
	if r.code != 1 || i < 0 {
		t.Fatalf("start.sh off a release: exit %d; want 1 and advice to check out a release:\n%s", r.code, r)
	}
	advice := strings.Fields(strings.SplitN(r.stderr[i+len("git checkout "):], "\n", 2)[0])
	f.git(t, f.copy, append([]string{"checkout", "-q"}, advice...)...)
	if got := f.head(t); got != verified {
		t.Errorf("git checkout %s, as advised, leads to %s (the commit of someone without the key: %v), not to the verified v0.2.0 at %s",
			strings.Join(advice, " "), got, got == evil, verified)
	}
}

// Correct: a ref that the remote has removed, kept in refs/osk-dns-watcher/fetched, cannot make every later fetch fail.
func TestStartStaleFetchedTagDoesNotFreezeUpdates(t *testing.T) {
	f := sgSetup(t)
	f.git(t, f.work, "tag", "zz", "v0.1.0^{commit}")
	f.git(t, f.work, "push", "-q", "origin", "zz")
	if r := f.start(t, nil, "update"); r.code != 0 {
		t.Fatal(r)
	}
	// The same pusher removes zz and pushes zz/a, which the stale
	// refs/osk-dns-watcher/fetched/zz blocks.
	f.git(t, f.work, "push", "-q", "origin", ":refs/tags/zz")
	f.git(t, f.work, "tag", "-d", "zz")
	f.git(t, f.work, "tag", "zz/a", "v0.1.0^{commit}")
	f.git(t, f.work, "push", "-q", "origin", "refs/tags/zz/a")
	f.release(t, "owner", "v0.2.0", nil)
	r := f.start(t, nil, "update")
	if got, want := f.head(t), f.commitOf(t, "v0.2.0"); r.code != 0 || got != want {
		t.Errorf("start.sh update: exit %d, copy at %s; want 0 and v0.2.0 at %s:\n%s", r.code, got, want, r)
	}
}

// Correct: start.sh builds with every git that it accepts (2.34 and later), or it asks for the version that its scripts need.
func TestStartWorksWithOldestAcceptedGit(t *testing.T) {
	f := sgSetup(t)
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	// git 2.34 and 2.35 have no "git ls-tree --format".
	stub := "#!/bin/sh\n[ \"$1\" != --version ] || { echo 'git version 2.34.1'; exit 0; }\n" +
		"case \" $* \" in *\" ls-tree \"*\" --format=\"*) echo 'error: unknown option format' >&2; exit 129 ;; esac\n" +
		"exec '" + gitPath + "' \"$@\"\n"
	if err := os.WriteFile(f.dir+"/bin/git", []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	r := f.start(t, nil)
	calls := f.calls(t)
	built := r.code == 0 && calls == sgBuilt("0.1.0")
	asked := r.code == 1 && strings.Contains(r.stderr, "this is git 2.34.1") && calls == ""
	if !built && !asked {
		t.Errorf("start.sh with git 2.34.1: exit %d; want the build of 0.1.0, or a stop that names the git version; docker got:\n%s\n%s", r.code, calls, r)
	}
}

// Correct: start.sh removes only its own temporary files and folders, whatever TMPDIR holds.
func TestStartTemporaryFolderRemovalStaysInside(t *testing.T) {
	f := sgSetup(t)
	tmp := f.dir + "/my tmp"
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := f.dir + "/my/keep"
	sgCopyText(t, keep, "keep\n")
	r := f.start(t, []string{"TMPDIR=" + tmp})
	if r.code != 0 {
		t.Fatal(r)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("start.sh with TMPDIR=%q removed %s: %v", tmp, f.dir+"/my", err)
	}
}

// Correct: when OSK_COMPOSE_EXTRA adds a Compose file to the verified release, start.sh says so.
func TestStartComposeExtraIsShown(t *testing.T) {
	f := sgSetup(t)
	extra := f.dir + "/extra.yaml"
	qsWrite(t, extra, "services:\n  watcher:\n    privileged: true\n")
	r := f.start(t, []string{"OSK_COMPOSE_EXTRA=" + extra})
	if !strings.Contains(r.stdout+r.stderr, "OSK_COMPOSE_EXTRA") {
		t.Errorf("start.sh ran the release with the extra Compose file %s and did not say so (exit %d):\n%s", extra, r.code, r)
	}
}

// Correct: label numbers order as numbers, also with a leading zero (or such a label is not a release): rc.9 is above rc.01.
func TestStartUpdateOrdersLabelNumbersWithLeadingZero(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0-rc.9", nil)
	f.release(t, "owner", "v0.2.0-rc.01", nil)
	r := f.start(t, nil, "update")
	if got, want := f.head(t), f.commitOf(t, "v0.2.0-rc.9"); r.code != 0 || got != want {
		t.Errorf("start.sh update: exit %d, copy at %s; want v0.2.0-rc.9 at %s:\n%s", r.code, got, want, r)
	}
}

// rvFirstCopyBlock gives the fenced block of release/README.md that starts a
// first copy with "git clone --no-checkout", and the URL that it clones.
func rvFirstCopyBlock(t *testing.T) (block, url string) {
	t.Helper()
	data, err := os.ReadFile(sgSrc(t) + "/release/README.md")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "```") {
			continue
		}
		j := i + 1
		for j < len(lines) && !strings.HasPrefix(lines[j], "```") {
			j++
		}
		if b := strings.Join(lines[i+1:j], "\n"); strings.Contains(b, "git clone --no-checkout ") {
			found = append(found, b+"\n")
		}
		i = j
	}
	if len(found) != 1 {
		t.Fatalf("release/README.md has %d blocks with git clone --no-checkout, want 1", len(found))
	}
	rest := found[0][strings.Index(found[0], "git clone --no-checkout ")+len("git clone --no-checkout "):]
	return found[0], strings.Fields(rest)[0]
}

// Correct: the steps that release/README.md gives for a first copy run no file of a commit whose tag the owner did not sign.
func TestVerifyFirstCopyStepsCheckTheTag(t *testing.T) {
	f := sgSetup(t)
	// Someone who can push, but has no key, moves v0.1.0 to a commit that
	// keeps the owner's key file, so its fingerprint is the published one,
	// and holds a start.sh of theirs.
	f.git(t, f.work, "checkout", "-q", "-b", "evil")
	if err := os.WriteFile(f.work+"/deploy/start.sh", []byte("#!/bin/sh\necho attacker-code-ran\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.git(t, f.work, "commit", "-qam", "evil")
	f.git(t, f.work, "tag", "-f", "v0.1.0")
	f.git(t, f.work, "push", "-q", "--force", "origin", "v0.1.0")
	// A stranger types the steps of the document; its URL leads to the
	// remote of the test.
	block, url := rvFirstCopyBlock(t)
	config, err := os.ReadFile(f.dir + "/gitconfig")
	if err != nil {
		t.Fatal(err)
	}
	qsWrite(t, f.dir+"/gitconfig", string(config)+"[url \"file://"+f.dir+"/remote.git\"]\n\tinsteadOf = "+url+"\n")
	stranger := f.dir + "/stranger"
	sgCopyText(t, stranger+"/first.sh", block)
	r := qsRun(qsBound, stranger, f.env, "", "sh", "-e", "first.sh")
	if strings.Contains(r.stdout+r.stderr, "attacker-code-ran") {
		t.Errorf("the first-copy steps of release/README.md ran the start.sh of a commit whose tag the owner did not sign:\n%s", r)
	}
}

// Correct: following the advice of start.sh once gives a copy that start.sh builds; it never names the commit that the copy is at.
func TestStartAdviceLeadsToACopyThatStarts(t *testing.T) {
	f := sgSetup(t)
	if r := f.start(t, nil); r.code != 0 {
		t.Fatal(r)
	}
	f.release(t, "owner", "v0.2.0", nil)
	// The user moves the copy by hand to the new signed release, as git
	// users do (or start.sh update stopped between its checkout and its record).
	f.git(t, f.copy, "fetch", "-q", "--tags")
	f.git(t, f.copy, "checkout", "-q", "v0.2.0")
	r := f.start(t, nil)
	if r.code != 0 {
		i := strings.Index(r.stderr, "git checkout ")
		if i < 0 {
			t.Fatalf("start.sh after a checkout by hand: exit %d and no advice:\n%s", r.code, r)
		}
		advice := strings.Fields(strings.SplitN(r.stderr[i+len("git checkout "):], "\n", 2)[0])
		f.git(t, f.copy, append([]string{"checkout", "-q"}, advice...)...)
		r = f.start(t, nil)
	}
	if got := f.calls(t); r.code != 0 || (got != sgBuilt("0.1.0") && got != sgBuilt("0.2.0")) {
		t.Errorf("start.sh after following its advice: exit %d; want the build of 0.1.0 or 0.2.0; docker got:\n%s\n%s", r.code, got, r)
	}
}

// Correct: a release whose tree holds a file name that git quotes (here one with a non-ASCII letter) builds.
func TestStartExportTakesQuotedFileNames(t *testing.T) {
	f := sgSetup(t)
	f.release(t, "owner", "v0.2.0", func() { qsWrite(t, f.work+"/caf\u00e9.txt", "x\n") })
	r := f.start(t, nil, "update")
	if got := f.calls(t); r.code != 0 || got != sgBuilt("0.2.0") {
		t.Errorf("start.sh update to a release with the file caf\u00e9.txt: exit %d; docker got:\n%s\n%s", r.code, got, r)
	}
}
