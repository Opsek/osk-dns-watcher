//go:build lab

package installtest

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// imDocument holds the block of the commands that run the published image.
const imDocument = "docs/install.md"

var (
	// The block names the image once, on the line of the anchor "image",
	// and every other service of it refers to that anchor.
	imAnchor = regexp.MustCompile(`(?m)^(\s+image: &image )(\S+)$`)
	imImage  = regexp.MustCompile(`(?m)^\s+image: (.*)$`)
)

// TestReleaseImageAlerts plays a stranger who runs the published image
// without a build: it runs the block "```sh image" of imDocument against the
// lab. The block must name the image by digest, as
// OSK_IMAGE@sha256:<digest>, with the placeholder that a user replaces by the
// digest that make verify-release prints; the test runs it word for word but
// for that name, which becomes OSK_RELEASE_IMAGE, the image of the release
// under test by its digest on this engine. As for the
// quick start, the lab adds only its network, its CA and its root server,
// through a second Compose file; that file also forbids a pull, so the image
// that runs is the local one. The gate runs this test alone, in a run of its
// own, so the project of the quick start is free for it, and TestMain
// removes what it started.
func TestReleaseImageAlerts(t *testing.T) {
	qsNeed(t, false)
	image, version := os.Getenv("OSK_RELEASE_IMAGE"), os.Getenv("OSK_RELEASE")
	if image == "" || version == "" || os.Getenv("OSK_IMAGE") == "" {
		t.Skip("OSK_RELEASE_IMAGE, OSK_RELEASE or OSK_IMAGE is not set: this test runs in the quickstart phase of the gate " +
			"with OSK_RELEASE, for a release whose CONTENTS names an image")
	}
	t.Cleanup(func() {
		if r := qsRun(qsBound, "", nil, "", "docker", "exec", qsRunner(), "labctl", "reset"); r.code != 0 {
			t.Error(r)
		}
	})
	work := imPrepare(t)
	script := imScript(t, image)
	start := time.Now()
	r := qsRun(60*time.Minute, work, qsEnviron(), "corp.test\n"+qsURL()+"\nyes\n", "sh", "-eu", script)
	end := time.Now()
	if r.code != 0 {
		t.Fatal(r)
	}
	dir := filepath.Join(work, "osk-dns-watcher")

	t.Run("the commands show the setup, then the test message", func(t *testing.T) {
		qsInOrder(t, "the commands of the image", r.stdout, append(qsSetupLines(t), "test slack sent"))
		texts := qsTexts(t)
		if len(texts) != 1 {
			t.Fatalf("the receiver holds %d messages, want 1:\n%s", len(texts), strings.Join(texts, "\n----\n"))
		}
		id := ""
		if m := qsRequest.FindStringSubmatch(texts[0]); m != nil {
			id = m[1]
		}
		qsTestNotice(t, texts[0], "request   "+id, start, end)
	})

	t.Run("the service runs the release image, healthy, on the platform of the test", func(t *testing.T) {
		id := strings.TrimSpace(qsMust(t, imCompose(dir, "ps", "-q", "watcher")))
		if id == "" || strings.ContainsAny(id, " \n") {
			t.Fatalf("docker compose ps -q watcher gave %q, want the id of one running container", id)
		}
		if got := qsInspect(t, "{{.Config.Image}}", id); got != image {
			t.Errorf("the service runs the image %s, want %s", got, image)
		}
		if got := qsInspect(t, "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", id); got != "running healthy" {
			t.Errorf("the container of osk-dns-watcher is %q, want running healthy", got)
		}
		if got := qsInspect(t, "{{.Os}}/{{.Architecture}}", qsInspect(t, "{{.Image}}", id)); got != qsPlatform {
			t.Errorf("the image of osk-dns-watcher is for %s, want %s", got, qsPlatform)
		}
		if got := qsMust(t, imCompose(dir, "exec", "-T", "watcher", "osk-dns-watcher", "version")); !strings.HasPrefix(got, "osk-dns-watcher "+version+"\n") {
			t.Errorf("osk-dns-watcher version gives:\n%s\nwant first osk-dns-watcher %s", got, version)
		}
	})

	t.Run("a changed record gives one alert", func(t *testing.T) {
		base := len(qsTexts(t))
		qsLabctl(t, "set", "both", "www.corp.test.", "300", "A", qsNet()+"99")
		texts := qsWaitTexts(t, qsBound, func(texts []string) bool { return qsCount(texts[base:], qsWWWHead) > 0 })
		if n := qsCount(texts[base:], qsWWWHead); n != 1 {
			t.Errorf("within %v the receiver got %d alerts on www.corp.test. A, want 1:\n%s", qsBound, n, strings.Join(texts[base:], "\n----\n"))
		}
	})
}

// imCompose runs docker compose as the stranger would: in the folder that
// the commands made, with the environment of the quick start.
func imCompose(dir string, args ...string) qsResult {
	return qsRun(qsBound, dir, qsEnviron(), "", "docker", append([]string{"compose"}, args...)...)
}

// imPrepare makes an empty home, an empty work folder, which it gives, and
// the lab's Compose file of the quick start, with no pull.
func imPrepare(t *testing.T) string {
	t.Helper()
	work := filepath.Join(qsRoot, "image")
	for _, dir := range []string{qsRoot + "/home", work} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	qsWrite(t, qsRoot+"/lab.yaml", `services:
  watcher:
    pull_policy: never
    networks: [lab]
    environment: {SSL_CERT_DIR: /lab}
    volumes:
      - {type: volume, source: lab, target: /lab, read_only: true, volume: {subpath: ca}}
  init:
    pull_policy: never
    networks: [lab]
    command: [init, --config, /data/config.json, --root-server, "`+qsNet()+`2", --extra-range, "`+qsNet()+`0/24"]
networks:
  lab: {name: osklab`+qsLab+`_lab, external: true}
volumes:
  lab: {name: osklab`+qsLab+`_lab, external: true}
`)
	return work
}

// imScript writes the block "```sh image" of imDocument to a file, with
// image in place of the image that it names, which must be the placeholder
// OSK_IMAGE@sha256:<digest>.
func imScript(t *testing.T, image string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(qsSrc, imDocument))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	start := slices.Index(lines, "```sh image")
	if start < 0 || slices.Index(lines[start+1:], "```sh image") >= 0 {
		t.Fatalf("%s must hold the line \"```sh image\" once", imDocument)
	}
	end := slices.Index(lines[start+1:], "```")
	if end < 0 {
		t.Fatalf("the block image of %s has no end", imDocument)
	}
	block := strings.Join(lines[start+1:start+1+end], "\n") + "\n"
	want := os.Getenv("OSK_IMAGE") + "@sha256:<digest>"
	anchors := imAnchor.FindAllStringSubmatch(block, -1)
	if len(anchors) != 1 || anchors[0][2] != want {
		t.Fatalf("the block image of %s must have one line \"image: &image %s\":\n%s", imDocument, want, block)
	}
	for _, m := range imImage.FindAllStringSubmatch(block, -1) {
		if m[1] != "*image" && m[1] != "&image "+want {
			t.Fatalf("the block image of %s names the image %q; each service must refer to the anchor with \"image: *image\"", imDocument, m[1])
		}
	}
	path := filepath.Join(qsRoot, "image.sh")
	// The gate gives a name of letters, digits and . / : _ - @ only, which
	// holds no $ for the expansion to read.
	qsWrite(t, path, imAnchor.ReplaceAllString(block, "${1}"+image))
	return path
}
