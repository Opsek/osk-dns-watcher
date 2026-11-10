#!/bin/sh
# Shows that the checks of the repository can fail. Each case copies the
# repository, puts one fault into the copy, runs the checks that must catch it
# and requires the line of the right check; the unchanged repository must
# pass. Run from the repository root inside the build container.
# Prints "ok <case>" or "FAIL <case>: <why>"; exits 0 only if every case
# behaved as required.
set -u

# Without -o the binary would land in the repository, which may be read-only.
# VCS stamping fails when .git belongs to another user, as on a mount.
build_archcheck() { # build_archcheck <binary>
	go build -mod=vendor -buildvcs=false -o "$1" ./gate/archcheck
}

# Each run_<command> runs a check on a copy.

# From outside the copy, so that only --root can lead to it.
run_archcheck() {
	(cd "$TMP" && "$ARCHCHECK" --root "$1")
}

run_static() {
	(cd "$1" && sh gate/phase/static.sh)
}

run_tests() {
	(cd "$1" && sh gate/phase/tests.sh)
}

# As the tests phase of gate/bin/gate runs the fuzz tests, but short.
run_fuzz() {
	(
		cd "$1" && list=$(sh gate/phase/fuzz.sh) || exit
		set -- $list
		while [ $# -ge 2 ]; do
			FUZZTIME=1s sh gate/phase/fuzz.sh "$1" "$2" >/dev/null || exit
			shift 2
		done
	)
}

# The planted lab tests need no lab: they run here, from the binary that the
# lab phase of gate/bin/gate would run in the runner.
run_labtests() {
	(
		cd "$1" && list=$(sh gate/phase/labtests.sh) || exit
		set -- $list
		while [ $# -ge 2 ]; do
			sh gate/phase/labtests.sh "$1" >"$TMP/lab.test" && chmod +x "$TMP/lab.test" &&
				(cd "$1" && "$TMP/lab.test" -test.run '^TestZz') || exit
			shift 2
		done
	)
}

# Every phase script, in a container that lacks the file that marks the build
# container.
run_outside() {
	mv /etc/osk-gate /etc/osk-gate.hidden || return 2
	status=0
	for phase in "$1"/gate/phase/*.sh; do
		(cd "$1" && sh "gate/phase/${phase##*/}") || status=$?
	done
	mv /etc/osk-gate.hidden /etc/osk-gate || return 2
	return "$status"
}

ROOT=$(pwd)
MOD=$(sed -n 's/^module //p' go.mod)
TMP=${TMPDIR:-/tmp}/osk-selftest.$$
mkdir -m 700 "$TMP" || exit 1
trap 'rm -rf "$TMP"' EXIT
trap 'exit 1' INT TERM
CLEAN=$TMP/clean
COPY=$TMP/repo
ARCHCHECK=$TMP/archcheck
bad=0

if ! build_archcheck "$ARCHCHECK"; then
	echo "FAIL selftest: gate/archcheck does not build"
	exit 1
fi
# Every case starts from this copy. Without .git, no check can depend on it.
if ! cp -R "$ROOT" "$CLEAN" || ! rm -rf "$CLEAN/.git" "$CLEAN/out" || ! mkdir "$CLEAN/out"; then
	echo "FAIL selftest: cannot copy the repository"
	exit 1
fi

fail() {
	echo "FAIL $1: $2"
	bad=1
}

# hint <output>: the first FAIL line of the output, or else its last line.
hint() {
	h=$(printf '%s\n' "$1" | grep '^FAIL' | head -n 1)
	[ -n "$h" ] || h=$(printf '%s\n' "$1" | tail -n 1)
	printf '%s' "$h"
}

# check <case> <fault> <command> <want> [<text>]
# <fault> is a command, with its arguments, that puts the fault into the copy.
# <want> is one of:
#   pass               exit 0 and no line that starts with FAIL;
#   "ok <check>"       that line: the check ran and passed;
#   "--- FAIL: <test>" a non-zero exit, that line of a Go test, and <text>
#                      in the output;
#   <check>            exit 1 and a line "FAIL <check>: <reason>" whose
#                      reason holds <text>.
check() {
	name=$1 fault=$2 cmd=$3 want=$4 text=${5:-}
	rm -rf "$COPY"
	if ! cp -R "$CLEAN" "$COPY"; then
		fail "$name" "cannot copy the repository"
		return
	fi
	if ! (cd "$COPY" && $fault); then
		fail "$name" "cannot put the fault into the copy"
		return
	fi
	out=$(run_$cmd "$COPY" 2>&1)
	rc=$?
	case $want in
	pass)
		if [ "$rc" -ne 0 ] || printf '%s\n' "$out" | grep -q '^FAIL'; then
			fail "$name" "must pass, got exit $rc: $(hint "$out")"
			return
		fi
		;;
	'ok '*)
		if ! printf '%s\n' "$out" | grep -qxF -- "$want"; then
			fail "$name" "no line \"$want\": $(hint "$out")"
			return
		fi
		;;
	'--- FAIL: '*)
		if [ "$rc" -eq 0 ] || ! printf '%s\n' "$out" | grep -q "^$want " ||
			! printf '%s\n' "$out" | grep -qF -- "$text"; then
			fail "$name" "want a failed run with \"$want\" and \"$text\", got exit $rc: $(hint "$out")"
			return
		fi
		;;
	*)
		if [ "$rc" -ne 1 ]; then
			fail "$name" "exit $rc, want 1: $(hint "$out")"
			return
		fi
		if ! printf '%s\n' "$out" | grep "^FAIL $want: " | grep -qF -- "$text"; then
			fail "$name" "no line \"FAIL $want: ...\" holds $text: $(hint "$out")"
			return
		fi
		;;
	esac
	echo "ok $name"
}

# ---- Helpers for the faults. They run in the root of the copy. ----

# put <file>: writes standard input to a new file.
put() {
	[ ! -e "$1" ] && mkdir -p "$(dirname "$1")" && cat > "$1"
}

# append <file> <line>: appends a line to a file that exists, also when its
# last line has no newline.
append() {
	[ -f "$1" ] || return 1
	[ -z "$(tail -c 1 "$1")" ] || echo >> "$1"
	printf '%s\n' "$2" >> "$1"
}

# link <folder>: the tool imports the package in the folder.
link() {
	put cmd/osk/zzlink.go <<EOF
package main

import _ "$MOD/$1"
EOF
}

# listener <file>, starter <file>: a package with a listening socket, or one
# that starts an external program.
listener() {
	put "$1" <<'EOF'
package zzfault

import "net"

func Fault() error {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	return l.Close()
}
EOF
}

starter() {
	put "$1" <<'EOF'
package zzfault

import "os/exec"

func Fault() error {
	return exec.Command("true").Run()
}
EOF
}

# plain <file>: a package with nothing wrong in it.
plain() {
	put "$1" <<'EOF'
package zzfault

const Fault = 1
EOF
}

# ---- Faults for archcheck ----

none() {
	:
}

thirdparty_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import "golang.org/x/net/dns/dnsmessage"

var Parser dnsmessage.Parser
EOF
}

thirdparty_build_tag() {
	put internal/zzfault/zzfault.go <<'EOF'
//go:build zzfault

package zzfault

import "golang.org/x/net/dns/dnsmessage"

var Parser dnsmessage.Parser
EOF
}

thirdparty_test_like_name() {
	put internal/zzfault/zzfault_test_util.go <<'EOF'
package zzfault

import "golang.org/x/net/dns/dnsmessage"

var Parser dnsmessage.Parser
EOF
}

sqlite_prefix_twin() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import _ "github.com/mattn/go-sqlite3x"
EOF
}

gomod_second_require() {
	append go.mod 'require golang.org/x/net v0.30.0'
}

gomod_require_block() {
	append go.mod 'require (' &&
		append go.mod '	golang.org/x/net v0.30.0 // indirect' &&
		append go.mod ')'
}

vendor_extra_module() {
	append vendor/modules.txt '# golang.org/x/net v0.30.0' &&
		append vendor/modules.txt '## explicit; go 1.18' &&
		append vendor/modules.txt 'golang.org/x/net/dns/dnsmessage'
}

net_listen() {
	listener internal/zzfault/zzfault.go
}

net_listenconfig() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import (
	"context"
	"net"
)

func Fault() error {
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	return l.Close()
}
EOF
}

net_alias_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import n "net"

func Fault() error {
	l, err := n.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	return l.Close()
}
EOF
}

net_dot_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import . "net"

func Fault() error {
	c, err := ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	return c.Close()
}
EOF
}

http_listenandserve() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import "net/http"

func Fault() error {
	return http.ListenAndServe("127.0.0.1:8080", nil)
}
EOF
}

http_serve() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import "net/http"

func Fault() error {
	return http.Serve(nil, nil)
}
EOF
}

http_server_struct() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import "net/http"

func Fault() error {
	srv := &http.Server{Addr: "127.0.0.1:8080"}
	return srv.ListenAndServe()
}
EOF
}

httptest_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import "net/http/httptest"

const Addr = httptest.DefaultRemoteAddr
EOF
}

tls_listen() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import "crypto/tls"

func Fault(config *tls.Config) error {
	l, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		return err
	}
	return l.Close()
}
EOF
}

tls_newlistener() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import (
	"crypto/tls"
	"net"
)

func Fault(inner net.Listener, config *tls.Config) net.Listener {
	return tls.NewListener(inner, config)
}
EOF
}

exec_in_main() {
	put cmd/osk/zzfault.go <<'EOF'
package main

import "os/exec"

func zzfault() error {
	return exec.Command("true").Run()
}
EOF
}

exec_alias_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import x "os/exec"

func Fault() error {
	return x.Command("true").Run()
}
EOF
}

exec_blank_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import _ "os/exec"
EOF
}

plugin_blank_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import _ "plugin"
EOF
}

os_startprocess() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import "os"

func Fault() error {
	_, err := os.StartProcess("/bin/true", []string{"true"}, &os.ProcAttr{})
	return err
}
EOF
}

os_startprocess_dot_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import . "os"

func Fault() error {
	_, err := StartProcess("/bin/true", []string{"true"}, &ProcAttr{})
	return err
}
EOF
}

syscall_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import "syscall"

func Fault() int {
	return syscall.Getpid()
}
EOF
}

syscall_alias_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import sc "syscall"

func Fault() int {
	return sc.Getpid()
}
EOF
}

syscall_blank_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import _ "syscall"
EOF
}

unsafe_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import "unsafe"

var Size = unsafe.Sizeof(0)
EOF
}

unsafe_blank_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

import _ "unsafe"
EOF
}

cgo_import() {
	put internal/zzfault/zzfault.go <<'EOF'
package zzfault

// #include <unistd.h>
import "C"

func Fault() int {
	return int(C.getpid())
}
EOF
}

# The tool imports a package outside cmd/ and internal/, or in a folder that
# "go build ./..." skips, so that no check but the build sees it.

layout_gate() {
	listener gate/zzfault/zzfault.go && link gate/zzfault
}

layout_top_folder() {
	starter zzfault/zzfault.go && link zzfault
}

layout_underscore() {
	listener internal/_zzfault/zzfault.go && link internal/_zzfault
}

layout_testdata() {
	starter internal/store/testdata/zzfault/zzfault.go && link internal/store/testdata/zzfault
}

# other_source <extension>: a file that the go command would compile or link
# into a package of the tool.
other_source() {
	plain internal/zzfault/zzfault.go &&
		echo '// zzfault' | put "internal/zzfault/zzfault.$1" && link internal/zzfault
}

# system_name <GOOS or GOARCH>: a file that only that system builds.
system_name() {
	plain internal/zzfault/zzfault.go &&
		plain "internal/zzfault/zzfault_$1.go" && link internal/zzfault
}

build_constraint() {
	put internal/zzfault/zzfault.go <<'EOF' && link internal/zzfault
//go:build linux

package zzfault

const Fault = 1
EOF
}

# A test file is not part of the tool.
test_file_constraint() {
	put internal/store/zzfault_linux_test.go <<'EOF'
//go:build lab

package store
EOF
}

# A package that the tool does not import is not part of it.
unreached_constraint() {
	put internal/zzfault/zzfault_linux.go <<'EOF'
//go:build lab

package zzfault

const Fault = 1
EOF
}

# Import rules. Each case brings its own line and packages.

rule_direct() {
	append gate/imports.txt "$MOD/internal/zzfault/a must-not-import $MOD/internal/zzfault/b" || return 1
	put internal/zzfault/b/b.go <<'EOF' || return 1
package b

const Value = 1
EOF
	put internal/zzfault/a/a.go <<EOF
package a

import "$MOD/internal/zzfault/b"

const Value = b.Value
EOF
}

rule_transitive() {
	append gate/imports.txt "$MOD/internal/zzfault/a must-not-import net" || return 1
	put internal/zzfault/b/b.go <<'EOF' || return 1
package b

import "net"

func Valid(s string) bool {
	return net.ParseIP(s) != nil
}
EOF
	put internal/zzfault/a/a.go <<EOF
package a

import "$MOD/internal/zzfault/b"

func Valid(s string) bool {
	return b.Valid(s)
}
EOF
}

rule_only() {
	append gate/imports.txt "only $MOD/internal/zzfault/a/... may-import $MOD/internal/zzfault/c/..." || return 1
	put internal/zzfault/c/c.go <<'EOF' || return 1
package c

const Value = 1
EOF
	put internal/zzfault/a/a.go <<EOF || return 1
package a

import "$MOD/internal/zzfault/c"

const Value = c.Value
EOF
	put internal/zzfault/b/b.go <<EOF
package b

import "$MOD/internal/zzfault/c"

const Value = c.Value
EOF
}

rule_unknown_package() {
	append gate/imports.txt "$MOD/internal/zzfault/... must-not-import net"
}

# The constructs of the cases above, in a test file of a package in scope.
test_file_constructs() {
	put cmd/osk/zzfault_test.go <<'EOF'
package main

import (
	"crypto/tls"
	"database/sql"
	. "net"
	"net/http"
	"net/http/httptest"
	"os"
	x "os/exec"
	_ "plugin"
	sc "syscall"
	"testing"
	"unsafe"
)

func TestFault(t *testing.T) {
	l, err := Listen("tcp", "127.0.0.1:0")
	if err == nil {
		l.Close()
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	_ = http.ListenAndServe
	_ = tls.NewListener
	_ = x.Command("true")
	_ = os.StartProcess
	_ = sc.Getpid()
	_ = unsafe.Sizeof(0)
	_ = sql.Drivers()
}
EOF
}

# Folders that only a test imports are not part of the tool.
test_file_imports() {
	listener gate/zzfault/zzfault.go &&
		starter _zzfault/zzfault.go &&
		listener testdata/zzfault/zzfault.go &&
		put cmd/osk/zzlink_test.go <<EOF
package main

import (
	_ "$MOD/_zzfault"
	_ "$MOD/gate/zzfault"
	_ "$MOD/testdata/zzfault"
)
EOF
}

# ---- Faults for the phase scripts ----
# Each one is valid Go that only its own tool rejects. The lab files sit in a
# package with ordinary files, so the untagged runs still find the package.

format_plain() {
	put internal/store/zzfault.go <<'EOF'
package store

func ZzFault(n int) int {
return n
}
EOF
}

format_lab() {
	put internal/store/zzfault_lab_test.go <<'EOF'
//go:build lab

package store

import "testing"

func TestZzFault(t *testing.T) {
t.Log("zzfault")
}
EOF
}

vendor_extra_file() {
	plain vendor/github.com/mattn/go-sqlite3/zzfault.go
}

vendor_changed_file() {
	append vendor/github.com/mattn/go-sqlite3/doc.go '// zzfault'
}

# A sum in go.sum that the module in the image does not have.
gosum_changed() {
	sed 's/h1:mnTM0ow/h1:AAAA0ow/' go.sum > go.sum.new && mv go.sum.new go.sum &&
		! grep -q h1:mnTM0ow go.sum
}

vet_plain() {
	put internal/store/zzfault.go <<'EOF'
package store

import (
	"fmt"
	"sync"
)

func ZzFault() string {
	var mu sync.Mutex
	return fmt.Sprint(mu)
}
EOF
}

vet_lab() {
	put internal/store/zzfault_lab_test.go <<'EOF'
//go:build lab

package store

import (
	"sync"
	"testing"
)

func TestZzFault(t *testing.T) {
	var mu sync.Mutex
	t.Log(mu)
}
EOF
}

errcheck_plain() {
	put internal/store/zzfault.go <<'EOF'
package store

import "os"

func ZzFault(path string) {
	os.Remove(path)
}
EOF
}

errcheck_lab() {
	put internal/store/zzfault_lab_test.go <<'EOF'
//go:build lab

package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestZzFault(t *testing.T) {
	os.Remove(filepath.Join(t.TempDir(), "zzfault"))
}
EOF
}

# In a folder outside cmd/ and internal/ that nothing imports.
errcheck_any_folder() {
	put zzfault/zzfault.go <<'EOF'
package zzfault

import "os"

func Fault(path string) {
	os.Remove(path)
}
EOF
}

staticcheck_plain() {
	put internal/store/zzfault.go <<'EOF'
package store

func ZzFault(b bool) bool {
	if b == true {
		return true
	}
	return false
}
EOF
}

staticcheck_lab() {
	put internal/store/zzfault_lab_test.go <<'EOF'
//go:build lab

package store

func ZzFault(b bool) bool {
	if b == true {
		return true
	}
	return false
}
EOF
}

exhaustive_plain() {
	put internal/store/zzfault.go <<'EOF'
package store

type ZzColor int

const (
	ZzRed ZzColor = iota
	ZzBlue
)

func ZzName(c ZzColor) string {
	switch c {
	case ZzRed:
		return "red"
	}
	return ""
}
EOF
}

exhaustive_lab() {
	put internal/store/zzfault_lab_test.go <<'EOF'
//go:build lab

package store

import "testing"

type ZzColor int

const (
	ZzRed ZzColor = iota
	ZzBlue
)

func TestZzFault(t *testing.T) {
	switch ZzColor(len(t.Name()) % 2) {
	case ZzRed:
		t.Log("red")
	}
}
EOF
}

# constraint [<expression>]: the build constraint line of a new file, if any.
constraint() {
	[ -z "${1:-}" ] || printf '//go:build %s\n\n' "$1"
}

# racy <file> [<build constraint>]: a test that passes without -race.
racy() {
	{
		constraint "${2:-}"
		cat <<'EOF'
package store

import "testing"

func TestZzFault(t *testing.T) {
	n := 0
	done := make(chan struct{})
	go func() {
		n++
		close(done)
	}()
	n++
	<-done
	t.Log(n)
}
EOF
	} | put "$1"
}

# A test that fails when it ran before, after one run that leaves its result
# in the build cache. The test cache does not see files that a test opens
# through syscall. The test logs a new value on each self-test, or the first
# run could come from the cache of an earlier self-test.
second_run_fails() {
	put internal/store/zzfault_test.go <<EOF && go test -json -race ./internal/store >/dev/null
package store

import (
	"syscall"
	"testing"
)

func TestZzFault(t *testing.T) {
	t.Log("$(cat /proc/sys/kernel/random/uuid)")
	fd, err := syscall.Open("../../out/zzfault-ran", syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal("this test ran before:", err)
	}
	if err := syscall.Close(fd); err != nil {
		t.Fatal(err)
	}
}
EOF
}

# fuzz_test <file> [<build constraint>]
fuzz_test() {
	{
		constraint "${2:-}"
		cat <<'EOF'
package store

import "testing"

func FuzzZzFault(f *testing.F) {
	f.Add("zzfault")
	f.Fuzz(func(t *testing.T, s string) {})
}
EOF
	} | put "$1"
}

lab_test() {
	put internal/store/zzfault_lab_test.go <<'EOF'
//go:build lab

package store

import "testing"

func TestZzFault(t *testing.T) {
	t.Log("needs no lab")
}
EOF
}

# ---- Cases ----

Z=internal/zzfault/zzfault.go
L=internal/store/zzfault_lab_test.go

check arch-clean                    none                       archcheck pass
check arch-test-file-constructs     test_file_constructs       archcheck pass
check arch-test-file-imports        test_file_imports          archcheck pass

check layout-gate                   layout_gate                archcheck plain-layout "$MOD/gate/zzfault,"
check layout-top-folder             layout_top_folder          archcheck plain-layout "$MOD/zzfault,"
check layout-underscore             layout_underscore          archcheck plain-layout "$MOD/internal/_zzfault,"
check layout-testdata               layout_testdata            archcheck plain-layout "$MOD/internal/store/testdata/zzfault,"
check layout-asm                    'other_source s'           archcheck plain-layout internal/zzfault/zzfault.s
check layout-asm-cpp                'other_source S'           archcheck plain-layout internal/zzfault/zzfault.S
check layout-c                      'other_source c'           archcheck plain-layout internal/zzfault/zzfault.c
check layout-c-header               'other_source h'           archcheck plain-layout internal/zzfault/zzfault.h
check layout-syso                   'other_source syso'        archcheck plain-layout internal/zzfault/zzfault.syso
check layout-goos-name              'system_name linux'        archcheck plain-layout internal/zzfault/zzfault_linux.go
check layout-goarch-name            'system_name amd64'        archcheck plain-layout internal/zzfault/zzfault_amd64.go
check layout-build-constraint       build_constraint           archcheck plain-layout "$Z:1"
check layout-test-file-constraint   test_file_constraint       archcheck pass
check layout-unreached-constraint   unreached_constraint       archcheck pass

check std-thirdparty-import         thirdparty_import          archcheck only-std-and-sqlite $Z
check std-thirdparty-build-tag      thirdparty_build_tag       archcheck only-std-and-sqlite $Z
check std-thirdparty-test-like-name thirdparty_test_like_name  archcheck only-std-and-sqlite internal/zzfault/zzfault_test_util.go
check std-sqlite-prefix-twin        sqlite_prefix_twin         archcheck only-std-and-sqlite $Z
check std-gomod-second-require      gomod_second_require       archcheck only-std-and-sqlite go.mod
check std-gomod-require-block       gomod_require_block        archcheck only-std-and-sqlite go.mod
check std-vendor-extra-module       vendor_extra_module        archcheck only-std-and-sqlite vendor/modules.txt

check listener-net-listen           net_listen                 archcheck no-listener $Z
check listener-net-listenconfig     net_listenconfig           archcheck no-listener $Z
check listener-net-alias-import     net_alias_import           archcheck no-listener $Z
check listener-net-dot-import       net_dot_import             archcheck no-listener $Z
check listener-http-listenandserve  http_listenandserve        archcheck no-listener $Z
check listener-http-serve           http_serve                 archcheck no-listener $Z
check listener-http-server-struct   http_server_struct         archcheck no-listener $Z
check listener-httptest-import      httptest_import            archcheck no-listener $Z
check listener-tls-listen           tls_listen                 archcheck no-listener $Z
check listener-tls-newlistener      tls_newlistener            archcheck no-listener $Z

check exec-in-main                  exec_in_main               archcheck no-exec cmd/osk/zzfault.go
check exec-alias-import             exec_alias_import          archcheck no-exec $Z
check exec-blank-import             exec_blank_import          archcheck no-exec $Z
check exec-plugin-blank-import      plugin_blank_import        archcheck no-exec $Z
check exec-os-startprocess          os_startprocess            archcheck no-exec $Z
check exec-os-dot-import            os_startprocess_dot_import archcheck no-exec $Z

check syscall-import                syscall_import             archcheck no-exec $Z
check syscall-alias-import          syscall_alias_import       archcheck no-exec $Z
check syscall-blank-import          syscall_blank_import       archcheck no-exec $Z
check syscall-not-under-no-listener syscall_import             archcheck 'ok no-listener'

check unsafe-import                 unsafe_import              archcheck no-unsafe $Z
check unsafe-blank-import           unsafe_blank_import        archcheck no-unsafe $Z
check unsafe-cgo-import             cgo_import                 archcheck no-unsafe $Z

check import-rules-direct           rule_direct                archcheck import-rules internal/zzfault/a/a.go
check import-rules-transitive       rule_transitive            archcheck import-rules internal/zzfault/b/b.go
check import-rules-only             rule_only                  archcheck import-rules internal/zzfault/b/b.go
check import-rules-unknown-package  rule_unknown_package       archcheck import-rules gate/imports.txt:3

check phase-clean-static            none                       static pass
check format-plain                  format_plain               static gofmt internal/store/zzfault.go
check format-lab                    format_lab                 static gofmt $L
check vendor-extra-file             vendor_extra_file          static vendor differs
check vendor-changed-file           vendor_changed_file        static vendor differs
check vendor-gosum-changed          gosum_changed              static vendor 'go mod vendor failed'
check vet-plain                     vet_plain                  static go-vet
check vet-lab                       vet_lab                    static go-vet-lab
check errcheck-plain                errcheck_plain             static errcheck
check errcheck-lab                  errcheck_lab               static errcheck-lab
check errcheck-any-folder           errcheck_any_folder        static errcheck
check staticcheck-plain             staticcheck_plain          static staticcheck
check staticcheck-lab               staticcheck_lab            static staticcheck-lab
check exhaustive-plain              exhaustive_plain           static exhaustive
check exhaustive-lab                exhaustive_lab             static exhaustive-lab

check phase-clean-tests             none                       tests pass
check race-plain                    'racy internal/store/zzfault_test.go' tests go-test-race
check tests-not-cached              second_run_fails           tests go-test-race

check fuzz-runs                     'fuzz_test internal/store/zzfault_test.go'  fuzz pass
check fuzz-not-found                "fuzz_test $L lab"         fuzz 'fuzz internal/store FuzzZzFault'

check labtests-run                  lab_test                   labtests pass
check race-lab                      "racy $L lab"              labtests '--- FAIL: TestZzFault' 'race detected'

for script in fuzz labtests static tests; do
	check "outside-container-$script" none outside build-container "gate/phase/$script.sh"
done

exit "$bad"
