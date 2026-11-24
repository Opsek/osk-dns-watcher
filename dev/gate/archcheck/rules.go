package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

const sqliteModule = "github.com/mattn/go-sqlite3"

// rule is one rule. check returns the faults that it finds.
type rule struct {
	name  string
	check func(t tree) []string
}

var ruleList = []rule{
	{"plain-layout", plainLayout},
	{"only-std-and-sqlite", onlyStdAndSqlite},
	{"no-listener", noListener},
	{"no-exec", noExec},
	{"no-unsafe", noUnsafe},
	{"import-rules", importRules},
	{"no-dns-update", noDNSUpdate},
	{"pure", pure},
}

// check runs every rule on the code under root. What could not be read is a
// fault of every rule, because no rule could check it.
func check(root string) []result {
	t, unread := load(root)
	var results []result
	for _, r := range ruleList {
		faults := append(slices.Clone(unread), r.check(t)...)
		results = append(results, result{r.name, faults})
	}
	return results
}

// otherSources are the extensions of the files besides Go that the go command
// compiles or links into a package.
var otherSources = []string{".c", ".cc", ".cpp", ".cxx", ".m", ".h", ".hh", ".hpp", ".hxx",
	".f", ".F", ".for", ".f90", ".s", ".S", ".sx", ".swig", ".swigcxx", ".syso"}

// systems are the values of GOOS and GOARCH that the go command knows. A file
// whose name ends in _<value> is built only for that system.
var systems = []string{
	"aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios", "js",
	"linux", "nacl", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows", "zos",
	"386", "amd64", "amd64p32", "arm", "armbe", "arm64", "arm64be", "loong64", "mips",
	"mipsle", "mips64", "mips64le", "mips64p32", "mips64p32le", "ppc", "ppc64", "ppc64le",
	"riscv", "riscv64", "s390", "s390x", "sparc", "sparc64", "wasm",
}

// plainLayout checks that the tool is built from the same files for every
// system and every build tag, and that these are the files the other rules,
// the linters and the tests see: each package that cmd/osk-dns-watcher reaches is one
// that load read, holds no source code other than Go, and has no file that
// only some builds use.
func plainLayout(t tree) []string {
	known := map[string]bool{}
	for _, p := range t.pkgs {
		known[p.path] = true
	}
	reached := reach(t.pkgs, func(p *pkg) bool { return p.dir == "cmd/osk-dns-watcher" })
	var faults []string
	for _, p := range t.pkgs {
		if reached[p] == "" {
			continue
		}
		for _, s := range p.imports {
			if under(s.path, t.module) && !known[s.path] {
				faults = append(faults, s.String()+", which is not a package of ./cmd/... or ./internal/...")
			}
		}
		for _, name := range p.names {
			if slices.Contains(otherSources, path.Ext(name)) {
				faults = append(faults, path.Join(p.dir, name)+" is source code other than Go")
			}
		}
		for _, f := range p.files {
			faults = append(faults, partialBuild(f)...)
		}
	}
	return faults
}

// partialBuild reports a file name or a build constraint that leaves the file
// out of some builds.
func partialBuild(f goFile) []string {
	var faults []string
	name := strings.TrimSuffix(path.Base(f.path), ".go")
	if i := strings.LastIndex(name, "_"); i >= 0 && slices.Contains(systems, name[i+1:]) {
		faults = append(faults, f.path+" has a name that limits it to some systems")
	}
	for _, g := range f.ast.Comments {
		if g.Pos() > f.ast.Package {
			break
		}
		for _, c := range g.List {
			if constraint.IsGoBuild(c.Text) || constraint.IsPlusBuild(c.Text) {
				faults = append(faults, f.pos(c.Pos())+" has a build constraint")
			}
		}
	}
	return faults
}

// onlyStdAndSqlite checks the imports, the requirements of go.mod and the
// modules of vendor/modules.txt.
func onlyStdAndSqlite(t tree) []string {
	var faults []string
	for _, p := range t.pkgs {
		for _, s := range p.imports {
			if !allowedImport(s.path, t.module) {
				faults = append(faults, s.String())
			}
		}
	}
	faults = append(faults, goModFaults(t.root)...)
	return append(faults, vendorFaults(t.root)...)
}

// allowedImport reports whether p is in the module, in the SQLite driver, or
// in the standard library, whose paths have no dot in their first element.
// "C" (cgo) has no dot but is not in the standard library.
func allowedImport(p, module string) bool {
	if under(p, module) || under(p, sqliteModule) {
		return true
	}
	first, _, _ := strings.Cut(p, "/")
	return p != "C" && !strings.Contains(first, ".")
}

// goModFaults reports every module that go.mod requires other than the
// SQLite driver.
func goModFaults(root string) []string {
	data, err := readOptional(root, "go.mod")
	if err != nil {
		return []string{err.Error()}
	}
	var faults []string
	block := ""
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "//")
		f := strings.Fields(line)
		req := ""
		switch {
		case len(f) == 0:
		case f[0] == ")":
			block = ""
		case f[len(f)-1] == "(":
			block = f[0]
		case f[0] == "require" && len(f) > 1:
			req = f[1]
		case block == "require":
			req = f[0]
		}
		if req = strings.Trim(req, `"`); req != "" && req != sqliteModule {
			faults = append(faults, "go.mod requires "+req)
		}
	}
	return faults
}

// vendorFaults reports every module of vendor/modules.txt other than the
// SQLite driver. Module lines start with "# ".
func vendorFaults(root string) []string {
	data, err := readOptional(root, "vendor/modules.txt")
	if err != nil {
		return []string{err.Error()}
	}
	var faults []string
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) > 1 && f[0] == "#" && f[1] != sqliteModule {
			faults = append(faults, "vendor/modules.txt lists "+f[1])
		}
	}
	return faults
}

// readOptional reads root/name. A missing file gives no data and no error.
func readOptional(root, name string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(root, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func noListener(t tree) []string {
	faults := findImports(t.pkgs, "net/http/httptest", "net/http/cgi", "net/http/fcgi", "net/rpc")
	return append(faults, findUses(t.pkgs, map[string][]string{
		"net":        {"Listen", "FileListener", "FilePacketConn"},
		"net/http":   {"Server", "Serve", "ListenAndServe"},
		"crypto/tls": {"Listen", "NewListener"},
	})...)
}

// noExec also bans syscall, which can start a process without os/exec, and
// listen without package net; only this rule reports it.
func noExec(t tree) []string {
	faults := findImports(t.pkgs, "os/exec", "plugin")
	faults = append(faults, findUses(t.pkgs, map[string][]string{"os": {"StartProcess"}})...)
	return append(faults, syscallUses(t.pkgs)...)
}

// allowedSyscall are the only names of syscall that the tool may use: two
// signals, and the three errors by which a UDP dial says that this machine
// has no route to an address. None of them starts a process or listens.
var allowedSyscall = []string{"SIGPIPE", "SIGTERM", "ENETUNREACH", "EADDRNOTAVAIL", "EAFNOSUPPORT"}

// syscallUses reports each name of syscall other than allowedSyscall, and a
// dot or blank import of it, after which its uses cannot be told.
func syscallUses(pkgs []*pkg) []string {
	var faults []string
	for _, p := range pkgs {
		for _, f := range p.files {
			for _, imp := range f.ast.Imports {
				if importPath(imp) != "syscall" {
					continue
				}
				name := "syscall"
				if imp.Name != nil {
					name = imp.Name.Name
				}
				if name == "." || name == "_" {
					faults = append(faults, f.pos(imp.Pos())+" imports syscall")
					continue
				}
				ast.Inspect(f.ast, func(n ast.Node) bool {
					if s, ok := n.(*ast.SelectorExpr); ok {
						if id, ok := s.X.(*ast.Ident); ok && id.Name == name && !slices.Contains(allowedSyscall, s.Sel.Name) {
							faults = append(faults, fmt.Sprintf("%s uses syscall.%s", f.pos(s.Pos()), s.Sel.Name))
						}
					}
					return true
				})
			}
		}
	}
	return faults
}

func noUnsafe(t tree) []string {
	return findImports(t.pkgs, "unsafe", "C")
}

const (
	dnswireDir    = "internal/dnswire"
	transportFile = dnswireDir + "/transport.go"
	writeFunc     = "writeQuery"
	// The fetch of a policy file must check the address that its connection
	// really uses, and net/http offers no hook for that but a dialer.
	httpDialFile = "internal/httpclient/dial.go"
)

// noDNSUpdate keeps the tool from sending any DNS message but a query: only
// the DNS codec dials, besides the net.Dialer of httpDialFile, which opens
// the TCP connection of an HTTPS request; only the codec's transport.go
// imports net, and there only writeQuery writes, which sends nothing but what
// Query.Pack makes. Packages that dial for their own protocols are banned
// everywhere. The rule has no type information: a write through fmt.Fprint
// or io.Copy, or through a function of another file of the codec, escapes the
// last part, and so does any dial through that net.Dialer.
func noDNSUpdate(t tree) []string {
	var outside, inside []goFile
	for _, p := range t.pkgs {
		if p.dir == dnswireDir {
			inside = append(inside, p.files...)
		} else {
			outside = append(outside, p.files...)
		}
	}
	faults := findImports(t.pkgs, "log/syslog", "net/smtp", "net/textproto")
	for _, f := range outside {
		for _, fault := range fileUses(f, map[string][]string{"net": {"Dial"}, "crypto/tls": {"Dial"}}) {
			if f.path != httpDialFile || !strings.HasSuffix(fault, " uses net.Dialer") {
				faults = append(faults, fault)
			}
		}
	}
	for _, f := range inside {
		for _, imp := range f.ast.Imports {
			if importPath(imp) == "net" && f.path != transportFile {
				faults = append(faults, f.pos(imp.Pos())+" imports net outside "+transportFile)
			}
		}
	}
	for _, f := range inside {
		if f.path == transportFile {
			faults = append(faults, writesOutside(f)...)
		}
	}
	return faults
}

// writesOutside reports each use of a name that starts with Write outside the
// function writeQuery: a call, and also a method value such as c.Write, which
// a later call can use.
func writesOutside(f goFile) []string {
	var faults []string
	for _, d := range f.ast.Decls {
		fn, isFunc := d.(*ast.FuncDecl)
		if isFunc && fn.Recv == nil && fn.Name.Name == writeFunc {
			continue
		}
		ast.Inspect(d, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if ok && strings.HasPrefix(id.Name, "Write") && !(isFunc && id == fn.Name) {
				faults = append(faults, fmt.Sprintf("%s uses %s outside %s", f.pos(id.Pos()), id.Name, writeFunc))
			}
			return true
		})
	}
	return faults
}

// pure keeps the judgement and the schedule of the tool repeatable: the
// packages under internal/decide, internal/expect, internal/alert and
// internal/schedule read no clock, network, file, store or randomness. Import
// rules cannot say this, because these packages reach net, os and crypto/rand
// through internal/dnswire, and they need package time for its types. So each
// direct import must be on a short list, and the names of an allowed package
// that read the clock, the time zone of the machine (from TZ and the disk),
// the network or standard input and output are banned. The rule has no type
// information: a method value such as t.Local, or a function handed in from
// outside, escapes it.
func pure(t tree) []string {
	dnswire := path.Join(t.module, dnswireDir)
	allowed := []string{"bytes", "cmp", "errors", "fmt", "maps", "net/netip", "slices", "strconv", "strings",
		"time", dnswire, path.Join(t.module, "internal/observe/obs")}
	var scope []*pkg
	for _, p := range t.pkgs {
		if under(p.dir, "internal/decide") || under(p.dir, "internal/expect") || under(p.dir, "internal/alert") || under(p.dir, "internal/schedule") {
			scope = append(scope, p)
			allowed = append(allowed, p.path)
		}
	}
	var faults []string
	for _, p := range scope {
		for _, s := range p.imports {
			if !slices.Contains(allowed, s.path) {
				faults = append(faults, s.String())
			}
		}
	}
	return append(faults, findUses(scope, map[string][]string{
		"time": {"Now", "Since", "Until", "Sleep", "After", "Tick", "NewTicker", "NewTimer",
			"LoadLocation", "Local", "Parse"},
		"fmt":   {"Print", "Scan"},
		dnswire: {"Exchange", "Transfer"},
	})...)
}

// findImports reports every import of one of the given paths, whatever name
// the import gives it (none, an alias, "." or "_").
func findImports(pkgs []*pkg, paths ...string) []string {
	var faults []string
	for _, p := range pkgs {
		for _, s := range p.imports {
			if slices.Contains(paths, s.path) {
				faults = append(faults, s.String())
			}
		}
	}
	return faults
}

// findUses reports every use of a name that starts with one of the prefixes
// listed for its package.
func findUses(pkgs []*pkg, prefixes map[string][]string) []string {
	var faults []string
	for _, p := range pkgs {
		for _, f := range p.files {
			faults = append(faults, fileUses(f, prefixes)...)
		}
	}
	return faults
}

// fileUses finds the uses of one file through its imports: pkg.Name where pkg
// is the package name or an alias, or Name alone after a dot import. After a
// dot import, a name of the file itself that starts with such a prefix is
// reported too.
func fileUses(f goFile, prefixes map[string][]string) []string {
	local := map[string]string{} // name in the file -> import path
	var dots []string
	for _, imp := range f.ast.Imports {
		p := importPath(imp)
		switch {
		case prefixes[p] == nil:
		case imp.Name == nil:
			local[path.Base(p)] = p
		case imp.Name.Name == ".":
			dots = append(dots, p)
		default:
			local[imp.Name.Name] = p
		}
	}
	var faults []string
	report := func(p, name string, pos token.Pos) {
		if slices.ContainsFunc(prefixes[p], func(pre string) bool { return strings.HasPrefix(name, pre) }) {
			faults = append(faults, fmt.Sprintf("%s uses %s.%s", f.pos(pos), p, name))
		}
	}
	selected := map[*ast.Ident]bool{} // the Name of each x.Name
	ast.Inspect(f.ast, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			selected[n.Sel] = true
			if id, ok := n.X.(*ast.Ident); ok {
				report(local[id.Name], n.Sel.Name, n.Pos())
			}
		case *ast.Ident:
			if !selected[n] {
				for _, p := range dots {
					report(p, n.Name, n.Pos())
				}
			}
		}
		return true
	})
	return faults
}

// importRule is a line of dev/gate/imports.txt: "<from> must-not-import <to>",
// or, when only is set, "only <from> may-import <to>".
type importRule struct {
	line     int
	only     bool
	from, to string
}

func (r importRule) String() string {
	if r.only {
		return "only " + r.from + " may-import " + r.to
	}
	return r.from + " must-not-import " + r.to
}

// importRules also fails on a pattern of the module that matches no package,
// so that a rule cannot pass because of a typing error or wait for a package
// that does not exist.
func importRules(t tree) []string {
	rules, faults := readImportRules(t.root)
	for _, r := range rules {
		for _, pattern := range []string{r.from, r.to} {
			matches := func(p *pkg) bool { return matchPattern(pattern, p.path) }
			if under(pattern, t.module) && !slices.ContainsFunc(t.pkgs, matches) {
				faults = append(faults, fmt.Sprintf("dev/gate/imports.txt:%d names %s, which matches no package", r.line, pattern))
			}
		}
		if r.only {
			faults = append(faults, onlyMayImport(r, t.pkgs)...)
		} else {
			faults = append(faults, mustNotImport(r, t.pkgs)...)
		}
	}
	return faults
}

// onlyMayImport reports every import of a package that matches r.to by a
// package that does not match r.from.
func onlyMayImport(r importRule, pkgs []*pkg) []string {
	var faults []string
	for _, p := range pkgs {
		if matchPattern(r.from, p.path) {
			continue
		}
		for _, s := range p.imports {
			if matchPattern(r.to, s.path) {
				faults = append(faults, fmt.Sprintf("%s (%s)", s, r))
			}
		}
	}
	return faults
}

// mustNotImport reports every import of a package that matches r.to by a
// package that matches r.from, or by a package of the module that such a
// package reaches. Each import is reported once, with the first package that
// reaches it.
func mustNotImport(r importRule, pkgs []*pkg) []string {
	source := reach(pkgs, func(p *pkg) bool { return matchPattern(r.from, p.path) })
	var faults []string
	for _, p := range pkgs {
		if source[p] == "" {
			continue
		}
		for _, s := range p.imports {
			if !matchPattern(r.to, s.path) {
				continue
			}
			if source[p] == p.path {
				faults = append(faults, fmt.Sprintf("%s (%s)", s, r))
			} else {
				faults = append(faults, fmt.Sprintf("%s, reached from %s (%s)", s, source[p], r))
			}
		}
	}
	return faults
}

// reach returns each package that a start package reaches through imports,
// itself included, with the import path of the first start package that
// reaches it.
func reach(pkgs []*pkg, start func(*pkg) bool) map[*pkg]string {
	byPath := map[string]*pkg{}
	for _, p := range pkgs {
		byPath[p.path] = p
	}
	source := map[*pkg]string{}
	var queue []*pkg
	for _, p := range pkgs {
		if start(p) {
			source[p] = p.path
			queue = append(queue, p)
		}
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, s := range p.imports {
			if q := byPath[s.path]; q != nil && source[q] == "" {
				source[q] = source[p]
				queue = append(queue, q)
			}
		}
	}
	return source
}

// matchPattern reports whether the import path p matches the pattern, as in
// the go command: "a/b" matches a/b only, "a/b/..." matches a/b and every
// path under it.
func matchPattern(pattern, p string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "/..."); ok {
		return under(p, prefix)
	}
	return p == pattern
}

// readImportRules reads dev/gate/imports.txt. A line that is not blank must be a
// rule.
func readImportRules(root string) ([]importRule, []string) {
	data, err := os.ReadFile(filepath.Join(root, "dev", "gate", "imports.txt"))
	if err != nil {
		return nil, []string{"dev/gate/imports.txt cannot be read"}
	}
	var rules []importRule
	var faults []string
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case len(f) == 3 && f[1] == "must-not-import":
			rules = append(rules, importRule{i + 1, false, f[0], f[2]})
		case len(f) == 4 && f[0] == "only" && f[2] == "may-import":
			rules = append(rules, importRule{i + 1, true, f[1], f[3]})
		default:
			faults = append(faults, fmt.Sprintf(
				`dev/gate/imports.txt:%d is neither "<pattern> must-not-import <pattern>" nor "only <pattern> may-import <pattern>"`, i+1))
		}
	}
	return rules, faults
}
