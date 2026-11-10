package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// tree is the code that the rules check: the module path of go.mod and the
// packages of the module under cmd/ and internal/.
type tree struct {
	root, module string
	pkgs         []*pkg
}

// pkg is a package of the module. Its files are its Go files that are not
// tests, whatever their build constraints.
type pkg struct {
	path    string   // import path
	dir     string   // folder, relative to the root, with slashes
	names   []string // every file in the folder
	files   []goFile
	imports []importSite
}

// goFile is a parsed Go file. path is relative to the root and uses slashes.
type goFile struct {
	path string
	fset *token.FileSet
	ast  *ast.File
}

// pos returns "<path>:<line>" for a position in the file.
func (f goFile) pos(p token.Pos) string {
	return fmt.Sprintf("%s:%d", f.path, f.fset.Position(p).Line)
}

// importSite is one import line: where it is and the path it imports.
type importSite struct {
	pos, path string
}

func (s importSite) String() string {
	return s.pos + " imports " + s.path
}

// load reads the packages that "go build ./cmd/... ./internal/..." sees,
// sorted by import path. cmd/osk is among them even when it is missing, so
// that a wrong root fails. The faults name what could not be read.
func load(root string) (tree, []string) {
	t := tree{root: root}
	var faults []string
	module, err := modulePath(root)
	if err != nil {
		faults = append(faults, err.Error())
	}
	t.module = module
	dirs, err := walk(root)
	if err != nil {
		faults = append(faults, err.Error())
	}
	dirs = append(dirs, "cmd/osk")
	slices.Sort(dirs)
	fset := token.NewFileSet()
	for _, dir := range slices.Compact(dirs) {
		p, bad := readPkg(root, module, dir, fset)
		faults = append(faults, bad...)
		t.pkgs = append(t.pkgs, p)
	}
	return t, faults
}

// modulePath returns the path on the module line of go.mod.
func modulePath(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", errors.New("go.mod cannot be read")
	}
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "//")
		if f := strings.Fields(line); len(f) == 2 && f[0] == "module" {
			return strings.Trim(f[1], `"`), nil
		}
	}
	return "", errors.New("go.mod has no module line")
}

// walk returns each folder under cmd/ and internal/ that holds a Go file that
// is not a test. Like "go build ./...", it skips folders named testdata or
// vendor and folders whose names start with "." or "_".
func walk(root string) ([]string, error) {
	var dirs []string
	for _, top := range []string{"cmd", "internal"} {
		start := filepath.Join(root, top)
		err := filepath.WalkDir(start, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == start && errors.Is(err, fs.ErrNotExist) {
					return fs.SkipAll
				}
				return err
			}
			name := d.Name()
			if d.IsDir() {
				if p != start && (name == "testdata" || name == "vendor" ||
					strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
					return fs.SkipDir
				}
				return nil
			}
			if !isSource(name) {
				return nil
			}
			rel, err := filepath.Rel(root, filepath.Dir(p))
			dirs = append(dirs, filepath.ToSlash(rel))
			return err
		})
		if err != nil {
			return dirs, err
		}
	}
	return dirs, nil
}

// readPkg reads the package in root/dir: the names of its files, and its Go
// files that are not tests, parsed with their comments, which hold the build
// constraints.
func readPkg(root, module, dir string, fset *token.FileSet) (*pkg, []string) {
	p := &pkg{path: path.Join(module, dir), dir: dir}
	entries, err := os.ReadDir(filepath.Join(root, dir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return p, []string{err.Error()}
	}
	var faults []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p.names = append(p.names, e.Name())
		if !isSource(e.Name()) {
			continue
		}
		rel := path.Join(dir, e.Name())
		f, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			faults = append(faults, fmt.Sprintf("%s cannot be parsed: %v", rel, err))
			continue
		}
		file := goFile{rel, fset, f}
		p.files = append(p.files, file)
		for _, imp := range f.Imports {
			p.imports = append(p.imports, importSite{file.pos(imp.Pos()), importPath(imp)})
		}
	}
	if p.files == nil && faults == nil {
		faults = append(faults, "no Go files in "+dir)
	}
	return p, faults
}

func isSource(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}

// importPath returns the path of an import without quotes.
func importPath(imp *ast.ImportSpec) string {
	p, _ := strconv.Unquote(imp.Path.Value)
	return p
}

// under reports whether the path p is prefix or lies below it.
func under(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}
