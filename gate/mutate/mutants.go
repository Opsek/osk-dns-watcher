package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"slices"
	"strconv"
)

// words name the mutations, in the order in which the mutants of one node
// are made.
var words = []string{"negate", "boundary", "and-or", "not", "bool", "arith", "drop-call"}

// The operators that each binary mutation changes, and into what.
var (
	negations = map[token.Token]token.Token{
		token.EQL: token.NEQ, token.NEQ: token.EQL,
		token.LSS: token.GEQ, token.GEQ: token.LSS,
		token.GTR: token.LEQ, token.LEQ: token.GTR,
	}
	boundaries = map[token.Token]token.Token{
		token.LSS: token.LEQ, token.LEQ: token.LSS,
		token.GTR: token.GEQ, token.GEQ: token.GTR,
	}
	andOr = map[token.Token]token.Token{token.LAND: token.LOR, token.LOR: token.LAND}
	arith = map[token.Token]token.Token{token.ADD: token.SUB, token.SUB: token.ADD}
)

// mutant is one change of one file: the bytes from start to end become text.
type mutant struct {
	id         string
	file       string // relative to the root, with slashes
	start, end int
	text       string
	change     string // "line <n>: <what changes>"
}

func (m mutant) apply(src []byte) []byte {
	return slices.Concat(src[:m.start], []byte(m.text), src[m.end:])
}

// mutate returns the mutants of the Go file src, in the order of its syntax
// tree. file is its path relative to the root.
func mutate(file string, src []byte) ([]mutant, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var ms []mutant
	for _, d := range f.Decls {
		at := place{fset, file, funcName(d)}
		ast.Inspect(d, func(n ast.Node) bool {
			ms = append(ms, at.mutants(n)...)
			return true
		})
	}
	number(ms)
	return ms, nil
}

// place is where mutants are made: a file and the function in it.
type place struct {
	fset     *token.FileSet
	file, fn string
}

// mutants returns the mutants of one node of the syntax tree.
func (p place) mutants(n ast.Node) []mutant {
	switch n := n.(type) {
	case *ast.BinaryExpr:
		return p.binary(n)
	case *ast.UnaryExpr:
		if n.Op == token.NOT {
			return []mutant{p.newMutant(n, "not", n.OpPos, n.OpPos+1, "", "! removed")}
		}
	case *ast.Ident:
		if n.Name == "true" || n.Name == "false" {
			other := strconv.FormatBool(n.Name == "false")
			return []mutant{p.newMutant(n, "bool", n.Pos(), n.End(), other, n.Name+" to "+other)}
		}
	case *ast.ExprStmt:
		// Without a panic the function could end without a return.
		call, ok := n.X.(*ast.CallExpr)
		if ok && !isIdent(call.Fun, "panic") {
			return []mutant{p.newMutant(call, "drop-call", n.Pos(), n.End(), "", "call removed")}
		}
	}
	return nil
}

func (p place) binary(n *ast.BinaryExpr) []mutant {
	var ms []mutant
	add := func(word string, table map[token.Token]token.Token) {
		if to, ok := table[n.Op]; ok {
			end := n.OpPos + token.Pos(len(n.Op.String()))
			ms = append(ms, p.newMutant(n, word, n.OpPos, end, to.String(), n.Op.String()+" to "+to.String()))
		}
	}
	add("negate", negations)
	add("boundary", boundaries)
	add("and-or", andOr)
	// "a" - b never compiles.
	if !isString(n.X) && !isString(n.Y) {
		add("arith", arith)
	}
	return ms
}

// newMutant returns the mutant that replaces the source from pos to end by
// text. Its ID quotes node, so it does not depend on where the node stands.
func (p place) newMutant(node ast.Node, word string, pos, end token.Pos, text, change string) mutant {
	at := p.fset.Position(pos)
	return mutant{
		id:     p.file + " " + p.fn + " " + word + " " + quote(p.fset, node),
		file:   p.file,
		start:  at.Offset,
		end:    p.fset.Position(end).Offset,
		text:   text,
		change: "line " + strconv.Itoa(at.Line) + ": " + change,
	}
}

// quote returns the node as gofmt prints it, cut to 60 bytes, quoted.
func quote(fset *token.FileSet, node ast.Node) string {
	var b bytes.Buffer
	// Printing into a buffer fails only for a kind of node never given here.
	_ = printer.Fprint(&b, fset, node)
	s := b.String()
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return strconv.Quote(s)
}

// number makes equal IDs of one file distinct: the second gets "#2", and so
// on, in source order.
func number(ms []mutant) {
	seen := map[string]int{}
	for i := range ms {
		seen[ms[i].id]++
		if n := seen[ms[i].id]; n > 1 {
			ms[i].id += "#" + strconv.Itoa(n)
		}
	}
}

// funcName is the name of the function that holds a declaration:
// "Type.Method" for a method, "-" outside a function.
func funcName(d ast.Decl) string {
	f, ok := d.(*ast.FuncDecl)
	if !ok {
		return "-"
	}
	if f.Recv == nil || len(f.Recv.List) == 0 {
		return f.Name.Name
	}
	return typeName(f.Recv.List[0].Type) + "." + f.Name.Name
}

// typeName is the name of a receiver type, without "*" and type parameters.
func typeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return typeName(t.X)
	case *ast.ParenExpr:
		return typeName(t.X)
	case *ast.IndexExpr:
		return typeName(t.X)
	case *ast.IndexListExpr:
		return typeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "-"
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func isString(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}
