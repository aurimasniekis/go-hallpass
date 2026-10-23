// Package txscope reports blocking or external work inside store write transactions (HP-DB-004).
//
// A write transaction is the function literal passed to a method named Tx on a type declared in a package
// whose path ends in "/internal/store". Inside it the analyzer forbids calls into network, SSH, notification,
// recording and process packages, time.Sleep, file fsyncs, channel receives and select statements.
package txscope

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Analyzer is the txscope analyzer.
var Analyzer = &analysis.Analyzer{
	Name:     "txscope",
	Doc:      "forbid network I/O, waits, fsyncs and external calls inside store write transactions",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

// bannedPkgs are import paths (exact or prefix followed by "/") that must not be called inside a transaction.
var bannedPkgs = []string{
	"net",
	"net/http",
	"os/exec",
	"golang.org/x/crypto/ssh",
}

// bannedInternal are module-relative package suffixes that must not be called inside a transaction.
var bannedInternal = []string{
	"/internal/notify",
	"/internal/sshproxy",
	"/internal/recording",
	"/internal/egress",
	"/internal/eventbus",
}

func run(pass *analysis.Pass) (any, error) {
	ins := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	ins.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call := n.(*ast.CallExpr)
		if !isStoreTx(pass, call) {
			return
		}
		for _, arg := range call.Args {
			if lit, ok := arg.(*ast.FuncLit); ok {
				checkBody(pass, lit.Body)
			}
		}
	})
	return nil, nil
}

func isStoreTx(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Tx" && !strings.HasPrefix(sel.Sel.Name, "Tx")) {
		return false
	}
	fn, ok := pass.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok {
		return false
	}
	recv := fn.Signature().Recv()
	if recv == nil {
		return false
	}
	t := recv.Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	return strings.HasSuffix(named.Obj().Pkg().Path(), "/internal/store")
}

func checkBody(pass *analysis.Pass, body *ast.BlockStmt) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectStmt:
			pass.Reportf(x.Pos(), "select statement inside store transaction: never wait while holding the writer")
		case *ast.UnaryExpr:
			if x.Op == token.ARROW {
				pass.Reportf(x.Pos(), "channel receive inside store transaction: never wait while holding the writer")
			}
		case *ast.SendStmt:
			pass.Reportf(x.Pos(), "channel send inside store transaction: publish events after commit")
		case *ast.CallExpr:
			checkCall(pass, x)
		}
		return true
	})
}

func checkCall(pass *analysis.Pass, call *ast.CallExpr) {
	var id *ast.Ident
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		id = f.Sel
	case *ast.Ident:
		id = f
	default:
		return
	}
	fn, ok := pass.TypesInfo.Uses[id].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return
	}
	path := fn.Pkg().Path()
	switch {
	case path == "time" && fn.Name() == "Sleep":
		pass.Reportf(call.Pos(), "time.Sleep inside store transaction")
		return
	case path == "os" && fn.Name() == "Sync":
		pass.Reportf(call.Pos(), "file fsync inside store transaction: fsync before or after the transaction")
		return
	}
	for _, b := range bannedPkgs {
		if path == b || strings.HasPrefix(path, b+"/") {
			pass.Reportf(call.Pos(), "call to %s.%s inside store transaction: no network or SSH I/O while holding the writer", path, fn.Name())
			return
		}
	}
	for _, b := range bannedInternal {
		if strings.HasSuffix(path, b) || strings.Contains(path, b+"/") {
			pass.Reportf(call.Pos(), "call to %s.%s inside store transaction: external side effects must run after commit", path, fn.Name())
			return
		}
	}
}
