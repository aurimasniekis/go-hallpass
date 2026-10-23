// Package nohostkeyignore reports any use of ssh.InsecureIgnoreHostKey (HP-SSH-011).
package nohostkeyignore

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const sshPkg = "golang.org/x/crypto/ssh"

// Analyzer flags references to ssh.InsecureIgnoreHostKey anywhere, including tests.
var Analyzer = &analysis.Analyzer{
	Name:     "nohostkeyignore",
	Doc:      "forbid golang.org/x/crypto/ssh.InsecureIgnoreHostKey; destination host keys must always be verified",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	ins := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	ins.Preorder([]ast.Node{(*ast.Ident)(nil)}, func(n ast.Node) {
		id := n.(*ast.Ident)
		fn, ok := pass.TypesInfo.Uses[id].(*types.Func)
		if !ok || fn.Pkg() == nil {
			return
		}
		if fn.Pkg().Path() == sshPkg && fn.Name() == "InsecureIgnoreHostKey" {
			pass.Reportf(id.Pos(), "ssh.InsecureIgnoreHostKey is forbidden: verify host keys against enrolled identities")
		}
	})
	return nil, nil
}
