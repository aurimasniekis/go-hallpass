// Command hallpass-vet runs Hallpass's custom analyzers. Use with: go vet -vettool=$(which hallpass-vet) ./...
package main

import (
	"golang.org/x/tools/go/analysis/unitchecker"

	"github.com/aurimasniekis/go-hallpass/tools/analyzers/nohostkeyignore"
	"github.com/aurimasniekis/go-hallpass/tools/analyzers/txscope"
)

func main() {
	unitchecker.Main(nohostkeyignore.Analyzer, txscope.Analyzer)
}
