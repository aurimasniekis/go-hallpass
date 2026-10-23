package txscope_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/aurimasniekis/go-hallpass/tools/analyzers/txscope"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), txscope.Analyzer, "example.com/hp/a")
}
