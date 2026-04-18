package cli

import (
	"testing"

	"github.com/cybercrit/cybercrit/internal/llm"
)

func TestToAnalyzerFinding_RegexFindingNotAutoFixable(t *testing.T) {
	f := llm.Finding{
		Fix: llm.Fix{
			Automated: false,
			FixedLine: "",
		},
	}
	agentUsed := "regex-builtin"
	af := toAnalyzerFinding(f, agentUsed)

	if af.AutoFixable != false {
		t.Errorf("expected AutoFixable = false, got %t", af.AutoFixable)
	}
}
