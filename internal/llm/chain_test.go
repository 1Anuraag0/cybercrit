package llm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type mockAgent struct {
	name       string
	available  bool
	result     *AnalysisResult
	err        error
	callCount  int
}

func (m *mockAgent) Name() string { return m.name }
func (m *mockAgent) Available(_ context.Context) bool { return m.available }
func (m *mockAgent) Analyze(_ context.Context, _ AnalyzeRequest) (*AnalysisResult, error) {
	m.callCount++
	return m.result, m.err
}

func TestChain_FirstAgentSucceeds(t *testing.T) {
	mock1 := &mockAgent{name: "one", available: true, result: &AnalysisResult{Findings: []Finding{{Confidence: 0.9}}, AgentUsed: "one"}}
	mock2 := &mockAgent{name: "two", available: true, result: &AnalysisResult{Findings: []Finding{{Confidence: 0.9}}, AgentUsed: "two"}}

	chain := AgentChain{mock1, mock2}
	result, err := chain.Analyze(AnalyzeRequest{})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.AgentUsed != "one" {
		t.Errorf("expected agent 'one', got %s", result.AgentUsed)
	}
	if mock1.callCount != 1 {
		t.Errorf("expected mock1 to be called once, got %d", mock1.callCount)
	}
	if mock2.callCount != 0 {
		t.Errorf("expected mock2 to not be called, got %d", mock2.callCount)
	}
}

func TestChain_FirstFailsFallsToSecond(t *testing.T) {
	mock1 := &mockAgent{name: "one", available: true, err: errors.New("fail")}
	mock2 := &mockAgent{name: "two", available: true, result: &AnalysisResult{Findings: []Finding{{Confidence: 0.9}}, AgentUsed: "two"}}

	chain := AgentChain{mock1, mock2}
	result, err := chain.Analyze(AnalyzeRequest{})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.AgentUsed != "two" {
		t.Errorf("expected agent 'two', got %s", result.AgentUsed)
	}
	if mock1.callCount != 1 {
		t.Errorf("expected mock1 to be called once, got %d", mock1.callCount)
	}
	if mock2.callCount != 1 {
		t.Errorf("expected mock2 to be called once, got %d", mock2.callCount)
	}
}

func TestChain_AllAgentsFailReturnsError(t *testing.T) {
	mock1 := &mockAgent{name: "one", available: true, err: errors.New("fail")}
	mock2 := &mockAgent{name: "two", available: true, err: errors.New("fail")}
	mock3 := &mockAgent{name: "three", available: true, err: errors.New("fail")}

	chain := AgentChain{mock1, mock2, mock3}
	_, err := chain.Analyze(AnalyzeRequest{})

	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "all agents exhausted") {
		t.Errorf("expected 'all agents exhausted' error, got %v", err)
	}
}

func TestChain_UnavailableAgentSkipped(t *testing.T) {
	mock1 := &mockAgent{name: "one", available: false}
	mock2 := &mockAgent{name: "two", available: true, result: &AnalysisResult{Findings: []Finding{{Confidence: 0.9}}, AgentUsed: "two"}}

	chain := AgentChain{mock1, mock2}
	result, err := chain.Analyze(AnalyzeRequest{})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.AgentUsed != "two" {
		t.Errorf("expected agent 'two', got %s", result.AgentUsed)
	}
	if mock1.callCount != 0 {
		t.Errorf("expected mock1 to not be called, got %d", mock1.callCount)
	}
	if mock2.callCount != 1 {
		t.Errorf("expected mock2 to be called once, got %d", mock2.callCount)
	}
}

func TestChain_LowConfidenceEscalates(t *testing.T) {
	mock1 := &mockAgent{name: "one", available: true, result: &AnalysisResult{Findings: []Finding{{Confidence: 0.60}}, AgentUsed: "one"}}
	mock2 := &mockAgent{name: "two", available: true, result: &AnalysisResult{Findings: []Finding{{Confidence: 0.95}}, AgentUsed: "two"}}

	chain := AgentChain{mock1, mock2}
	result, err := chain.Analyze(AnalyzeRequest{})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.AgentUsed != "two" {
		t.Errorf("expected agent 'two', got %s", result.AgentUsed)
	}
	if mock1.callCount != 1 {
		t.Errorf("expected mock1 to be called once, got %d", mock1.callCount)
	}
	if mock2.callCount != 1 {
		t.Errorf("expected mock2 to be called once, got %d", mock2.callCount)
	}
}

func TestChain_LowConfidenceOnLastAgentReturns(t *testing.T) {
	mock1 := &mockAgent{name: "one", available: true, result: &AnalysisResult{Findings: []Finding{{Confidence: 0.60}}, AgentUsed: "one"}}

	chain := AgentChain{mock1}
	result, err := chain.Analyze(AnalyzeRequest{})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.AgentUsed != "one" {
		t.Errorf("expected agent 'one', got %s", result.AgentUsed)
	}
	if mock1.callCount != 1 {
		t.Errorf("expected mock1 to be called once, got %d", mock1.callCount)
	}
}

func TestRegexAgent_SQLInjectionDetected(t *testing.T) {
	agent := NewRegexAgent()
	req := AnalyzeRequest{
		FilePath:   "test.go",
		AddedLines: `query := "SELECT * FROM users WHERE id=" + userID`,
	}
	result, err := agent.Analyze(context.Background(), req)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Findings) < 1 {
		t.Fatalf("expected at least 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].VulnClass != "INJECTION" {
		t.Errorf("expected INJECTION, got %s", result.Findings[0].VulnClass)
	}
}

func TestRegexAgent_AWSKeyDetected(t *testing.T) {
	agent := NewRegexAgent()
	req := AnalyzeRequest{
		FilePath:   "test.go",
		AddedLines: `key := "AKIAIOSFODNN7EXAMPLE"`,
	}
	result, err := agent.Analyze(context.Background(), req)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Findings) < 1 {
		t.Fatalf("expected at least 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", result.Findings[0].Severity)
	}
	if result.Findings[0].VulnClass != "SECRETS" {
		t.Errorf("expected SECRETS, got %s", result.Findings[0].VulnClass)
	}
}
