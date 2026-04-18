package llm

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/cybercrit/cybercrit/internal/config"
)

type AgentChain []Agent

// Analyze runs agents in order. Falls back on error or low confidence.
// Never returns error if RegexAgent is in the chain — regex never fails.
func (chain AgentChain) Analyze(req AnalyzeRequest) (*AnalysisResult, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    for i, agent := range chain {
        if !agent.Available(ctx) {
            log.Printf("[cybercrit] agent %q unavailable, skipping", agent.Name())
            continue
        }

        start := time.Now()
        result, err := agent.Analyze(ctx, req)
        latency := time.Since(start).Milliseconds()

        if err != nil {
            log.Printf("[cybercrit] agent %q failed (%dms): %v", agent.Name(), latency, err)
            continue
        }

        // empty findings is a valid clean result — return immediately
        if result == nil {
            result = &AnalysisResult{Findings: []Finding{}}
        }
        if len(result.Findings) == 0 {
            result.AgentUsed = agent.Name()
            result.LatencyMs = latency
            return result, nil
        }

        // confidence escalation: if best finding is below threshold
        // AND a next agent exists, try next for a stronger opinion
        isLast := i == len(chain)-1
        if maxConfidence(result) < 0.75 && !isLast {
            log.Printf("[cybercrit] agent %q max confidence %.2f < 0.75, escalating",
                agent.Name(), maxConfidence(result))
            continue
        }

        result.AgentUsed = agent.Name()
        result.LatencyMs = latency
        return result, nil
    }

    return nil, fmt.Errorf("cybercrit: all agents exhausted")
}

func maxConfidence(r *AnalysisResult) float64 {
    max := 0.0
    for _, f := range r.Findings {
        if f.Confidence > max {
            max = f.Confidence
        }
    }
    return max
}

// NewDefaultChain builds the chain from config.
// Order is always: Gemini → OpenRouter → Ollama → Regex.
// Regex is always appended last — it never requires a key and never fails.
func NewDefaultChain(cfg config.Config) AgentChain {
    var chain AgentChain

    // Use credential resolution directly here or via the config struct
    geminiKey := cfg.ResolveGeminiAPIKey()
    openrouterKey := cfg.ResolveOpenRouterAPIKey()

    if geminiKey != "" {
        chain = append(chain, NewGeminiAgent(geminiKey))
    }
    if openrouterKey != "" {
        chain = append(chain, NewOpenRouterAgent(openrouterKey))
    }
    if cfg.LocalModel != "" {
        chain = append(chain, NewOllamaAgent(cfg.LocalModel))
    }

    // regex is always the final safety net — unconditional
    chain = append(chain, NewRegexAgent())
    return chain
}
