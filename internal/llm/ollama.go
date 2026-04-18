package llm

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "time"
)

type OllamaAgent struct {
    model      string
    baseURL    string
    httpClient *http.Client
}

func NewOllamaAgent(model string) *OllamaAgent {
    return &OllamaAgent{
        model:      model,
        baseURL:    "http://localhost:11434",
        httpClient: &http.Client{Timeout: 30 * time.Second},
    }
}

func (a *OllamaAgent) Name() string { return "ollama-" + a.model }

// Available checks two things:
// 1. Ollama is running (GET /api/tags returns 200 within 200ms)
// 2. The configured model exists in the returned model list
func (a *OllamaAgent) Available(ctx context.Context) bool {
    hctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
    defer cancel()

    req, err := http.NewRequestWithContext(hctx, http.MethodGet,
        a.baseURL+"/api/tags", nil)
    if err != nil {
        return false
    }
    resp, err := a.httpClient.Do(req)
    if err != nil || resp.StatusCode != http.StatusOK {
        return false
    }
    defer resp.Body.Close()

    var result struct {
        Models []struct{ Name string `json:"name"` } `json:"models"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return false
    }
    for _, m := range result.Models {
        if strings.HasPrefix(m.Name, a.model) {
            return true
        }
    }
    return false
}

func (a *OllamaAgent) Analyze(ctx context.Context, req AnalyzeRequest) (*AnalysisResult, error) {
    body := buildOpenAIRequest(a.model, SystemPrompt, BuildUserMessage(req))

    httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
        a.baseURL+"/v1/chat/completions", body)
    if err != nil {
        return nil, err
    }
    httpReq.Header.Set("Content-Type", "application/json")
    // no auth header — Ollama is local

    resp, err := a.httpClient.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("ollama: status %d", resp.StatusCode)
    }
    return parseOpenAIResponse(resp.Body)
}
