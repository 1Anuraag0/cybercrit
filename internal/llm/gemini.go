package llm

import (
    "context"
    "fmt"
    "net/http"
    "time"
)

const geminiBaseURL = "https://generativelanguage.googleapis.com/v1beta/openai"

type GeminiAgent struct {
    apiKey string
    model  string
    client *http.Client
}

func NewGeminiAgent(apiKey string) *GeminiAgent {
    return &GeminiAgent{
        apiKey: apiKey,
        model:  "gemini-2.0-flash",
        client: &http.Client{Timeout: 5 * time.Second},
    }
}

func (a *GeminiAgent) Name() string { return "gemini-2.0-flash" }

func (a *GeminiAgent) Available(_ context.Context) bool {
    return a.apiKey != ""
}

func (a *GeminiAgent) Analyze(ctx context.Context, req AnalyzeRequest) (*AnalysisResult, error) {
    body := buildOpenAIRequest(a.model, SystemPrompt, BuildUserMessage(req))

    httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
        geminiBaseURL+"/chat/completions", body)
    if err != nil {
        return nil, err
    }
    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)

    resp, err := a.client.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // treat 403 and 429 as hard failures — caller will try next agent
    if resp.StatusCode == http.StatusForbidden {
        return nil, fmt.Errorf("gemini: 403 forbidden (region block or bad key)")
    }
    if resp.StatusCode == http.StatusTooManyRequests {
        return nil, fmt.Errorf("gemini: 429 rate limited")
    }
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("gemini: unexpected status %d", resp.StatusCode)
    }

    return parseOpenAIResponse(resp.Body)
}
