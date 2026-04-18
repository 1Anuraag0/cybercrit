package llm

import (
    "context"
    "fmt"
    "net/http"
    "time"
)

const openRouterBaseURL = "https://openrouter.ai/api/v1"

type OpenRouterAgent struct {
    apiKey string
    model  string
    client *http.Client
}

func NewOpenRouterAgent(apiKey string) *OpenRouterAgent {
    return &OpenRouterAgent{
        apiKey: apiKey,
        model:  "mistralai/mistral-7b-instruct",
        client: &http.Client{Timeout: 8 * time.Second},
    }
}

func (a *OpenRouterAgent) Name() string { return "openrouter-mistral-7b" }

func (a *OpenRouterAgent) Available(_ context.Context) bool {
    return a.apiKey != ""
}

func (a *OpenRouterAgent) Analyze(ctx context.Context, req AnalyzeRequest) (*AnalysisResult, error) {
    body := buildOpenAIRequest(a.model, SystemPrompt, BuildUserMessage(req))

    httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
        openRouterBaseURL+"/chat/completions", body)
    if err != nil {
        return nil, err
    }
    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
    httpReq.Header.Set("HTTP-Referer", "https://cybercrit.dev")
    httpReq.Header.Set("X-Title", "cybercrit")

    resp, err := a.client.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusUnauthorized {
        return nil, fmt.Errorf("openrouter: 401 unauthorized")
    }
    if resp.StatusCode == http.StatusTooManyRequests {
        return nil, fmt.Errorf("openrouter: 429 rate limited")
    }
    if resp.StatusCode == http.StatusServiceUnavailable {
        return nil, fmt.Errorf("openrouter: 503 service unavailable")
    }
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("openrouter: unexpected status %d", resp.StatusCode)
    }

    return parseOpenAIResponse(resp.Body)
}
