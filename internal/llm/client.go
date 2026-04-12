package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Provider endpoints for OpenAI-compatible APIs.
var providerEndpoints = map[string]string{
	"groq":   "https://api.groq.com/openai/v1/chat/completions",
	"openai": "https://api.openai.com/v1/chat/completions",
}

// Client handles communication with an OpenAI-compatible LLM API.
type Client struct {
	apiKey   string
	endpoint string
	model    string
	timeout  time.Duration
}

// NewClient creates an LLM client using the BYOK credential chain.
// It checks environment variables in order:
//  1. CYBERCRIT_API_KEY (provider-agnostic override)
//  2. GROQ_API_KEY (if provider is "groq")
//  3. OPENAI_API_KEY (if provider is "openai")
//
// Returns nil, nil if no API key is found (graceful skip).
func NewClient(provider, model string, timeoutSeconds int) (*Client, error) {
	apiKey := resolveAPIKey(provider)
	if apiKey == "" {
		return nil, nil // no key — graceful skip
	}

	endpoint, ok := providerEndpoints[provider]
	if !ok {
		return nil, fmt.Errorf("unknown LLM provider: %q (supported: groq, openai)", provider)
	}

	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return &Client{
		apiKey:   apiKey,
		endpoint: endpoint,
		model:    model,
		timeout:  timeout,
	}, nil
}

// resolveAPIKey checks env vars in BYOK priority order.
func resolveAPIKey(provider string) string {
	// Universal override
	if key := os.Getenv("CYBERCRIT_API_KEY"); key != "" {
		return key
	}

	// Provider-specific
	switch provider {
	case "groq":
		return os.Getenv("GROQ_API_KEY")
	case "openai":
		return os.Getenv("OPENAI_API_KEY")
	default:
		return ""
	}
}

// chatRequest is the OpenAI-compatible chat completion request body.
type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse is the OpenAI-compatible chat completion response body.
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// Complete sends a chat completion request and returns the raw response text.
// Enforces HardTimeout (LLM-04). Returns error on timeout or API failure.
func (c *Client) Complete(systemPrompt, userPrompt string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	reqBody := chatRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.1, // low temp for deterministic security analysis
		MaxTokens:   4096,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("LLM request timed out after %s", c.timeout)
		}
		return "", fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("LLM API returned %d: %s", resp.StatusCode, string(respBytes))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBytes, &chatResp); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if chatResp.Error != nil {
		return "", fmt.Errorf("LLM error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("LLM returned no choices")
	}

	return chatResp.Choices[0].Message.Content, nil
}
