package llm

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
)

type openAIRequest struct {
    Model       string          `json:"model"`
    Messages    []openAIMessage `json:"messages"`
    Temperature float64         `json:"temperature"`
}

type openAIMessage struct {
    Role    string `json:"role"`
    Content string `json:"content"`
}

func buildOpenAIRequest(model, systemPrompt, userMsg string) io.Reader {
    req := openAIRequest{
        Model: model,
        Messages: []openAIMessage{
            {Role: "system", Content: systemPrompt},
            {Role: "user", Content: userMsg},
        },
        Temperature: 0.1,
    }
    b, _ := json.Marshal(req)
    return bytes.NewReader(b)
}

type openAIResponse struct {
    Choices []struct {
        Message struct {
            Content string `json:"content"`
        } `json:"message"`
    } `json:"choices"`
}

func parseOpenAIResponse(r io.Reader) (*AnalysisResult, error) {
    var resp openAIResponse
    if err := json.NewDecoder(r).Decode(&resp); err != nil {
        return nil, fmt.Errorf("llm: decode response: %v", err)
    }

    if len(resp.Choices) == 0 {
        return nil, fmt.Errorf("llm: response contained no choices")
    }

    content := resp.Choices[0].Message.Content
    content = StripFences(content)

    var result AnalysisResult
    if err := json.Unmarshal([]byte(content), &result); err != nil {
        return nil, fmt.Errorf("llm: unmarshal findings: %v", err)
    }

    // findings key might be present but empty, which is valid.
    // result.Findings is what we care about.
    if result.Findings == nil {
        result.Findings = []Finding{}
    }

    return &result, nil
}
