package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAICompatibleProvider talks to any service exposing the
// `/chat/completions` shape.
//
// Using one wire format rather than one vendor SDK means the same adapter works
// against a hosted API and against a local model server, which is what the
// product's "support local provider deployment" requirement needs. It also keeps
// the dependency surface at zero: this is a POST with a JSON body.
type OpenAICompatibleProvider struct {
	name    string
	baseURL string
	apiKey  string
	model   string

	client *http.Client

	// maxTokens bounds the model's output. It is a cost control and a latency
	// control, not a formatting preference.
	maxTokens int

	// temperature is pinned low: an analyst summary should be repeatable, and a
	// creative model is more likely to invent a plausible detail.
	temperature float64
}

// ProviderOptions configures the HTTP provider.
type ProviderOptions struct {
	// Name is recorded on the analysis so a reader knows which backend produced
	// it. It defaults to the model name.
	Name string

	// BaseURL is the API root, for example https://api.example.test/v1.
	BaseURL string

	// APIKey is the bearer credential. It stays server-side and is never
	// included in a response, a log line or an error message.
	APIKey string

	// Model is the model identifier to request.
	Model string

	// Timeout bounds one request.
	Timeout time.Duration

	// MaxTokens bounds the response length.
	MaxTokens int
}

// DefaultProviderOptions returns conservative defaults.
func DefaultProviderOptions() ProviderOptions {
	return ProviderOptions{
		Timeout:   30 * time.Second,
		MaxTokens: 700,
	}
}

// NewOpenAICompatibleProvider builds a provider.
//
// A missing base URL or model is a configuration error rather than a silent
// fallback: an operator who configured a provider expects it to be used, and
// silently disabling it would hide the mistake.
func NewOpenAICompatibleProvider(opts ProviderOptions) (*OpenAICompatibleProvider, error) {
	def := DefaultProviderOptions()
	if opts.Timeout <= 0 {
		opts.Timeout = def.Timeout
	}
	if opts.MaxTokens <= 0 {
		opts.MaxTokens = def.MaxTokens
	}
	if strings.TrimSpace(opts.BaseURL) == "" {
		return nil, fmt.Errorf("ai: provider base url is required")
	}
	if strings.TrimSpace(opts.Model) == "" {
		return nil, fmt.Errorf("ai: provider model is required")
	}
	if opts.Name == "" {
		opts.Name = opts.Model
	}

	return &OpenAICompatibleProvider{
		name:    opts.Name,
		baseURL: strings.TrimRight(opts.BaseURL, "/"),
		apiKey:  opts.APIKey,
		model:   opts.Model,
		client: &http.Client{
			Timeout: opts.Timeout,
			// The provider is an external service: do not follow redirects, so a
			// misconfigured or hostile endpoint cannot redirect the request (and
			// with it the Authorization header) to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		maxTokens:   opts.MaxTokens,
		temperature: 0.1,
	}, nil
}

// Name implements Provider.
func (p *OpenAICompatibleProvider) Name() string { return p.name }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens"`
	Temperature float64       `json:"temperature"`
	Stream      bool          `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// Complete implements Provider.
//
// The provider's error text is deliberately not propagated to the caller. It can
// contain request fragments, and an upstream error body is not something an
// operator needs to see to understand that the AI feature is unavailable.
func (p *OpenAICompatibleProvider) Complete(ctx context.Context, system, user string) (string, error) {
	body := chatRequest{
		Model: p.model,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		MaxTokens:   p.maxTokens,
		Temperature: p.temperature,
		Stream:      false,
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("ai: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/chat/completions", bytes.NewReader(encoded))
	if err != nil {
		return "", fmt.Errorf("ai: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ai: request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("ai: provider returned status %d", resp.StatusCode)
	}

	var parsed chatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return "", fmt.Errorf("ai: decode response: %w", err)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("ai: provider reported an error")
	}
	if len(parsed.Choices) == 0 {
		return "", ErrEmptyResponse
	}
	return parsed.Choices[0].Message.Content, nil
}
