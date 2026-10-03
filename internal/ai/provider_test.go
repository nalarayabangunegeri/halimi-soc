package ai_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/ai"
)

func TestProviderRequiresConfiguration(t *testing.T) {
	// A half-configured provider is a mistake worth failing on: silently
	// disabling AI would hide it.
	if _, err := ai.NewOpenAICompatibleProvider(ai.ProviderOptions{Model: "m"}); err == nil {
		t.Error("expected an error when the base url is missing")
	}
	if _, err := ai.NewOpenAICompatibleProvider(ai.ProviderOptions{BaseURL: "https://x.test"}); err == nil {
		t.Error("expected an error when the model is missing")
	}
}

func TestProviderComplete(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path

		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"  grounded summary  "}}]}`))
	}))
	defer srv.Close()

	p, err := ai.NewOpenAICompatibleProvider(ai.ProviderOptions{
		BaseURL: srv.URL + "/v1",
		APIKey:  "test-key-value",
		Model:   "test-model",
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := p.Complete(context.Background(), "system text", "user text")
	if err != nil {
		t.Fatalf("Complete() = %v", err)
	}
	if strings.TrimSpace(got) != "grounded summary" {
		t.Fatalf("content = %q", got)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("path = %q, want /v1/chat/completions", gotPath)
	}
	if gotAuth != "Bearer test-key-value" {
		t.Errorf("auth header = %q", gotAuth)
	}

	// The request must carry the system instruction as its own message, so the
	// trust boundary is stated by the system role rather than mixed into data.
	msgs, _ := gotBody["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("messages = %d, want 2", len(msgs))
	}
	first, _ := msgs[0].(map[string]any)
	if first["role"] != "system" {
		t.Errorf("first message role = %v, want system", first["role"])
	}
	if gotBody["stream"] != false {
		t.Error("streaming must be disabled")
	}
}

func TestProviderRejectsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"internal detail that must not leak"}}`))
	}))
	defer srv.Close()

	p, err := ai.NewOpenAICompatibleProvider(ai.ProviderOptions{
		BaseURL: srv.URL, Model: "m",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.Complete(context.Background(), "s", "u")
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	// The upstream error text can contain request fragments, so it is not
	// propagated.
	if strings.Contains(err.Error(), "internal detail") {
		t.Errorf("provider error text leaked into the error: %v", err)
	}
}

func TestProviderDoesNotFollowRedirects(t *testing.T) {
	// A redirect would carry the Authorization header to another host.
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"pwned"}}]}`))
	}))
	defer evil.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	p, err := ai.NewOpenAICompatibleProvider(ai.ProviderOptions{
		BaseURL: redirector.URL, APIKey: "secret-token", Model: "m",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := p.Complete(context.Background(), "s", "u"); err == nil {
		t.Fatal("expected the redirect to be refused")
	}
	if leaked != "" {
		t.Fatalf("the credential was forwarded to the redirect target: %q", leaked)
	}
}

func TestProviderHonoursContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()

	p, err := ai.NewOpenAICompatibleProvider(ai.ProviderOptions{
		BaseURL: srv.URL, Model: "m", Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := p.Complete(ctx, "s", "u"); err == nil {
		t.Fatal("expected a cancellation error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("cancellation took %s, the context was not honoured", elapsed)
	}
}

func TestProviderRejectsEmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer srv.Close()

	p, err := ai.NewOpenAICompatibleProvider(ai.ProviderOptions{BaseURL: srv.URL, Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Complete(context.Background(), "s", "u"); err == nil {
		t.Fatal("expected an error when the provider returned no choices")
	}
}

func TestProviderNameDefaultsToModel(t *testing.T) {
	p, err := ai.NewOpenAICompatibleProvider(ai.ProviderOptions{BaseURL: "https://x.test", Model: "my-model"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "my-model" {
		t.Errorf("name = %q, want my-model", p.Name())
	}
}
