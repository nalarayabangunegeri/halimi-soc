package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// writeRules writes a merged YAML document into dir/rules.yaml.
func writeRules(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
}
