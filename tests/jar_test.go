package tests

import (
	"net/http/cookiejar"
	"testing"
)

// newJar returns a cookie jar, failing the test if one cannot be created.
func newJar(t *testing.T) *cookiejar.Jar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	return jar
}
