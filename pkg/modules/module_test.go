package modules

import "testing"

func TestExtractHost(t *testing.T) {
	tests := map[string]string{
		"example.com":               "example.com",
		"https://example.com/path":  "example.com",
		"http://example.com:8080/a": "example.com",
		"https://[::1]:8443/path":   "::1",
	}

	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			if got := extractHost(input); got != want {
				t.Fatalf("extractHost(%q) = %q, want %q", input, got, want)
			}
		})
	}
}
