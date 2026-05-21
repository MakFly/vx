package cmd

import (
	"reflect"
	"testing"
)

func TestNormalizeTarget(t *testing.T) {
	tests := map[string]string{
		"example.com/":         "https://example.com",
		"https://example.com/": "https://example.com",
		"http://example.com/a": "http://example.com/a",
	}

	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			if got := normalizeTarget(input); got != want {
				t.Fatalf("normalizeTarget(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestSplitList(t *testing.T) {
	got := splitList("headers, cookies,,xss ")
	want := []string{"headers", "cookies", "xss"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitList mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}
