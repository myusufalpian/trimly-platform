package link

import "testing"

func TestTrimRedirectSlug(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "standard slug", path: "/r/abc123", expected: "abc123"},
		{name: "leading whitespace", path: "/r/  abc123", expected: "abc123"},
		{name: "trailing whitespace", path: "/r/abc123  ", expected: "abc123"},
		{name: "no prefix", path: "abc123", expected: "abc123"},
		{name: "empty path", path: "", expected: ""},
		{name: "short path", path: "/r", expected: "/r"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimRedirectSlug(tt.path)
			if got != tt.expected {
				t.Errorf("trimRedirectSlug(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}
