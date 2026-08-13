package security

import (
	"context"
	"testing"
)

func TestMockURLScanner(t *testing.T) {
	t.Run("NewMockURLScanner Constructor and Domain Matching", func(t *testing.T) {
		scanner := NewMockURLScanner("bad.test", " PHISHING.COM ", "MALWARE.NET")

		// Test malicious domain match (case-insensitive & trimmed)
		malicious, err := scanner.CheckURL(context.Background(), "https://bad.test/phishing-path")
		if err != nil || !malicious {
			t.Fatalf("expected bad.test to be flagged malicious, got malicious=%v err=%v", malicious, err)
		}

		malicious, err = scanner.CheckURL(context.Background(), "http://phishing.com/login")
		if err != nil || !malicious {
			t.Fatalf("expected phishing.com to be flagged malicious, got malicious=%v err=%v", malicious, err)
		}

		// Test safe domain
		safe, err := scanner.CheckURL(context.Background(), "https://safe.test/home")
		if err != nil || safe {
			t.Fatalf("expected safe.test to be safe, got malicious=%v err=%v", safe, err)
		}
	})

	t.Run("Invalid Target URL Error Handling", func(t *testing.T) {
		scanner := NewMockURLScanner("bad.test")
		_, err := scanner.CheckURL(context.Background(), "::not-a-valid-url::")
		if err == nil {
			t.Fatal("expected error when checking invalid URL string, got nil")
		}
	})

	t.Run("Trailing dot bypass is flagged", func(t *testing.T) {
		scanner := NewMockURLScanner("phishing.com")
		malicious, err := scanner.CheckURL(context.Background(), "http://phishing.com./login")
		if err != nil || !malicious {
			t.Fatalf("expected trailing-dot phishing.com to be flagged, got malicious=%v err=%v", malicious, err)
		}
	})

	t.Run("Subdomain of malicious domain is flagged", func(t *testing.T) {
		scanner := NewMockURLScanner("phishing.com")
		malicious, err := scanner.CheckURL(context.Background(), "http://evil.phishing.com/login")
		if err != nil || !malicious {
			t.Fatalf("expected evil.phishing.com to be flagged, got malicious=%v err=%v", malicious, err)
		}
	})

	t.Run("Domain containing malicious name as suffix is safe", func(t *testing.T) {
		scanner := NewMockURLScanner("phishing.com")
		safe, err := scanner.CheckURL(context.Background(), "http://phishing.com.evil.io/login")
		if err != nil || safe {
			t.Fatalf("expected phishing.com.evil.io to be safe, got malicious=%v err=%v", safe, err)
		}
	})
}

func TestNormalizeHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Phishing.COM", "phishing.com"},
		{"phishing.com.", "phishing.com"},
		{"  evil.test  ", "evil.test"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := NormalizeHostname(tt.input); got != tt.expected {
			t.Errorf("NormalizeHostname(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestIsHostInSet(t *testing.T) {
	domains := map[string]bool{"phishing.com": true, "bad.test": true}

	t.Run("Exact match", func(t *testing.T) {
		if !IsHostInSet("phishing.com", domains) {
			t.Error("expected exact host to match")
		}
	})
	t.Run("Subdomain match", func(t *testing.T) {
		if !IsHostInSet("evil.phishing.com", domains) {
			t.Error("expected subdomain of blacklisted host to match")
		}
	})
	t.Run("Suffix-only domain does not match", func(t *testing.T) {
		if IsHostInSet("phishing.com.evil.io", domains) {
			t.Error("expected unrelated registrable domain not to match")
		}
	})
	t.Run("Unrelated host does not match", func(t *testing.T) {
		if IsHostInSet("safe.test", domains) {
			t.Error("expected safe host not to match")
		}
	})
	t.Run("Empty host does not match", func(t *testing.T) {
		if IsHostInSet("", domains) {
			t.Error("expected empty host not to match")
		}
	})
}
