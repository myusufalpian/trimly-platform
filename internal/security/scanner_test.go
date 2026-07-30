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
}
