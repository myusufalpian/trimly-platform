package security

import (
	"context"
	"net/url"
	"strings"
)

type MockURLScanner struct {
	MaliciousDomains map[string]bool
}

func NewMockURLScanner(domains ...string) *MockURLScanner {
	maliciousDomains := make(map[string]bool, len(domains))
	for _, domain := range domains {
		maliciousDomains[strings.ToLower(strings.TrimSpace(domain))] = true
	}
	return &MockURLScanner{MaliciousDomains: maliciousDomains}
}

func (s *MockURLScanner) CheckURL(_ context.Context, targetURL string) (bool, error) {
	parsed, err := url.ParseRequestURI(targetURL)
	if err != nil {
		return false, err
	}
	return s.MaliciousDomains[strings.ToLower(parsed.Hostname())], nil
}
