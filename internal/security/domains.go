package security

import "strings"

func NormalizeHostname(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	return strings.TrimSuffix(host, ".")
}

func IsHostInSet(host string, domains map[string]bool) bool {
	host = NormalizeHostname(host)
	if host == "" {
		return false
	}
	for domain := range domains {
		if domain == "" {
			continue
		}
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
