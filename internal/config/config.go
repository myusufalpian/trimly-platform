package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port           string
	DatabaseURL    string
	SMTPHost       string
	SMTPPort       string
	ThreatDomains  []string
	CookieSecure   bool
	TrustedProxies []string
}

func LoadConfig() (*Config, error) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, errors.New("DATABASE_URL environment variable is required")
	}

	smtpHost := os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		smtpHost = "localhost"
	}

	smtpPort := os.Getenv("SMTP_PORT")
	if smtpPort == "" {
		smtpPort = "1025"
	}

	cookieSecure := os.Getenv("COOKIE_SECURE")
	if cookieSecure == "" {
		cookieSecure = "true"
	}
	cookieSecureParsed, err := strconv.ParseBool(cookieSecure)
	if err != nil {
		return nil, errors.New("COOKIE_SECURE must be a boolean")
	}

	var threatDomains []string
	for _, domain := range strings.Split(os.Getenv("THREAT_DOMAINS"), ",") {
		if domain = strings.TrimSpace(strings.ToLower(domain)); domain != "" {
			threatDomains = append(threatDomains, domain)
		}
	}
	if len(threatDomains) == 0 {
		threatDomains = []string{"malicious.com", "phishing.com"}
	}

	var trustedProxies []string
	for _, cidr := range strings.Split(os.Getenv("TRUSTED_PROXIES"), ",") {
		if cidr = strings.TrimSpace(cidr); cidr != "" {
			trustedProxies = append(trustedProxies, cidr)
		}
	}

	return &Config{
		Port:           port,
		DatabaseURL:    dbURL,
		SMTPHost:       smtpHost,
		SMTPPort:       smtpPort,
		ThreatDomains:  threatDomains,
		CookieSecure:   cookieSecureParsed,
		TrustedProxies: trustedProxies,
	}, nil
}
