package config

import (
	"os"
	"strings"
)

type Config struct {
	Port          string
	DatabaseURL   string
	SMTPHost      string
	SMTPPort      string
	ThreatDomains []string
}

func LoadConfig() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://trimly_user:trimly_password@localhost:5432/trimly_db?sslmode=disable"
	}

	smtpHost := os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		smtpHost = "localhost"
	}

	smtpPort := os.Getenv("SMTP_PORT")
	if smtpPort == "" {
		smtpPort = "1025"
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

	return &Config{
		Port:          port,
		DatabaseURL:   dbURL,
		SMTPHost:      smtpHost,
		SMTPPort:      smtpPort,
		ThreatDomains: threatDomains,
	}
}
