package config

import (
	"os"
)

type Config struct {
	Port        string
	DatabaseURL string
	SMTPHost    string
	SMTPPort    string
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

	return &Config{
		Port:        port,
		DatabaseURL: dbURL,
		SMTPHost:    smtpHost,
		SMTPPort:    smtpPort,
	}
}
