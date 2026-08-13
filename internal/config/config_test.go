package config

import "testing"

func TestLoadConfigRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error when DATABASE_URL is not set")
	}
}

func TestLoadConfigWithEnvironment(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@db:5432/app?sslmode=require")
	t.Setenv("PORT", "9090")
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("THREAT_DOMAINS", "malicious.com, phishing.com")
	t.Setenv("COOKIE_SECURE", "false")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.Port != "9090" {
		t.Errorf("expected port 9090, got %q", cfg.Port)
	}
	if cfg.DatabaseURL != "postgres://user:pass@db:5432/app?sslmode=require" {
		t.Errorf("unexpected database URL: %q", cfg.DatabaseURL)
	}
	if cfg.SMTPHost != "smtp.example.com" || cfg.SMTPPort != "587" {
		t.Errorf("unexpected smtp config: %q %q", cfg.SMTPHost, cfg.SMTPPort)
	}
	if len(cfg.ThreatDomains) != 2 || cfg.ThreatDomains[0] != "malicious.com" {
		t.Errorf("unexpected threat domains: %v", cfg.ThreatDomains)
	}
	if cfg.CookieSecure {
		t.Errorf("expected CookieSecure false, got true")
	}
}

func TestLoadConfigTrustedProxies(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@db:5432/app")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.10, ")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(cfg.TrustedProxies) != 2 {
		t.Fatalf("expected 2 trusted proxies, got %v", cfg.TrustedProxies)
	}
	if cfg.TrustedProxies[0] != "10.0.0.0/8" || cfg.TrustedProxies[1] != "192.168.1.10" {
		t.Errorf("unexpected trusted proxies: %v", cfg.TrustedProxies)
	}
}

func TestLoadConfigTrustedProxiesEmpty(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@db:5432/app")
	t.Setenv("TRUSTED_PROXIES", "")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Errorf("expected no trusted proxies by default, got %v", cfg.TrustedProxies)
	}
}

func TestLoadConfigCookieSecureDefaultsTrue(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@db:5432/app")
	t.Setenv("COOKIE_SECURE", "")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !cfg.CookieSecure {
		t.Error("expected CookieSecure to default to true")
	}
}

func TestLoadConfigInvalidCookieSecure(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@db:5432/app")
	t.Setenv("COOKIE_SECURE", "not-a-bool")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for invalid COOKIE_SECURE")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@db:5432/app")
	t.Setenv("PORT", "")
	t.Setenv("SMTP_HOST", "")
	t.Setenv("SMTP_PORT", "")
	t.Setenv("THREAT_DOMAINS", "")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.Port != "8080" {
		t.Errorf("expected default port 8080, got %q", cfg.Port)
	}
	if cfg.SMTPHost != "localhost" || cfg.SMTPPort != "1025" {
		t.Errorf("unexpected smtp defaults: %q %q", cfg.SMTPHost, cfg.SMTPPort)
	}
	if len(cfg.ThreatDomains) != 2 || cfg.ThreatDomains[0] != "malicious.com" {
		t.Errorf("expected default threat domains, got %v", cfg.ThreatDomains)
	}
}
