package apikey

import (
	"net/http/httptest"
	"testing"
)

func TestExtractAPIKeyFromRequest(t *testing.T) {
	t.Run("X-API-Key header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "  trimly_live_abc123  ")

		key := extractAPIKeyFromRequest(req)
		if key != "trimly_live_abc123" {
			t.Errorf("expected 'trimly_live_abc123', got %q", key)
		}
	})

	t.Run("Bearer token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer trimly_live_abc123")

		key := extractAPIKeyFromRequest(req)
		if key != "trimly_live_abc123" {
			t.Errorf("expected 'trimly_live_abc123', got %q", key)
		}
	})

	t.Run("no API key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)

		key := extractAPIKeyFromRequest(req)
		if key != "" {
			t.Errorf("expected empty string, got %q", key)
		}
	})

	t.Run("X-API-Key takes precedence", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "trimly_live_xapikey")
		req.Header.Set("Authorization", "Bearer trimly_live_bearer")

		key := extractAPIKeyFromRequest(req)
		if key != "trimly_live_xapikey" {
			t.Errorf("expected 'trimly_live_xapikey', got %q", key)
		}
	})
}
