package apikey

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"trimly-platform/internal/auth"
)

type mockAPIKeyRepo struct {
	apiKeyResp      *APIKeyResponse
	createErr       error
	keys            []APIKeyResponse
	getKeysErr      error
	revokeErr       error
	user            *auth.User
	apiKeyID        string
	validateErr     error
	quotaErr        error
	usageHistory    []APIUsageDaily
	usageHistoryErr error
}

func (m *mockAPIKeyRepo) CreateAPIKey(ctx context.Context, userID, keyPrefix, rawKey string) (*APIKeyResponse, error) {
	return m.apiKeyResp, m.createErr
}

func (m *mockAPIKeyRepo) GetUserAPIKeys(ctx context.Context, userID string) ([]APIKeyResponse, error) {
	return m.keys, m.getKeysErr
}

func (m *mockAPIKeyRepo) RevokeAPIKey(ctx context.Context, keyID, userID string) error {
	return m.revokeErr
}

func (m *mockAPIKeyRepo) ValidateAPIKey(ctx context.Context, rawKey string) (*auth.User, string, error) {
	return m.user, m.apiKeyID, m.validateErr
}

func (m *mockAPIKeyRepo) IncrementAndCheckDailyQuota(ctx context.Context, apiKeyID string) error {
	return m.quotaErr
}

func (m *mockAPIKeyRepo) GetAPIUsageHistory(ctx context.Context, userID string) ([]APIUsageDaily, error) {
	return m.usageHistory, m.usageHistoryErr
}

func TestServiceCreateAPIKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &mockAPIKeyRepo{
			apiKeyResp: &APIKeyResponse{ID: "key-1", KeyPrefix: "trimly_live"},
		}
		svc := NewService(repo)
		user := &auth.User{ID: "user-1", PlanCode: "BUSINESS"}

		resp, err := svc.CreateAPIKey(context.Background(), user)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if resp == nil {
			t.Fatal("expected response, got nil")
		}
	})

	t.Run("non-business plan", func(t *testing.T) {
		repo := &mockAPIKeyRepo{}
		svc := NewService(repo)
		user := &auth.User{ID: "user-1", PlanCode: "FREE"}

		_, err := svc.CreateAPIKey(context.Background(), user)
		if !errors.Is(err, ErrBusinessPlanRequired) {
			t.Errorf("expected ErrBusinessPlanRequired, got %v", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		repo := &mockAPIKeyRepo{createErr: errors.New("database error")}
		svc := NewService(repo)
		user := &auth.User{ID: "user-1", PlanCode: "BUSINESS"}

		_, err := svc.CreateAPIKey(context.Background(), user)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestServiceGetUserAPIKeys(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &mockAPIKeyRepo{
			keys: []APIKeyResponse{
				{ID: "key-1", KeyPrefix: "trimly_live"},
				{ID: "key-2", KeyPrefix: "trimly_live"},
			},
		}
		svc := NewService(repo)

		keys, err := svc.GetUserAPIKeys(context.Background(), "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(keys) != 2 {
			t.Errorf("expected 2 keys, got %d", len(keys))
		}
	})

	t.Run("database error", func(t *testing.T) {
		repo := &mockAPIKeyRepo{getKeysErr: errors.New("database error")}
		svc := NewService(repo)

		_, err := svc.GetUserAPIKeys(context.Background(), "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestServiceRevokeAPIKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &mockAPIKeyRepo{}
		svc := NewService(repo)

		err := svc.RevokeAPIKey(context.Background(), "key-1", "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		repo := &mockAPIKeyRepo{revokeErr: errors.New("database error")}
		svc := NewService(repo)

		err := svc.RevokeAPIKey(context.Background(), "key-1", "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestServiceGetAPIUsageHistory(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &mockAPIKeyRepo{
			usageHistory: []APIUsageDaily{
				{APIKeyID: "key-1", Date: "2024-01-01", AcceptedRequestCount: 100},
			},
		}
		svc := NewService(repo)

		history, err := svc.GetAPIUsageHistory(context.Background(), "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(history) != 1 {
			t.Errorf("expected 1 record, got %d", len(history))
		}
	})

	t.Run("database error", func(t *testing.T) {
		repo := &mockAPIKeyRepo{usageHistoryErr: errors.New("database error")}
		svc := NewService(repo)

		_, err := svc.GetAPIUsageHistory(context.Background(), "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestGenerateAPIKeyString(t *testing.T) {
	rawKey, keyPrefix, err := generateAPIKeyString()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if rawKey == "" {
		t.Error("expected raw key, got empty")
	}
	if keyPrefix == "" {
		t.Error("expected key prefix, got empty")
	}
	if len(keyPrefix) != apiKeyPrefixLen {
		t.Errorf("expected key prefix length %d, got %d", apiKeyPrefixLen, len(keyPrefix))
	}
}

func TestAPIKeyAuthMiddlewareValidKey(t *testing.T) {
	repo := &mockAPIKeyRepo{
		user:     &auth.User{ID: "user-1", PlanCode: "BUSINESS"},
		apiKeyID: "key-1",
	}
	svc := NewService(repo)
	middleware := svc.APIKeyAuthMiddleware

	req := httptest.NewRequest("POST", "/v1/api/links", nil)
	req.Header.Set("X-API-Key", "trimly_live_abc123")
	rr := httptest.NewRecorder()

	var capturedUser *auth.User
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = r.Context().Value(auth.UserContextKey).(*auth.User)
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
	if capturedUser == nil {
		t.Fatal("expected user in context, got nil")
	}
	if capturedUser.ID != "user-1" {
		t.Errorf("expected user-1, got %s", capturedUser.ID)
	}
}

func TestAPIKeyAuthMiddlewareInvalidKey(t *testing.T) {
	repo := &mockAPIKeyRepo{validateErr: errors.New("invalid or revoked API key")}
	svc := NewService(repo)
	middleware := svc.APIKeyAuthMiddleware

	req := httptest.NewRequest("POST", "/v1/api/links", nil)
	req.Header.Set("X-API-Key", "trimly_live_invalid")
	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rr.Code)
	}
}

func TestAPIKeyAuthMiddlewareDailyQuotaExceeded(t *testing.T) {
	repo := &mockAPIKeyRepo{
		user:     &auth.User{ID: "user-1", PlanCode: "BUSINESS"},
		apiKeyID: "key-1",
		quotaErr: errors.New("daily API quota of 5,000 requests exceeded"),
	}
	svc := NewService(repo)
	middleware := svc.APIKeyAuthMiddleware

	req := httptest.NewRequest("POST", "/v1/api/links", nil)
	req.Header.Set("X-API-Key", "trimly_live_abc123")
	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 Too Many Requests, got %d", rr.Code)
	}
}

func TestAPIKeyAuthMiddlewareRateLimitExceeded(t *testing.T) {
	repo := &mockAPIKeyRepo{
		user:     &auth.User{ID: "user-1", PlanCode: "BUSINESS"},
		apiKeyID: "key-1",
	}
	svc := NewService(repo)
	middleware := svc.APIKeyAuthMiddleware

	limiter := svc.getRateLimiter("key-1")
	for i := 0; i < b2bRateBurst; i++ {
		if !limiter.Allow() {
			t.Fatal("expected limiter to allow until burst exhausted")
		}
	}

	req := httptest.NewRequest("POST", "/v1/api/links", nil)
	req.Header.Set("X-API-Key", "trimly_live_abc123")
	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 Too Many Requests, got %d", rr.Code)
	}
}

func TestGetRateLimiterReturnsSameInstance(t *testing.T) {
	repo := &mockAPIKeyRepo{}
	svc := NewService(repo)

	limiter1 := svc.getRateLimiter("key-1")
	limiter2 := svc.getRateLimiter("key-1")

	if limiter1 != limiter2 {
		t.Error("expected same limiter instance for same API key")
	}

	limiter3 := svc.getRateLimiter("key-2")
	if limiter1 == limiter3 {
		t.Error("expected different limiter instance for different API key")
	}
}
