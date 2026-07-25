package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trimly-platform/internal/auth"
)

func TestHashTokenDeterministic(t *testing.T) {
	token := "sample_token_string_123"
	hash1 := auth.HashToken(token)
	hash2 := auth.HashToken(token)

	if hash1 == "" {
		t.Fatalf("expected non-empty hash string")
	}

	if hash1 != hash2 {
		t.Errorf("expected deterministic hash output, got %s vs %s", hash1, hash2)
	}
}

func TestRequireVerifiedEmailMiddleware(t *testing.T) {
	handler := auth.NewHandler(nil)
	middleware := handler.RequireVerifiedEmailMiddleware

	now := time.Now()

	tests := []struct {
		name           string
		user           *auth.User
		expectedStatus int
	}{
		{
			name:           "Unverified User Blocked",
			user:           &auth.User{ID: "user-1", Email: "unverified@example.com", EmailVerifiedAt: nil},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Verified User Permitted",
			user:           &auth.User{ID: "user-2", Email: "verified@example.com", EmailVerifiedAt: &now},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/v1/links", nil)
			ctx := context.WithValue(req.Context(), auth.UserContextKey, tt.user)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware(nextHandler).ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestAuthMiddlewareTokenExtraction(t *testing.T) {
	handler := auth.NewHandler(nil)
	middleware := handler.AuthMiddleware

	req := httptest.NewRequest("GET", "/v1/auth/me", nil)
	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for missing token, got %d", rr.Code)
	}
}

func TestRegisterValidation(t *testing.T) {
	svc := auth.NewService(nil, nil)

	_, errShort := svc.Register(context.Background(), auth.RegisterRequest{Email: "user@example.com", Password: "short"})
	if errShort == nil {
		t.Fatalf("expected error for short password, got nil")
	}

	if errShort.Error() != "password must be at least 8 characters long" {
		t.Errorf("expected password length error, got %q", errShort.Error())
	}

	_, errEmpty := svc.Register(context.Background(), auth.RegisterRequest{Email: "", Password: "validpassword123"})
	if errEmpty == nil {
		t.Fatalf("expected error for empty email, got nil")
	}
}
