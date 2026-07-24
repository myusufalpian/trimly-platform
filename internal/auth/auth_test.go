package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trimly-platform/internal/auth"
)

type mockEmailSender struct {
	sentEmails map[string]string
}

func (m *mockEmailSender) SendVerificationEmail(toEmail, token string) error {
	if m.sentEmails == nil {
		m.sentEmails = make(map[string]string)
	}
	m.sentEmails[toEmail] = token
	return nil
}

func TestHashTokenDeterministic(t *testing.T) {
	rawToken := "sample_secret_token_123"
	hash1 := auth.HashToken(rawToken)
	hash2 := auth.HashToken(rawToken)

	if hash1 == "" {
		t.Fatalf("expected non-empty hash string")
	}

	if hash1 != hash2 {
		t.Errorf("expected deterministic hash output, got %s vs %s", hash1, hash2)
	}
}

func TestRequireVerifiedEmailMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		user           *auth.User
		expectedStatus int
	}{
		{
			name:           "Unverified User Blocked",
			user:           &auth.User{ID: "user-1", Email: "unverified@trimly.app", EmailVerifiedAt: nil},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "Verified User Permitted",
			user: func() *auth.User {
				now := time.Now()
				return &auth.User{ID: "user-2", Email: "verified@trimly.app", EmailVerifiedAt: &now}
			}(),
			expectedStatus: http.StatusOK,
		},
	}

	authHandler := auth.NewHandler(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := authHandler.RequireVerifiedEmailMiddleware(nextHandler)

			req := httptest.NewRequest("GET", "/test-protected", nil)
			ctx := context.WithValue(req.Context(), auth.UserContextKey, tt.user)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			middleware.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestAuthMiddlewareTokenExtraction(t *testing.T) {
	authHandler := auth.NewHandler(nil)

	reqCookie := httptest.NewRequest("GET", "/test", nil)
	reqCookie.AddCookie(&http.Cookie{Name: "session_token", Value: "cookie_token_abc"})

	reqBearer := httptest.NewRequest("GET", "/test", nil)
	reqBearer.Header.Set("Authorization", "Bearer bearer_token_xyz")

	reqUnauth := httptest.NewRequest("GET", "/test", nil)

	rrCookie := httptest.NewRecorder()
	authHandler.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rrCookie, reqCookie)
	// Status should be 401 because service is nil, but it passes token extraction check stage
	if rrCookie.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for nil service, got %d", rrCookie.Code)
	}

	rrUnauth := httptest.NewRecorder()
	authHandler.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rrUnauth, reqUnauth)
	if rrUnauth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 unauthenticated for missing token, got %d", rrUnauth.Code)
	}

	if !strings.Contains(rrUnauth.Body.String(), "UNAUTHENTICATED") {
		t.Errorf("expected UNAUTHENTICATED error code in response")
	}
}
