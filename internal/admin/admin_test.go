package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"trimly-platform/internal/admin"
	"trimly-platform/internal/auth"
)

func TestRequirePlatformAdminMiddleware(t *testing.T) {
	svc := admin.NewService(nil)
	middleware := svc.RequirePlatformAdminMiddleware

	tests := []struct {
		name           string
		user           *auth.User
		expectedStatus int
	}{
		{
			name:           "Regular User Blocked",
			user:           &auth.User{ID: "user-1", Email: "user@trimly.app", IsPlatformAdmin: false},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Platform Admin Permitted",
			user:           &auth.User{ID: "admin-1", Email: "admin@trimly.app", IsPlatformAdmin: true},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/v1/admin/users", nil)
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

func TestAddBlacklistDomainValidation(t *testing.T) {
	svc := admin.NewService(nil)

	err := svc.AddBlacklistDomain(context.Background(), "", "phishing site", "admin-1")
	if err == nil {
		t.Fatalf("expected error for empty domain, got nil")
	}

	if err.Error() != "domain is required" {
		t.Errorf("expected error 'domain is required', got %q", err.Error())
	}
}
