package link_test

import (
	"context"
	"testing"
	"time"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/link"
)

type mockBlacklistChecker struct {
	blacklistedDomains map[string]bool
}

func (m *mockBlacklistChecker) IsDomainBlacklisted(ctx context.Context, domain string) bool {
	if m.blacklistedDomains == nil {
		return false
	}
	return m.blacklistedDomains[domain]
}

func TestCreateLinkValidations(t *testing.T) {
	mockChecker := &mockBlacklistChecker{
		blacklistedDomains: map[string]bool{
			"malicious.com": true,
		},
	}

	svc := link.NewService(nil, mockChecker)

	userFree := &auth.User{ID: "user-free-1", PlanCode: "FREE"}
	userPro := &auth.User{ID: "user-pro-1", PlanCode: "PRO"}

	futureTime := time.Now().Add(24 * time.Hour)

	tests := []struct {
		name          string
		user          *auth.User
		req           link.CreateLinkRequest
		expectedError string
	}{
		{
			name:          "Empty Target URL",
			user:          userFree,
			req:           link.CreateLinkRequest{TargetURL: ""},
			expectedError: "target_url is required",
		},
		{
			name:          "Invalid Target URL Format",
			user:          userFree,
			req:           link.CreateLinkRequest{TargetURL: "invalid-url-string"},
			expectedError: "invalid target_url format",
		},
		{
			name:          "Blacklisted Domain Target URL",
			user:          userFree,
			req:           link.CreateLinkRequest{TargetURL: "https://malicious.com/phishing"},
			expectedError: "target_url domain is blacklisted and cannot be shortened",
		},
		{
			name:          "Custom Alias Prohibited for Free Plan",
			user:          userFree,
			req:           link.CreateLinkRequest{TargetURL: "https://example.com", CustomAlias: "my-custom-slug"},
			expectedError: "custom alias is only available on Pro or Business plans",
		},
		{
			name:          "Expiry Time Prohibited for Free Plan",
			user:          userFree,
			req:           link.CreateLinkRequest{TargetURL: "https://example.com", ExpiresAt: &futureTime},
			expectedError: "expiry time is only available on Pro or Business plans",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateLink(context.Background(), tt.user, tt.req)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectedError)
			}
			if err.Error() != tt.expectedError {
				t.Errorf("expected error %q, got %q", tt.expectedError, err.Error())
			}
		})
	}

	_ = userPro
}

func TestCheckDowngradeAllowedValidation(t *testing.T) {
	svc := link.NewService(nil, nil)

	err := svc.CheckDowngradeAllowed(context.Background(), "user-1", "PRO")
	if err != nil {
		t.Errorf("expected no error for PRO downgrade, got %v", err)
	}
}

func TestExportCSVAnalyticsPlanGating(t *testing.T) {
	svc := link.NewService(nil, nil)

	userFree := &auth.User{ID: "user-free-1", PlanCode: "FREE"}
	_, err := svc.ExportCSVAnalytics(context.Background(), userFree, "link-1")
	if err == nil {
		t.Fatalf("expected error for Free plan CSV export, got nil")
	}

	expectedErr := "CSV analytics export is only available on Pro or Business plans"
	if err.Error() != expectedErr {
		t.Errorf("expected error %q, got %q", expectedErr, err.Error())
	}
}
