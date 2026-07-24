package link_test

import (
	"context"
	"testing"
	"time"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/link"
)

func TestCreateLinkValidations(t *testing.T) {
	svc := link.NewService(nil)

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
	svc := link.NewService(nil)

	// When downgrading to non-FREE plan (e.g. PRO), no active count check required
	err := svc.CheckDowngradeAllowed(context.Background(), "user-1", "PRO")
	if err != nil {
		t.Errorf("expected no error for PRO downgrade, got %v", err)
	}
}
