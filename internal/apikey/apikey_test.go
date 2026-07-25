package apikey_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"trimly-platform/internal/apikey"
	"trimly-platform/internal/auth"
)

func TestHashAPIKeyDeterministic(t *testing.T) {
	rawKey := "trimly_live_abc123xyz890"
	hash1 := apikey.HashAPIKey(rawKey)
	hash2 := apikey.HashAPIKey(rawKey)

	if hash1 == "" {
		t.Fatalf("expected non-empty hash string")
	}

	if hash1 != hash2 {
		t.Errorf("expected deterministic hash output, got %s vs %s", hash1, hash2)
	}
}

func TestCreateAPIKeyPlanGating(t *testing.T) {
	svc := apikey.NewService(nil)

	userFree := &auth.User{ID: "user-free", PlanCode: "FREE"}
	userPro := &auth.User{ID: "user-pro", PlanCode: "PRO"}

	_, errFree := svc.CreateAPIKey(context.Background(), userFree)
	if errFree == nil {
		t.Fatalf("expected error for Free plan user, got nil")
	}

	if errFree.Error() != "API key generation is exclusive to Business plan" {
		t.Errorf("expected Business plan error, got %q", errFree.Error())
	}

	_, errPro := svc.CreateAPIKey(context.Background(), userPro)
	if errPro == nil {
		t.Fatalf("expected error for Pro plan user, got nil")
	}
}

func TestAPIKeyAuthMiddlewareUnauthenticated(t *testing.T) {
	svc := apikey.NewService(nil)
	middleware := svc.APIKeyAuthMiddleware

	req := httptest.NewRequest("POST", "/v1/api/links", nil)
	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for missing API key, got %d", rr.Code)
	}
}

func TestHandlerRevokeAPIKeyMissingParam(t *testing.T) {
	handler := apikey.NewHandler(nil)
	user := &auth.User{ID: "user-1", PlanCode: "BUSINESS"}

	req := httptest.NewRequest("DELETE", "/v1/api-keys/", nil)
	ctx := context.WithValue(req.Context(), auth.UserContextKey, user)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.RevokeAPIKey(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for missing key_id, got %d", rr.Code)
	}
}
