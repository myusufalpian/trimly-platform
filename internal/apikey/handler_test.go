package apikey_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"trimly-platform/internal/apikey"
	"trimly-platform/internal/auth"
)

type stubAPIKeyService struct {
	createResp   *apikey.APIKeyResponse
	createErr    error
	keys         []apikey.APIKeyResponse
	listErr      error
	revokeErr    error
	usageHistory []apikey.APIUsageDaily
	usageErr     error
}

func (s *stubAPIKeyService) CreateAPIKey(ctx context.Context, user *auth.User) (*apikey.APIKeyResponse, error) {
	return s.createResp, s.createErr
}

func (s *stubAPIKeyService) GetUserAPIKeys(ctx context.Context, userID string) ([]apikey.APIKeyResponse, error) {
	return s.keys, s.listErr
}

func (s *stubAPIKeyService) RevokeAPIKey(ctx context.Context, keyID, userID string) error {
	return s.revokeErr
}

func (s *stubAPIKeyService) GetAPIUsageHistory(ctx context.Context, userID string) ([]apikey.APIUsageDaily, error) {
	return s.usageHistory, s.usageErr
}

func withUser(req *http.Request) *http.Request {
	ctx := context.WithValue(req.Context(), auth.UserContextKey, &auth.User{ID: "user-1", PlanCode: "BUSINESS"})
	return req.WithContext(ctx)
}

func TestCreateAPIKeyHandlerSuccess(t *testing.T) {
	handler := apikey.NewHandler(&stubAPIKeyService{createResp: &apikey.APIKeyResponse{ID: "key-1", KeyPrefix: "trimly_liv"}})
	rr := httptest.NewRecorder()
	handler.CreateAPIKey(rr, withUser(httptest.NewRequest("POST", "/v1/api-keys", nil)))

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rr.Code)
	}
}

func TestCreateAPIKeyHandlerForbidden(t *testing.T) {
	handler := apikey.NewHandler(&stubAPIKeyService{createErr: apikey.ErrBusinessPlanRequired})
	rr := httptest.NewRecorder()
	handler.CreateAPIKey(rr, withUser(httptest.NewRequest("POST", "/v1/api-keys", nil)))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestCreateAPIKeyHandlerGenericError(t *testing.T) {
	handler := apikey.NewHandler(&stubAPIKeyService{createErr: errors.New("db error")})
	rr := httptest.NewRecorder()
	handler.CreateAPIKey(rr, withUser(httptest.NewRequest("POST", "/v1/api-keys", nil)))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestListAPIKeysHandlerSuccess(t *testing.T) {
	handler := apikey.NewHandler(&stubAPIKeyService{keys: []apikey.APIKeyResponse{{ID: "key-1"}}})
	rr := httptest.NewRecorder()
	handler.ListAPIKeys(rr, withUser(httptest.NewRequest("GET", "/v1/api-keys", nil)))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestListAPIKeysHandlerError(t *testing.T) {
	handler := apikey.NewHandler(&stubAPIKeyService{listErr: errors.New("db error")})
	rr := httptest.NewRecorder()
	handler.ListAPIKeys(rr, withUser(httptest.NewRequest("GET", "/v1/api-keys", nil)))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestRevokeAPIKeyHandlerSuccess(t *testing.T) {
	handler := apikey.NewHandler(&stubAPIKeyService{})
	rr := httptest.NewRecorder()
	handler.RevokeAPIKey(rr, withUser(httptest.NewRequest("DELETE", "/v1/api-keys/key-1", nil)))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRevokeAPIKeyHandlerMissingKeyID(t *testing.T) {
	handler := apikey.NewHandler(&stubAPIKeyService{})
	rr := httptest.NewRecorder()
	handler.RevokeAPIKey(rr, withUser(httptest.NewRequest("DELETE", "/v1/api-keys/", nil)))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestRevokeAPIKeyHandlerError(t *testing.T) {
	handler := apikey.NewHandler(&stubAPIKeyService{revokeErr: errors.New("db error")})
	rr := httptest.NewRecorder()
	handler.RevokeAPIKey(rr, withUser(httptest.NewRequest("DELETE", "/v1/api-keys/key-1", nil)))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestGetUsageHistoryHandlerSuccess(t *testing.T) {
	handler := apikey.NewHandler(&stubAPIKeyService{usageHistory: []apikey.APIUsageDaily{{APIKeyID: "key-1"}}})
	rr := httptest.NewRecorder()
	handler.GetUsageHistory(rr, withUser(httptest.NewRequest("GET", "/v1/api-usage", nil)))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestGetUsageHistoryHandlerError(t *testing.T) {
	handler := apikey.NewHandler(&stubAPIKeyService{usageErr: errors.New("db error")})
	rr := httptest.NewRecorder()
	handler.GetUsageHistory(rr, withUser(httptest.NewRequest("GET", "/v1/api-usage", nil)))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestAPIKeyHandlersUnauthenticated(t *testing.T) {
	handler := apikey.NewHandler(&stubAPIKeyService{})

	t.Run("CreateAPIKey", func(t *testing.T) {
		rr := httptest.NewRecorder()
		handler.CreateAPIKey(rr, httptest.NewRequest("POST", "/v1/api-keys", nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("ListAPIKeys", func(t *testing.T) {
		rr := httptest.NewRecorder()
		handler.ListAPIKeys(rr, httptest.NewRequest("GET", "/v1/api-keys", nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("RevokeAPIKey", func(t *testing.T) {
		rr := httptest.NewRecorder()
		handler.RevokeAPIKey(rr, httptest.NewRequest("DELETE", "/v1/api-keys/key-1", nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("GetUsageHistory", func(t *testing.T) {
		rr := httptest.NewRecorder()
		handler.GetUsageHistory(rr, httptest.NewRequest("GET", "/v1/api-usage", nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}
