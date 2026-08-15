package admin_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trimly-platform/internal/admin"
	"trimly-platform/internal/auth"
)

type stubAdminService struct {
	users              []auth.User
	listUsersErr       error
	addBlacklistErr    error
	removeBlacklistErr error
	unflagErr          error
}

func (s *stubAdminService) ListUsers(ctx context.Context) ([]auth.User, error) {
	return s.users, s.listUsersErr
}

func (s *stubAdminService) AddBlacklistDomain(ctx context.Context, domain, reason, adminID string) error {
	return s.addBlacklistErr
}

func (s *stubAdminService) RemoveBlacklistDomain(ctx context.Context, domain string) error {
	return s.removeBlacklistErr
}

func (s *stubAdminService) UnflagClick(ctx context.Context, clickID string) error {
	return s.unflagErr
}

func withAdminUser(req *http.Request) *http.Request {
	ctx := context.WithValue(req.Context(), auth.UserContextKey, &auth.User{ID: "admin-1", IsPlatformAdmin: true})
	return req.WithContext(ctx)
}

func TestListUsersHandlerSuccess(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{
		users: []auth.User{{ID: "user-1", Email: "a@test.com"}},
	})
	rr := httptest.NewRecorder()
	handler.ListUsers(rr, withAdminUser(httptest.NewRequest("GET", "/v1/admin/users", nil)))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestListUsersHandlerError(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{listUsersErr: errors.New("db error")})
	rr := httptest.NewRecorder()
	handler.ListUsers(rr, withAdminUser(httptest.NewRequest("GET", "/v1/admin/users", nil)))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestAddBlacklistDomainHandlerSuccess(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{})
	rr := httptest.NewRecorder()
	handler.AddBlacklistDomain(rr, withAdminUser(httptest.NewRequest("POST", "/v1/admin/blacklist-domains", strings.NewReader(`{"domain":"evil.com","reason":"phishing"}`))))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestAddBlacklistDomainHandlerValidationError(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{addBlacklistErr: admin.ErrDomainRequired})
	rr := httptest.NewRecorder()
	handler.AddBlacklistDomain(rr, withAdminUser(httptest.NewRequest("POST", "/v1/admin/blacklist-domains", strings.NewReader(`{"domain":"","reason":""}`))))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAddBlacklistDomainHandlerGenericError(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{addBlacklistErr: errors.New("db error")})
	rr := httptest.NewRecorder()
	handler.AddBlacklistDomain(rr, withAdminUser(httptest.NewRequest("POST", "/v1/admin/blacklist-domains", strings.NewReader(`{"domain":"evil.com","reason":"phishing"}`))))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestAddBlacklistDomainHandlerUnauthenticated(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{})
	rr := httptest.NewRecorder()
	handler.AddBlacklistDomain(rr, httptest.NewRequest("POST", "/v1/admin/blacklist-domains", strings.NewReader(`{"domain":"evil.com","reason":"phishing"}`)))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAddBlacklistDomainHandlerInvalidJSON(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{})
	rr := httptest.NewRecorder()
	handler.AddBlacklistDomain(rr, withAdminUser(httptest.NewRequest("POST", "/v1/admin/blacklist-domains", strings.NewReader(`{invalid-json`))))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestRemoveBlacklistDomainHandlerSuccess(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{})
	rr := httptest.NewRecorder()
	handler.RemoveBlacklistDomain(rr, withAdminUser(httptest.NewRequest("DELETE", "/v1/admin/blacklist-domains/evil.com", nil)))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRemoveBlacklistDomainHandlerMissingDomain(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{})
	rr := httptest.NewRecorder()
	handler.RemoveBlacklistDomain(rr, withAdminUser(httptest.NewRequest("DELETE", "/v1/admin/blacklist-domains/", nil)))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestRemoveBlacklistDomainHandlerError(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{removeBlacklistErr: errors.New("db error")})
	rr := httptest.NewRecorder()
	handler.RemoveBlacklistDomain(rr, withAdminUser(httptest.NewRequest("DELETE", "/v1/admin/blacklist-domains/evil.com", nil)))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestUnflagClickHandlerSuccess(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{})
	rr := httptest.NewRecorder()
	handler.UnflagClick(rr, withAdminUser(httptest.NewRequest("POST", "/v1/admin/clicks/unflag", strings.NewReader(`{"click_id":"click-1"}`))))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestUnflagClickHandlerValidationError(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{unflagErr: admin.ErrClickIDRequired})
	rr := httptest.NewRecorder()
	handler.UnflagClick(rr, withAdminUser(httptest.NewRequest("POST", "/v1/admin/clicks/unflag", strings.NewReader(`{"click_id":""}`))))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestUnflagClickHandlerGenericError(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{unflagErr: errors.New("db error")})
	rr := httptest.NewRecorder()
	handler.UnflagClick(rr, withAdminUser(httptest.NewRequest("POST", "/v1/admin/clicks/unflag", strings.NewReader(`{"click_id":"click-1"}`))))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestUnflagClickHandlerInvalidJSON(t *testing.T) {
	handler := admin.NewHandler(&stubAdminService{})
	rr := httptest.NewRecorder()
	handler.UnflagClick(rr, withAdminUser(httptest.NewRequest("POST", "/v1/admin/clicks/unflag", strings.NewReader(`{invalid-json`))))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}
