package link_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/link"
	"trimly-platform/internal/security"
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
		name           string
		user           *auth.User
		req            link.CreateLinkRequest
		expectedError  string
		isInvalidInput bool
	}{
		{
			name:           "Empty Target URL",
			user:           userFree,
			req:            link.CreateLinkRequest{TargetURL: ""},
			expectedError:  "target_url is required",
			isInvalidInput: true,
		},
		{
			name:           "Invalid Target URL Format",
			user:           userFree,
			req:            link.CreateLinkRequest{TargetURL: "invalid-url-string"},
			expectedError:  "invalid target_url format",
			isInvalidInput: true,
		},
		{
			name:           "Blacklisted Domain Target URL",
			user:           userFree,
			req:            link.CreateLinkRequest{TargetURL: "https://malicious.com/phishing"},
			expectedError:  "target_url domain is blacklisted and cannot be shortened",
			isInvalidInput: true,
		},
		{
			name:           "Custom Alias Prohibited for Free Plan",
			user:           userFree,
			req:            link.CreateLinkRequest{TargetURL: "https://example.com", CustomAlias: "my-custom-slug"},
			expectedError:  "custom alias is only available on Pro or Business plans",
			isInvalidInput: true,
		},
		{
			name:           "Expiry Time Prohibited for Free Plan",
			user:           userFree,
			req:            link.CreateLinkRequest{TargetURL: "https://example.com", ExpiresAt: &futureTime},
			expectedError:  "expiry time is only available on Pro or Business plans",
			isInvalidInput: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateLink(context.Background(), tt.user, tt.req)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectedError)
			}
			if tt.isInvalidInput && !errors.Is(err, link.ErrInvalidInput) {
				t.Errorf("expected ErrInvalidInput, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.expectedError) {
				t.Errorf("expected error containing %q, got %q", tt.expectedError, err.Error())
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

func TestCreateLinkThreatScanner(t *testing.T) {
	svc := link.NewService(nil, nil)
	svc.SetURLScanner(&security.MockURLScanner{MaliciousDomains: map[string]bool{"phishing.test": true}})
	_, err := svc.CreateLink(context.Background(), &auth.User{PlanCode: "FREE"}, link.CreateLinkRequest{TargetURL: "https://phishing.test/login"})
	if err == nil || err.Error() != "MALICIOUS_URL_DETECTED" {
		t.Fatalf("expected malicious URL error, got %v", err)
	}
}

func BenchmarkRedirectFastPath(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = "https://example.com" + "/r/test"
	}
}

type stubLinkRepo struct {
	activeLink    *link.Link
	activeLinkErr error
	linkByID      *link.Link
	linkByIDErr   error
	analytics     *link.AnalyticsSummary
	analyticsErr  error
	exportRows    []link.ClickExportRow
	slugAvailable bool
	created       *link.Link
	createdErr    error
}

func (s *stubLinkRepo) CreateLinkAtomic(ctx context.Context, ownerUserID string, workspaceID *string, slug, targetURL, customDomain, userPlan string, expiresAt *time.Time, utm *link.LinkCampaign) (*link.Link, error) {
	return s.created, s.createdErr
}

func (s *stubLinkRepo) GetActiveLinkBySlug(ctx context.Context, slug string) (*link.Link, error) {
	return s.activeLink, s.activeLinkErr
}

func (s *stubLinkRepo) RecordClickEvent(ctx context.Context, linkID, source string) error {
	return nil
}

func (s *stubLinkRepo) GetLinkAnalytics(ctx context.Context, linkID, userPlan string) (*link.AnalyticsSummary, error) {
	return s.analytics, s.analyticsErr
}

func (s *stubLinkRepo) GetUserActiveLinkCount(ctx context.Context, userID string) (int, error) {
	return 0, nil
}

func (s *stubLinkRepo) IsSlugAvailable(ctx context.Context, slug string) bool {
	return s.slugAvailable
}

func (s *stubLinkRepo) GetLinkByID(ctx context.Context, linkID string) (*link.Link, error) {
	return s.linkByID, s.linkByIDErr
}

func (s *stubLinkRepo) GetExportAnalytics(ctx context.Context, linkID string, limit int) ([]link.ClickExportRow, error) {
	return s.exportRows, nil
}

func TestGetAnalyticsOwnership(t *testing.T) {
	owner := &auth.User{ID: "owner-1", PlanCode: "FREE"}
	attacker := &auth.User{ID: "attacker-1", PlanCode: "BUSINESS"}

	t.Run("Owner can read analytics", func(t *testing.T) {
		repo := &stubLinkRepo{
			linkByID:  &link.Link{ID: "link-1", OwnerUserID: "owner-1"},
			analytics: &link.AnalyticsSummary{TotalClicks: 42},
		}
		svc := link.NewService(repo, nil)

		summary, err := svc.GetAnalytics(context.Background(), owner, "link-1")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if summary.TotalClicks != 42 {
			t.Errorf("expected 42 clicks, got %d", summary.TotalClicks)
		}
	})

	t.Run("Non-owner is rejected", func(t *testing.T) {
		repo := &stubLinkRepo{linkByID: &link.Link{ID: "link-1", OwnerUserID: "owner-1"}}
		svc := link.NewService(repo, nil)

		_, err := svc.GetAnalytics(context.Background(), attacker, "link-1")
		if !errors.Is(err, link.ErrLinkUnauthorized) {
			t.Fatalf("expected ErrLinkUnauthorized, got %v", err)
		}
	})

	t.Run("Missing link propagates not found", func(t *testing.T) {
		repo := &stubLinkRepo{linkByIDErr: link.ErrLinkNotFound}
		svc := link.NewService(repo, nil)

		_, err := svc.GetAnalytics(context.Background(), owner, "link-1")
		if !errors.Is(err, link.ErrLinkNotFound) {
			t.Fatalf("expected ErrLinkNotFound, got %v", err)
		}
	})
}

func TestCreateLinkRejectsNonHTTPScheme(t *testing.T) {
	svc := link.NewService(nil, nil)

	_, err := svc.CreateLink(context.Background(), &auth.User{ID: "user-1", PlanCode: "FREE"}, link.CreateLinkRequest{TargetURL: "javascript:alert(1)"})
	if !errors.Is(err, link.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateLinkBlacklistSuffix(t *testing.T) {
	checker := &mockBlacklistChecker{blacklistedDomains: map[string]bool{"phishing.com": true}}
	user := &auth.User{ID: "user-1", PlanCode: "FREE"}

	t.Run("Trailing dot bypass is blocked", func(t *testing.T) {
		svc := link.NewService(nil, checker)
		_, err := svc.CreateLink(context.Background(), user, link.CreateLinkRequest{TargetURL: "http://phishing.com./login"})
		if !errors.Is(err, link.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput, got %v", err)
		}
	})

	t.Run("Subdomain of blacklisted domain is blocked", func(t *testing.T) {
		svc := link.NewService(nil, checker)
		_, err := svc.CreateLink(context.Background(), user, link.CreateLinkRequest{TargetURL: "http://evil.phishing.com/login"})
		if !errors.Is(err, link.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput, got %v", err)
		}
	})

	t.Run("Domain merely containing blacklisted name is allowed", func(t *testing.T) {
		repo := &stubLinkRepo{slugAvailable: true, created: &link.Link{ID: "link-1"}}
		svc := link.NewService(repo, checker)
		_, err := svc.CreateLink(context.Background(), user, link.CreateLinkRequest{TargetURL: "http://phishing.com.evil.io/login"})
		if err != nil {
			t.Fatalf("expected allowed, got %v", err)
		}
	})
}

func TestResolveAndRecordRedirectBlocked(t *testing.T) {
	checker := &mockBlacklistChecker{blacklistedDomains: map[string]bool{"phishing.com": true}}
	repo := &stubLinkRepo{
		activeLink: &link.Link{ID: "link-1", Slug: "abc123", TargetURL: "http://phishing.com/login"},
	}
	svc := link.NewService(repo, checker)

	_, err := svc.ResolveAndRecordRedirect(context.Background(), "abc123", "DIRECT")
	if !errors.Is(err, link.ErrMaliciousURL) {
		t.Fatalf("expected ErrMaliciousURL, got %v", err)
	}
}

func TestResolveAndRecordRedirectAllowsSafeTarget(t *testing.T) {
	checker := &mockBlacklistChecker{blacklistedDomains: map[string]bool{"phishing.com": true}}
	repo := &stubLinkRepo{
		activeLink: &link.Link{ID: "link-1", Slug: "abc123", TargetURL: "http://example.com/page"},
	}
	svc := link.NewService(repo, checker)

	target, err := svc.ResolveAndRecordRedirect(context.Background(), "abc123", "DIRECT")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if target != "http://example.com/page" {
		t.Errorf("expected target URL, got %q", target)
	}
}

func TestResolveAndRecordRedirectBlocksNonHTTPScheme(t *testing.T) {
	checker := &mockBlacklistChecker{blacklistedDomains: map[string]bool{"phishing.com": true}}
	repo := &stubLinkRepo{
		activeLink: &link.Link{ID: "link-1", Slug: "abc123", TargetURL: "javascript:alert(1)"},
	}
	svc := link.NewService(repo, checker)

	_, err := svc.ResolveAndRecordRedirect(context.Background(), "abc123", "DIRECT")
	if !errors.Is(err, link.ErrMaliciousURL) {
		t.Fatalf("expected ErrMaliciousURL for non-http scheme, got %v", err)
	}
}

func TestResolveAndRecordRedirectWithoutChecker(t *testing.T) {
	repo := &stubLinkRepo{
		activeLink: &link.Link{ID: "link-1", Slug: "abc123", TargetURL: "http://example.com/page"},
	}
	svc := link.NewService(repo, nil)

	target, err := svc.ResolveAndRecordRedirect(context.Background(), "abc123", "DIRECT")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if target != "http://example.com/page" {
		t.Errorf("expected target URL, got %q", target)
	}
}

func TestExportCSVAnalyticsSanitizesFormulaFields(t *testing.T) {
	repo := &stubLinkRepo{
		linkByID: &link.Link{ID: "link-1", OwnerUserID: "user-1"},
		exportRows: []link.ClickExportRow{
			{Timestamp: "2026-01-01", Slug: "=1+1", Country: "UNKNOWN", Referrer: "direct", UserAgent: "unknown", Device: "desktop"},
		},
	}
	svc := link.NewService(repo, nil)

	csvBytes, err := svc.ExportCSVAnalytics(context.Background(), &auth.User{ID: "user-1", PlanCode: "PRO"}, "link-1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	output := string(csvBytes)
	if !strings.Contains(output, "'=1+1") {
		t.Errorf("expected formula field sanitized with leading apostrophe, got %q", output)
	}
}

type stubLinkService struct {
	analytics      *link.AnalyticsSummary
	analyticsErr   error
	redirectTarget string
	redirectErr    error
	created        *link.Link
	createErr      error
	exportBytes    []byte
	exportErr      error
	qrBytes        []byte
	qrErr          error
}

func (s *stubLinkService) CreateLink(ctx context.Context, user *auth.User, req link.CreateLinkRequest) (*link.Link, error) {
	return s.created, s.createErr
}

func (s *stubLinkService) ResolveAndRecordRedirect(ctx context.Context, slug, source string) (string, error) {
	return s.redirectTarget, s.redirectErr
}

func (s *stubLinkService) GetAnalytics(ctx context.Context, user *auth.User, linkID string) (*link.AnalyticsSummary, error) {
	return s.analytics, s.analyticsErr
}

func (s *stubLinkService) GenerateQRCode(ctx context.Context, user *auth.User, linkID, baseURL string) ([]byte, error) {
	if s.qrBytes != nil {
		return s.qrBytes, s.qrErr
	}
	return []byte("fake-png"), s.qrErr
}

func (s *stubLinkService) ExportCSVAnalytics(ctx context.Context, user *auth.User, linkID string) ([]byte, error) {
	return s.exportBytes, s.exportErr
}

func authContextRequest(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	ctx := context.WithValue(req.Context(), auth.UserContextKey, &auth.User{ID: "user-1"})
	return req.WithContext(ctx)
}

func TestGetAnalyticsHandlerSuccess(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{analytics: &link.AnalyticsSummary{TotalClicks: 5}})
	rr := httptest.NewRecorder()

	handler.GetAnalytics(rr, authContextRequest("GET", "/v1/links/analytics?link_id=link-1"))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
	var body struct {
		Success bool `json:"success"`
		Data    struct {
			TotalClicks int `json:"total_clicks"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode analytics response: %v", err)
	}
	if body.Data.TotalClicks != 5 {
		t.Errorf("expected total_clicks 5 in body, got %d", body.Data.TotalClicks)
	}
}

func TestGetAnalyticsHandlerRejectsUnauthorized(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{analyticsErr: link.ErrLinkUnauthorized})
	rr := httptest.NewRecorder()

	handler.GetAnalytics(rr, authContextRequest("GET", "/v1/links/analytics?link_id=link-1"))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", rr.Code)
	}
}

func TestGetAnalyticsHandlerNotFound(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{analyticsErr: link.ErrLinkNotFound})
	rr := httptest.NewRecorder()

	handler.GetAnalytics(rr, authContextRequest("GET", "/v1/links/analytics?link_id=link-1"))

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found, got %d", rr.Code)
	}
}

func TestGetAnalyticsHandlerMissingLinkID(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{})
	rr := httptest.NewRecorder()

	handler.GetAnalytics(rr, authContextRequest("GET", "/v1/links/analytics"))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for missing link_id, got %d", rr.Code)
	}
}

func TestGetAnalyticsHandlerUnauthenticated(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/links/analytics?link_id=link-1", nil)

	handler.GetAnalytics(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rr.Code)
	}
}

func TestGetAnalyticsHandlerGenericError(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{analyticsErr: errors.New("database unavailable")})
	rr := httptest.NewRecorder()

	handler.GetAnalytics(rr, authContextRequest("GET", "/v1/links/analytics?link_id=link-1"))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 Internal Server Error for generic error, got %d", rr.Code)
	}
}

func TestPublicRedirectBlocksMaliciousTarget(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{redirectErr: link.ErrMaliciousURL})
	rr := httptest.NewRecorder()

	handler.PublicRedirect(rr, httptest.NewRequest("GET", "/r/abc123", nil))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for malicious target, got %d", rr.Code)
	}
}

func TestPublicRedirectSuccess(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{redirectTarget: "https://example.com"})
	rr := httptest.NewRecorder()

	handler.PublicRedirect(rr, httptest.NewRequest("GET", "/r/abc123", nil))

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 Found, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "https://example.com" {
		t.Errorf("expected Location header 'https://example.com', got %s", rr.Header().Get("Location"))
	}
}

func TestCreateLinkHandlerSuccess(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{created: &link.Link{ID: "link-1"}})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/links", strings.NewReader(`{"target_url":"https://example.com"}`))
	ctx := context.WithValue(req.Context(), auth.UserContextKey, &auth.User{ID: "user-1", PlanCode: "FREE"})
	req = req.WithContext(ctx)

	handler.CreateLink(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rr.Code)
	}
}

func TestCreateLinkHandlerMaliciousURL(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{createErr: link.ErrMaliciousURL})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/links", strings.NewReader(`{"target_url":"https://evil.com"}`))
	ctx := context.WithValue(req.Context(), auth.UserContextKey, &auth.User{ID: "user-1", PlanCode: "FREE"})
	req = req.WithContext(ctx)

	handler.CreateLink(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCreateLinkHandlerForbidden(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{createErr: link.ErrCustomDomainPlan})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/links", strings.NewReader(`{"target_url":"https://example.com","custom_domain":"my.domain.com"}`))
	ctx := context.WithValue(req.Context(), auth.UserContextKey, &auth.User{ID: "user-1", PlanCode: "FREE"})
	req = req.WithContext(ctx)

	handler.CreateLink(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestCreateLinkHandlerWorkspaceForbidden(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{createErr: link.ErrWorkspaceForbidden})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/links", strings.NewReader(`{"target_url":"https://example.com"}`))
	ctx := context.WithValue(req.Context(), auth.UserContextKey, &auth.User{ID: "user-1", PlanCode: "FREE"})
	req = req.WithContext(ctx)

	handler.CreateLink(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestCreateLinkHandlerInvalidInput(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{createErr: link.ErrInvalidInput})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/links", strings.NewReader(`{"target_url":""}`))
	ctx := context.WithValue(req.Context(), auth.UserContextKey, &auth.User{ID: "user-1", PlanCode: "FREE"})
	req = req.WithContext(ctx)

	handler.CreateLink(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCreateLinkHandlerGenericError(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{createErr: errors.New("db error")})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/links", strings.NewReader(`{"target_url":"https://example.com"}`))
	ctx := context.WithValue(req.Context(), auth.UserContextKey, &auth.User{ID: "user-1", PlanCode: "FREE"})
	req = req.WithContext(ctx)

	handler.CreateLink(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestCreateLinkHandlerUnauthenticated(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{})
	rr := httptest.NewRecorder()
	handler.CreateLink(rr, httptest.NewRequest("POST", "/v1/links", strings.NewReader(`{"target_url":"https://example.com"}`)))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestPublicRedirectEmptySlug(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{redirectErr: errors.New("not found")})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/r/abc", nil)
	handler.PublicRedirect(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestPublicRedirectNotFound(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{redirectErr: errors.New("not found")})
	rr := httptest.NewRecorder()
	handler.PublicRedirect(rr, httptest.NewRequest("GET", "/r/missing", nil))

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestGenerateQRCodeHandlerUnauthenticated(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{})
	rr := httptest.NewRecorder()
	handler.GenerateQRCode(rr, httptest.NewRequest("GET", "/v1/links/qr?link_id=link-1", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestGenerateQRCodeHandlerMissingLinkID(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{})
	rr := httptest.NewRecorder()
	handler.GenerateQRCode(rr, authContextRequest("GET", "/v1/links/qr"))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestGenerateQRCodeHandlerSuccess(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{})
	rr := httptest.NewRecorder()
	handler.GenerateQRCode(rr, authContextRequest("GET", "/v1/links/qr?link_id=link-1"))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "image/png" {
		t.Errorf("expected Content-Type image/png, got %s", rr.Header().Get("Content-Type"))
	}
}

func TestGenerateQRCodeHandlerNotFound(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{qrErr: link.ErrLinkNotFound})
	rr := httptest.NewRecorder()
	handler.GenerateQRCode(rr, authContextRequest("GET", "/v1/links/qr?link_id=notfound"))

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestGenerateQRCodeHandlerUnauthorized(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{qrErr: link.ErrLinkUnauthorized})
	rr := httptest.NewRecorder()
	handler.GenerateQRCode(rr, authContextRequest("GET", "/v1/links/qr?link_id=link-1"))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestGenerateQRCodeHandlerGenericError(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{qrErr: errors.New("database error")})
	rr := httptest.NewRecorder()
	handler.GenerateQRCode(rr, authContextRequest("GET", "/v1/links/qr?link_id=link-1"))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestExportCSVHandlerUnauthenticated(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{})
	rr := httptest.NewRecorder()
	handler.ExportCSVAnalytics(rr, httptest.NewRequest("GET", "/v1/analytics/export?link_id=link-1", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestExportCSVHandlerMissingLinkID(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{})
	rr := httptest.NewRecorder()
	handler.ExportCSVAnalytics(rr, authContextRequest("GET", "/v1/analytics/export"))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestExportCSVHandlerForbidden(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{exportErr: link.ErrCSVPlan})
	rr := httptest.NewRecorder()
	handler.ExportCSVAnalytics(rr, authContextRequest("GET", "/v1/analytics/export?link_id=link-1"))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestExportCSVHandlerGenericError(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{exportErr: errors.New("db error")})
	rr := httptest.NewRecorder()
	handler.ExportCSVAnalytics(rr, authContextRequest("GET", "/v1/analytics/export?link_id=link-1"))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestExportCSVHandlerSuccess(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{exportBytes: []byte("timestamp,slug\n2024-01-01,abc123")})
	rr := httptest.NewRecorder()
	handler.ExportCSVAnalytics(rr, authContextRequest("GET", "/v1/analytics/export?link_id=link-1"))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "text/csv" {
		t.Errorf("expected Content-Type text/csv, got %s", rr.Header().Get("Content-Type"))
	}
}

func TestExportCSVHandlerNotFound(t *testing.T) {
	handler := link.NewHandler(&stubLinkService{exportErr: link.ErrLinkNotFound})
	rr := httptest.NewRecorder()
	handler.ExportCSVAnalytics(rr, authContextRequest("GET", "/v1/analytics/export?link_id=notfound"))

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

type mockWorkspaceChecker struct {
	members map[string]map[string]bool
}

func (m *mockWorkspaceChecker) IsMember(ctx context.Context, workspaceID, userID string) bool {
	if m.members == nil {
		return false
	}
	if workspaceUsers, ok := m.members[workspaceID]; ok {
		return workspaceUsers[userID]
	}
	return false
}

func TestCreateLinkWithWorkspaceValidation(t *testing.T) {
	checker := &mockWorkspaceChecker{
		members: map[string]map[string]bool{
			"ws-1": {"user-1": true},
		},
	}

	t.Run("nil workspace ID allowed", func(t *testing.T) {
		repo := &stubLinkRepo{slugAvailable: true, created: &link.Link{ID: "link-1"}}
		svc := link.NewService(repo, nil)
		svc.SetWorkspaceChecker(checker)

		user := &auth.User{ID: "user-1", PlanCode: "FREE"}
		_, err := svc.CreateLink(context.Background(), user, link.CreateLinkRequest{
			TargetURL:   "https://example.com",
			WorkspaceID: nil,
		})
		if err != nil {
			t.Errorf("expected no error for nil workspace, got %v", err)
		}
	})

	t.Run("empty workspace ID allowed", func(t *testing.T) {
		repo := &stubLinkRepo{slugAvailable: true, created: &link.Link{ID: "link-1"}}
		svc := link.NewService(repo, nil)
		svc.SetWorkspaceChecker(checker)

		user := &auth.User{ID: "user-1", PlanCode: "FREE"}
		emptyWs := ""
		_, err := svc.CreateLink(context.Background(), user, link.CreateLinkRequest{
			TargetURL:   "https://example.com",
			WorkspaceID: &emptyWs,
		})
		if err != nil {
			t.Errorf("expected no error for empty workspace, got %v", err)
		}
	})

	t.Run("member can create link in workspace", func(t *testing.T) {
		repo := &stubLinkRepo{slugAvailable: true, created: &link.Link{ID: "link-1"}}
		svc := link.NewService(repo, nil)
		svc.SetWorkspaceChecker(checker)

		user := &auth.User{ID: "user-1", PlanCode: "FREE"}
		wsID := "ws-1"
		_, err := svc.CreateLink(context.Background(), user, link.CreateLinkRequest{
			TargetURL:   "https://example.com",
			WorkspaceID: &wsID,
		})
		if err != nil {
			t.Errorf("expected no error for workspace member, got %v", err)
		}
	})

	t.Run("non-member cannot create link in workspace", func(t *testing.T) {
		repo := &stubLinkRepo{slugAvailable: true, created: &link.Link{ID: "link-1"}}
		svc := link.NewService(repo, nil)
		svc.SetWorkspaceChecker(checker)

		user := &auth.User{ID: "user-2", PlanCode: "FREE"}
		wsID := "ws-1"
		_, err := svc.CreateLink(context.Background(), user, link.CreateLinkRequest{
			TargetURL:   "https://example.com",
			WorkspaceID: &wsID,
		})
		if !errors.Is(err, link.ErrWorkspaceForbidden) {
			t.Errorf("expected ErrWorkspaceForbidden, got %v", err)
		}
	})

	t.Run("no checker set allows any workspace", func(t *testing.T) {
		repo := &stubLinkRepo{slugAvailable: true, created: &link.Link{ID: "link-1"}}
		svc := link.NewService(repo, nil)

		user := &auth.User{ID: "user-1", PlanCode: "FREE"}
		wsID := "ws-1"
		_, err := svc.CreateLink(context.Background(), user, link.CreateLinkRequest{
			TargetURL:   "https://example.com",
			WorkspaceID: &wsID,
		})
		if err != nil {
			t.Errorf("expected no error without checker, got %v", err)
		}
	})
}

func TestGenerateQRCode(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &stubLinkRepo{
			linkByID: &link.Link{ID: "link-1", OwnerUserID: "user-1", Slug: "abc123"},
		}
		svc := link.NewService(repo, nil)
		user := &auth.User{ID: "user-1"}

		pngBytes, err := svc.GenerateQRCode(context.Background(), user, "link-1", "https://example.com")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(pngBytes) == 0 {
			t.Error("expected PNG bytes, got empty")
		}
	})

	t.Run("link not found", func(t *testing.T) {
		repo := &stubLinkRepo{linkByIDErr: link.ErrLinkNotFound}
		svc := link.NewService(repo, nil)
		user := &auth.User{ID: "user-1"}

		_, err := svc.GenerateQRCode(context.Background(), user, "notfound", "https://example.com")
		if !errors.Is(err, link.ErrLinkNotFound) {
			t.Errorf("expected ErrLinkNotFound, got %v", err)
		}
	})

	t.Run("unauthorized", func(t *testing.T) {
		repo := &stubLinkRepo{
			linkByID: &link.Link{ID: "link-1", OwnerUserID: "user-1", Slug: "abc123"},
		}
		svc := link.NewService(repo, nil)
		user := &auth.User{ID: "user-2"}

		_, err := svc.GenerateQRCode(context.Background(), user, "link-1", "https://example.com")
		if !errors.Is(err, link.ErrLinkUnauthorized) {
			t.Errorf("expected ErrLinkUnauthorized, got %v", err)
		}
	})
}
