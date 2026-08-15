package bio_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/bio"
)

type stubBioService struct {
	page       *bio.Page
	createErr  error
	addErr     error
	publicPage *bio.PublicPage
	publicErr  error
}

func (s *stubBioService) CreatePage(ctx context.Context, user *auth.User, req bio.CreatePageRequest) (*bio.Page, error) {
	return s.page, s.createErr
}

func (s *stubBioService) AddLink(ctx context.Context, user *auth.User, pageID string, req bio.AddLinkRequest) error {
	return s.addErr
}

func (s *stubBioService) GetPublicPage(ctx context.Context, slug, baseURL string) (*bio.PublicPage, error) {
	return s.publicPage, s.publicErr
}

func withUser(req *http.Request) *http.Request {
	ctx := context.WithValue(req.Context(), auth.UserContextKey, &auth.User{ID: "user-1", PlanCode: "FREE"})
	return req.WithContext(ctx)
}

func TestCreatePageHandlerSuccess(t *testing.T) {
	handler := bio.NewHandler(&stubBioService{page: &bio.Page{ID: "page-1"}})
	rr := httptest.NewRecorder()
	handler.CreatePage(rr, withUser(httptest.NewRequest("POST", "/v1/bio-pages", strings.NewReader(`{"title":"My Page","slug":"my-page"}`))))

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rr.Code)
	}
}

func TestCreatePageHandlerFreeLimit(t *testing.T) {
	handler := bio.NewHandler(&stubBioService{createErr: bio.ErrFreePageLimit})
	rr := httptest.NewRecorder()
	handler.CreatePage(rr, withUser(httptest.NewRequest("POST", "/v1/bio-pages", strings.NewReader(`{"title":"My Page","slug":"my-page"}`))))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestCreatePageHandlerUnauthenticated(t *testing.T) {
	handler := bio.NewHandler(&stubBioService{})
	rr := httptest.NewRecorder()
	handler.CreatePage(rr, httptest.NewRequest("POST", "/v1/bio-pages", strings.NewReader(`{"title":"My Page","slug":"my-page"}`)))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAddLinkHandlerSuccess(t *testing.T) {
	handler := bio.NewHandler(&stubBioService{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/bio-pages/page-1/links", strings.NewReader(`{"link_id":"link-1"}`))
	req = withUser(req)
	handler.AddLink(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rr.Code)
	}
}

func TestAddLinkHandlerUnauthorized(t *testing.T) {
	handler := bio.NewHandler(&stubBioService{addErr: bio.ErrBioPageUnauthorized})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/bio-pages/page-1/links", strings.NewReader(`{"link_id":"link-1"}`))
	req = withUser(req)
	handler.AddLink(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestAddLinkHandlerNotFound(t *testing.T) {
	handler := bio.NewHandler(&stubBioService{addErr: bio.ErrBioPageNotFound})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/bio-pages/page-1/links", strings.NewReader(`{"link_id":"link-1"}`))
	req = withUser(req)
	handler.AddLink(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestAddLinkHandlerUnauthenticated(t *testing.T) {
	handler := bio.NewHandler(&stubBioService{})
	rr := httptest.NewRecorder()
	handler.AddLink(rr, httptest.NewRequest("POST", "/v1/bio-pages/page-1/links", strings.NewReader(`{"link_id":"link-1"}`)))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestPublicPageHandlerSuccess(t *testing.T) {
	handler := bio.NewHandler(&stubBioService{publicPage: &bio.PublicPage{Title: "My Page"}})
	rr := httptest.NewRecorder()
	handler.PublicPage(rr, httptest.NewRequest("GET", "/v1/bio-pages/public/my-page", nil))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestPublicPageHandlerEmptySlug(t *testing.T) {
	handler := bio.NewHandler(&stubBioService{})
	rr := httptest.NewRecorder()
	handler.PublicPage(rr, httptest.NewRequest("GET", "/v1/bio-pages/public/", nil))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestPublicPageHandlerNotFound(t *testing.T) {
	handler := bio.NewHandler(&stubBioService{publicErr: errors.New("page not found")})
	rr := httptest.NewRecorder()
	handler.PublicPage(rr, httptest.NewRequest("GET", "/v1/bio-pages/public/missing", nil))

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}
