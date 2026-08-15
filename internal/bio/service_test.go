package bio

import (
	"context"
	"errors"
	"testing"

	"trimly-platform/internal/auth"
)

type stubPageRepo struct {
	page          *Page
	createErr     error
	freePage      *Page
	freeCreateErr error
	getPage       *Page
	getPageErr    error
	addLinkErr    error
	publicPage    *PublicPage
	publicErr     error
}

func (s *stubPageRepo) CreatePage(ctx context.Context, userID string, req CreatePageRequest) (*Page, error) {
	return s.page, s.createErr
}

func (s *stubPageRepo) CreateFreePage(ctx context.Context, userID string, req CreatePageRequest) (*Page, error) {
	return s.freePage, s.freeCreateErr
}

func (s *stubPageRepo) GetPage(ctx context.Context, pageID string) (*Page, error) {
	return s.getPage, s.getPageErr
}

func (s *stubPageRepo) AddLink(ctx context.Context, pageID, linkID string, displayOrder int, userID string) error {
	return s.addLinkErr
}

func (s *stubPageRepo) GetPublicPage(ctx context.Context, slug, baseURL string) (*PublicPage, error) {
	return s.publicPage, s.publicErr
}

func TestCreatePageValidation(t *testing.T) {
	repo := &stubPageRepo{page: &Page{ID: "page-1"}}
	svc := NewService(repo)

	tests := []struct {
		name        string
		user        *auth.User
		req         CreatePageRequest
		expectedErr error
	}{
		{
			name:        "empty title",
			user:        &auth.User{ID: "user-1", PlanCode: "PRO"},
			req:         CreatePageRequest{Title: "", Slug: "my-page"},
			expectedErr: ErrInvalidInput,
		},
		{
			name:        "empty slug",
			user:        &auth.User{ID: "user-1", PlanCode: "PRO"},
			req:         CreatePageRequest{Title: "My Page", Slug: ""},
			expectedErr: ErrInvalidInput,
		},
		{
			name:        "title too long",
			user:        &auth.User{ID: "user-1", PlanCode: "PRO"},
			req:         CreatePageRequest{Title: string(make([]byte, 101)), Slug: "my-page"},
			expectedErr: ErrInvalidInput,
		},
		{
			name:        "slug too long",
			user:        &auth.User{ID: "user-1", PlanCode: "PRO"},
			req:         CreatePageRequest{Title: "My Page", Slug: string(make([]byte, 51))},
			expectedErr: ErrInvalidInput,
		},
		{
			name:        "invalid slug pattern",
			user:        &auth.User{ID: "user-1", PlanCode: "PRO"},
			req:         CreatePageRequest{Title: "My Page", Slug: "My_Page"},
			expectedErr: ErrInvalidInput,
		},
		{
			name:        "valid input for paid plan",
			user:        &auth.User{ID: "user-1", PlanCode: "PRO"},
			req:         CreatePageRequest{Title: "My Page", Slug: "my-page"},
			expectedErr: nil,
		},
		{
			name:        "valid input for free plan",
			user:        &auth.User{ID: "user-1", PlanCode: "FREE"},
			req:         CreatePageRequest{Title: "My Page", Slug: "my-page"},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreatePage(context.Background(), tt.user, tt.req)
			if tt.expectedErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.expectedErr)
				} else if !errors.Is(err, tt.expectedErr) {
					t.Errorf("expected error %v, got %v", tt.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestCreatePageFreePlanCallsCreateFreePage(t *testing.T) {
	repo := &stubPageRepo{freePage: &Page{ID: "free-page-1"}}
	svc := NewService(repo)

	user := &auth.User{ID: "user-1", PlanCode: "FREE"}
	req := CreatePageRequest{Title: "My Page", Slug: "my-page"}

	page, err := svc.CreatePage(context.Background(), user, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if page == nil {
		t.Fatal("expected page, got nil")
	}
	if page.ID != "free-page-1" {
		t.Errorf("expected free-page-1, got %s", page.ID)
	}
}

func TestCreatePagePaidPlanCallsCreatePage(t *testing.T) {
	repo := &stubPageRepo{page: &Page{ID: "pro-page-1"}}
	svc := NewService(repo)

	user := &auth.User{ID: "user-1", PlanCode: "PRO"}
	req := CreatePageRequest{Title: "My Page", Slug: "my-page"}

	page, err := svc.CreatePage(context.Background(), user, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if page == nil {
		t.Fatal("expected page, got nil")
	}
	if page.ID != "pro-page-1" {
		t.Errorf("expected pro-page-1, got %s", page.ID)
	}
}

func TestAddLinkValidation(t *testing.T) {
	t.Run("empty link_id", func(t *testing.T) {
		repo := &stubPageRepo{}
		svc := NewService(repo)
		user := &auth.User{ID: "user-1"}

		err := svc.AddLink(context.Background(), user, "page-1", AddLinkRequest{LinkID: ""})
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("expected ErrInvalidInput, got %v", err)
		}
	})

	t.Run("page not found", func(t *testing.T) {
		repo := &stubPageRepo{getPageErr: ErrBioPageNotFound}
		svc := NewService(repo)
		user := &auth.User{ID: "user-1"}

		err := svc.AddLink(context.Background(), user, "page-1", AddLinkRequest{LinkID: "link-1"})
		if !errors.Is(err, ErrBioPageNotFound) {
			t.Errorf("expected ErrBioPageNotFound, got %v", err)
		}
	})

	t.Run("unauthorized - different owner", func(t *testing.T) {
		repo := &stubPageRepo{
			getPage: &Page{ID: "page-1", OwnerUserID: "user-1"},
		}
		svc := NewService(repo)
		user := &auth.User{ID: "user-2"}

		err := svc.AddLink(context.Background(), user, "page-1", AddLinkRequest{LinkID: "link-1"})
		if !errors.Is(err, ErrBioPageUnauthorized) {
			t.Errorf("expected ErrBioPageUnauthorized, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		repo := &stubPageRepo{
			getPage: &Page{ID: "page-1", OwnerUserID: "user-1"},
		}
		svc := NewService(repo)
		user := &auth.User{ID: "user-1"}

		err := svc.AddLink(context.Background(), user, "page-1", AddLinkRequest{LinkID: "link-1"})
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})
}

func TestServiceGetPublicPage(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := &stubPageRepo{
			publicPage: &PublicPage{Title: "My Page"},
		}
		svc := NewService(repo)

		page, err := svc.GetPublicPage(context.Background(), "my-page", "https://example.com/")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if page == nil {
			t.Fatal("expected page, got nil")
		}
		if page.Title != "My Page" {
			t.Errorf("expected 'My Page', got %s", page.Title)
		}
	})

	t.Run("database error", func(t *testing.T) {
		repo := &stubPageRepo{publicErr: errors.New("database error")}
		svc := NewService(repo)

		_, err := svc.GetPublicPage(context.Background(), "my-page", "https://example.com/")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}
