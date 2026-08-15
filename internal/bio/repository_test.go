package bio

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
)

func TestNewRepository(t *testing.T) {
	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewRepository(mock)
	if repo == nil {
		t.Error("expected repository, got nil")
	}
}

func TestCreatePage(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("INSERT INTO bio_pages").
			WithArgs("user-1", "My Page", "my-page", "Description").
			WillReturnRows(pgxmock.NewRows([]string{"id", "owner_user_id", "title", "slug", "bio_description", "created_at", "updated_at"}).
				AddRow("page-1", "user-1", "My Page", "my-page", "Description", now, now))

		req := CreatePageRequest{Title: "My Page", Slug: "my-page", BioDescription: "Description"}
		page, err := repo.CreatePage(ctx, "user-1", req)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if page.ID != "page-1" {
			t.Errorf("expected page-1, got %s", page.ID)
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("INSERT INTO bio_pages").
			WillReturnError(errors.New("database error"))

		req := CreatePageRequest{Title: "My Page", Slug: "my-page"}
		_, err = repo.CreatePage(ctx, "user-1", req)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestCreateFreePage(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id FROM users WHERE id.*FOR UPDATE").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id"}).
				AddRow("user-1"))
		mock.ExpectQuery("SELECT COUNT.*FROM bio_pages WHERE owner_user_id").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).
				AddRow(0))
		mock.ExpectQuery("INSERT INTO bio_pages").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "owner_user_id", "title", "slug", "bio_description", "created_at", "updated_at"}).
				AddRow("page-1", "user-1", "My Page", "my-page", "", now, now))
		mock.ExpectCommit()

		req := CreatePageRequest{Title: "My Page", Slug: "my-page"}
		page, err := repo.CreateFreePage(ctx, "user-1", req)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if page.ID != "page-1" {
			t.Errorf("expected page-1, got %s", page.ID)
		}
	})

	t.Run("limit reached", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT COUNT.*FROM bio_pages WHERE owner_user_id").
			WillReturnRows(pgxmock.NewRows([]string{"count"}).
				AddRow(1))

		req := CreatePageRequest{Title: "My Page", Slug: "my-page"}
		_, err = repo.CreateFreePage(ctx, "user-1", req)
		if err == nil {
			t.Error("expected error for limit reached, got nil")
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT COUNT.*FROM bio_pages WHERE owner_user_id").
			WillReturnError(errors.New("database error"))

		req := CreatePageRequest{Title: "My Page", Slug: "my-page"}
		_, err = repo.CreateFreePage(ctx, "user-1", req)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("user not found on lock", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id FROM users WHERE id.*FOR UPDATE").
			WillReturnError(pgx.ErrNoRows)
		mock.ExpectRollback()

		req := CreatePageRequest{Title: "My Page", Slug: "my-page"}
		_, err = repo.CreateFreePage(ctx, "user-1", req)
		if err == nil {
			t.Error("expected error for user not found, got nil")
		}
	})
}

func TestAddLinkUnauthorized(t *testing.T) {
	ctx := context.Background()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewRepository(mock)

	mock.ExpectExec("INSERT INTO bio_page_links").
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 0))

	err = repo.AddLink(ctx, "page-1", "link-1", 1, "user-2")
	if !errors.Is(err, ErrBioLinkUnauthorized) {
		t.Errorf("expected ErrBioLinkUnauthorized, got %v", err)
	}
}

func TestGetPage(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("SELECT.*FROM bio_pages WHERE id").
			WithArgs("page-1").
			WillReturnRows(pgxmock.NewRows([]string{"id", "owner_user_id", "title", "slug", "bio_description", "created_at", "updated_at"}).
				AddRow("page-1", "user-1", "My Page", "my-page", "", now, now))

		page, err := repo.GetPage(ctx, "page-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if page.ID != "page-1" {
			t.Errorf("expected page-1, got %s", page.ID)
		}
	})

	t.Run("not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM bio_pages WHERE id").
			WillReturnError(pgx.ErrNoRows)

		_, err = repo.GetPage(ctx, "notfound")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM bio_pages WHERE id").
			WillReturnError(errors.New("database error"))

		_, err = repo.GetPage(ctx, "page-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestAddLink(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectExec("INSERT INTO bio_page_links").
			WithArgs("page-1", "link-1", 1, "user-1").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err = repo.AddLink(ctx, "page-1", "link-1", 1, "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectExec("INSERT INTO bio_page_links").
			WillReturnError(errors.New("database error"))

		err = repo.AddLink(ctx, "page-1", "link-1", 1, "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestGetPublicPage(t *testing.T) {
	ctx := context.Background()

	t.Run("success with links", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM bio_pages WHERE slug").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"title", "slug", "bio_description"}).
				AddRow("My Page", "my-page", "Description"))
		mock.ExpectQuery("SELECT.*FROM bio_page_links bpl JOIN links l").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"link_id", "slug", "display_order"}).
				AddRow("link-1", "abc123", 1))

		page, err := repo.GetPublicPage(ctx, "my-page", "https://example.com")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if page.Title != "My Page" {
			t.Errorf("expected 'My Page', got %s", page.Title)
		}
		if len(page.Links) != 1 {
			t.Errorf("expected 1 link, got %d", len(page.Links))
		}
	})

	t.Run("success without links", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM bio_pages WHERE slug").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"title", "slug", "bio_description"}).
				AddRow("My Page", "my-page", "Description"))
		mock.ExpectQuery("SELECT.*FROM bio_page_links bpl JOIN links l").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"link_id", "slug", "display_order"}))

		page, err := repo.GetPublicPage(ctx, "my-page", "https://example.com")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(page.Links) != 0 {
			t.Errorf("expected 0 links, got %d", len(page.Links))
		}
	})

	t.Run("page not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM bio_pages WHERE slug").
			WithArgs(pgxmock.AnyArg()).
			WillReturnError(pgx.ErrNoRows)

		_, err = repo.GetPublicPage(ctx, "notfound", "https://example.com")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM bio_pages WHERE slug").
			WithArgs(pgxmock.AnyArg()).
			WillReturnError(errors.New("database error"))

		_, err = repo.GetPublicPage(ctx, "my-page", "https://example.com")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}
