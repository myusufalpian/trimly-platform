package link

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

func TestCreateLinkAtomic(t *testing.T) {
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
		mock.ExpectQuery("SELECT active_link_count, plan_code FROM plan_usage.*FOR UPDATE").
			WithArgs("user-1").
			WillReturnRows(pgxmock.NewRows([]string{"active_link_count", "plan_code"}).
				AddRow(5, "FREE"))
		mock.ExpectQuery("INSERT INTO links").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "owner_user_id", "workspace_id", "slug", "target_url", "custom_domain", "status", "expires_at", "created_at", "updated_at"}).
				AddRow("link-1", "user-1", nil, "abc123", "https://example.com", "", "ACTIVE", nil, now, now))
		mock.ExpectExec("UPDATE plan_usage SET active_link_count").
			WithArgs("user-1").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		link, err := repo.CreateLinkAtomic(ctx, "user-1", nil, "abc123", "https://example.com", "", "FREE", nil, nil)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if link.ID != "link-1" {
			t.Errorf("expected link-1, got %s", link.ID)
		}
	})

	t.Run("free plan limit reached", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT active_link_count, plan_code FROM plan_usage.*FOR UPDATE").
			WillReturnRows(pgxmock.NewRows([]string{"active_link_count", "plan_code"}).
				AddRow(10, "FREE"))
		mock.ExpectRollback()

		_, err = repo.CreateLinkAtomic(ctx, "user-1", nil, "abc123", "https://example.com", "", "FREE", nil, nil)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("with UTM campaign", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()
		utm := &LinkCampaign{
			UTMSource:   "google",
			UTMMedium:   "cpc",
			UTMCampaign: "summer-sale",
		}

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT active_link_count, plan_code FROM plan_usage.*FOR UPDATE").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"active_link_count", "plan_code"}).
				AddRow(5, "PRO"))
		mock.ExpectQuery("INSERT INTO links").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "owner_user_id", "workspace_id", "slug", "target_url", "custom_domain", "status", "expires_at", "created_at", "updated_at"}).
				AddRow("link-1", "user-1", nil, "abc123", "https://example.com", "", "ACTIVE", nil, now, now))
		mock.ExpectExec("INSERT INTO link_campaigns").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec("UPDATE plan_usage SET active_link_count").
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		link, err := repo.CreateLinkAtomic(ctx, "user-1", nil, "abc123", "https://example.com", "", "PRO", nil, utm)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if link.UTMCampaign == nil {
			t.Error("expected UTM campaign to be set")
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT active_link_count, plan_code FROM plan_usage.*FOR UPDATE").
			WillReturnError(errors.New("database error"))
		mock.ExpectRollback()

		_, err = repo.CreateLinkAtomic(ctx, "user-1", nil, "abc123", "https://example.com", "", "FREE", nil, nil)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("insert link error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT active_link_count, plan_code FROM plan_usage.*FOR UPDATE").
			WillReturnRows(pgxmock.NewRows([]string{"active_link_count", "plan_code"}).
				AddRow(5, "FREE"))
		mock.ExpectQuery("INSERT INTO links").
			WillReturnError(errors.New("insert error"))
		mock.ExpectRollback()

		_, err = repo.CreateLinkAtomic(ctx, "user-1", nil, "abc123", "https://example.com", "", "FREE", nil, nil)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestGetActiveLinkBySlug(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("SELECT.*FROM links WHERE slug").
			WithArgs("abc123").
			WillReturnRows(pgxmock.NewRows([]string{"id", "owner_user_id", "workspace_id", "slug", "target_url", "custom_domain", "status", "expires_at", "created_at", "updated_at"}).
				AddRow("link-1", "user-1", nil, "abc123", "https://example.com", "", "ACTIVE", nil, now, now))

		link, err := repo.GetActiveLinkBySlug(ctx, "abc123")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if link.ID != "link-1" {
			t.Errorf("expected link-1, got %s", link.ID)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM links WHERE slug").
			WillReturnError(pgx.ErrNoRows)

		_, err = repo.GetActiveLinkBySlug(ctx, "notfound")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("link expired", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()
		expired := now.Add(-24 * time.Hour)

		mock.ExpectQuery("SELECT.*FROM links WHERE slug").
			WillReturnRows(pgxmock.NewRows([]string{"id", "owner_user_id", "workspace_id", "slug", "target_url", "custom_domain", "status", "expires_at", "created_at", "updated_at"}).
				AddRow("link-1", "user-1", nil, "abc123", "https://example.com", "", "ACTIVE", &expired, now, now))

		_, err = repo.GetActiveLinkBySlug(ctx, "abc123")
		if err == nil {
			t.Error("expected error for expired link, got nil")
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM links WHERE slug").
			WillReturnError(errors.New("database error"))

		_, err = repo.GetActiveLinkBySlug(ctx, "abc123")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestRecordClickEvent(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectExec("INSERT INTO click_events").
			WithArgs("link-1", "DIRECT").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err = repo.RecordClickEvent(ctx, "link-1", "DIRECT")
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

		mock.ExpectExec("INSERT INTO click_events").
			WillReturnError(errors.New("database error"))

		err = repo.RecordClickEvent(ctx, "link-1", "DIRECT")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestGetLinkAnalytics(t *testing.T) {
	ctx := context.Background()

	t.Run("free plan", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT COUNT.*FROM click_events").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).
				AddRow(10))
		mock.ExpectQuery("SELECT DATE.*FROM click_events.*GROUP BY DATE").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"date", "click_count"}).
				AddRow("2024-01-01", 5).
				AddRow("2024-01-02", 5))

		analytics, err := repo.GetLinkAnalytics(ctx, "link-1", "FREE")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if analytics.TotalClicks != 10 {
			t.Errorf("expected 10 total clicks, got %d", analytics.TotalClicks)
		}
	})

	t.Run("pro plan with breakdown", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT COUNT.*FROM click_events").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).
				AddRow(100))
		mock.ExpectQuery("SELECT DATE.*FROM click_events.*GROUP BY DATE").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"date", "click_count"}).
				AddRow("2024-01-01", 100))
		mock.ExpectQuery("SELECT COALESCE.*FROM click_events ce JOIN link_campaigns").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"utm_source", "utm_campaign", "click_count"}).
				AddRow("google", "summer-sale", 100))

		analytics, err := repo.GetLinkAnalytics(ctx, "link-1", "PRO")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if analytics.TotalClicks != 100 {
			t.Errorf("expected 100 total clicks, got %d", analytics.TotalClicks)
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT COUNT.*FROM click_events").
			WillReturnError(errors.New("database error"))

		_, err = repo.GetLinkAnalytics(ctx, "link-1", "FREE")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestGetUserActiveLinkCount(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT active_link_count FROM plan_usage").
			WithArgs("user-1").
			WillReturnRows(pgxmock.NewRows([]string{"active_link_count"}).
				AddRow(5))

		count, err := repo.GetUserActiveLinkCount(ctx, "user-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if count != 5 {
			t.Errorf("expected 5, got %d", count)
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT active_link_count FROM plan_usage").
			WillReturnError(errors.New("database error"))

		_, err = repo.GetUserActiveLinkCount(ctx, "user-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestIsSlugAvailable(t *testing.T) {
	ctx := context.Background()

	t.Run("available", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT 1 FROM links WHERE slug").
			WithArgs("new-slug").
			WillReturnError(pgx.ErrNoRows)

		available := repo.IsSlugAvailable(ctx, "new-slug")
		if !available {
			t.Error("expected slug to be available")
		}
	})

	t.Run("taken", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT 1 FROM links WHERE slug").
			WillReturnRows(pgxmock.NewRows([]string{"1"}).
				AddRow(1))

		available := repo.IsSlugAvailable(ctx, "taken-slug")
		if available {
			t.Error("expected slug to be taken")
		}
	})
}

func TestGetLinkByID(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)
		now := time.Now()

		mock.ExpectQuery("SELECT.*FROM links WHERE id").
			WithArgs("link-1").
			WillReturnRows(pgxmock.NewRows([]string{"id", "owner_user_id", "workspace_id", "slug", "target_url", "custom_domain", "status", "expires_at", "created_at", "updated_at"}).
				AddRow("link-1", "user-1", nil, "abc123", "https://example.com", "", "ACTIVE", nil, now, now))

		link, err := repo.GetLinkByID(ctx, "link-1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if link.ID != "link-1" {
			t.Errorf("expected link-1, got %s", link.ID)
		}
	})

	t.Run("not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM links WHERE id").
			WithArgs(pgxmock.AnyArg()).
			WillReturnError(pgx.ErrNoRows)

		_, err = repo.GetLinkByID(ctx, "notfound")
		if !errors.Is(err, ErrLinkNotFound) {
			t.Errorf("expected ErrLinkNotFound, got %v", err)
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM links WHERE id").
			WithArgs(pgxmock.AnyArg()).
			WillReturnError(errors.New("database error"))

		_, err = repo.GetLinkByID(ctx, "link-1")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestGetExportAnalytics(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM click_events ce JOIN links l").
			WithArgs("link-1", 10000).
			WillReturnRows(pgxmock.NewRows([]string{"timestamp", "slug", "country", "referrer", "user_agent", "device"}).
				AddRow("2024-01-01 10:00:00", "abc123", "US", "direct", "Mozilla/5.0", "desktop"))

		rows, err := repo.GetExportAnalytics(ctx, "link-1", 10000)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(rows) != 1 {
			t.Errorf("expected 1 row, got %d", len(rows))
		}
	})

	t.Run("no data", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM click_events ce JOIN links l").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"timestamp", "slug", "country", "referrer", "user_agent", "device"}))

		rows, err := repo.GetExportAnalytics(ctx, "link-1", 10000)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(rows) != 0 {
			t.Errorf("expected 0 rows, got %d", len(rows))
		}
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherAny))
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		repo := NewRepository(mock)

		mock.ExpectQuery("SELECT.*FROM click_events ce JOIN links l").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnError(errors.New("database error"))

		_, err = repo.GetExportAnalytics(ctx, "link-1", 10000)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}
