package link

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateLinkAtomic(ctx context.Context, ownerUserID string, workspaceID *string, slug, targetURL, userPlan string, expiresAt *time.Time, utm *LinkCampaign) (*Link, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var activeCount int
	var planCode string
	lockQuery := `
		SELECT active_link_count, plan_code FROM plan_usage
		WHERE user_id = $1 FOR UPDATE
	`
	err = tx.QueryRow(ctx, lockQuery, ownerUserID).Scan(&activeCount, &planCode)
	if err != nil {
		return nil, err
	}

	if planCode == "FREE" && activeCount >= 10 {
		return nil, errors.New("active link limit reached for Free plan (maximum 10 active links)")
	}

	link := &Link{}
	insertQuery := `
		INSERT INTO links (owner_user_id, workspace_id, slug, target_url, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, owner_user_id, workspace_id, slug, target_url, status, expires_at, created_at, updated_at
	`
	err = tx.QueryRow(ctx, insertQuery, ownerUserID, workspaceID, slug, targetURL, expiresAt).Scan(
		&link.ID, &link.OwnerUserID, &link.WorkspaceID, &link.Slug, &link.TargetURL, &link.Status, &link.ExpiresAt, &link.CreatedAt, &link.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Insert UTM Campaign metadata if provided (FR-23)
	if utm != nil {
		utmQuery := `
			INSERT INTO link_campaigns (link_id, utm_source, utm_medium, utm_campaign, utm_term, utm_content)
			VALUES ($1, $2, $3, $4, $5, $6)
		`
		_, err = tx.Exec(ctx, utmQuery, link.ID, utm.UTMSource, utm.UTMMedium, utm.UTMCampaign, utm.UTMTerm, utm.UTMContent)
		if err != nil {
			return nil, err
		}
		link.UTMCampaign = utm
	}

	_, err = tx.Exec(ctx, `UPDATE plan_usage SET active_link_count = active_link_count + 1 WHERE user_id = $1`, ownerUserID)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return link, nil
}

func (r *Repository) GetActiveLinkBySlug(ctx context.Context, slug string) (*Link, error) {
	link := &Link{}
	query := `
		SELECT id, owner_user_id, workspace_id, slug, target_url, status, expires_at, created_at, updated_at
		FROM links
		WHERE slug = $1 AND status = 'ACTIVE' AND deleted_at IS NULL
	`
	err := r.db.QueryRow(ctx, query, slug).Scan(
		&link.ID, &link.OwnerUserID, &link.WorkspaceID, &link.Slug, &link.TargetURL, &link.Status, &link.ExpiresAt, &link.CreatedAt, &link.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("shortlink not found or inactive")
		}
		return nil, err
	}

	if link.ExpiresAt != nil && time.Now().After(*link.ExpiresAt) {
		return nil, errors.New("shortlink has expired")
	}

	return link, nil
}

func (r *Repository) RecordClickEvent(ctx context.Context, linkID, source string) error {
	query := `
		INSERT INTO click_events (link_id, source, clicked_at)
		VALUES ($1, $2, NOW())
	`
	_, err := r.db.Exec(ctx, query, linkID, source)
	return err
}

func (r *Repository) GetLinkAnalytics(ctx context.Context, linkID, userPlan string) (*AnalyticsSummary, error) {
	retentionDays := 7
	if userPlan == "PRO" || userPlan == "BUSINESS" {
		retentionDays = 90
	}

	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	var totalClicks int
	_ = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM click_events WHERE link_id = $1 AND clicked_at >= $2`, linkID, cutoffDate).Scan(&totalClicks)

	query := `
		SELECT DATE(clicked_at)::text as date, COUNT(*) as click_count
		FROM click_events
		WHERE link_id = $1 AND clicked_at >= $2
		GROUP BY DATE(clicked_at)
		ORDER BY date ASC
	`
	rows, err := r.db.Query(ctx, query, linkID, cutoffDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []DailyClickPoint
	for rows.Next() {
		var p DailyClickPoint
		if err := rows.Scan(&p.Date, &p.ClickCount); err == nil {
			points = append(points, p)
		}
	}

	summary := &AnalyticsSummary{
		TotalClicks: totalClicks,
		DailyClicks: points,
	}

	// Gated breakdown analytics per campaign (FR-24 / AC-26: Pro & Business only)
	if userPlan == "PRO" || userPlan == "BUSINESS" {
		breakdownQuery := `
			SELECT COALESCE(lc.utm_source, 'none') as utm_source, COALESCE(lc.utm_campaign, 'none') as utm_campaign, COUNT(*) as click_count
			FROM click_events ce
			JOIN link_campaigns lc ON ce.link_id = lc.link_id
			WHERE ce.link_id = $1 AND ce.clicked_at >= $2
			GROUP BY lc.utm_source, lc.utm_campaign
		`
		breakdownRows, err := r.db.Query(ctx, breakdownQuery, linkID, cutoffDate)
		if err == nil {
			defer breakdownRows.Close()
			var breakdown []CampaignBreakdownRow
			for breakdownRows.Next() {
				var b CampaignBreakdownRow
				if err := breakdownRows.Scan(&b.UTMSource, &b.UTMCampaign, &b.ClickCount); err == nil {
					breakdown = append(breakdown, b)
				}
			}
			summary.CampaignBreakdown = breakdown
		}
	}

	return summary, nil
}

func (r *Repository) GetUserActiveLinkCount(ctx context.Context, userID string) (int, error) {
	var count int
	query := `SELECT active_link_count FROM plan_usage WHERE user_id = $1`
	err := r.db.QueryRow(ctx, query, userID).Scan(&count)
	return count, err
}

func (r *Repository) IsSlugAvailable(ctx context.Context, slug string) bool {
	var dummy int
	err := r.db.QueryRow(ctx, `SELECT 1 FROM links WHERE slug = $1 AND deleted_at IS NULL`, slug).Scan(&dummy)
	return err == pgx.ErrNoRows
}

func (r *Repository) GetLinkByID(ctx context.Context, linkID string) (*Link, error) {
	link := &Link{}
	query := `
		SELECT id, owner_user_id, workspace_id, slug, target_url, status, expires_at, created_at, updated_at
		FROM links
		WHERE id = $1 AND deleted_at IS NULL
	`
	err := r.db.QueryRow(ctx, query, linkID).Scan(
		&link.ID, &link.OwnerUserID, &link.WorkspaceID, &link.Slug, &link.TargetURL, &link.Status, &link.ExpiresAt, &link.CreatedAt, &link.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("shortlink not found")
		}
		return nil, err
	}
	return link, nil
}

type ClickExportRow struct {
	Timestamp string
	Slug      string
	Country   string
	Referrer  string
	UserAgent string
	Device    string
}

func (r *Repository) GetExportAnalytics(ctx context.Context, linkID string) ([]ClickExportRow, error) {
	query := `
		SELECT 
			ce.clicked_at::text as timestamp,
			l.slug,
			COALESCE(ce.source, 'UNKNOWN') as country,
			'direct' as referrer,
			'unknown' as user_agent,
			'desktop' as device
		FROM click_events ce
		JOIN links l ON ce.link_id = l.id
		WHERE ce.link_id = $1
		ORDER BY ce.clicked_at DESC
	`
	rows, err := r.db.Query(ctx, query, linkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []ClickExportRow
	for rows.Next() {
		var row ClickExportRow
		if err := rows.Scan(&row.Timestamp, &row.Slug, &row.Country, &row.Referrer, &row.UserAgent, &row.Device); err != nil {
			return nil, err
		}
		results = append(results, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
