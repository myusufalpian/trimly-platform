package admin

import (
	"context"

	"trimly-platform/internal/auth"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) ListUsers(ctx context.Context) ([]auth.User, error) {
	query := `
		SELECT id, email, plan_code, is_platform_admin, created_at, updated_at
		FROM users
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []auth.User
	for rows.Next() {
		var u auth.User
		if err := rows.Scan(&u.ID, &u.Email, &u.PlanCode, &u.IsPlatformAdmin, &u.CreatedAt, &u.UpdatedAt); err == nil {
			users = append(users, u)
		}
	}
	return users, nil
}

func (r *Repository) AddBlacklistDomain(ctx context.Context, domain, reason, adminID string) error {
	query := `
		INSERT INTO blacklist_domains (domain, reason, created_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (domain) DO UPDATE SET reason = EXCLUDED.reason
	`
	_, err := r.db.Exec(ctx, query, domain, reason, adminID)
	return err
}

func (r *Repository) RemoveBlacklistDomain(ctx context.Context, domain string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM blacklist_domains WHERE domain = $1`, domain)
	return err
}

func (r *Repository) IsDomainBlacklisted(ctx context.Context, domain string) bool {
	var dummy int
	err := r.db.QueryRow(ctx, `SELECT 1 FROM blacklist_domains WHERE domain = $1`, domain).Scan(&dummy)
	return err == nil
}

func (r *Repository) UnflagClick(ctx context.Context, clickID string) error {
	_, err := r.db.Exec(ctx, `UPDATE click_events SET fraud_status = 'VALID', fraud_reason = NULL WHERE id = $1`, clickID)
	return err
}
