package apikey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"trimly-platform/internal/auth"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func HashAPIKey(rawKey string) string {
	hash := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(hash[:])
}

func (r *Repository) CreateAPIKey(ctx context.Context, userID, keyPrefix, rawKey string) (*APIKeyResponse, error) {
	keyHash := HashAPIKey(rawKey)
	key := &APIKeyResponse{}

	query := `
		INSERT INTO api_keys (user_id, key_prefix, key_hash)
		VALUES ($1, $2, $3)
		RETURNING id, key_prefix, created_at
	`
	err := r.db.QueryRow(ctx, query, userID, keyPrefix, keyHash).Scan(&key.ID, &key.KeyPrefix, &key.CreatedAt)
	if err != nil {
		return nil, err
	}

	key.APIKey = rawKey
	return key, nil
}

func (r *Repository) GetUserAPIKeys(ctx context.Context, userID string) ([]APIKeyResponse, error) {
	query := `
		SELECT id, key_prefix, created_at
		FROM api_keys
		WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []APIKeyResponse
	for rows.Next() {
		var k APIKeyResponse
		if err := rows.Scan(&k.ID, &k.KeyPrefix, &k.CreatedAt); err == nil {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (r *Repository) RevokeAPIKey(ctx context.Context, keyID, userID string) error {
	_, err := r.db.Exec(ctx, `UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND user_id = $2`, keyID, userID)
	return err
}

func (r *Repository) ValidateAPIKey(ctx context.Context, rawKey string) (*auth.User, string, error) {
	keyHash := HashAPIKey(rawKey)
	user := &auth.User{}
	var apiKeyID string

	query := `
		SELECT k.id, u.id, u.email, u.plan_code, u.is_platform_admin, u.created_at, u.updated_at
		FROM api_keys k
		JOIN users u ON k.user_id = u.id
		WHERE k.key_hash = $1 AND k.revoked_at IS NULL AND u.deleted_at IS NULL
	`
	err := r.db.QueryRow(ctx, query, keyHash).Scan(
		&apiKeyID, &user.ID, &user.Email, &user.PlanCode, &user.IsPlatformAdmin, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", errors.New("invalid or revoked API key")
		}
		return nil, "", err
	}

	// B2B API Key is exclusive to BUSINESS plan (FR-18)
	if user.PlanCode != "BUSINESS" {
		return nil, "", errors.New("API key access is exclusive to Business plan")
	}

	return user, apiKeyID, nil
}

func (r *Repository) IncrementAndCheckDailyQuota(ctx context.Context, apiKeyID string) error {
	today := time.Now().Format("2006-01-02")
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var currentCount int
	query := `
		INSERT INTO api_usage_daily (api_key_id, date, accepted_request_count)
		VALUES ($1, $2, 1)
		ON CONFLICT (api_key_id, date) DO UPDATE
		SET accepted_request_count = api_usage_daily.accepted_request_count + 1
		RETURNING accepted_request_count
	`
	err = tx.QueryRow(ctx, query, apiKeyID, today).Scan(&currentCount)
	if err != nil {
		return err
	}

	// Daily Quota Limit 5,000 req/day (FR-21 / AC-24)
	if currentCount > 5000 {
		return errors.New("daily API quota of 5,000 requests exceeded")
	}

	return tx.Commit(ctx)
}

func (r *Repository) GetAPIUsageHistory(ctx context.Context, userID string) ([]APIUsageDaily, error) {
	query := `
		SELECT u.api_key_id::text, u.date::text, u.accepted_request_count
		FROM api_usage_daily u
		JOIN api_keys k ON u.api_key_id = k.id
		WHERE k.user_id = $1
		ORDER BY u.date DESC
	`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []APIUsageDaily
	for rows.Next() {
		var h APIUsageDaily
		if err := rows.Scan(&h.APIKeyID, &h.Date, &h.AcceptedRequestCount); err == nil {
			history = append(history, h)
		}
	}
	return history, nil
}
