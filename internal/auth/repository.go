package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func HashToken(rawToken string) string {
	hash := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hash[:])
}

func (r *Repository) CreateUserWithPlan(ctx context.Context, email, passwordHash string) (*User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	user := &User{}
	userQuery := `
		INSERT INTO users (email, password_hash, plan_code, is_platform_admin)
		VALUES ($1, $2, 'FREE', false)
		RETURNING id, email, plan_code, is_platform_admin, created_at, updated_at
	`
	err = tx.QueryRow(ctx, userQuery, email, passwordHash).Scan(
		&user.ID, &user.Email, &user.PlanCode, &user.IsPlatformAdmin, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	planQuery := `
		INSERT INTO plan_usage (user_id, plan_code, active_link_count)
		VALUES ($1, 'FREE', 0)
	`
	_, err = tx.Exec(ctx, planQuery, user.ID)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return user, nil
}

func (r *Repository) SaveVerificationToken(ctx context.Context, userID, rawToken string, expiresAt time.Time) error {
	tokenDigest := HashToken(rawToken)
	query := `
		INSERT INTO email_verification_tokens (user_id, token_digest, expires_at)
		VALUES ($1, $2, $3)
	`
	_, err := r.db.Exec(ctx, query, userID, tokenDigest, expiresAt)
	return err
}

func (r *Repository) VerifyEmailToken(ctx context.Context, rawToken string) error {
	tokenDigest := HashToken(rawToken)
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var userID string
	var expiresAt time.Time
	var consumedAt *time.Time

	query := `
		SELECT user_id, expires_at, consumed_at
		FROM email_verification_tokens
		WHERE token_digest = $1
		FOR UPDATE
	`
	err = tx.QueryRow(ctx, query, tokenDigest).Scan(&userID, &expiresAt, &consumedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("invalid or expired token")
		}
		return err
	}

	if consumedAt != nil || time.Now().After(expiresAt) {
		return errors.New("invalid or expired token")
	}

	// Update token consumed status
	now := time.Now()
	_, err = tx.Exec(ctx, `UPDATE email_verification_tokens SET consumed_at = $1 WHERE token_digest = $2`, now, tokenDigest)
	if err != nil {
		return err
	}

	// Update user email_verified_at
	_, err = tx.Exec(ctx, `UPDATE users SET email_verified_at = $1, updated_at = $1 WHERE id = $2`, now, userID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	user := &User{}
	query := `
		SELECT id, email, password_hash, email_verified_at, plan_code, is_platform_admin, created_at, updated_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL
	`
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.EmailVerifiedAt, &user.PlanCode, &user.IsPlatformAdmin, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *Repository) GetUserByID(ctx context.Context, userID string) (*User, error) {
	user := &User{}
	query := `
		SELECT id, email, password_hash, email_verified_at, plan_code, is_platform_admin, created_at, updated_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`
	err := r.db.QueryRow(ctx, query, userID).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.EmailVerifiedAt, &user.PlanCode, &user.IsPlatformAdmin, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *Repository) CreateSession(ctx context.Context, userID, rawToken string, expiresAt time.Time) error {
	tokenHash := HashToken(rawToken)
	query := `
		INSERT INTO sessions (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`
	_, err := r.db.Exec(ctx, query, userID, tokenHash, expiresAt)
	return err
}

func (r *Repository) GetSessionUser(ctx context.Context, rawToken string) (*User, error) {
	tokenHash := HashToken(rawToken)
	user := &User{}
	query := `
		SELECT u.id, u.email, u.password_hash, u.email_verified_at, u.plan_code, u.is_platform_admin, u.created_at, u.updated_at
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.token_hash = $1 AND s.expires_at > NOW() AND s.revoked_at IS NULL AND u.deleted_at IS NULL
	`
	err := r.db.QueryRow(ctx, query, tokenHash).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.EmailVerifiedAt, &user.PlanCode, &user.IsPlatformAdmin, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *Repository) RevokeSession(ctx context.Context, rawToken string) error {
	tokenHash := HashToken(rawToken)
	_, err := r.db.Exec(ctx, `UPDATE sessions SET revoked_at = NOW() WHERE token_hash = $1`, tokenHash)
	return err
}
