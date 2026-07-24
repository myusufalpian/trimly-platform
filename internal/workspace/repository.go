package workspace

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

func (r *Repository) CreateWorkspace(ctx context.Context, name, userID string) (*Workspace, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	ws := &Workspace{}
	wsQuery := `
		INSERT INTO workspaces (name, created_by)
		VALUES ($1, $2)
		RETURNING id, name, created_by, created_at, updated_at
	`
	err = tx.QueryRow(ctx, wsQuery, name, userID).Scan(&ws.ID, &ws.Name, &ws.CreatedBy, &ws.CreatedAt, &ws.UpdatedAt)
	if err != nil {
		return nil, err
	}

	memberQuery := `
		INSERT INTO workspace_members (workspace_id, user_id, role)
		VALUES ($1, $2, 'OWNER')
	`
	_, err = tx.Exec(ctx, memberQuery, ws.ID, userID)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return ws, nil
}

func (r *Repository) GetUserWorkspaces(ctx context.Context, userID string) ([]Workspace, error) {
	query := `
		SELECT w.id, w.name, w.created_by, w.created_at, w.updated_at
		FROM workspaces w
		JOIN workspace_members wm ON w.id = wm.workspace_id
		WHERE wm.user_id = $1 AND w.deleted_at IS NULL
		ORDER BY w.created_at DESC
	`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var workspaces []Workspace
	for rows.Next() {
		var ws Workspace
		if err := rows.Scan(&ws.ID, &ws.Name, &ws.CreatedBy, &ws.CreatedAt, &ws.UpdatedAt); err != nil {
			return nil, err
		}
		workspaces = append(workspaces, ws)
	}

	return workspaces, nil
}

func (r *Repository) GetMemberRole(ctx context.Context, workspaceID, userID string) (Role, error) {
	var role string
	query := `
		SELECT role FROM workspace_members
		WHERE workspace_id = $1 AND user_id = $2
	`
	err := r.db.QueryRow(ctx, query, workspaceID, userID).Scan(&role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errors.New("member not found in workspace")
		}
		return "", err
	}
	return Role(role), nil
}

func (r *Repository) AddMemberByEmail(ctx context.Context, workspaceID, targetEmail string, role Role) error {
	var targetUserID string
	userQuery := `SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL`
	err := r.db.QueryRow(ctx, userQuery, targetEmail).Scan(&targetUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("user with this email does not exist")
		}
		return err
	}

	query := `
		INSERT INTO workspace_members (workspace_id, user_id, role)
		VALUES ($1, $2, $3)
		ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role
	`
	_, err = r.db.Exec(ctx, query, workspaceID, targetUserID, string(role))
	return err
}

func (r *Repository) RemoveMemberOrLeave(ctx context.Context, workspaceID, targetUserID string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Check if targetUser is sole owner
	var role string
	err = tx.QueryRow(ctx, `SELECT role FROM workspace_members WHERE workspace_id = $1 AND user_id = $2`, workspaceID, targetUserID).Scan(&role)
	if err != nil {
		return err
	}

	if Role(role) == RoleOwner {
		var ownerCount, totalMembers int
		_ = tx.QueryRow(ctx, `SELECT COUNT(*) FROM workspace_members WHERE workspace_id = $1 AND role = 'OWNER'`, workspaceID).Scan(&ownerCount)
		_ = tx.QueryRow(ctx, `SELECT COUNT(*) FROM workspace_members WHERE workspace_id = $1`, workspaceID).Scan(&totalMembers)

		if ownerCount == 1 && totalMembers > 1 {
			return errors.New("sole owner cannot leave workspace with active members; transfer ownership first")
		}

		if totalMembers == 1 {
			// Soft-delete workspace if sole member
			now := time.Now()
			_, _ = tx.Exec(ctx, `UPDATE workspaces SET deleted_at = $1 WHERE id = $2`, now, workspaceID)
		}
	}

	_, err = tx.Exec(ctx, `DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2`, workspaceID, targetUserID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}
