package bio

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct{ db *pgxpool.Pool }

func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func (r *Repository) CreatePage(ctx context.Context, ownerID string, req CreatePageRequest) (*Page, error) {
	return insertPage(ctx, r.db, ownerID, req)
}

func (r *Repository) CreateFreePage(ctx context.Context, ownerID string, req CreatePageRequest) (*Page, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var lockedOwner string
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, ownerID).Scan(&lockedOwner); err != nil {
		return nil, err
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM bio_pages WHERE owner_user_id = $1`, ownerID).Scan(&count); err != nil {
		return nil, err
	}
	if count >= 1 {
		return nil, ErrFreePageLimit
	}
	page, err := insertPage(ctx, tx, ownerID, req)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return page, nil
}

type queryRower interface {
	QueryRow(context.Context, string, ...interface{}) pgx.Row
}

func insertPage(ctx context.Context, db queryRower, ownerID string, req CreatePageRequest) (*Page, error) {
	page := &Page{}
	err := db.QueryRow(ctx, `
		INSERT INTO bio_pages (owner_user_id, title, slug, bio_description)
		VALUES ($1, $2, $3, $4)
		RETURNING id, owner_user_id, title, slug, bio_description, created_at, updated_at
	`, ownerID, req.Title, req.Slug, req.BioDescription).Scan(
		&page.ID, &page.OwnerUserID, &page.Title, &page.Slug, &page.BioDescription, &page.CreatedAt, &page.UpdatedAt,
	)
	return page, err
}

func (r *Repository) GetPage(ctx context.Context, id string) (*Page, error) {
	page := &Page{}
	err := r.db.QueryRow(ctx, `SELECT id, owner_user_id, title, slug, bio_description, created_at, updated_at FROM bio_pages WHERE id = $1`, id).Scan(
		&page.ID, &page.OwnerUserID, &page.Title, &page.Slug, &page.BioDescription, &page.CreatedAt, &page.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrBioPageNotFound
	}
	return page, err
}

func (r *Repository) AddLink(ctx context.Context, pageID, linkID string, displayOrder int, ownerID string) error {
	result, err := r.db.Exec(ctx, `
		INSERT INTO bio_page_links (bio_page_id, link_id, display_order)
		SELECT $1, $2, $3
		WHERE EXISTS (SELECT 1 FROM links WHERE id = $2 AND owner_user_id = $4)
	`, pageID, linkID, displayOrder, ownerID)
	if err == nil && result.RowsAffected() == 0 {
		return ErrBioLinkUnauthorized
	}
	return err
}

func (r *Repository) GetPublicPage(ctx context.Context, slug, baseURL string) (*PublicPage, error) {
	page := &PublicPage{}
	err := r.db.QueryRow(ctx, `SELECT title, slug, bio_description FROM bio_pages WHERE slug = $1`, slug).Scan(&page.Title, &page.Slug, &page.BioDescription)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrBioPageNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `
		SELECT bpl.link_id, l.slug, bpl.display_order
		FROM bio_page_links bpl JOIN links l ON l.id = bpl.link_id
		JOIN bio_pages bp ON bp.id = bpl.bio_page_id
		WHERE bp.slug = $1 AND l.status = 'ACTIVE' AND l.deleted_at IS NULL
		ORDER BY bpl.display_order ASC, bpl.created_at ASC
	`, slug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item PageLink
		if err := rows.Scan(&item.LinkID, &item.Slug, &item.DisplayOrder); err != nil {
			return nil, err
		}
		item.ShortURL = baseURL + "/r/" + item.Slug
		page.Links = append(page.Links, item)
	}
	return page, rows.Err()
}
