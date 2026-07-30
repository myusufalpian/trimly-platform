package bio

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"trimly-platform/internal/auth"
)

type pageRepository interface {
	CreatePage(context.Context, string, CreatePageRequest) (*Page, error)
	CreateFreePage(context.Context, string, CreatePageRequest) (*Page, error)
	GetPage(context.Context, string) (*Page, error)
	AddLink(context.Context, string, string, int, string) error
	GetPublicPage(context.Context, string, string) (*PublicPage, error)
}

type Service struct{ repo pageRepository }

var (
	ErrFreePageLimit       = errors.New("Free plan allows only one bio page")
	ErrBioPageUnauthorized = errors.New("unauthorized access to bio page")
	ErrBioLinkUnauthorized = errors.New("link does not belong to user")
	ErrBioPageNotFound     = errors.New("bio page not found")
)

func NewService(repo pageRepository) *Service { return &Service{repo: repo} }

var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func (s *Service) CreatePage(ctx context.Context, user *auth.User, req CreatePageRequest) (*Page, error) {
	req.Title, req.Slug = strings.TrimSpace(req.Title), strings.ToLower(strings.TrimSpace(req.Slug))
	if req.Title == "" || req.Slug == "" {
		return nil, errors.New("title and slug are required")
	}
	if len(req.Title) > 100 || len(req.Slug) > 50 || !slugPattern.MatchString(req.Slug) {
		return nil, errors.New("invalid title or slug")
	}
	if user.PlanCode == "FREE" {
		return s.repo.CreateFreePage(ctx, user.ID, req)
	}
	return s.repo.CreatePage(ctx, user.ID, req)
}

func (s *Service) AddLink(ctx context.Context, user *auth.User, pageID string, req AddLinkRequest) error {
	if req.LinkID == "" {
		return errors.New("link_id is required")
	}
	page, err := s.repo.GetPage(ctx, pageID)
	if err != nil {
		return err
	}
	if page.OwnerUserID != user.ID {
		return ErrBioPageUnauthorized
	}
	return s.repo.AddLink(ctx, pageID, req.LinkID, req.DisplayOrder, user.ID)
}

func (s *Service) GetPublicPage(ctx context.Context, slug, baseURL string) (*PublicPage, error) {
	return s.repo.GetPublicPage(ctx, strings.TrimSpace(slug), strings.TrimRight(baseURL, "/"))
}
