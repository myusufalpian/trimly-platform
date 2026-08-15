package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"
)

type adminRepository interface {
	ListUsers(ctx context.Context) ([]auth.User, error)
	AddBlacklistDomain(ctx context.Context, domain, reason, adminID string) error
	RemoveBlacklistDomain(ctx context.Context, domain string) error
	IsDomainBlacklisted(ctx context.Context, domain string) bool
	UnflagClick(ctx context.Context, clickID string) error
}

type Service struct {
	repo adminRepository
}

var (
	ErrDomainRequired  = errors.New("domain is required")
	ErrClickIDRequired = errors.New("click_id is required")
)

func NewService(repo adminRepository) *Service {
	return &Service{repo: repo}
}

func (s *Service) ListUsers(ctx context.Context) ([]auth.User, error) {
	users, err := s.repo.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

func (s *Service) AddBlacklistDomain(ctx context.Context, domain, reason, adminID string) error {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return ErrDomainRequired
	}
	if err := s.repo.AddBlacklistDomain(ctx, domain, reason, adminID); err != nil {
		return fmt.Errorf("add blacklist domain: %w", err)
	}
	return nil
}

func (s *Service) RemoveBlacklistDomain(ctx context.Context, domain string) error {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if err := s.repo.RemoveBlacklistDomain(ctx, domain); err != nil {
		return fmt.Errorf("remove blacklist domain: %w", err)
	}
	return nil
}

func (s *Service) IsDomainBlacklisted(ctx context.Context, domain string) bool {
	domain = strings.TrimSpace(strings.ToLower(domain))
	return s.repo.IsDomainBlacklisted(ctx, domain)
}

func (s *Service) UnflagClick(ctx context.Context, clickID string) error {
	if clickID == "" {
		return ErrClickIDRequired
	}
	if err := s.repo.UnflagClick(ctx, clickID); err != nil {
		return fmt.Errorf("unflag click: %w", err)
	}
	return nil
}

func (s *Service) RequirePlatformAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(auth.UserContextKey).(*auth.User)
		if !ok || user == nil {
			httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
			return
		}

		if !user.IsPlatformAdmin {
			httputil.RespondError(w, http.StatusForbidden, "FORBIDDEN", "Platform admin access required")
			return
		}

		next.ServeHTTP(w, r)
	})
}
