package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) ListUsers(ctx context.Context) ([]auth.User, error) {
	return s.repo.ListUsers(ctx)
}

func (s *Service) AddBlacklistDomain(ctx context.Context, domain, reason, adminID string) error {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return errors.New("domain is required")
	}
	return s.repo.AddBlacklistDomain(ctx, domain, reason, adminID)
}

func (s *Service) RemoveBlacklistDomain(ctx context.Context, domain string) error {
	domain = strings.TrimSpace(strings.ToLower(domain))
	return s.repo.RemoveBlacklistDomain(ctx, domain)
}

func (s *Service) IsDomainBlacklisted(ctx context.Context, domain string) bool {
	domain = strings.TrimSpace(strings.ToLower(domain))
	return s.repo.IsDomainBlacklisted(ctx, domain)
}

func (s *Service) UnflagClick(ctx context.Context, clickID string) error {
	if clickID == "" {
		return errors.New("click_id is required")
	}
	return s.repo.UnflagClick(ctx, clickID)
}

// RequirePlatformAdminMiddleware
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
