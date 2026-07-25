package apikey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"

	"golang.org/x/time/rate"
)

type Service struct {
	repo     *Repository
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
}

func NewService(repo *Repository) *Service {
	return &Service{
		repo:     repo,
		limiters: make(map[string]*rate.Limiter),
	}
}

func (s *Service) getRateLimiter(apiKeyID string) *rate.Limiter {
	s.mu.RLock()
	limiter, exists := s.limiters[apiKeyID]
	s.mu.RUnlock()

	if exists {
		return limiter
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double check after lock
	if limiter, exists = s.limiters[apiKeyID]; exists {
		return limiter
	}

	// 60 requests per minute = 1 req/sec with a burst capability of 60 (FR-21 / AC-23)
	limiter = rate.NewLimiter(rate.Limit(1.0), 60)
	s.limiters[apiKeyID] = limiter
	return limiter
}

func generateAPIKeyString() (string, string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", "", err
	}
	randomPart := hex.EncodeToString(b)
	rawKey := "trimly_live_" + randomPart
	keyPrefix := rawKey[:12]
	return rawKey, keyPrefix, nil
}

func (s *Service) CreateAPIKey(ctx context.Context, user *auth.User) (*APIKeyResponse, error) {
	if user.PlanCode != "BUSINESS" {
		return nil, errors.New("API key generation is exclusive to Business plan")
	}

	rawKey, keyPrefix, err := generateAPIKeyString()
	if err != nil {
		return nil, err
	}

	return s.repo.CreateAPIKey(ctx, user.ID, keyPrefix, rawKey)
}

func (s *Service) GetUserAPIKeys(ctx context.Context, userID string) ([]APIKeyResponse, error) {
	return s.repo.GetUserAPIKeys(ctx, userID)
}

func (s *Service) RevokeAPIKey(ctx context.Context, keyID, userID string) error {
	return s.repo.RevokeAPIKey(ctx, keyID, userID)
}

func (s *Service) GetAPIUsageHistory(ctx context.Context, userID string) ([]APIUsageDaily, error) {
	return s.repo.GetAPIUsageHistory(ctx, userID)
}

// B2B API Key Authentication & Rate Limiting Middleware
func (s *Service) APIKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawKey := extractAPIKeyFromRequest(r)
		if rawKey == "" {
			httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "API key required in Authorization header or X-API-Key header")
			return
		}

		user, apiKeyID, err := s.repo.ValidateAPIKey(r.Context(), rawKey)
		if err != nil {
			httputil.RespondError(w, http.StatusUnauthorized, "INVALID_API_KEY", err.Error())
			return
		}

		// 1. Minute Rate Limiter (60 req/min in-memory check - AC-23)
		limiter := s.getRateLimiter(apiKeyID)
		if !limiter.Allow() {
			httputil.RespondError(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Rate limit of 60 requests per minute exceeded")
			return
		}

		// 2. Transactional Daily Quota Check (5,000 req/day DB check - AC-24)
		err = s.repo.IncrementAndCheckDailyQuota(r.Context(), apiKeyID)
		if err != nil {
			httputil.RespondError(w, http.StatusTooManyRequests, "DAILY_QUOTA_EXCEEDED", err.Error())
			return
		}

		ctx := context.WithValue(r.Context(), auth.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractAPIKeyFromRequest(r *http.Request) string {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" {
		return strings.TrimSpace(apiKey)
	}

	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}

	return ""
}
