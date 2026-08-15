package apikey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/pkg/httputil"

	"golang.org/x/time/rate"
)

const (
	b2bRateLimitPerSec = 1.0
	b2bRateBurst       = 60
	b2bDailyQuota      = 5000
	apiKeyPrefix       = "trimly_live_"
	apiKeyPrefixLen    = 12
	apiKeyRandBytes    = 16
)

var (
	ErrBusinessPlanRequired = errors.New("API key generation is exclusive to Business plan")
)

type apiKeyRepository interface {
	CreateAPIKey(ctx context.Context, userID, keyPrefix, rawKey string) (*APIKeyResponse, error)
	GetUserAPIKeys(ctx context.Context, userID string) ([]APIKeyResponse, error)
	RevokeAPIKey(ctx context.Context, keyID, userID string) error
	ValidateAPIKey(ctx context.Context, rawKey string) (*auth.User, string, error)
	IncrementAndCheckDailyQuota(ctx context.Context, apiKeyID string) error
	GetAPIUsageHistory(ctx context.Context, userID string) ([]APIUsageDaily, error)
}

type Service struct {
	repo     apiKeyRepository
	limiters sync.Map
}

func NewService(repo apiKeyRepository) *Service {
	return &Service{
		repo: repo,
	}
}

func (s *Service) getRateLimiter(apiKeyID string) *rate.Limiter {
	if v, ok := s.limiters.Load(apiKeyID); ok {
		return v.(*rate.Limiter)
	}
	limiter := rate.NewLimiter(rate.Limit(b2bRateLimitPerSec), b2bRateBurst)
	actual, _ := s.limiters.LoadOrStore(apiKeyID, limiter)
	return actual.(*rate.Limiter)
}

func generateAPIKeyString() (string, string, error) {
	b := make([]byte, apiKeyRandBytes)
	_, err := rand.Read(b)
	if err != nil {
		return "", "", err
	}
	randomPart := hex.EncodeToString(b)
	rawKey := apiKeyPrefix + randomPart
	keyPrefix := rawKey[:apiKeyPrefixLen]
	return rawKey, keyPrefix, nil
}

func (s *Service) CreateAPIKey(ctx context.Context, user *auth.User) (*APIKeyResponse, error) {
	if user.PlanCode != "BUSINESS" {
		return nil, ErrBusinessPlanRequired
	}

	rawKey, keyPrefix, err := generateAPIKeyString()
	if err != nil {
		return nil, fmt.Errorf("create api key: generate: %w", err)
	}

	resp, err := s.repo.CreateAPIKey(ctx, user.ID, keyPrefix, rawKey)
	if err != nil {
		return nil, fmt.Errorf("create api key: %w", err)
	}
	return resp, nil
}

func (s *Service) GetUserAPIKeys(ctx context.Context, userID string) ([]APIKeyResponse, error) {
	keys, err := s.repo.GetUserAPIKeys(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user api keys: %w", err)
	}
	return keys, nil
}

func (s *Service) RevokeAPIKey(ctx context.Context, keyID, userID string) error {
	if err := s.repo.RevokeAPIKey(ctx, keyID, userID); err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	return nil
}

func (s *Service) GetAPIUsageHistory(ctx context.Context, userID string) ([]APIUsageDaily, error) {
	history, err := s.repo.GetAPIUsageHistory(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get api usage history: %w", err)
	}
	return history, nil
}

func (s *Service) APIKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawKey := extractAPIKeyFromRequest(r)
		if rawKey == "" {
			httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "API key required in Authorization header or X-API-Key header")
			return
		}

		user, apiKeyID, err := s.repo.ValidateAPIKey(r.Context(), rawKey)
		if err != nil {
			httputil.RespondError(w, http.StatusUnauthorized, "INVALID_API_KEY", "invalid or revoked API key")
			return
		}

		limiter := s.getRateLimiter(apiKeyID)
		if !limiter.Allow() {
			httputil.RespondError(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", fmt.Sprintf("Rate limit of %d requests per minute exceeded", b2bRateBurst))
			return
		}

		err = s.repo.IncrementAndCheckDailyQuota(r.Context(), apiKeyID)
		if err != nil {
			httputil.RespondError(w, http.StatusTooManyRequests, "DAILY_QUOTA_EXCEEDED", fmt.Sprintf("Daily API quota of %d requests exceeded", b2bDailyQuota))
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
