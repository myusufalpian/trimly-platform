package link

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/url"
	"strings"
	"time"

	"trimly-platform/internal/auth"
)

type clickTask struct {
	linkID string
	source string
}

type Service struct {
	repo      *Repository
	clickChan chan clickTask
}

func NewService(repo *Repository) *Service {
	s := &Service{
		repo:      repo,
		clickChan: make(chan clickTask, 5000), // Buffer 5000 events for NFR-3 high throughput
	}
	go s.startClickWorker()
	return s
}

func (s *Service) startClickWorker() {
	for task := range s.clickChan {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.repo.RecordClickEvent(ctx, task.linkID, task.source)
		if err != nil {
			log.Printf("[ClickWorker] Error recording click for link %s: %v", task.linkID, err)
		}
		cancel()
	}
}

func generateRandomSlug(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:length]
}

func (s *Service) CreateLink(ctx context.Context, user *auth.User, req CreateLinkRequest) (*Link, error) {
	if req.TargetURL == "" {
		return nil, errors.New("target_url is required")
	}

	_, err := url.ParseRequestURI(req.TargetURL)
	if err != nil {
		return nil, errors.New("invalid target_url format")
	}

	// Enforcement PRD FR-4 & AC-5: Custom alias prohibited for Free plan
	slug := strings.TrimSpace(req.CustomAlias)
	if slug != "" {
		if user.PlanCode == "FREE" {
			return nil, errors.New("custom alias is only available on Pro or Business plans")
		}
		if !s.repo.IsSlugAvailable(ctx, slug) {
			return nil, errors.New("custom alias is already taken")
		}
	} else {
		slug = generateRandomSlug(7)
	}

	// Enforcement PRD FR-5: Expiry dates prohibited for Free plan
	if req.ExpiresAt != nil && user.PlanCode == "FREE" {
		return nil, errors.New("expiry time is only available on Pro or Business plans")
	}

	return s.repo.CreateLinkAtomic(ctx, user.ID, req.WorkspaceID, slug, req.TargetURL, user.PlanCode, req.ExpiresAt)
}

func (s *Service) ResolveAndRecordRedirect(ctx context.Context, slug, source string) (string, error) {
	link, err := s.repo.GetActiveLinkBySlug(ctx, slug)
	if err != nil {
		return "", err
	}

	// Non-blocking async click ingestion for NFR-2 (<100ms p95 latency) & NFR-3 (500 concurrent events)
	select {
	case s.clickChan <- clickTask{linkID: link.ID, source: source}:
	default:
		log.Printf("[Service] Click buffer full, dropping click event for link %s", link.ID)
	}

	return link.TargetURL, nil
}

func (s *Service) GetAnalytics(ctx context.Context, user *auth.User, linkID string) (*AnalyticsSummary, error) {
	return s.repo.GetLinkAnalytics(ctx, linkID, user.PlanCode)
}

func (s *Service) CheckDowngradeAllowed(ctx context.Context, userID, newPlan string) error {
	if newPlan == "FREE" {
		activeCount, err := s.repo.GetUserActiveLinkCount(ctx, userID)
		if err != nil {
			return err
		}
		if activeCount > 10 {
			return errors.New("cannot downgrade to Free: you have more than 10 active links. Please delete excess links first")
		}
	}
	return nil
}
