package link

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"log"
	"net/url"
	"strings"
	"time"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/security"

	"github.com/skip2/go-qrcode"
)

type DomainBlacklistChecker interface {
	IsDomainBlacklisted(ctx context.Context, domain string) bool
}

var (
	ErrMaliciousURL     = errors.New("MALICIOUS_URL_DETECTED")
	ErrCustomDomainPlan = errors.New("custom domain is only available on Business plans")
	ErrLinkNotFound     = errors.New("shortlink not found")
	ErrLinkUnauthorized = errors.New("unauthorized access to shortlink")
	ErrCSVPlan          = errors.New("CSV analytics export is only available on Pro or Business plans")
)

type clickTask struct {
	linkID string
	source string
}

type Service struct {
	repo             *Repository
	blacklistChecker DomainBlacklistChecker
	scanner          security.URLScanner
	clickChan        chan clickTask
}

func NewService(repo *Repository, blacklistChecker DomainBlacklistChecker) *Service {
	s := &Service{
		repo:             repo,
		blacklistChecker: blacklistChecker,
		clickChan:        make(chan clickTask, 5000),
	}
	go s.startClickWorker()
	return s
}

func (s *Service) SetURLScanner(scanner security.URLScanner) { s.scanner = scanner }

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

	parsedURL, err := url.ParseRequestURI(req.TargetURL)
	if err != nil {
		return nil, errors.New("invalid target_url format")
	}
	if s.scanner != nil {
		malicious, scanErr := s.scanner.CheckURL(ctx, req.TargetURL)
		if scanErr != nil {
			return nil, errors.New("unable to scan target_url")
		}
		if malicious {
			return nil, ErrMaliciousURL
		}
	}
	if req.CustomDomain != "" && user.PlanCode != "BUSINESS" {
		return nil, ErrCustomDomainPlan
	}

	// Enforcement PRD FR-38 & AC-34: Check domain blacklist
	if s.blacklistChecker != nil {
		domain := strings.ToLower(parsedURL.Hostname())
		if s.blacklistChecker.IsDomainBlacklisted(ctx, domain) {
			return nil, errors.New("target_url domain is blacklisted and cannot be shortened")
		}
	}

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

	if req.ExpiresAt != nil && user.PlanCode == "FREE" {
		return nil, errors.New("expiry time is only available on Pro or Business plans")
	}

	return s.repo.CreateLinkAtomic(ctx, user.ID, req.WorkspaceID, slug, req.TargetURL, req.CustomDomain, user.PlanCode, req.ExpiresAt, req.UTM)
}

func (s *Service) ResolveAndRecordRedirect(ctx context.Context, slug, source string) (string, error) {
	link, err := s.repo.GetActiveLinkBySlug(ctx, slug)
	if err != nil {
		return "", err
	}

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

func (s *Service) GenerateQRCode(ctx context.Context, user *auth.User, linkID, baseURL string) ([]byte, error) {
	link, err := s.repo.GetLinkByID(ctx, linkID)
	if err != nil {
		return nil, err
	}

	if link.OwnerUserID != user.ID {
		return nil, ErrLinkUnauthorized
	}

	targetURL := strings.TrimRight(baseURL, "/") + "/r/" + link.Slug
	pngBytes, err := qrcode.Encode(targetURL, qrcode.Medium, 256)
	if err != nil {
		return nil, errors.New("failed to generate QR code PNG")
	}

	return pngBytes, nil
}

func (s *Service) ExportCSVAnalytics(ctx context.Context, user *auth.User, linkID string) ([]byte, error) {
	if user.PlanCode != "PRO" && user.PlanCode != "BUSINESS" {
		return nil, ErrCSVPlan
	}

	link, err := s.repo.GetLinkByID(ctx, linkID)
	if err != nil {
		return nil, err
	}

	if link.OwnerUserID != user.ID {
		return nil, ErrLinkUnauthorized
	}

	rows, err := s.repo.GetExportAnalytics(ctx, linkID)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write CSV Header
	_ = writer.Write([]string{"timestamp", "slug", "country", "referrer", "user_agent", "device"})

	for _, r := range rows {
		_ = writer.Write([]string{r.Timestamp, r.Slug, r.Country, r.Referrer, r.UserAgent, r.Device})
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
