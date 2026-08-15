package link

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/security"

	"github.com/skip2/go-qrcode"
)

const (
	freeActiveLinkLimit = 10
	randomSlugLength    = 7
	clickChanBufferSize = 5000
	clickWorkerTimeout  = 5 * time.Second
	qrCodeSize          = 256
	csvExportLimit      = 10000
)

type DomainBlacklistChecker interface {
	IsDomainBlacklisted(ctx context.Context, domain string) bool
}

type WorkspaceMembershipChecker interface {
	IsMember(ctx context.Context, workspaceID, userID string) bool
}

type linkRepository interface {
	CreateLinkAtomic(ctx context.Context, ownerUserID string, workspaceID *string, slug, targetURL, customDomain, userPlan string, expiresAt *time.Time, utm *LinkCampaign) (*Link, error)
	GetActiveLinkBySlug(ctx context.Context, slug string) (*Link, error)
	RecordClickEvent(ctx context.Context, linkID, source string) error
	GetLinkAnalytics(ctx context.Context, linkID, userPlan string) (*AnalyticsSummary, error)
	GetUserActiveLinkCount(ctx context.Context, userID string) (int, error)
	IsSlugAvailable(ctx context.Context, slug string) bool
	GetLinkByID(ctx context.Context, linkID string) (*Link, error)
	GetExportAnalytics(ctx context.Context, linkID string, limit int) ([]ClickExportRow, error)
}

var (
	ErrMaliciousURL       = errors.New("MALICIOUS_URL_DETECTED")
	ErrCustomDomainPlan   = errors.New("custom domain is only available on Business plans")
	ErrLinkNotFound       = errors.New("shortlink not found")
	ErrLinkUnauthorized   = errors.New("unauthorized access to shortlink")
	ErrCSVPlan            = errors.New("CSV analytics export is only available on Pro or Business plans")
	ErrInvalidInput       = errors.New("invalid input")
	ErrWorkspaceForbidden = errors.New("you are not a member of this workspace")
)

var csvFormulaPrefixes = []string{"=", "+", "-", "@", "\t", "\r"}

func isAllowedTargetScheme(scheme string) bool {
	return scheme == "http" || scheme == "https"
}

func isHostBlacklisted(ctx context.Context, checker DomainBlacklistChecker, rawHost string) bool {
	host := security.NormalizeHostname(rawHost)
	if host == "" {
		return false
	}
	for {
		if checker.IsDomainBlacklisted(ctx, host) {
			return true
		}
		idx := strings.IndexByte(host, '.')
		if idx < 0 {
			return false
		}
		host = host[idx+1:]
	}
}

func sanitizeCSVField(value string) string {
	for _, prefix := range csvFormulaPrefixes {
		if strings.HasPrefix(value, prefix) {
			return "'" + value
		}
	}
	return value
}

type clickTask struct {
	linkID string
	source string
}

type Service struct {
	repo             linkRepository
	blacklistChecker DomainBlacklistChecker
	workspaceChecker WorkspaceMembershipChecker
	scanner          security.URLScanner
	clickChan        chan clickTask
}

func NewService(repo linkRepository, blacklistChecker DomainBlacklistChecker) *Service {
	s := &Service{
		repo:             repo,
		blacklistChecker: blacklistChecker,
		clickChan:        make(chan clickTask, clickChanBufferSize),
	}
	go s.startClickWorker()
	return s
}

func (s *Service) SetURLScanner(scanner security.URLScanner) { s.scanner = scanner }

func (s *Service) SetWorkspaceChecker(checker WorkspaceMembershipChecker) {
	s.workspaceChecker = checker
}

func (s *Service) startClickWorker() {
	for task := range s.clickChan {
		ctx, cancel := context.WithTimeout(context.Background(), clickWorkerTimeout)
		err := s.repo.RecordClickEvent(ctx, task.linkID, task.source)
		if err != nil {
			slog.Error("ClickWorker: failed to record click", slog.String("link_id", task.linkID), slog.String("error", err.Error()))
		}
		cancel()
	}
}

func generateRandomSlug(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:length]
}

func (s *Service) validateTargetURL(ctx context.Context, targetURL string) (*url.URL, error) {
	if targetURL == "" {
		return nil, fmt.Errorf("%w: target_url is required", ErrInvalidInput)
	}

	parsedURL, err := url.ParseRequestURI(targetURL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid target_url format", ErrInvalidInput)
	}
	if !isAllowedTargetScheme(parsedURL.Scheme) {
		return nil, fmt.Errorf("%w: invalid target_url scheme", ErrInvalidInput)
	}

	if s.scanner != nil {
		malicious, scanErr := s.scanner.CheckURL(ctx, targetURL)
		if scanErr != nil {
			return nil, errors.New("unable to scan target_url")
		}
		if malicious {
			return nil, ErrMaliciousURL
		}
	}

	if s.blacklistChecker != nil && isHostBlacklisted(ctx, s.blacklistChecker, parsedURL.Hostname()) {
		return nil, fmt.Errorf("%w: target_url domain is blacklisted and cannot be shortened", ErrInvalidInput)
	}

	return parsedURL, nil
}

func (s *Service) resolveSlug(ctx context.Context, user *auth.User, customAlias string) (string, error) {
	slug := strings.TrimSpace(customAlias)
	if slug != "" {
		if user.PlanCode == "FREE" {
			return "", fmt.Errorf("%w: custom alias is only available on Pro or Business plans", ErrInvalidInput)
		}
		if !s.repo.IsSlugAvailable(ctx, slug) {
			return "", fmt.Errorf("%w: custom alias is already taken", ErrInvalidInput)
		}
		return slug, nil
	}
	return generateRandomSlug(randomSlugLength), nil
}

func (s *Service) validatePlanFeatures(user *auth.User, req CreateLinkRequest) error {
	if req.CustomDomain != "" && user.PlanCode != "BUSINESS" {
		return ErrCustomDomainPlan
	}
	if req.ExpiresAt != nil && user.PlanCode == "FREE" {
		return fmt.Errorf("%w: expiry time is only available on Pro or Business plans", ErrInvalidInput)
	}
	return nil
}

func (s *Service) validateWorkspace(ctx context.Context, user *auth.User, workspaceID *string) error {
	if workspaceID == nil || *workspaceID == "" {
		return nil
	}
	if s.workspaceChecker == nil {
		return nil
	}
	if !s.workspaceChecker.IsMember(ctx, *workspaceID, user.ID) {
		return ErrWorkspaceForbidden
	}
	return nil
}

func (s *Service) CreateLink(ctx context.Context, user *auth.User, req CreateLinkRequest) (*Link, error) {
	if _, err := s.validateTargetURL(ctx, req.TargetURL); err != nil {
		return nil, err
	}

	if err := s.validatePlanFeatures(user, req); err != nil {
		return nil, err
	}

	if err := s.validateWorkspace(ctx, user, req.WorkspaceID); err != nil {
		return nil, err
	}

	slug, err := s.resolveSlug(ctx, user, req.CustomAlias)
	if err != nil {
		return nil, err
	}

	return s.repo.CreateLinkAtomic(ctx, user.ID, req.WorkspaceID, slug, req.TargetURL, req.CustomDomain, user.PlanCode, req.ExpiresAt, req.UTM)
}

func (s *Service) ResolveAndRecordRedirect(ctx context.Context, slug, source string) (string, error) {
	link, err := s.repo.GetActiveLinkBySlug(ctx, slug)
	if err != nil {
		return "", err
	}

	if s.isTargetBlocked(ctx, link.TargetURL) {
		return "", ErrMaliciousURL
	}

	select {
	case s.clickChan <- clickTask{linkID: link.ID, source: source}:
	default:
		slog.Warn("Click buffer full, dropping click event", slog.String("link_id", link.ID))
	}

	return link.TargetURL, nil
}

func (s *Service) GetAnalytics(ctx context.Context, user *auth.User, linkID string) (*AnalyticsSummary, error) {
	link, err := s.repo.GetLinkByID(ctx, linkID)
	if err != nil {
		return nil, err
	}
	if link.OwnerUserID != user.ID {
		return nil, ErrLinkUnauthorized
	}
	return s.repo.GetLinkAnalytics(ctx, linkID, user.PlanCode)
}

func (s *Service) isTargetBlocked(ctx context.Context, targetURL string) bool {
	if s.blacklistChecker == nil {
		return false
	}
	parsed, err := url.ParseRequestURI(targetURL)
	if err != nil {
		return true
	}
	if !isAllowedTargetScheme(parsed.Scheme) {
		return true
	}
	return s.blacklistChecker.IsDomainBlacklisted(ctx, security.NormalizeHostname(parsed.Hostname()))
}

func (s *Service) CheckDowngradeAllowed(ctx context.Context, userID, newPlan string) error {
	if newPlan == "FREE" {
		activeCount, err := s.repo.GetUserActiveLinkCount(ctx, userID)
		if err != nil {
			return fmt.Errorf("check downgrade: %w", err)
		}
		if activeCount > freeActiveLinkLimit {
			return fmt.Errorf("cannot downgrade to Free: you have more than %d active links. Please delete excess links first", freeActiveLinkLimit)
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
	pngBytes, err := qrcode.Encode(targetURL, qrcode.Medium, qrCodeSize)
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

	rows, err := s.repo.GetExportAnalytics(ctx, linkID, csvExportLimit)
	if err != nil {
		return nil, fmt.Errorf("export csv: %w", err)
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	_ = writer.Write([]string{"timestamp", "slug", "country", "referrer", "user_agent", "device"})

	for _, r := range rows {
		_ = writer.Write([]string{
			sanitizeCSVField(r.Timestamp),
			sanitizeCSVField(r.Slug),
			sanitizeCSVField(r.Country),
			sanitizeCSVField(r.Referrer),
			sanitizeCSVField(r.UserAgent),
			sanitizeCSVField(r.Device),
		})
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("export csv flush: %w", err)
	}

	return buf.Bytes(), nil
}
