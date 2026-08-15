package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	netmail "net/mail"
	"strings"
	"sync"
	"time"

	"trimly-platform/internal/pkg/mail"

	"golang.org/x/crypto/bcrypt"
)

type authRepository interface {
	CreateUserWithPlan(ctx context.Context, email, passwordHash string) (*User, error)
	SaveVerificationToken(ctx context.Context, userID, rawToken string, expiresAt time.Time) error
	VerifyEmailToken(ctx context.Context, rawToken string) error
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	CreateSession(ctx context.Context, userID, rawToken string, expiresAt time.Time) error
	RevokeSession(ctx context.Context, rawToken string) error
	GetSessionUser(ctx context.Context, rawToken string) (*User, error)
}

type Service struct {
	repo       authRepository
	mailSender mail.EmailSender
	emailChan  chan emailTask
	done       chan struct{}
	wg         sync.WaitGroup
}

type emailTask struct {
	email string
	token string
}

const (
	emailChanBufferSize = 100
	verificationExpiry  = 24 * time.Hour
	sessionExpiry       = 7 * 24 * time.Hour
	tokenBytesLen       = 16
	sessionTokenBytes   = 32
)

func NewService(repo authRepository, mailSender mail.EmailSender) *Service {
	s := &Service{
		repo:       repo,
		mailSender: mailSender,
		emailChan:  make(chan emailTask, emailChanBufferSize),
		done:       make(chan struct{}),
	}
	s.wg.Add(1)
	go s.startEmailWorker()
	return s
}

func (s *Service) startEmailWorker() {
	defer s.wg.Done()
	for {
		select {
		case task, ok := <-s.emailChan:
			if !ok {
				return
			}
			_ = s.mailSender.SendVerificationEmail(task.email, task.token)
		case <-s.done:
			for task := range s.emailChan {
				_ = s.mailSender.SendVerificationEmail(task.email, task.token)
			}
			return
		}
	}
}

func (s *Service) Shutdown() {
	close(s.done)
	close(s.emailChan)
	s.wg.Wait()
}

func generateRandomToken(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var ErrInvalidInput = errors.New("invalid input")

type inputError struct{ msg string }

func (e *inputError) Error() string { return e.msg }

func (e *inputError) Is(target error) bool { return target == ErrInvalidInput }

func invalidInput(msg string) error { return &inputError{msg: msg} }

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func canonicalEmail(email string) (string, error) {
	addr, err := netmail.ParseAddress(email)
	if err != nil || addr.Address == "" {
		return "", errors.New("invalid email format")
	}
	return addr.Address, nil
}

func (s *Service) Register(ctx context.Context, req RegisterRequest) (*User, error) {
	normalized := normalizeEmail(req.Email)
	if normalized == "" || req.Password == "" {
		return nil, invalidInput("email and password are required")
	}

	email, err := canonicalEmail(normalized)
	if err != nil {
		return nil, invalidInput("invalid email format")
	}

	if len(req.Password) < 8 {
		return nil, invalidInput("password must be at least 8 characters long")
	}

	if len(req.Password) > 72 {
		return nil, invalidInput("password must not exceed 72 characters")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("register: hash password: %w", err)
	}

	user, err := s.repo.CreateUserWithPlan(ctx, email, string(hashedPassword))
	if err != nil {
		return nil, fmt.Errorf("register: create user: %w", err)
	}

	rawToken, err := generateRandomToken(tokenBytesLen)
	if err == nil {
		expiresAt := time.Now().Add(verificationExpiry)
		_ = s.repo.SaveVerificationToken(ctx, user.ID, rawToken, expiresAt)

		select {
		case s.emailChan <- emailTask{email: user.Email, token: rawToken}:
		default:
		}
	}

	return user, nil
}

func (s *Service) VerifyEmail(ctx context.Context, req VerifyEmailRequest) error {
	if req.Token == "" {
		return invalidInput("verification token is required")
	}
	if err := s.repo.VerifyEmailToken(ctx, req.Token); err != nil {
		return fmt.Errorf("verify email: %w", err)
	}
	return nil
}

func (s *Service) Login(ctx context.Context, req LoginRequest) (string, *User, error) {
	email := normalizeEmail(req.Email)
	if email == "" || req.Password == "" {
		return "", nil, invalidInput("email and password are required")
	}

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return "", nil, errors.New("invalid email or password")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		return "", nil, errors.New("invalid email or password")
	}

	sessionToken, err := generateRandomToken(sessionTokenBytes)
	if err != nil {
		return "", nil, fmt.Errorf("login: generate token: %w", err)
	}

	expiresAt := time.Now().Add(sessionExpiry)
	err = s.repo.CreateSession(ctx, user.ID, sessionToken, expiresAt)
	if err != nil {
		return "", nil, fmt.Errorf("login: create session: %w", err)
	}

	return sessionToken, user, nil
}

func (s *Service) Logout(ctx context.Context, sessionToken string) error {
	if sessionToken == "" {
		return nil
	}
	if err := s.repo.RevokeSession(ctx, sessionToken); err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	return nil
}

func (s *Service) GetUserFromSession(ctx context.Context, sessionToken string) (*User, error) {
	if sessionToken == "" {
		return nil, errors.New("unauthenticated")
	}
	user, err := s.repo.GetSessionUser(ctx, sessionToken)
	if err != nil {
		return nil, fmt.Errorf("get session user: %w", err)
	}
	return user, nil
}
