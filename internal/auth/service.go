package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"trimly-platform/internal/pkg/mail"

	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	repo       *Repository
	mailSender mail.EmailSender
	emailChan  chan emailTask
}

type emailTask struct {
	email string
	token string
}

func NewService(repo *Repository, mailSender mail.EmailSender) *Service {
	s := &Service{
		repo:       repo,
		mailSender: mailSender,
		emailChan:  make(chan emailTask, 100),
	}
	go s.startEmailWorker()
	return s
}

func (s *Service) startEmailWorker() {
	for task := range s.emailChan {
		_ = s.mailSender.SendVerificationEmail(task.email, task.token)
	}
}

func generateRandomToken(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Service) Register(ctx context.Context, req RegisterRequest) (*User, error) {
	if req.Email == "" || req.Password == "" {
		return nil, errors.New("email and password are required")
	}

	if len(req.Password) < 8 {
		return nil, errors.New("password must be at least 8 characters long")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user, err := s.repo.CreateUserWithPlan(ctx, req.Email, string(hashedPassword))
	if err != nil {
		return nil, err
	}

	rawToken, err := generateRandomToken(16)
	if err == nil {
		expiresAt := time.Now().Add(24 * time.Hour)
		_ = s.repo.SaveVerificationToken(ctx, user.ID, rawToken, expiresAt)

		// Dispatch async verification email (Non-blocking)
		select {
		case s.emailChan <- emailTask{email: user.Email, token: rawToken}:
		default:
			// Buffer full, fallback log/drop
		}
	}

	return user, nil
}

func (s *Service) VerifyEmail(ctx context.Context, req VerifyEmailRequest) error {
	if req.Token == "" {
		return errors.New("verification token is required")
	}
	return s.repo.VerifyEmailToken(ctx, req.Token)
}

func (s *Service) Login(ctx context.Context, req LoginRequest) (string, *User, error) {
	if req.Email == "" || req.Password == "" {
		return "", nil, errors.New("email and password are required")
	}

	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return "", nil, errors.New("invalid email or password")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		return "", nil, errors.New("invalid email or password")
	}

	sessionToken, err := generateRandomToken(32)
	if err != nil {
		return "", nil, err
	}

	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	err = s.repo.CreateSession(ctx, user.ID, sessionToken, expiresAt)
	if err != nil {
		return "", nil, err
	}

	return sessionToken, user, nil
}

func (s *Service) Logout(ctx context.Context, sessionToken string) error {
	if sessionToken == "" {
		return nil
	}
	return s.repo.RevokeSession(ctx, sessionToken)
}

func (s *Service) GetUserFromSession(ctx context.Context, sessionToken string) (*User, error) {
	if sessionToken == "" {
		return nil, errors.New("unauthenticated")
	}
	return s.repo.GetSessionUser(ctx, sessionToken)
}
