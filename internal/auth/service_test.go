package auth_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"trimly-platform/internal/auth"

	"golang.org/x/crypto/bcrypt"
)

type stubAuthRepo struct {
	createdEmail     string
	createErr        error
	lookupEmail      string
	userByEmail      *auth.User
	userByEmailErr   error
	createSessionErr error
	revokedToken     string
	revokeErr        error
	verificationErr  error
}

func (s *stubAuthRepo) CreateUserWithPlan(ctx context.Context, email, passwordHash string) (*auth.User, error) {
	s.createdEmail = email
	if s.createErr != nil {
		return nil, s.createErr
	}
	return &auth.User{ID: "user-1", Email: email, PasswordHash: passwordHash, PlanCode: "FREE"}, nil
}

func (s *stubAuthRepo) SaveVerificationToken(ctx context.Context, userID, rawToken string, expiresAt time.Time) error {
	return nil
}

func (s *stubAuthRepo) VerifyEmailToken(ctx context.Context, rawToken string) error {
	return s.verificationErr
}

func (s *stubAuthRepo) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	s.lookupEmail = email
	return s.userByEmail, s.userByEmailErr
}

func (s *stubAuthRepo) CreateSession(ctx context.Context, userID, rawToken string, expiresAt time.Time) error {
	return s.createSessionErr
}

func (s *stubAuthRepo) RevokeSession(ctx context.Context, rawToken string) error {
	s.revokedToken = rawToken
	return s.revokeErr
}

func (s *stubAuthRepo) GetSessionUser(ctx context.Context, rawToken string) (*auth.User, error) {
	if rawToken == "valid-token" {
		return &auth.User{ID: "user-1", Email: "user@test.com", PlanCode: "FREE"}, nil
	}
	return nil, errors.New("invalid session")
}

type stubMailSender struct {
	sentTo    string
	sentToken string
}

func (m *stubMailSender) SendVerificationEmail(toEmail, token string) error {
	m.sentTo = toEmail
	m.sentToken = token
	return nil
}

func newTestService(repo *stubAuthRepo) (*auth.Service, *stubMailSender) {
	mailer := &stubMailSender{}
	return auth.NewService(repo, mailer), mailer
}

func TestRegisterNormalizesEmail(t *testing.T) {
	repo := &stubAuthRepo{}
	svc, _ := newTestService(repo)

	user, err := svc.Register(context.Background(), auth.RegisterRequest{Email: "  User@Test.COM  ", Password: "Password123"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.createdEmail != "user@test.com" {
		t.Errorf("expected normalized email user@test.com, got %q", repo.createdEmail)
	}
	if user.Email != "user@test.com" {
		t.Errorf("expected user email normalized, got %q", user.Email)
	}
}

func TestRegisterEmailTaken(t *testing.T) {
	repo := &stubAuthRepo{createErr: auth.ErrEmailTaken}
	svc, _ := newTestService(repo)

	_, err := svc.Register(context.Background(), auth.RegisterRequest{Email: "taken@test.com", Password: "Password123"})
	if !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("expected ErrEmailTaken, got %v", err)
	}
}

func TestRegisterEmptyInput(t *testing.T) {
	svc, _ := newTestService(&stubAuthRepo{})

	if _, err := svc.Register(context.Background(), auth.RegisterRequest{Email: "", Password: "Password123"}); err == nil {
		t.Fatal("expected error for empty email")
	}
	if _, err := svc.Register(context.Background(), auth.RegisterRequest{Email: "a@b.c", Password: ""}); err == nil {
		t.Fatal("expected error for empty password")
	}
	if _, err := svc.Register(context.Background(), auth.RegisterRequest{Email: "a@b.c", Password: "short"}); err == nil {
		t.Fatal("expected error for short password")
	}
}

func TestRegisterRejectsInvalidEmail(t *testing.T) {
	svc, _ := newTestService(&stubAuthRepo{})

	for _, email := range []string{"notanemail", "evil@x.com\r\nBcc:victim@y.com"} {
		_, err := svc.Register(context.Background(), auth.RegisterRequest{Email: email, Password: "Password123"})
		if !errors.Is(err, auth.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput for email %q, got %v", email, err)
		}
	}
}

func TestRegisterRejectsOversizedPassword(t *testing.T) {
	svc, _ := newTestService(&stubAuthRepo{})

	long := strings.Repeat("a", 73)
	_, err := svc.Register(context.Background(), auth.RegisterRequest{Email: "a@b.c", Password: long})
	if !errors.Is(err, auth.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for oversized password, got %v", err)
	}
}

func TestRegisterCanonicalizesDisplayNameEmail(t *testing.T) {
	repo := &stubAuthRepo{}
	svc, _ := newTestService(repo)

	_, err := svc.Register(context.Background(), auth.RegisterRequest{Email: "John Doe <John@Test.COM>", Password: "Password123"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.createdEmail != "john@test.com" {
		t.Errorf("expected canonical email john@test.com, got %q", repo.createdEmail)
	}
}

func TestLoginNormalizesEmailAndCreatesSession(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("failed to hash test password: %v", err)
	}
	repo := &stubAuthRepo{
		userByEmail: &auth.User{ID: "user-1", Email: "user@test.com", PasswordHash: string(hash)},
	}
	svc, _ := newTestService(repo)

	token, user, err := svc.Login(context.Background(), auth.LoginRequest{Email: "  USER@TEST.COM  ", Password: "Password123"})
	if err != nil {
		t.Fatalf("expected successful login, got %v", err)
	}
	if repo.lookupEmail != "user@test.com" {
		t.Errorf("expected normalized email lookup, got %q", repo.lookupEmail)
	}
	if token == "" {
		t.Error("expected a session token")
	}
	if user.ID != "user-1" {
		t.Errorf("expected logged-in user, got %q", user.ID)
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	t.Run("Unknown email", func(t *testing.T) {
		repo := &stubAuthRepo{userByEmailErr: context.DeadlineExceeded}
		svc, _ := newTestService(repo)

		_, _, err := svc.Login(context.Background(), auth.LoginRequest{Email: "nobody@test.com", Password: "Password123"})
		if err == nil || err.Error() != "invalid email or password" {
			t.Fatalf("expected generic invalid credentials, got %v", err)
		}
	})

	t.Run("Wrong password", func(t *testing.T) {
		hash, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.MinCost)
		repo := &stubAuthRepo{userByEmail: &auth.User{ID: "user-1", PasswordHash: string(hash)}}
		svc, _ := newTestService(repo)

		_, _, err := svc.Login(context.Background(), auth.LoginRequest{Email: "user@test.com", Password: "WrongPassword"})
		if err == nil || err.Error() != "invalid email or password" {
			t.Fatalf("expected generic invalid credentials, got %v", err)
		}
	})
}

func TestValidationErrorsAreErrInvalidInput(t *testing.T) {
	svc, _ := newTestService(&stubAuthRepo{})

	t.Run("Register short password", func(t *testing.T) {
		_, err := svc.Register(context.Background(), auth.RegisterRequest{Email: "a@b.c", Password: "short"})
		if !errors.Is(err, auth.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput, got %v", err)
		}
	})
	t.Run("Login empty email", func(t *testing.T) {
		_, _, err := svc.Login(context.Background(), auth.LoginRequest{Email: "", Password: "Password123"})
		if !errors.Is(err, auth.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput, got %v", err)
		}
	})
	t.Run("VerifyEmail empty token", func(t *testing.T) {
		err := svc.VerifyEmail(context.Background(), auth.VerifyEmailRequest{Token: ""})
		if !errors.Is(err, auth.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput, got %v", err)
		}
	})
}

func TestLoginEmptyInput(t *testing.T) {
	svc, _ := newTestService(&stubAuthRepo{})

	if _, _, err := svc.Login(context.Background(), auth.LoginRequest{Email: "", Password: "Password123"}); err == nil {
		t.Fatal("expected error for empty email")
	}
	if _, _, err := svc.Login(context.Background(), auth.LoginRequest{Email: "a@b.c", Password: ""}); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestLoginSessionCreationError(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.MinCost)
	repo := &stubAuthRepo{
		userByEmail:      &auth.User{ID: "user-1", PasswordHash: string(hash)},
		createSessionErr: context.Canceled,
	}
	svc, _ := newTestService(repo)

	_, _, err := svc.Login(context.Background(), auth.LoginRequest{Email: "user@test.com", Password: "Password123"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected session creation error to propagate, got %v", err)
	}
}

func TestVerifyEmailEmptyToken(t *testing.T) {
	repo := &stubAuthRepo{}
	svc, _ := newTestService(repo)

	err := svc.VerifyEmail(context.Background(), auth.VerifyEmailRequest{Token: ""})
	if err == nil {
		t.Fatal("expected error for empty verification token")
	}
}

func TestVerifyEmailSuccess(t *testing.T) {
	repo := &stubAuthRepo{}
	svc, _ := newTestService(repo)

	err := svc.VerifyEmail(context.Background(), auth.VerifyEmailRequest{Token: "valid-token"})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestVerifyEmailPropagatesRepoError(t *testing.T) {
	repo := &stubAuthRepo{verificationErr: context.Canceled}
	svc, _ := newTestService(repo)

	err := svc.VerifyEmail(context.Background(), auth.VerifyEmailRequest{Token: "tok"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected repo error to propagate, got %v", err)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	repo := &stubAuthRepo{}
	svc, _ := newTestService(repo)

	if err := svc.Logout(context.Background(), "session-tok"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.revokedToken != "session-tok" {
		t.Errorf("expected session token to be revoked, got %q", repo.revokedToken)
	}
}

func TestLogoutEmptyToken(t *testing.T) {
	repo := &stubAuthRepo{}
	svc, _ := newTestService(repo)

	err := svc.Logout(context.Background(), "")
	if err != nil {
		t.Errorf("expected no error for empty token, got %v", err)
	}
}

func TestLogoutDatabaseError(t *testing.T) {
	repo := &stubAuthRepo{revokeErr: errors.New("database error")}
	svc, _ := newTestService(repo)

	err := svc.Logout(context.Background(), "session-tok")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestGetUserFromSession(t *testing.T) {
	svc, _ := newTestService(&stubAuthRepo{})

	t.Run("valid session", func(t *testing.T) {
		user, err := svc.GetUserFromSession(context.Background(), "valid-token")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if user.ID != "user-1" {
			t.Errorf("expected user-1, got %q", user.ID)
		}
	})

	t.Run("empty token", func(t *testing.T) {
		_, err := svc.GetUserFromSession(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty token")
		}
	})

	t.Run("invalid session", func(t *testing.T) {
		_, err := svc.GetUserFromSession(context.Background(), "bad-token")
		if err == nil {
			t.Fatal("expected error for invalid session")
		}
	})
}

type trackingMailSender struct {
	sync.Mutex
	sentEmails []string
}

func (m *trackingMailSender) SendVerificationEmail(toEmail, token string) error {
	m.Lock()
	defer m.Unlock()
	m.sentEmails = append(m.sentEmails, toEmail)
	return nil
}

func (m *trackingMailSender) count() int {
	m.Lock()
	defer m.Unlock()
	return len(m.sentEmails)
}

func TestShutdownDrainsEmailQueue(t *testing.T) {
	mailer := &trackingMailSender{}
	svc := auth.NewService(&stubAuthRepo{}, mailer)

	for i := 0; i < 5; i++ {
		_, _ = svc.Register(context.Background(), auth.RegisterRequest{
			Email:    fmt.Sprintf("user%d@test.com", i),
			Password: "Password123",
		})
	}

	svc.Shutdown()

	if mailer.count() != 5 {
		t.Errorf("expected 5 emails sent after shutdown, got %d", mailer.count())
	}
}
