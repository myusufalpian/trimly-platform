package auth

import (
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type countingMailSender struct {
	mu     sync.Mutex
	sent   int
	sentCh chan struct{}
}

func newCountingMailSender() *countingMailSender {
	return &countingMailSender{sentCh: make(chan struct{}, 10)}
}

func (m *countingMailSender) SendVerificationEmail(toEmail, token string) error {
	m.mu.Lock()
	m.sent++
	m.mu.Unlock()

	select {
	case m.sentCh <- struct{}{}:
	default:
	}
	return nil
}

func (m *countingMailSender) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sent
}

func TestStartEmailWorkerProcessesTask(t *testing.T) {
	mailer := newCountingMailSender()
	s := &Service{
		repo:       nil,
		mailSender: mailer,
		emailChan:  make(chan emailTask, 1),
		done:       make(chan struct{}),
	}
	s.wg.Add(1)
	go s.startEmailWorker()

	s.emailChan <- emailTask{email: "test@example.com", token: "tok-123"}

	select {
	case <-mailer.sentCh:
	case <-time.After(2 * time.Second):
		t.Fatal("email was not sent within deadline")
	}

	s.Shutdown()
}

func TestStartEmailWorkerDrainsOnShutdown(t *testing.T) {
	mailer := newCountingMailSender()
	s := &Service{
		repo:       nil,
		mailSender: mailer,
		emailChan:  make(chan emailTask, 3),
		done:       make(chan struct{}),
	}
	s.wg.Add(1)
	go s.startEmailWorker()

	s.emailChan <- emailTask{email: "a@test.com", token: "tok-1"}
	s.emailChan <- emailTask{email: "b@test.com", token: "tok-2"}
	s.emailChan <- emailTask{email: "c@test.com", token: "tok-3"}

	s.Shutdown()

	if mailer.count() != 3 {
		t.Errorf("expected 3 emails sent, got %d", mailer.count())
	}
}

func TestGenerateRandomToken(t *testing.T) {
	token, err := generateRandomToken(16)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
	expectedLen := 16 * 2
	if len(token) != expectedLen {
		t.Errorf("expected token length %d, got %d", expectedLen, len(token))
	}

	token2, err := generateRandomToken(16)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token == token2 {
		t.Error("expected different random tokens")
	}
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"User@Example.COM", "user@example.com"},
		{"  spaced@test.com  ", "spaced@test.com"},
		{"Mixed.Case@Test.com", "mixed.case@test.com"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeEmail(tt.input); got != tt.expected {
			t.Errorf("normalizeEmail(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestCanonicalEmail(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"user@example.com", "user@example.com", false},
		{"a@b.c", "a@b.c", false},
		{"John Doe <john@test.com>", "john@test.com", false},
		{"notanemail", "", true},
		{"", "", true},
		{"evil@x.com\r\nBcc:victim@y.com", "", true},
		{"evil@x.com Bcc:victim@y.com", "", true},
	}
	for _, tt := range tests {
		got, err := canonicalEmail(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("canonicalEmail(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.expected {
			t.Errorf("canonicalEmail(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSessionCookieFlags(t *testing.T) {
	c := sessionCookie("tok-123", 0, true)

	if c.Name != "session_token" {
		t.Errorf("expected cookie name session_token, got %q", c.Name)
	}
	if c.Value != "tok-123" {
		t.Errorf("expected cookie value tok-123, got %q", c.Value)
	}
	if !c.HttpOnly {
		t.Error("expected HttpOnly cookie")
	}
	if !c.Secure {
		t.Error("expected Secure cookie when secure is true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite Lax, got %v", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("expected Path /, got %q", c.Path)
	}
}

func TestSessionCookieInsecureWhenConfigured(t *testing.T) {
	c := sessionCookie("tok-123", 0, false)

	if c.Secure {
		t.Error("expected non-Secure cookie when secure is false (dev over HTTP)")
	}
}

func TestSessionCookieLogoutClearsToken(t *testing.T) {
	c := sessionCookie("", -1, true)

	if c.Value != "" {
		t.Errorf("expected empty cookie value, got %q", c.Value)
	}
	if c.MaxAge != -1 {
		t.Errorf("expected MaxAge -1, got %d", c.MaxAge)
	}
}

func TestIsDuplicateKeyError(t *testing.T) {
	uniqueViolation := &pgconn.PgError{Code: "23505"}

	if !isDuplicateKeyError(uniqueViolation) {
		t.Error("expected unique violation PgError to be detected as duplicate key")
	}

	if isDuplicateKeyError(&pgconn.PgError{Code: "22P02"}) {
		t.Error("did not expect invalid input syntax to be treated as duplicate key")
	}

	if isDuplicateKeyError(errors.New("connection refused")) {
		t.Error("did not expect generic error to be treated as duplicate key")
	}
}
