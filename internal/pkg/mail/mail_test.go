package mail

import (
	"errors"
	"net/smtp"
	"strings"
	"testing"
)

func TestNewMailHogAdapter(t *testing.T) {
	adapter := NewMailHogAdapter("localhost", "1025")
	if adapter == nil {
		t.Fatal("expected adapter, got nil")
	}
	if adapter.smtpHost != "localhost" {
		t.Errorf("expected host localhost, got %q", adapter.smtpHost)
	}
	if adapter.smtpPort != "1025" {
		t.Errorf("expected port 1025, got %q", adapter.smtpPort)
	}
}

func TestSendVerificationEmailSuccess(t *testing.T) {
	var capturedAddr string
	var capturedAuth smtp.Auth
	var capturedFrom string
	var capturedTo []string
	var capturedMsg []byte

	origSendMail := sendMail
	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedAddr = addr
		capturedAuth = a
		capturedFrom = from
		capturedTo = to
		capturedMsg = msg
		return nil
	}
	defer func() { sendMail = origSendMail }()

	adapter := NewMailHogAdapter("localhost", "1025")
	err := adapter.SendVerificationEmail("test@example.com", "tok-123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if capturedAddr != "localhost:1025" {
		t.Errorf("expected addr localhost:1025, got %q", capturedAddr)
	}
	if capturedAuth != nil {
		t.Errorf("expected nil auth for MailHog, got %v", capturedAuth)
	}
	if capturedFrom != "noreply@trimly.app" {
		t.Errorf("expected from noreply@trimly.app, got %q", capturedFrom)
	}
	if len(capturedTo) != 1 || capturedTo[0] != "test@example.com" {
		t.Errorf("expected to [test@example.com], got %v", capturedTo)
	}

	msg := string(capturedMsg)
	for _, want := range []string{"From: noreply@trimly.app", "To: test@example.com", "Subject: Verify your Trimly Account", "tok-123"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q, got %q", want, msg)
		}
	}
}

func TestSendVerificationEmailFailure(t *testing.T) {
	origSendMail := sendMail
	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		return errors.New("smtp connection refused")
	}
	defer func() { sendMail = origSendMail }()

	adapter := NewMailHogAdapter("127.0.0.1", "1")
	err := adapter.SendVerificationEmail("test@example.com", "tok-123")
	if err == nil {
		t.Error("expected error, got nil")
	}
}
