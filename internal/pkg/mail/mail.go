package mail

import (
	"fmt"
	"log"
	"net/smtp"
)

type EmailSender interface {
	SendVerificationEmail(toEmail, token string) error
}

type MailHogAdapter struct {
	smtpHost string
	smtpPort string
}

func NewMailHogAdapter(host, port string) *MailHogAdapter {
	return &MailHogAdapter{
		smtpHost: host,
		smtpPort: port,
	}
}

func (m *MailHogAdapter) SendVerificationEmail(toEmail, token string) error {
	from := "noreply@trimly.app"
	subject := "Verify your Trimly Account"
	body := fmt.Sprintf("Welcome to Trimly!\n\nPlease verify your email using token: %s", token)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", from, toEmail, subject, body)
	addr := fmt.Sprintf("%s:%s", m.smtpHost, m.smtpPort)

	// MailHog does not require authentication
	err := smtp.SendMail(addr, nil, from, []string{toEmail}, []byte(msg))
	if err != nil {
		log.Printf("[MailHogAdapter] Error sending verification email to %s: %v", toEmail, err)
		return err
	}

	log.Printf("[MailHogAdapter] Verification email sent to %s via MailHog", toEmail)
	return nil
}
