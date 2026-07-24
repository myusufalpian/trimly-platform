package auth

import (
	"time"
)

type User struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	PasswordHash    string     `json:"-"`
	EmailVerifiedAt *time.Time `json:"email_verified_at"`
	PlanCode        string     `json:"plan_code"`
	IsPlatformAdmin bool       `json:"is_platform_admin"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TokenHash string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type VerificationToken struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	TokenDigest string     `json:"-"`
	ExpiresAt   time.Time  `json:"expires_at"`
	ConsumedAt  *time.Time `json:"consumed_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type VerifyEmailRequest struct {
	Token string `json:"token"`
}

type AuthResponse struct {
	User    *User  `json:"user,omitempty"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}
