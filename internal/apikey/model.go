package apikey

import (
	"time"
)

type APIKey struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	KeyPrefix string     `json:"key_prefix"`
	KeyHash   string     `json:"-"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type APIKeyResponse struct {
	ID        string    `json:"id"`
	KeyPrefix string    `json:"key_prefix"`
	APIKey    string    `json:"api_key,omitempty"` // Only returned once on creation
	CreatedAt time.Time `json:"created_at"`
}

type APIUsageDaily struct {
	APIKeyID             string `json:"api_key_id"`
	Date                 string `json:"date"`
	AcceptedRequestCount int    `json:"accepted_request_count"`
}
