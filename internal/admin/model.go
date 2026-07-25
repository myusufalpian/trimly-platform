package admin

import (
	"time"
)

type BlacklistDomain struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Reason    string    `json:"reason,omitempty"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

type AddBlacklistRequest struct {
	Domain string `json:"domain"`
	Reason string `json:"reason,omitempty"`
}

type UnflagClickRequest struct {
	ClickID string `json:"click_id"`
}
