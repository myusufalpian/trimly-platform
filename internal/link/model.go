package link

import (
	"time"
)

type LinkStatus string

const (
	StatusActive   LinkStatus = "ACTIVE"
	StatusInactive LinkStatus = "INACTIVE"
)

type Link struct {
	ID          string        `json:"id"`
	OwnerUserID string        `json:"owner_user_id"`
	WorkspaceID *string       `json:"workspace_id,omitempty"`
	Slug        string        `json:"slug"`
	TargetURL   string        `json:"target_url"`
	Status      LinkStatus    `json:"status"`
	ExpiresAt   *time.Time    `json:"expires_at,omitempty"`
	UTMCampaign *LinkCampaign `json:"utm_campaign,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

type LinkCampaign struct {
	UTMSource   string `json:"utm_source,omitempty"`
	UTMMedium   string `json:"utm_medium,omitempty"`
	UTMCampaign string `json:"utm_campaign,omitempty"`
	UTMTerm     string `json:"utm_term,omitempty"`
	UTMContent  string `json:"utm_content,omitempty"`
}

type ClickEvent struct {
	ID        string    `json:"id"`
	LinkID    string    `json:"link_id"`
	Source    string    `json:"source"`
	ClickedAt time.Time `json:"clicked_at"`
	IPSubnet  string    `json:"ip_subnet,omitempty"`
}

type CreateLinkRequest struct {
	TargetURL   string        `json:"target_url"`
	CustomAlias string        `json:"custom_alias,omitempty"`
	WorkspaceID *string       `json:"workspace_id,omitempty"`
	ExpiresAt   *time.Time    `json:"expires_at,omitempty"`
	UTM         *LinkCampaign `json:"utm,omitempty"`
}

type AnalyticsSummary struct {
	TotalClicks       int                    `json:"total_clicks"`
	DailyClicks       []DailyClickPoint      `json:"daily_clicks"`
	CampaignBreakdown []CampaignBreakdownRow `json:"campaign_breakdown,omitempty"`
}

type DailyClickPoint struct {
	Date       string `json:"date"`
	ClickCount int    `json:"click_count"`
}

type CampaignBreakdownRow struct {
	UTMSource   string `json:"utm_source"`
	UTMCampaign string `json:"utm_campaign"`
	ClickCount  int    `json:"click_count"`
}
