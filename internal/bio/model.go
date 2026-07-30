package bio

import "time"

type Page struct {
	ID             string    `json:"id"`
	OwnerUserID    string    `json:"owner_user_id"`
	Title          string    `json:"title"`
	Slug           string    `json:"slug"`
	BioDescription string    `json:"bio_description"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type PageLink struct {
	LinkID       string `json:"link_id"`
	Slug         string `json:"slug"`
	ShortURL     string `json:"short_url"`
	DisplayOrder int    `json:"display_order"`
}

type PublicPage struct {
	Title          string     `json:"title"`
	Slug           string     `json:"slug"`
	BioDescription string     `json:"bio_description"`
	Links          []PageLink `json:"links"`
}

type CreatePageRequest struct {
	Title          string `json:"title"`
	Slug           string `json:"slug"`
	BioDescription string `json:"bio_description"`
}

type AddLinkRequest struct {
	LinkID       string `json:"link_id"`
	DisplayOrder int    `json:"display_order"`
}
