-- +goose Up
CREATE TABLE IF NOT EXISTS bio_pages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(100) NOT NULL,
    slug VARCHAR(50) UNIQUE NOT NULL,
    bio_description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bio_pages_slug ON bio_pages(slug);
CREATE INDEX IF NOT EXISTS idx_bio_pages_owner ON bio_pages(owner_user_id);

CREATE TABLE IF NOT EXISTS bio_page_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bio_page_id UUID NOT NULL REFERENCES bio_pages(id) ON DELETE CASCADE,
    link_id UUID NOT NULL REFERENCES links(id) ON DELETE CASCADE,
    display_order INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(bio_page_id, link_id)
);

CREATE INDEX IF NOT EXISTS idx_bio_page_links_page ON bio_page_links(bio_page_id, display_order ASC);

ALTER TABLE links ADD COLUMN IF NOT EXISTS custom_domain VARCHAR(255) DEFAULT NULL;
CREATE INDEX IF NOT EXISTS idx_links_custom_domain ON links(custom_domain) WHERE custom_domain IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_links_custom_domain;
ALTER TABLE links DROP COLUMN IF EXISTS custom_domain;
DROP TABLE IF EXISTS bio_page_links;
DROP TABLE IF EXISTS bio_pages;
