package bio

import (
	"context"
	"testing"

	"trimly-platform/internal/auth"
)

type mockRepo struct {
	count int
	page  *Page
}

func (m *mockRepo) CreatePage(context.Context, string, CreatePageRequest) (*Page, error) {
	return m.page, nil
}
func (m *mockRepo) CreateFreePage(context.Context, string, CreatePageRequest) (*Page, error) {
	if m.count >= 1 {
		return nil, ErrFreePageLimit
	}
	return m.page, nil
}
func (m *mockRepo) GetPage(context.Context, string) (*Page, error) { return m.page, nil }
func (m *mockRepo) AddLink(context.Context, string, string, int, string) error {
	return nil
}
func (m *mockRepo) GetPublicPage(context.Context, string, string) (*PublicPage, error) {
	return &PublicPage{}, nil
}

func TestFreePlanBioPageLimit(t *testing.T) {
	svc := NewService(&mockRepo{count: 1})
	_, err := svc.CreatePage(context.Background(), &auth.User{ID: "u1", PlanCode: "FREE"}, CreatePageRequest{Title: "Me", Slug: "me"})
	if err == nil {
		t.Fatal("expected Free plan limit error")
	}
}

func TestBioPageSlugValidation(t *testing.T) {
	svc := NewService(&mockRepo{})
	_, err := svc.CreatePage(context.Background(), &auth.User{ID: "u1", PlanCode: "PRO"}, CreatePageRequest{Title: "Me", Slug: "Not Valid"})
	if err == nil {
		t.Fatal("expected slug validation error")
	}
}
