package workspace

import (
	"time"
)

type Role string

const (
	RoleOwner  Role = "OWNER"
	RoleAdmin  Role = "ADMIN"
	RoleMember Role = "MEMBER"
)

type Workspace struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type WorkspaceMember struct {
	WorkspaceID string    `json:"workspace_id"`
	UserID      string    `json:"user_id"`
	UserEmail   string    `json:"user_email,omitempty"`
	Role        Role      `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}

type CreateWorkspaceRequest struct {
	Name string `json:"name"`
}

type AddMemberRequest struct {
	UserEmail string `json:"user_email"`
	Role      Role   `json:"role"`
}

type UpdateMemberRoleRequest struct {
	Role Role `json:"role"`
}
