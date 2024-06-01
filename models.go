package apikeys

type APIKeyInfo struct {
	UserID   string         `json:"user_id"`
	OrgID    string         `json:"org_id"`
	Name     string         `json:"name"`
	Email    string         `json:"email"`
	Metadata map[string]any `json:"metadata"`
}
