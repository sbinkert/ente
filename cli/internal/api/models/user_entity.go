package models

// EntityKey is the per-user, per-type key that encrypts user entities.
// It is itself encrypted with the account's master key (secretbox).
type EntityKey struct {
	UserID       int64  `json:"userID"`
	Type         string `json:"type"`
	EncryptedKey string `json:"encryptedKey"`
	Header       string `json:"header"`
	CreatedAt    int64  `json:"createdAt"`
}

// EntityData is a single encrypted user entity as returned by the server.
type EntityData struct {
	ID            string  `json:"id"`
	UserID        int64   `json:"userID"`
	Type          string  `json:"type"`
	EncryptedData *string `json:"encryptedData"`
	Header        *string `json:"header"`
	IsDeleted     bool    `json:"isDeleted"`
	CreatedAt     int64   `json:"createdAt"`
	UpdatedAt     int64   `json:"updatedAt"`
}
