package types

import (
	"github.com/google/uuid"
)

// OTPCredentials ...
type OTPCredentials struct {
	UserID        uuid.UUID `json:"userID,omitempty"`
	TokenValidity int       `json:"validity,omitempty"`
	Token         string    `json:"token"`
	EmailAddress  string    `json:"email"`
}
