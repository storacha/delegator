package models

import "time"

// Provider represents a Warm Storage Provider in the system
type Provider struct {
	ID              string    `json:"id" db:"id"`
	DID             string    `json:"did" db:"did"`
	FQDN            string    `json:"fqdn" db:"fqdn"`
	FilecoinAddress string    `json:"filecoin_address" db:"filecoin_address"`
	ProofSetID      string    `json:"proof_set_id" db:"proof_set_id"`
	Weight          int       `json:"weight" db:"weight"`
	Status          string    `json:"status" db:"status"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

// ProviderStatus constants
const (
	StatusPending   = "pending"
	StatusVerified  = "verified"
	StatusActive    = "active"
	StatusSuspended = "suspended"
)

// OnboardingRequest represents a provider onboarding request
type OnboardingRequest struct {
	DID             string `json:"did" validate:"required"`
	FQDN            string `json:"fqdn" validate:"required"`
	FilecoinAddress string `json:"filecoin_address" validate:"required"`
	ProofSetID      string `json:"proof_set_id" validate:"required"`
}

// DelegationResponse represents a delegation response
type DelegationResponse struct {
	Delegation string `json:"delegation"`
	Proof      string `json:"proof"`
	ExpiresAt  string `json:"expires_at"`
}
