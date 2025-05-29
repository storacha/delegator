package models

import "time"

// OnboardingSession tracks multi-step onboarding progress
type OnboardingSession struct {
	SessionID       string    `json:"session_id" db:"session_id"`
	DID             string    `json:"did" db:"did"`
	Status          string    `json:"status" db:"status"`
	DelegationData  string    `json:"delegation_data,omitempty" db:"delegation_data"`
	FQDN            string    `json:"fqdn,omitempty" db:"fqdn"`
	Proof           string    `json:"proof,omitempty" db:"proof"`
	FilecoinAddress string    `json:"filecoin_address,omitempty" db:"filecoin_address"`
	ProofSetID      uint64    `json:"proof_set_id,omitempty" db:"proof_set_id"`
	OperatorEmail   string    `json:"operator_email,omitempty" db:"operator_email"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
	ExpiresAt       time.Time `json:"expires_at" db:"expires_at"`
}

// OnboardingSession status constants
const (
	StatusStarted       = "started"
	StatusDIDVerified   = "did_verified"
	StatusFQDNVerified  = "fqdn_verified"
	StatusProofVerified = "proof_verified"
	StatusCompleted     = "completed"
	StatusExpired       = "expired"
)

// DIDAllowlist manages allowed DIDs for WSP onboarding
type DIDAllowlist struct {
	DID     string    `json:"did" db:"did"`
	AddedBy string    `json:"added_by" db:"added_by"`
	AddedAt time.Time `json:"added_at" db:"added_at"`
	Notes   string    `json:"notes,omitempty" db:"notes"`
}

// StorageProvider represents the main provider table
type StorageProvider struct {
	Provider   string    `json:"provider" db:"provider"`
	Endpoint   string    `json:"endpoint" db:"endpoint"`
	Proof      string    `json:"proof" db:"proof"`
	Weight     int       `json:"weight" db:"weight"`
	InsertedAt time.Time `json:"inserted_at" db:"inserted_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}

// StorageProviderInfo represents the provider metadata table
type StorageProviderInfo struct {
	// Provider is the did:key of the storage node.
	Provider string `json:"provider" db:"provider"`
	// Endpoint is the domain the storage node is reachable at.
	Endpoint string `json:"endpoint" db:"endpoint"`
	// Address is the ethereum address the storage node uses to submit proofs.
	Address string `json:"address" db:"address"`
	// ProofSet is the proof set ID the storage node will use.
	ProofSet uint64 `json:"proof_set" db:"proof_set"`
	// OperatorEmail is the email address of the storage nodes operator.
	OperatorEmail string `json:"operator_email" db:"operator_email"`
	// Proof is a delegation allowing the upload service to send invocations to the storage node.
	Proof string `json:"proof" db:"proof"`
	// InsertedAt is the time this record was created.
	InsertedAt time.Time `json:"inserted_at" db:"inserted_at"`
	// UpdatedAt is the time this record was last modified.
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// DIDRegisterRequest represents the request for DID verification
type DIDRegisterRequest struct {
	DID             string `json:"did" validate:"required"`
	FilecoinAddress string `json:"filecoin_address" validate:"required"`
	ProofSetID      uint64 `json:"proof_set_id" validate:"required"`
	OperatorEmail   string `json:"operator_email" validate:"required"`
}

type FQDNRegisterRequest struct {
	SessionID string `json:"session_id" validate:"required"`
	URL       string `json:"url" validate:"required"`
}

type ProofRegisterRequest struct {
	SessionID string `json:"session_id" validate:"required"`
	Proof     string `json:"proof" validate:"required"`
}

// DIDVerifyResponse represents the response for DID verification
type DIDVerifyResponse struct {
	SessionID       string `json:"session_id"`
	DelegationURL   string `json:"delegation_url"`
	FilecoinAddress string `json:"filecoin_address"`
	ProofSetID      uint64 `json:"proof_set_id"`
	OperatorEmail   string `json:"operator_email"`
}

// FQDNVerifyResponse represents the response for FQDN verification
type FQDNVerifyResponse struct {
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
	FQDN      string `json:"fqdn"`
}

// ProofVerifyResponse represents the response for proof verification
type ProofVerifyResponse struct {
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
}

// OnboardingStatusResponse represents the status of an onboarding session
type OnboardingStatusResponse struct {
	SessionID       string `json:"session_id"`
	DID             string `json:"did"`
	Status          string `json:"status"`
	FilecoinAddress string `json:"filecoin_address,omitempty"`
	ProofSetID      uint64 `json:"proof_set_id,omitempty"`
	OperatorEmail   string `json:"operator_email,omitempty"`
	CreatedAt       string `json:"created_at"`
	ExpiresAt       string `json:"expires_at"`
	NextStep        string `json:"next_step,omitempty"`
}
