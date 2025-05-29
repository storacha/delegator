package storage

import "github.com/storacha/delegator/internal/models"

type PersistentStore interface {
	IsAllowedDID(did string) (bool, error)
	IsRegisteredDID(did string) (bool, error)
	RegisterProvider(provider *models.StorageProviderInfo) error
}

// SessionStore combines all storage interfaces
type SessionStore interface {
	CreateSession(session *models.OnboardingSession) error
	GetSession(sessionID string) (*models.OnboardingSession, error)
	UpdateSession(session *models.OnboardingSession) error
	GetSessionByDID(did string) (*models.OnboardingSession, error)
	CreateProviderInfo(info *models.StorageProviderInfo) error
}
