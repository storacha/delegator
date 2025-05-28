package api

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/models"
	"github.com/storacha/delegator/internal/storage"
)

// RegisterRoutes registers all API routes
func RegisterRoutes(e *echo.Echo, cfg *config.Config, store storage.Store) error {
	// Initialize storage
	if err := store.SetAllowedDIDs(cfg.Onboarding.AllowedDIDs); err != nil {
		return err
	}

	// Initialize handlers
	onboardingHandler, err := NewOnboardingHandler(store, cfg.Onboarding)
	if err != nil {
		return fmt.Errorf("createing onboarding handler: %w", err)
	}
	// Health check
	e.GET("/health", healthCheck)

	// API v1 routes
	v1 := e.Group("/api/v1")

	// Onboarding routes
	onboard := v1.Group("/onboard")
	onboard.POST("/register-did", onboardingHandler.registerDID)
	onboard.POST("/register-fqdn", onboardingHandler.registerFQDN)
	onboard.POST("/register-proof", onboardingHandler.registerProof)
	onboard.GET("/status/:session_id", onboardingHandler.getSessionStatus)
	onboard.GET("/delegation/:session_id", onboardingHandler.getDelegation)

	return nil
}

// healthCheck returns the health status of the service
func healthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Delegator service is healthy",
		Data: map[string]string{
			"status":  "ok",
			"service": "delegator",
		},
	})
}
