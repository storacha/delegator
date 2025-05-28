package api

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/labstack/echo/v4"

	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/models"
	"github.com/storacha/delegator/internal/storage"
	"github.com/storacha/delegator/web/handlers"
)

// RegisterRoutes registers all API and web routes
func RegisterRoutes(e *echo.Echo, cfg *config.Config, store storage.Store) error {
	// Simple test route first
	e.GET("/ping", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "pong"})
	})

	// Initialize storage
	if err := store.SetAllowedDIDs(cfg.Onboarding.AllowedDIDs); err != nil {
		return err
	}

	// Initialize API handlers
	onboardingHandler, err := NewOnboardingHandler(store, cfg.Onboarding)
	if err != nil {
		return fmt.Errorf("creating onboarding handler: %w", err)
	}

	// Always provide basic health check
	e.GET("/health", healthCheck)

	// Try to set up web UI - if templates are available
	templatesDir := filepath.Join("web", "templates")
	renderer, err := handlers.NewTemplateRenderer(templatesDir)
	if err == nil {
		e.Renderer = renderer

		// Serve static files (CSS, JS, images)
		e.Static("/static", "web/static")

		// Initialize web handlers
		webHandler, err := handlers.NewWebHandler(templatesDir, store, cfg)
		if err == nil {
			// Web UI routes (HTML pages)
			e.GET("/", webHandler.Home)
			e.GET("/onboard", webHandler.OnboardingIndex)
			e.GET("/onboard/new", webHandler.NewOnboardingSession)
			e.POST("/onboard/register-did", webHandler.RegisterDID)
			e.POST("/onboard/register-fqdn", webHandler.RegisterFQDN)
			e.POST("/onboard/register-proof", webHandler.RegisterProof)
			e.GET("/onboard/status/:session_id", webHandler.SessionStatus)
			e.GET("/onboard/status", webHandler.SessionStatus) // For query param version
			e.GET("/onboard/delegation/:session_id", webHandler.GetDelegation)
		} else {
			// Web handler failed, provide basic root route
			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, models.APIResponse{
					Success: true,
					Message: "Delegator service running (web UI unavailable)",
					Data: map[string]string{
						"status":  "ok",
						"service": "delegator",
						"error":   fmt.Sprintf("Web UI error: %v", err),
					},
				})
			})
		}
	} else {
		// Template renderer failed, provide basic root route
		e.GET("/", func(c echo.Context) error {
			return c.JSON(http.StatusOK, models.APIResponse{
				Success: true,
				Message: "Delegator service running (templates unavailable)",
				Data: map[string]string{
					"status":  "ok",
					"service": "delegator",
					"error":   fmt.Sprintf("Template error: %v", err),
				},
			})
		})
	}

	// API v1 routes (JSON API)
	v1 := e.Group("/api/v1")

	// Onboarding API routes
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
