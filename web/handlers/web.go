package handlers

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"path/filepath"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	ed25519 "github.com/storacha/go-ucanto/principal/ed25519/signer"

	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/models"
	"github.com/storacha/delegator/internal/storage"
)

// WebHandler handles web UI requests
type WebHandler struct {
	templates *template.Template
	store     storage.Store
	config    *config.Config
	helpTexts *models.OnboardingHelpTexts
}

// NewWebHandler creates a new web handler
func NewWebHandler(templatesDir string, store storage.Store, cfg *config.Config) (*WebHandler, error) {
	// Parse templates
	templates, err := template.ParseGlob(filepath.Join(templatesDir, "*.html"))
	if err != nil {
		return nil, err
	}

	uploadPrincipal, err := ed25519.Parse(cfg.Onboarding.UploadServiceKey)
	if err != nil {
		return nil, fmt.Errorf("DEVELOPER ERROR: failed to parse indexing service key: %w", err)
	}
	// Generate help texts with configuration values
	configMap := map[string]interface{}{
		"ServiceName": cfg.Onboarding.ServiceName,
		"ServiceDid":  uploadPrincipal.DID().String(),
	}

	// Add more dynamic values from config if needed
	helpTexts := models.GenerateHelpTexts(configMap)

	return &WebHandler{
		templates: templates,
		store:     store,
		config:    cfg,
		helpTexts: helpTexts,
	}, nil
}

// TemplateData represents common template data
type TemplateData struct {
	Title     string
	Flash     *FlashMessage
	Error     string
	Health    *HealthData
	Stats     *StatsData
	SessionID string // Added to store current session ID
}

// FlashMessage represents a flash message
type FlashMessage struct {
	Type    string // success, error, warning, info
	Message string
}

// HealthData represents service health information
type HealthData struct {
	Healthy bool
	Uptime  string
}

// StatsData represents dashboard statistics
type StatsData struct {
	TotalSessions     int
	CompletedSessions int
	ActiveProviders   int
}

// Home renders the home/dashboard page
func (h *WebHandler) Home(c echo.Context) error {
	// Try to get session ID from cookie or URL param
	sessionID := h.getSessionID(c)

	data := &TemplateData{
		Title:     "Dashboard",
		Health:    h.getHealthData(),
		Stats:     h.getStatsData(),
		SessionID: sessionID,
	}

	return h.render(c, "home.html", data)
}

// Health renders the health check page
func (h *WebHandler) Health(c echo.Context) error {
	health := h.getHealthData()

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Delegator service is healthy",
		Data: map[string]interface{}{
			"status":  "ok",
			"service": "delegator",
			"healthy": health.Healthy,
			"uptime":  health.Uptime,
		},
	})
}

// render renders a template with common data
func (h *WebHandler) render(c echo.Context, templateName string, data interface{}) error {
	fmt.Printf("DEBUG render: Template %s with data type %T\n", templateName, data)

	// Ensure we have session ID in the template data if available anywhere
	sessionID := h.getSessionID(c) // Get from cookie or URL

	if sessionID != "" {
		fmt.Printf("DEBUG render: Found sessionID: %s\n", sessionID)

		// Update template data with session ID
		if templateData, ok := data.(*TemplateData); ok {
			if templateData.SessionID == "" {
				templateData.SessionID = sessionID
				fmt.Printf("DEBUG render: Updated TemplateData with sessionID\n")
			}
		} else if onboardingData, ok := data.(*OnboardingTemplateData); ok {
			if onboardingData.TemplateData.SessionID == "" {
				onboardingData.TemplateData.SessionID = sessionID
				fmt.Printf("DEBUG render: Updated OnboardingTemplateData with sessionID\n")
			}
		}
	}

	// If data contains template data with session ID, save it to cookie
	if templateData, ok := data.(*TemplateData); ok && templateData.SessionID != "" {
		fmt.Printf("DEBUG render: Setting cookie from TemplateData with sessionID: %s\n", templateData.SessionID)
		h.setSessionCookie(c, templateData.SessionID)
	} else if onboardingData, ok := data.(*OnboardingTemplateData); ok {
		if onboardingData.Session != nil {
			fmt.Printf("DEBUG render: Setting cookie from OnboardingTemplateData.Session with sessionID: %s\n", onboardingData.Session.SessionID)
			h.setSessionCookie(c, onboardingData.Session.SessionID)
		} else if onboardingData.TemplateData != nil && onboardingData.TemplateData.SessionID != "" {
			fmt.Printf("DEBUG render: Setting cookie from OnboardingTemplateData.TemplateData with sessionID: %s\n", onboardingData.TemplateData.SessionID)
			h.setSessionCookie(c, onboardingData.TemplateData.SessionID)
		}
	}

	return c.Render(http.StatusOK, templateName, data)
}

// getSessionID gets the session ID from cookie first, then falls back to URL parameter
func (h *WebHandler) getSessionID(c echo.Context) string {
	// Try to get session ID from cookie first
	sess, err := session.Get("delegator_session", c)
	if err != nil {
		fmt.Printf("DEBUG getSessionID: Error getting session: %v\n", err)
	} else {
		fmt.Printf("DEBUG getSessionID: Session values: %+v\n", sess.Values)
		if sess.Values["session_id"] != nil {
			if sessionID, ok := sess.Values["session_id"].(string); ok && sessionID != "" {
				fmt.Printf("DEBUG getSessionID: Found sessionID in cookie: %s\n", sessionID)
				return sessionID
			}
		}
	}

	// Fall back to URL parameter
	sessionID := c.QueryParam("session_id")
	fmt.Printf("DEBUG getSessionID: Using URL parameter sessionID: %s\n", sessionID)
	return sessionID
}

// setSessionCookie saves the session ID to a cookie
func (h *WebHandler) setSessionCookie(c echo.Context, sessionID string) {
	if sessionID == "" {
		fmt.Printf("DEBUG setSessionCookie: Empty sessionID, not setting cookie\n")
		return
	}

	fmt.Printf("DEBUG setSessionCookie: Setting cookie with sessionID: %s\n", sessionID)

	sess, err := session.Get("delegator_session", c)
	if err != nil {
		fmt.Printf("DEBUG setSessionCookie: Error getting session: %v\n", err)
		// Just use a new session object since we can't create one directly
		sess = &sessions.Session{
			Values: make(map[interface{}]interface{}),
			Options: &sessions.Options{
				Path:     "/",
				MaxAge:   86400 * 7,
				HttpOnly: true,
			},
		}
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 1 week
		HttpOnly: true,
		Secure:   c.Request().TLS != nil, // Secure if HTTPS
		SameSite: http.SameSiteLaxMode,
	}

	// Set session ID
	sess.Values["session_id"] = sessionID

	// Save session
	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		fmt.Printf("DEBUG setSessionCookie: Error saving session: %v\n", err)
	} else {
		fmt.Printf("DEBUG setSessionCookie: Session saved successfully\n")
	}
}

// getHealthData returns current health status
func (h *WebHandler) getHealthData() *HealthData {
	// Simple health check - in production this could check dependencies
	return &HealthData{
		Healthy: true,
		Uptime:  "Available", // Could calculate actual uptime
	}
}

// getStatsData returns dashboard statistics
func (h *WebHandler) getStatsData() *StatsData {
	// Get basic statistics from storage
	// This is a simple implementation - could be enhanced with actual metrics
	stats := &StatsData{
		TotalSessions:     0,
		CompletedSessions: 0,
		ActiveProviders:   0,
	}

	// Try to get stats from storage if implemented
	// For now, return basic stats
	return stats
}

// TemplateRenderer implements Echo's Renderer interface
type TemplateRenderer struct {
	templates map[string]*template.Template
}

// NewTemplateRenderer creates a new template renderer
func NewTemplateRenderer(templatesDir string) (*TemplateRenderer, error) {
	// Create a map to store parsed templates
	templates := make(map[string]*template.Template)

	// Parse base template
	baseTemplate := filepath.Join(templatesDir, "base.html")

	// Get list of page templates
	pageTemplates, err := filepath.Glob(filepath.Join(templatesDir, "*.html"))
	if err != nil {
		return nil, err
	}

	// For each page template, parse it with the base template
	for _, page := range pageTemplates {
		if filepath.Base(page) == "base.html" {
			continue // Skip base template
		}

		// Create a new template with the base and specific page
		filename := filepath.Base(page)
		tmpl := template.New("base.html")
		tmpl, err = tmpl.ParseFiles(baseTemplate, page)
		if err != nil {
			return nil, err
		}

		// Store in map with filename as key
		templates[filename] = tmpl
	}

	if len(templates) == 0 {
		return nil, fmt.Errorf("no templates found in %s", templatesDir)
	}

	return &TemplateRenderer{
		templates: templates,
	}, nil
}

// Render renders a template
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	// Get the template from the cache
	tmpl, exists := t.templates[name]
	if !exists {
		return fmt.Errorf("template %s not found", name)
	}

	// Execute the base template, which will include the content block from the specific page
	if err := tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		return err
	}

	return nil
}

// toPascalCase converts snake_case to PascalCase for template variables
func toPascalCase(input string) string {
	var result string
	capitalize := true

	for _, char := range input {
		if char == '_' {
			capitalize = true
		} else if capitalize {
			// Check if we need to convert to uppercase
			if 'a' <= char && char <= 'z' {
				char = char - 32 // Convert to uppercase
			}
			result += string(char)
			capitalize = false
		} else {
			result += string(char)
		}
	}

	return result
}
