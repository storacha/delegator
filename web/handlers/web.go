package handlers

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"github.com/gorilla/sessions"
	logging "github.com/ipfs/go-log"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/storacha/go-ucanto/did"

	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/models"
	"github.com/storacha/delegator/internal/onboarding"
	"github.com/storacha/delegator/internal/storage"
)

var StartTime time.Time

func init() {
	StartTime = time.Now()
}

var log = logging.Logger("web")

// WebHandler handles web UI requests
type WebHandler struct {
	templates      *template.Template
	sessionStore   storage.SessionStore
	persistedStore storage.PersistentStore
	config         *config.Config
	helpTexts      *models.OnboardingHelpTexts
	service        *onboarding.Service
}

// NewWebHandler creates a new web handler
func NewWebHandler(templatesDir string, sessionStore storage.SessionStore, persistedStore storage.PersistentStore, cfg *config.Config) (*WebHandler, error) {
	// Parse templates
	templates, err := template.ParseGlob(filepath.Join(templatesDir, "*.html"))
	if err != nil {
		return nil, err
	}

	uploadDID, err := did.Parse(cfg.Onboarding.UploadServiceDID)
	if err != nil {
		return nil, fmt.Errorf("DEVELOPER ERROR: failed to parse indexing service key: %w", err)
	}
	// Generate help texts with configuration values
	configMap := map[string]interface{}{
		"ServiceDid": uploadDID.String(),
	}

	// Add more dynamic values from config if needed
	helpTexts := models.GenerateHelpTexts(configMap)

	service, err := onboarding.New(
		cfg.Onboarding,
		onboarding.WithSessionStore(sessionStore),
		onboarding.WithPersistedStore(persistedStore),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create onboarding service: %w", err)
	}

	return &WebHandler{
		templates:      templates,
		sessionStore:   sessionStore,
		persistedStore: persistedStore,
		config:         cfg,
		helpTexts:      helpTexts,
		service:        service,
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
	// Ensure we have session ID in the template data if available anywhere
	sessionID := h.getSessionID(c) // Get from cookie or URL

	if sessionID != "" {

		// Update template data with session ID
		if templateData, ok := data.(*TemplateData); ok {
			if templateData.SessionID == "" {
				templateData.SessionID = sessionID
			}
		} else if onboardingData, ok := data.(*OnboardingTemplateData); ok {
			if onboardingData.TemplateData.SessionID == "" {
				onboardingData.TemplateData.SessionID = sessionID
			}
		}
	}

	// If data contains template data with session ID, save it to cookie
	if templateData, ok := data.(*TemplateData); ok && templateData.SessionID != "" {
		h.setSessionCookie(c, templateData.SessionID)
	} else if onboardingData, ok := data.(*OnboardingTemplateData); ok {
		if onboardingData.Session != nil {
			h.setSessionCookie(c, onboardingData.Session.SessionID)
		} else if onboardingData.TemplateData != nil && onboardingData.TemplateData.SessionID != "" {
			h.setSessionCookie(c, onboardingData.TemplateData.SessionID)
		}
	}

	return c.Render(http.StatusOK, templateName, data)
}

// getSessionID gets the session ID from cookie only
func (h *WebHandler) getSessionID(c echo.Context) string {
	// Get session ID from cookie
	sess, err := session.Get("delegator_session", c)
	if err != nil {
		return ""
	}

	if sess.Values["session_id"] != nil {
		if sessionID, ok := sess.Values["session_id"].(string); ok && sessionID != "" {
			return sessionID
		}
	}

	return ""
}

// setSessionCookie saves the session ID to a cookie
func (h *WebHandler) setSessionCookie(c echo.Context, sessionID string) {
	if sessionID == "" {
		return
	}

	sess, err := session.Get("delegator_session", c)
	if err != nil {
		// Just use a new session object since we can't create one directly
		sess = &sessions.Session{
			Values: make(map[interface{}]interface{}),
			Options: &sessions.Options{
				Path:     "/",
				HttpOnly: true,
			},
		}
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Request().TLS != nil, // Secure if HTTPS
		SameSite: http.SameSiteLaxMode,
	}

	// Set session ID
	sess.Values["session_id"] = sessionID

	// Save session
	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		log.Errorw("Error saving session cookie", "error", err)
	}
}

// clearSessionCookie removes the session cookie
func (h *WebHandler) clearSessionCookie(c echo.Context) {
	sess, err := session.Get("delegator_session", c)
	if err != nil {
		return
	}

	// Set session options for deletion (expired)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   -1, // Negative value means delete cookie
		HttpOnly: true,
		Secure:   c.Request().TLS != nil,
		SameSite: http.SameSiteLaxMode,
	}

	// Remove session ID
	delete(sess.Values, "session_id")

	// Save the session to apply changes
	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		log.Errorw("Error clearing session cookie", "error", err)
	}
}

// getHealthData returns current health status
func (h *WebHandler) getHealthData() *HealthData {
	// Simple health check - in production this could check dependencies
	return &HealthData{
		Healthy: true,
		Uptime:  time.Since(StartTime).String(),
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
		return nil, fmt.Errorf("failed to glob templates: %w", err)
	}

	fmt.Printf("Found %d templates in %s: %v\n", len(pageTemplates), templatesDir, pageTemplates)

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
