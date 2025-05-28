package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/storacha/go-ucanto/did"

	"github.com/storacha/delegator/internal/models"
	"github.com/storacha/delegator/internal/services"
)

// OnboardingTemplateData represents onboarding page data
type OnboardingTemplateData struct {
	*TemplateData
	Step               int
	Session            *models.OnboardingSession
	NextStep           string
	FormData           *FormData
	RequestedSessionID string
	HelpTexts          models.OnboardingHelpTexts
}

// FormData represents form input data
type FormData struct {
	DID   string
	URL   string
	Proof string
}

// OnboardingIndex shows the onboarding flow based on step or session
func (h *WebHandler) OnboardingIndex(c echo.Context) error {
	// Get session ID from cookie first, then fall back to URL parameter
	sessionID := h.getSessionID(c)
	stepParam := c.QueryParam("step")

	data := &OnboardingTemplateData{
		TemplateData: &TemplateData{
			Title:     "WSP Onboarding",
			SessionID: sessionID,
		},
		Step:      1, // Default to step 1
		FormData:  &FormData{},
		HelpTexts: h.getHelpTexts(),
	}

	// If session ID is provided, get session and determine step
	if sessionID != "" {
		session, err := h.store.GetSession(sessionID)
		if err == nil {
			data.Session = session
			data.Step = h.getStepFromStatus(session.Status)
		} else {
			fmt.Printf("ERROR retrieving session '%s': %v\n", sessionID, err)
			// For the test session, create a dummy session to help debug
			if sessionID == "test-session" {
				data.Session = &models.OnboardingSession{
					SessionID: "test-session",
					DID:       "did:key:test",
					Status:    models.StatusDIDVerified,
				}
			}
		}
	}

	// Override step if explicitly provided
	if stepParam != "" {
		if step, err := strconv.Atoi(stepParam); err == nil && step >= 1 && step <= 4 {
			data.Step = step
		}
	}

	return h.render(c, "onboard.html", data)
}

// RegisterDID handles DID registration form submission
func (h *WebHandler) RegisterDID(c echo.Context) error {
	fmt.Println("DEBUG RegisterDID: Handler called")

	didStr := c.FormValue("did")
	fmt.Printf("DEBUG RegisterDID: DID value: %s\n", didStr)

	// Check for existing session
	existingSessionID := h.getSessionID(c)
	fmt.Printf("DEBUG RegisterDID: Existing session ID: %s\n", existingSessionID)

	data := &OnboardingTemplateData{
		TemplateData: &TemplateData{
			Title: "WSP Onboarding",
		},
		Step: 1,
		FormData: &FormData{
			DID: didStr,
		},
		HelpTexts: h.getHelpTexts(),
	}

	// Validate input
	if didStr == "" {
		data.Error = "DID is required"
		return h.render(c, "onboard.html", data)
	}

	// Parse and validate DID
	parsedDID, err := did.Parse(didStr)
	if err != nil {
		data.Error = fmt.Sprintf("Invalid DID format: %v", err)
		return h.render(c, "onboard.html", data)
	}

	// Create onboarding service
	onboardingService, err := h.createOnboardingService()
	if err != nil {
		data.Error = "Service configuration error"
		return h.render(c, "onboard.html", data)
	}

	// Register DID
	fmt.Printf("DEBUG RegisterDID: Calling service.RegisterDID with DID: %s\n", parsedDID.String())
	resp, err := onboardingService.RegisterDID(parsedDID)
	if err != nil {
		fmt.Printf("DEBUG RegisterDID: Error from RegisterDID: %v\n", err)

		if errors.Is(err, services.ErrIsNotAllowed) {
			data.Error = fmt.Sprintf("DID '%s' is not authorized for onboarding", didStr)
		} else if errors.Is(err, services.ErrIsAlreadyRegistered) {
			data.Error = fmt.Sprintf("DID '%s' is already registered", didStr)
		} else {
			data.Error = fmt.Sprintf("Registration failed: %v", err)
		}
		return h.render(c, "onboard.html", data)
	}

	// Session creation was successful
	fmt.Printf("DEBUG RegisterDID: Success! Created session ID: %s\n", resp.SessionID)

	// Save session ID to cookie
	h.setSessionCookie(c, resp.SessionID)

	// Check if cookie was set
	sess, err := session.Get("delegator_session", c)
	if err != nil {
		fmt.Printf("DEBUG RegisterDID: After set, error getting session: %v\n", err)
	} else {
		fmt.Printf("DEBUG RegisterDID: After set, session values: %+v\n", sess.Values)
	}

	// Success - redirect to step 2 with session
	// We still include the session_id in URL for backward compatibility
	redirectURL := fmt.Sprintf("/onboard?session_id=%s&step=2", resp.SessionID)
	fmt.Printf("DEBUG RegisterDID: Redirecting to: %s\n", redirectURL)
	return c.Redirect(http.StatusSeeOther, redirectURL)
}

// RegisterFQDN handles FQDN registration form submission
func (h *WebHandler) RegisterFQDN(c echo.Context) error {
	// Try to get session ID from cookie first, then form value
	sessionID := h.getSessionID(c)
	formSessionID := c.FormValue("session_id")

	// Debug session ID sources
	fmt.Printf("DEBUG RegisterFQDN: Cookie sessionID: %s, Form sessionID: %s\n", sessionID, formSessionID)

	// Use form value if cookie is empty
	if sessionID == "" && formSessionID != "" {
		sessionID = formSessionID
		fmt.Printf("DEBUG RegisterFQDN: Using form session ID: %s\n", sessionID)
	}

	// Log cookie contents
	sess, err := session.Get("delegator_session", c)
	if err != nil {
		fmt.Printf("DEBUG RegisterFQDN: Error getting session cookie: %v\n", err)
	} else {
		fmt.Printf("DEBUG RegisterFQDN: Session cookie values: %+v\n", sess.Values)
	}

	urlStr := c.FormValue("url")
	fmt.Printf("DEBUG RegisterFQDN: URL: %s\n", urlStr)

	data := &OnboardingTemplateData{
		TemplateData: &TemplateData{
			Title:     "WSP Onboarding",
			SessionID: sessionID,
		},
		Step: 2,
		FormData: &FormData{
			URL: urlStr,
		},
		HelpTexts: h.getHelpTexts(),
	}

	// Get session from storage
	if sessionID != "" {
		session, err := h.store.GetSession(sessionID)
		if err == nil {
			data.Session = session
			fmt.Printf("DEBUG RegisterFQDN: Found session in store: %+v\n", session)
		} else {
			fmt.Printf("DEBUG RegisterFQDN: Failed to get session from store: %v\n", err)
		}
	}

	// Validate input
	if sessionID == "" {
		data.Error = "Session ID is required"
		return h.render(c, "onboard.html", data)
	}

	if urlStr == "" {
		data.Error = "URL is required"
		return h.render(c, "onboard.html", data)
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		data.Error = fmt.Sprintf("Invalid URL format: %v", err)
		return h.render(c, "onboard.html", data)
	}

	// Create onboarding service
	onboardingService, err := h.createOnboardingService()
	if err != nil {
		data.Error = "Service configuration error"
		return h.render(c, "onboard.html", data)
	}

	// Register FQDN
	fmt.Printf("DEBUG RegisterFQDN: Calling service.RegisterFQDN with sessionID: %s, URL: %s\n", sessionID, parsedURL.String())
	resp, err := onboardingService.RegisterFQDN(sessionID, *parsedURL)
	if err != nil {
		fmt.Printf("DEBUG RegisterFQDN: Error from RegisterFQDN: %v\n", err)

		if errors.Is(err, services.ErrSessionNotFound) {
			data.Error = "Session not found or expired"
			// Retry with form session ID as a last resort if different
			if formSessionID != "" && formSessionID != sessionID {
				fmt.Printf("DEBUG RegisterFQDN: Retrying with form session ID: %s\n", formSessionID)
				resp2, err2 := onboardingService.RegisterFQDN(formSessionID, *parsedURL)
				if err2 == nil {
					// Success with form session ID
					h.setSessionCookie(c, resp2.SessionID)
					return c.Redirect(http.StatusSeeOther, fmt.Sprintf("/onboard?session_id=%s&step=3", resp2.SessionID))
				}
				fmt.Printf("DEBUG RegisterFQDN: Retry also failed: %v\n", err2)
			}
		} else if errors.Is(err, services.ErrInvalidSessionState) {
			data.Error = "Invalid session state - please start over"
		} else if errors.Is(err, services.ErrFQDNVerificationFailed) {
			data.Error = fmt.Sprintf("FQDN verification failed: %v", err)
		} else {
			data.Error = fmt.Sprintf("Verification failed: %v", err)
		}
		return h.render(c, "onboard.html", data)
	}

	// Save/update session ID in cookie
	fmt.Printf("DEBUG RegisterFQDN: Success! Setting cookie with session ID: %s\n", resp.SessionID)
	h.setSessionCookie(c, resp.SessionID)

	// Success - redirect to step 3
	return c.Redirect(http.StatusSeeOther, fmt.Sprintf("/onboard?session_id=%s&step=3", resp.SessionID))
}

// RegisterProof handles proof registration form submission
func (h *WebHandler) RegisterProof(c echo.Context) error {
	// Try to get session ID from cookie first, then form value
	sessionID := h.getSessionID(c)
	if sessionID == "" {
		sessionID = c.FormValue("session_id") // Fallback to form value if cookie not present
	}

	proof := c.FormValue("proof")

	data := &OnboardingTemplateData{
		TemplateData: &TemplateData{
			Title:     "WSP Onboarding",
			SessionID: sessionID,
		},
		Step: 3,
		FormData: &FormData{
			Proof: proof,
		},
		HelpTexts: h.getHelpTexts(),
	}

	// Get session
	if sessionID != "" {
		session, err := h.store.GetSession(sessionID)
		if err == nil {
			data.Session = session
		}
	}

	// Validate input
	if sessionID == "" {
		data.Error = "Session ID is required"
		return h.render(c, "onboard.html", data)
	}

	if proof == "" {
		data.Error = "Delegation proof is required"
		return h.render(c, "onboard.html", data)
	}

	// Create onboarding service
	onboardingService, err := h.createOnboardingService()
	if err != nil {
		data.Error = "Service configuration error"
		return h.render(c, "onboard.html", data)
	}

	// Register proof
	resp, err := onboardingService.RegisterProof(sessionID, proof)
	if err != nil {
		if errors.Is(err, services.ErrSessionNotFound) {
			data.Error = "Session not found or expired"
		} else if errors.Is(err, services.ErrInvalidSessionState) {
			data.Error = "Invalid session state - please start over"
		} else if errors.Is(err, services.ErrProofVerificationFailed) {
			data.Error = fmt.Sprintf("Proof verification failed: %v", err)
		} else {
			data.Error = fmt.Sprintf("Verification failed: %v", err)
		}
		return h.render(c, "onboard.html", data)
	}

	// Save/update session ID in cookie
	h.setSessionCookie(c, resp.SessionID)

	// Success - redirect to completion page
	return c.Redirect(http.StatusSeeOther, fmt.Sprintf("/onboard?session_id=%s&step=4", resp.SessionID))
}

// SessionStatus shows the status of an onboarding session
func (h *WebHandler) SessionStatus(c echo.Context) error {
	// First check URL path param, then query param, then cookie
	sessionID := c.Param("session_id")
	if sessionID == "" {
		sessionID = h.getSessionID(c)
	}

	data := &OnboardingTemplateData{
		TemplateData: &TemplateData{
			Title:     "Session Status",
			SessionID: sessionID,
		},
		RequestedSessionID: sessionID,
		HelpTexts:          h.getHelpTexts(),
	}

	if sessionID == "" {
		return h.render(c, "status.html", data)
	}

	// Get session
	session, err := h.store.GetSession(sessionID)
	if err != nil {
		data.Error = "Session not found or expired"
		return h.render(c, "status.html", data)
	}

	data.Session = session
	data.NextStep = h.getNextStepFromStatus(session.Status)

	return h.render(c, "status.html", data)
}

// GetDelegation serves the delegation file for download
func (h *WebHandler) GetDelegation(c echo.Context) error {
	// Try to get session ID from path param first, then cookie
	sessionID := c.Param("session_id")
	if sessionID == "" {
		sessionID = h.getSessionID(c)
		if sessionID == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "Session ID is required",
			})
		}
	}

	// Create onboarding service
	onboardingService, err := h.createOnboardingService()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Service configuration error",
		})
	}

	// Get delegation
	delegationData, err := onboardingService.GetDelegation(sessionID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "Delegation not found",
		})
	}

	// Return as downloadable file
	c.Response().Header().Set("Content-Type", "application/octet-stream")
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=delegation-%s.b64", sessionID))
	return c.Blob(http.StatusOK, "application/octet-stream", []byte(delegationData))
}

// Helper methods

func (h *WebHandler) createOnboardingService() (*services.OnboardingService, error) {
	return services.NewOnboardingServiceFromConfig(h.store, h.config.Onboarding)
}

// SetHelpTexts allows overriding the default help texts
func (h *WebHandler) SetHelpTexts(helpTexts models.OnboardingHelpTexts) {
	h.helpTexts = &helpTexts
}

// getHelpTexts returns the current help texts, falling back to defaults if none are set
func (h *WebHandler) getHelpTexts() models.OnboardingHelpTexts {
	if h.helpTexts != nil {
		return *h.helpTexts
	}
	return models.DefaultOnboardingHelpTexts
}

func (h *WebHandler) getStepFromStatus(status string) int {
	switch status {
	case models.StatusDIDVerified:
		return 2
	case models.StatusFQDNVerified:
		return 3
	case models.StatusProofVerified, models.StatusCompleted:
		return 4
	default:
		return 1
	}
}

func (h *WebHandler) getNextStepFromStatus(status string) string {
	switch status {
	case models.StatusDIDVerified:
		return "register-fqdn"
	case models.StatusFQDNVerified:
		return "register-proof"
	case models.StatusProofVerified, models.StatusCompleted:
		return "completed"
	default:
		return "register-did"
	}
}
