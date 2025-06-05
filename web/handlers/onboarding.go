package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/storacha/go-ucanto/did"

	"github.com/storacha/delegator/internal/models"
	"github.com/storacha/delegator/internal/onboarding"
)

// Note: We already have a logger in web.go as log = logging.Logger("web")

// OnboardingTemplateData represents onboarding page data
type OnboardingTemplateData struct {
	*TemplateData
	Step               int
	Session            *models.OnboardingSession
	NextStep           string
	FormData           *FormData
	RequestedSessionID string
	HelpTexts          models.OnboardingHelpTexts
	PiriNodeEnvVars    map[string]string // Environment variables to display in step 5
}

// FormData represents form input data
type FormData struct {
	DID             string
	FilecoinAddress string
	ProofSetID      uint64
	OperatorEmail   string
	URL             string
	Proof           string
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
		session, err := h.sessionStore.GetSession(sessionID)
		if err == nil {
			data.Session = session
			data.Step = h.getStepFromStatus(session.Status)
		} else {
			log.Errorw("OnboardingIndex: Error retrieving session", "session_id", sessionID, "error", err)
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
		if step, err := strconv.Atoi(stepParam); err == nil && step >= 1 && step <= 5 {
			data.Step = step
		}
	}

	// If we're on step 5 and have a valid session, populate the environment variables
	if data.Step == 5 && data.Session != nil {
		data.PiriNodeEnvVars = h.generatePiriNodeEnvVars(data.Session)
	}

	return h.render(c, "onboard.html", data)
}

// NewOnboardingSession clears any existing session and starts a new onboarding flow
func (h *WebHandler) NewOnboardingSession(c echo.Context) error {
	// Clear any existing session
	h.clearSessionCookie(c)

	// Redirect to step 1 (DID registration)
	return c.Redirect(http.StatusSeeOther, "/onboard")
}

// RegisterDID handles DID registration form submission
func (h *WebHandler) RegisterDID(c echo.Context) error {
	log.Debug("RegisterDID: Handler called")

	didStr := c.FormValue("did")
	filecoinAddr := c.FormValue("filecoin_address")
	proofSetIDStr := c.FormValue("proof_set_id")
	operatorEmail := c.FormValue("operator_email")

	log.Debugw("RegisterDID: Form values",
		"did", didStr,
		"filecoin_address", filecoinAddr,
		"proof_set_id", proofSetIDStr,
		"operator_email", operatorEmail)

	// Check for existing session
	existingSessionID := h.getSessionID(c)
	log.Debugw("RegisterDID: Existing session ID", "session_id", existingSessionID)

	// Parse proof set ID
	var proofSetID uint64
	if proofSetIDStr != "" {
		parsedID, err := strconv.ParseUint(proofSetIDStr, 10, 64)
		if err == nil {
			proofSetID = parsedID
		}
	}

	data := &OnboardingTemplateData{
		TemplateData: &TemplateData{
			Title: "WSP Onboarding",
		},
		Step: 1,
		FormData: &FormData{
			DID:             didStr,
			FilecoinAddress: filecoinAddr,
			ProofSetID:      proofSetID,
			OperatorEmail:   operatorEmail,
		},
		HelpTexts: h.getHelpTexts(),
	}

	// Validate input
	if didStr == "" {
		data.Error = "DID is required"
		return h.render(c, "onboard.html", data)
	}

	if filecoinAddr == "" {
		data.Error = "Filecoin Address is required"
		return h.render(c, "onboard.html", data)
	}

	if proofSetIDStr == "" || proofSetID == 0 {
		data.Error = "Proof Set ID is required and must be greater than 0"
		return h.render(c, "onboard.html", data)
	}

	if operatorEmail == "" {
		data.Error = "Operator Email is required"
		return h.render(c, "onboard.html", data)
	}

	// Parse and validate DID
	parsedDID, err := did.Parse(didStr)
	if err != nil {
		data.Error = fmt.Sprintf("Invalid DID format: %v", err)
		return h.render(c, "onboard.html", data)
	}

	// Register DID
	log.Debugw("RegisterDID: Calling service.RegisterDID",
		"did", parsedDID.String(),
		"filecoin_address", filecoinAddr,
		"proof_set_id", proofSetID,
		"operator_email", operatorEmail)
	resp, err := h.service.RegisterDID(parsedDID, filecoinAddr, proofSetID, operatorEmail)
	if err != nil {
		log.Errorw("RegisterDID: Error from service.RegisterDID", "error", err)

		if errors.Is(err, onboarding.ErrIsNotAllowed) {
			data.Error = fmt.Sprintf("DID '%s' is not authorized for onboarding", didStr)
		} else if errors.Is(err, onboarding.ErrIsAlreadyRegistered) {
			data.Error = fmt.Sprintf("DID '%s' is already registered", didStr)
		} else {
			data.Error = fmt.Sprintf("Registration failed: %v", err)
		}
		return h.render(c, "onboard.html", data)
	}

	// Session creation was successful
	log.Debugw("RegisterDID: Success! Created session", "session_id", resp.SessionID)

	// Save session ID to cookie
	h.setSessionCookie(c, resp.SessionID)

	// Check if cookie was set
	sess, err := session.Get("delegator_session", c)
	if err != nil {
		log.Errorw("RegisterDID: After set, error getting session", "error", err)
	} else {
		log.Debugw("RegisterDID: After set, session values", "values", sess.Values)
	}

	// Success - redirect to step 2 with session
	redirectURL := "/onboard?step=2"
	log.Debugw("RegisterDID: Redirecting", "url", redirectURL)
	return c.Redirect(http.StatusSeeOther, redirectURL)
}

// RegisterFQDN handles FQDN registration form submission
func (h *WebHandler) RegisterFQDN(c echo.Context) error {
	// Try to get session ID from cookie first, then form value
	sessionID := h.getSessionID(c)
	formSessionID := c.FormValue("session_id")

	// Debug session ID sources
	log.Debugw("RegisterFQDN: Session IDs", "cookie_session_id", sessionID, "form_session_id", formSessionID)

	// Use form value if cookie is empty
	if sessionID == "" && formSessionID != "" {
		sessionID = formSessionID
		log.Debugw("RegisterFQDN: Using form session ID", "session_id", sessionID)
	}

	// Log cookie contents
	sess, err := session.Get("delegator_session", c)
	if err != nil {
		log.Errorw("RegisterFQDN: Error getting session cookie", "error", err)
	} else {
		log.Debugw("RegisterFQDN: Session cookie values", "values", sess.Values)
	}

	urlStr := c.FormValue("url")
	log.Debugw("RegisterFQDN: URL", "url", urlStr)

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
		session, err := h.sessionStore.GetSession(sessionID)
		if err == nil {
			data.Session = session
			log.Debugw("RegisterFQDN: Found session in store", "session", session)
		} else {
			log.Errorw("RegisterFQDN: Failed to get session from store", "error", err)
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

	// Register FQDN
	log.Debugw("RegisterFQDN: Calling service.RegisterFQDN", "session_id", sessionID, "url", parsedURL.String())
	resp, err := h.service.RegisterFQDN(sessionID, *parsedURL)
	if err != nil {
		log.Errorw("RegisterFQDN: Error from RegisterFQDN", "error", err)

		if errors.Is(err, onboarding.ErrSessionNotFound) {
			data.Error = "Session not found or expired"
			// Retry with form session ID as a last resort if different
			if formSessionID != "" && formSessionID != sessionID {
				log.Debugw("RegisterFQDN: Retrying with form session ID", "session_id", formSessionID)
				resp2, err2 := h.service.RegisterFQDN(formSessionID, *parsedURL)
				if err2 == nil {
					// Success with form session ID
					h.setSessionCookie(c, resp2.SessionID)
					return c.Redirect(http.StatusSeeOther, "/onboard?step=3")
				}
				log.Errorw("RegisterFQDN: Retry also failed", "error", err2)
			}
		} else if errors.Is(err, onboarding.ErrInvalidSessionState) {
			data.Error = "Invalid session state - please start over"
		} else if errors.Is(err, onboarding.ErrFQDNVerificationFailed) {
			data.Error = fmt.Sprintf("FQDN verification failed: %v", err)
		} else {
			data.Error = fmt.Sprintf("Verification failed: %v", err)
		}
		return h.render(c, "onboard.html", data)
	}

	// Save/update session ID in cookie
	log.Debugw("RegisterFQDN: Success! Setting cookie with session ID", "session_id", resp.SessionID)
	h.setSessionCookie(c, resp.SessionID)

	// Success - redirect to step 3
	return c.Redirect(http.StatusSeeOther, "/onboard?step=3")
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
		session, err := h.sessionStore.GetSession(sessionID)
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

	// Register proof
	resp, err := h.service.RegisterProof(sessionID, proof)
	if err != nil {
		if errors.Is(err, onboarding.ErrSessionNotFound) {
			data.Error = "Session not found or expired"
		} else if errors.Is(err, onboarding.ErrInvalidSessionState) {
			data.Error = "Invalid session state - please start over"
		} else if errors.Is(err, onboarding.ErrProofVerificationFailed) {
			data.Error = fmt.Sprintf("Proof verification failed: %v", err)
		} else {
			data.Error = fmt.Sprintf("Verification failed: %v", err)
		}
		return h.render(c, "onboard.html", data)
	}

	// Save/update session ID in cookie
	h.setSessionCookie(c, resp.SessionID)

	// Success - redirect to completion page
	return c.Redirect(http.StatusSeeOther, "/onboard?step=4")
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
	session, err := h.sessionStore.GetSession(sessionID)
	if err != nil {
		data.Error = "Session not found or expired"
		return h.render(c, "status.html", data)
	}

	data.Session = session
	data.NextStep = h.getNextStepFromStatus(session.Status)

	return h.render(c, "status.html", data)
}

// SubmitProvider handles the final submission of the provider to the persistent store
func (h *WebHandler) SubmitProvider(c echo.Context) error {
	// Try to get session ID from cookie or form value
	sessionID := h.getSessionID(c)
	if sessionID == "" {
		sessionID = c.FormValue("session_id")
	}

	data := &OnboardingTemplateData{
		TemplateData: &TemplateData{
			Title:     "WSP Onboarding",
			SessionID: sessionID,
		},
		Step:      4,
		HelpTexts: h.getHelpTexts(),
	}

	// Get session
	if sessionID != "" {
		session, err := h.sessionStore.GetSession(sessionID)
		if err == nil {
			data.Session = session
			// Make sure step is 4 for proof verified status
			if session.Status == models.StatusProofVerified {
				data.Step = 4
			}
		} else {
			data.Error = "Session not found or expired"
			return h.render(c, "onboard.html", data)
		}
	} else {
		data.Error = "Session ID is required"
		return h.render(c, "onboard.html", data)
	}

	// Use the onboarding service to submit the provider
	if err := h.service.SubmitProvider(sessionID); err != nil {
		if errors.Is(err, onboarding.ErrSessionNotFound) {
			data.Error = "Session not found or expired"
		} else if errors.Is(err, onboarding.ErrInvalidSessionState) {
			data.Error = "Invalid session state - please start over"
		} else {
			data.Error = fmt.Sprintf("Failed to register provider: %v", err)
		}
		return h.render(c, "onboard.html", data)
	}

	// Get the updated session
	updatedSession, err := h.sessionStore.GetSession(sessionID)
	if err != nil {
		data.Error = fmt.Sprintf("Failed to get updated session: %v", err)
		return h.render(c, "onboard.html", data)
	}

	data.Session = updatedSession

	// Success - redirect to the final completion page (step 5)
	return c.Redirect(http.StatusSeeOther, "/onboard?step=5")
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

	// Get delegation
	delegationData, err := h.service.GetDelegation(sessionID)
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
	case models.StatusProofVerified:
		return 4
	case models.StatusCompleted:
		return 5
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
	case models.StatusProofVerified:
		return "submit-provider"
	case models.StatusCompleted:
		return "completed"
	default:
		return "register-did"
	}
}

// generatePiriNodeEnvVars generates the environment variables for piri node configuration
func (h *WebHandler) generatePiriNodeEnvVars(session *models.OnboardingSession) map[string]string {
	envVars := make(map[string]string)

	// Add session-specific values
	envVars["PIRI_PUBLIC_URL"] = session.FQDN
	envVars["PIRI_PDP_PROOFSET"] = session.FilecoinAddress
	envVars["PIRI_INDEXING_SERVICE_PROOF"] = session.DelegationData

	// Add delegator URL from current request
	envVars["PIRI_NODE_DELEGATOR_URL"] = h.config.Onboarding.UploadServiceDID

	// Add any additional environment variables from the config
	for key, value := range h.config.Onboarding.PiriNodeEnvVars {
		envVars[strings.ToUpper(key)] = value
	}

	return envVars
}
