package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/storacha/go-ucanto/did"

	"github.com/storacha/delegator/internal/models"
)

// TestStorageTemplateData represents template data for test storage pages
type TestStorageTemplateData struct {
	*TemplateData
	Step          int
	TestSession   *TestSession
	TestSessionID string
	FormData      map[string]string
	Success       bool
	TestResult    string
	TestError     string
	TestProgress  *models.TestProgress
	HelpTexts     models.OnboardingHelpTexts
	DelegatorDID  string
}

// TestSession represents a test storage session for display
type TestSession struct {
	SessionID  string
	DID        string
	Delegation string
	URL        string
	FQDN       string // Add FQDN field for template compatibility
}

// TestStorageDID shows the test storage DID entry page
func (h *WebHandler) TestStorageDID(c echo.Context) error {
	// Clear any existing test storage session
	h.clearSessionCookieByType(c, "test_storage")

	// Create help texts with test storage specific info
	testHelpTexts := *h.helpTexts
	testHelpTexts.DelegationProof.Command = fmt.Sprintf("# Using the key file you saved during setup (either PEM or JSON format):\npiri delegation generate \\\n  --key-file=service.pem \\\n  --client-did=%s\n\n# If you saved your key as JSON instead of PEM:\npiri delegation generate \\\n  --key-file=service.json \\\n  --client-did=%s", h.service.GetDelegatorDID(), h.service.GetDelegatorDID())

	data := &TestStorageTemplateData{
		TemplateData: &TemplateData{
			Title: "Test Storage - Enter DID",
		},
		Step:         1,
		FormData:     make(map[string]string),
		HelpTexts:    testHelpTexts,
		DelegatorDID: h.service.GetDelegatorDID(),
	}

	return h.render(c, "test-storage-did.html", data)
}

// TestStorageDIDSubmit handles the DID submission for test storage
func (h *WebHandler) TestStorageDIDSubmit(c echo.Context) error {
	// Get form data
	didStr := strings.TrimSpace(c.FormValue("did"))
	urlStr := strings.TrimSpace(c.FormValue("url"))

	// Basic validation
	if !strings.HasPrefix(didStr, "did:key:") {
		// Create help texts with test storage specific info
		testHelpTexts := *h.helpTexts
		testHelpTexts.DelegationProof.Command = fmt.Sprintf("# Using the key file you saved during setup (either PEM or JSON format):\npiri delegation generate \\\n  --key-file=service.pem \\\n  --client-did=%s\n\n# If you saved your key as JSON instead of PEM:\npiri delegation generate \\\n  --key-file=service.json \\\n  --client-did=%s", h.service.GetDelegatorDID(), h.service.GetDelegatorDID())

		data := &TestStorageTemplateData{
			TemplateData: &TemplateData{
				Title: "Test Storage - Enter DID",
				Error: "Invalid DID format. DID must start with 'did:key:'",
			},
			Step: 1,
			FormData: map[string]string{
				"DID": didStr,
				"URL": urlStr,
			},
			HelpTexts:    testHelpTexts,
			DelegatorDID: h.service.GetDelegatorDID(),
		}
		return h.render(c, "test-storage-did.html", data)
	}

	// Validate URL
	if urlStr == "" {
		// Create help texts with test storage specific info
		testHelpTexts := *h.helpTexts
		testHelpTexts.DelegationProof.Command = fmt.Sprintf("# Using the key file you saved during setup (either PEM or JSON format):\npiri delegation generate \\\n  --key-file=service.pem \\\n  --client-did=%s\n\n# If you saved your key as JSON instead of PEM:\npiri delegation generate \\\n  --key-file=service.json \\\n  --client-did=%s", h.service.GetDelegatorDID(), h.service.GetDelegatorDID())

		data := &TestStorageTemplateData{
			TemplateData: &TemplateData{
				Title: "Test Storage - Enter DID",
				Error: "Storage Node URL is required",
			},
			Step: 1,
			FormData: map[string]string{
				"DID": didStr,
				"URL": urlStr,
			},
			HelpTexts:    testHelpTexts,
			DelegatorDID: h.service.GetDelegatorDID(),
		}
		return h.render(c, "test-storage-did.html", data)
	}

	// Parse DID to ensure it's valid
	_, err := did.Parse(didStr)
	if err != nil {
		// Create help texts with test storage specific info
		testHelpTexts := *h.helpTexts
		testHelpTexts.DelegationProof.Command = fmt.Sprintf("# Using the key file you saved during setup (either PEM or JSON format):\npiri delegation generate \\\n  --key-file=service.pem \\\n  --client-did=%s\n\n# If you saved your key as JSON instead of PEM:\npiri delegation generate \\\n  --key-file=service.json \\\n  --client-did=%s", h.service.GetDelegatorDID(), h.service.GetDelegatorDID())

		data := &TestStorageTemplateData{
			TemplateData: &TemplateData{
				Title: "Test Storage - Enter DID",
				Error: fmt.Sprintf("Invalid DID: %v", err),
			},
			Step: 1,
			FormData: map[string]string{
				"DID": didStr,
				"URL": urlStr,
			},
			HelpTexts:    testHelpTexts,
			DelegatorDID: h.service.GetDelegatorDID(),
		}
		return h.render(c, "test-storage-did.html", data)
	}

	// Create test session using the service
	sessionID, err := h.service.StartTestStorageSession(didStr, urlStr)
	if err != nil {
		// Create help texts with test storage specific info
		testHelpTexts := *h.helpTexts
		testHelpTexts.DelegationProof.Command = fmt.Sprintf("# Using the key file you saved during setup (either PEM or JSON format):\npiri delegation generate \\\n  --key-file=service.pem \\\n  --client-did=%s\n\n# If you saved your key as JSON instead of PEM:\npiri delegation generate \\\n  --key-file=service.json \\\n  --client-did=%s", h.service.GetDelegatorDID(), h.service.GetDelegatorDID())

		data := &TestStorageTemplateData{
			TemplateData: &TemplateData{
				Title: "Test Storage - Enter DID",
				Error: fmt.Sprintf("Failed to create test session: %v", err),
			},
			Step: 1,
			FormData: map[string]string{
				"DID": didStr,
				"URL": urlStr,
			},
			HelpTexts:    testHelpTexts,
			DelegatorDID: h.service.GetDelegatorDID(),
		}
		return h.render(c, "test-storage-did.html", data)
	}

	// Store session ID in cookie
	h.setSessionCookieByType(c, sessionID, "test_storage")

	// Redirect to delegation page
	return c.Redirect(http.StatusSeeOther, fmt.Sprintf("/test-storage/delegation?test_session_id=%s", sessionID))
}

// TestStorageDelegation shows the delegation entry page
func (h *WebHandler) TestStorageDelegation(c echo.Context) error {
	// Get test session ID from cookie or params
	testSessionID := c.QueryParam("test_session_id")
	if testSessionID == "" {
		testSessionID = h.getSessionIDByType(c, "test_storage")
	}

	if testSessionID == "" {
		// No session found, redirect to start
		return c.Redirect(http.StatusSeeOther, "/test-storage")
	}

	// Get session from service
	session, err := h.service.GetTestStorageSession(testSessionID)
	if err != nil {
		// Session not found or expired, redirect to start
		return c.Redirect(http.StatusSeeOther, "/test-storage")
	}

	// Create help texts with test storage specific info
	testHelpTexts := *h.helpTexts
	testHelpTexts.DelegationProof.Command = fmt.Sprintf("# Using the key file you saved during setup (either PEM or JSON format):\npiri delegation generate \\\n  --key-file=service.pem \\\n  --client-did=%s\n\n# If you saved your key as JSON instead of PEM:\npiri delegation generate \\\n  --key-file=service.json \\\n  --client-did=%s", h.service.GetDelegatorDID(), h.service.GetDelegatorDID())

	data := &TestStorageTemplateData{
		TemplateData: &TemplateData{
			Title: "Test Storage - Provide Delegation",
		},
		Step:          2,
		TestSessionID: testSessionID,
		TestSession: &TestSession{
			SessionID: testSessionID,
			DID:       session.DID,
			FQDN:      session.FQDN,
		},
		FormData:     make(map[string]string),
		HelpTexts:    testHelpTexts,
		DelegatorDID: h.service.GetDelegatorDID(),
	}

	return h.render(c, "test-storage-delegation.html", data)
}

// TestStorageDelegationSubmit handles the delegation submission
func (h *WebHandler) TestStorageDelegationSubmit(c echo.Context) error {
	// Get test session ID
	testSessionID := c.FormValue("test_session_id")
	if testSessionID == "" {
		testSessionID = h.getSessionIDByType(c, "test_storage")
	}

	if testSessionID == "" {
		// No session found, redirect to start
		return c.Redirect(http.StatusSeeOther, "/test-storage")
	}

	// Get session from service
	session, err := h.service.GetTestStorageSession(testSessionID)
	if err != nil {
		// Session not found or expired, redirect to start
		return c.Redirect(http.StatusSeeOther, "/test-storage")
	}

	// Get delegation
	dlg := strings.TrimSpace(c.FormValue("delegation"))
	if dlg == "" {
		// Create help texts with test storage specific info
		testHelpTexts := *h.helpTexts
		testHelpTexts.DelegationProof.Command = fmt.Sprintf("# Using the key file you saved during setup (either PEM or JSON format):\npiri delegation generate \\\n  --key-file=service.pem \\\n  --client-did=%s\n\n# If you saved your key as JSON instead of PEM:\npiri delegation generate \\\n  --key-file=service.json \\\n  --client-did=%s", h.service.GetDelegatorDID(), h.service.GetDelegatorDID())

		data := &TestStorageTemplateData{
			TemplateData: &TemplateData{
				Title: "Test Storage - Provide Delegation",
				Error: "Delegation is required",
			},
			Step:          2,
			TestSessionID: testSessionID,
			TestSession: &TestSession{
				SessionID: testSessionID,
				DID:       session.DID,
				FQDN:      session.FQDN,
			},
			FormData: map[string]string{
				"Delegation": dlg,
			},
			HelpTexts:    testHelpTexts,
			DelegatorDID: h.service.GetDelegatorDID(),
		}
		return h.render(c, "test-storage-delegation.html", data)
	}

	// Store delegation in session for the test
	session.Proof = dlg
	session.Status = "test_storage_delegated"
	if err := h.sessionStore.UpdateSession(session); err != nil {
		// Create help texts with test storage specific info
		testHelpTexts := *h.helpTexts
		testHelpTexts.DelegationProof.Command = fmt.Sprintf("# Using the key file you saved during setup (either PEM or JSON format):\npiri delegation generate \\\n  --key-file=service.pem \\\n  --client-did=%s\n\n# If you saved your key as JSON instead of PEM:\npiri delegation generate \\\n  --key-file=service.json \\\n  --client-did=%s", h.service.GetDelegatorDID(), h.service.GetDelegatorDID())

		data := &TestStorageTemplateData{
			TemplateData: &TemplateData{
				Title: "Test Storage - Provide Delegation",
				Error: "Failed to update session",
			},
			Step:          2,
			TestSessionID: testSessionID,
			TestSession: &TestSession{
				SessionID: testSessionID,
				DID:       session.DID,
				FQDN:      session.FQDN,
			},
			FormData: map[string]string{
				"Delegation": dlg,
			},
			HelpTexts:    testHelpTexts,
			DelegatorDID: h.service.GetDelegatorDID(),
		}
		return h.render(c, "test-storage-delegation.html", data)
	}

	// Start the test in a goroutine
	go func() {
		_, err := h.service.TestStorage(testSessionID, dlg)
		if err != nil {
			// Update session with error status
			session, getErr := h.service.GetTestStorageSession(testSessionID)
			if getErr == nil {
				session.Status = "test_storage_failed"
				// Properly encode error as JSON
				errorJSON, _ := json.Marshal(map[string]string{"error": err.Error()})
				session.TestResult = string(errorJSON)
				_ = h.sessionStore.UpdateSession(session)
			}
		}
	}()

	// Redirect to progress page
	return c.Redirect(http.StatusSeeOther, fmt.Sprintf("/test-storage/progress?test_session_id=%s", testSessionID))
}

// TestStorageProgress shows the progress of the storage test
func (h *WebHandler) TestStorageProgress(c echo.Context) error {
	// Get test session ID
	testSessionID := c.QueryParam("test_session_id")
	if testSessionID == "" {
		testSessionID = h.getSessionIDByType(c, "test_storage")
	}

	if testSessionID == "" {
		// No session found, redirect to start
		return c.Redirect(http.StatusSeeOther, "/test-storage")
	}

	// Get session from service
	session, err := h.service.GetTestStorageSession(testSessionID)
	if err != nil {
		// Session not found or expired, redirect to start
		return c.Redirect(http.StatusSeeOther, "/test-storage")
	}

	// Parse progress if available
	var progress *models.TestProgress
	if session.TestProgress != "" {
		progress = &models.TestProgress{}
		if err := json.Unmarshal([]byte(session.TestProgress), progress); err != nil {
			// Ignore parse errors
			progress = nil
		}
	}

	// Check if test is completed or failed
	if session.Status == "test_storage_completed" || session.Status == "test_storage_failed" {
		// Parse error if exists
		var testError string
		if session.Status == "test_storage_failed" && session.TestResult != "" {
			var errorData struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal([]byte(session.TestResult), &errorData); err == nil {
				testError = errorData.Error
			} else {
				testError = session.TestResult // Fallback to raw message
			}
		}

		// Show results
		data := &TestStorageTemplateData{
			TemplateData: &TemplateData{
				Title: "Test Storage - Results",
			},
			Step: 3,
			TestSession: &TestSession{
				SessionID: testSessionID,
				DID:       session.DID,
				URL:       session.FQDN,
				FQDN:      session.FQDN,
			},
			Success:      session.Status == "test_storage_completed",
			TestResult:   session.TestResult,
			TestError:    testError,
			TestProgress: progress,
		}
		return h.render(c, "test-storage-result.html", data)
	}

	// Show progress page
	data := &TestStorageTemplateData{
		TemplateData: &TemplateData{
			Title: "Test Storage - In Progress",
		},
		Step:          3,
		TestSessionID: testSessionID,
		TestSession: &TestSession{
			SessionID: testSessionID,
			DID:       session.DID,
			URL:       session.FQDN,
			FQDN:      session.FQDN,
		},
		TestProgress: progress,
	}

	return h.render(c, "test-storage-progress.html", data)
}

// TestStorageProgressAPI returns the current progress as JSON for AJAX polling
func (h *WebHandler) TestStorageProgressAPI(c echo.Context) error {
	// Get test session ID
	testSessionID := c.QueryParam("test_session_id")
	if testSessionID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "test_session_id required"})
	}

	// Get session from service
	session, err := h.service.GetTestStorageSession(testSessionID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "session not found"})
	}

	// Parse progress if available
	var progress *models.TestProgress
	if session.TestProgress != "" {
		progress = &models.TestProgress{}
		if err := json.Unmarshal([]byte(session.TestProgress), progress); err != nil {
			progress = nil
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":   session.Status,
		"progress": progress,
		"result":   session.TestResult,
	})
}
