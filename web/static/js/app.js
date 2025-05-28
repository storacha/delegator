// Progressive Enhancement JavaScript for Delegator Web UI
(function() {
    'use strict';

    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        initFormValidation();
        initAutoRefresh();
        initClipboard();
        initFormEnhancements();
        initSessionManagement();
    });

    // Enhanced form validation
    function initFormValidation() {
        const forms = document.querySelectorAll('form');
        
        forms.forEach(function(form) {
            // Add real-time validation for DID inputs
            const didInput = form.querySelector('input[name="did"]');
            if (didInput) {
                didInput.addEventListener('input', function() {
                    validateDID(this);
                });
            }

            // Add real-time validation for URL inputs
            const urlInput = form.querySelector('input[name="url"]');
            if (urlInput) {
                urlInput.addEventListener('input', function() {
                    validateURL(this);
                });
            }

            // Prevent double-submission
            form.addEventListener('submit', function() {
                const submitBtn = form.querySelector('button[type="submit"]');
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Processing...';
                    
                    // Re-enable after 5 seconds as fallback
                    setTimeout(function() {
                        submitBtn.disabled = false;
                        submitBtn.textContent = submitBtn.getAttribute('data-original-text') || 'Submit';
                    }, 5000);
                }
            });
        });
    }

    // Validate DID format
    function validateDID(input) {
        const value = input.value.trim();
        const isValid = value === '' || value.startsWith('did:');
        
        updateFieldValidation(input, isValid, 'DID must start with "did:"');
    }

    // Validate URL format
    function validateURL(input) {
        const value = input.value.trim();
        let isValid = true;
        let message = '';

        if (value !== '') {
            try {
                const url = new URL(value);
                if (url.protocol !== 'https:' && url.protocol !== 'http:') {
                    isValid = false;
                    message = 'URL must use HTTP or HTTPS protocol';
                }
            } catch (e) {
                isValid = false;
                message = 'Please enter a valid URL';
            }
        }

        updateFieldValidation(input, isValid, message);
    }

    // Update field validation state
    function updateFieldValidation(input, isValid, message) {
        const helpElement = input.parentNode.querySelector('.form-help');
        
        if (isValid) {
            input.classList.remove('error');
            if (helpElement && helpElement.classList.contains('error-message')) {
                helpElement.style.display = 'none';
            }
        } else {
            input.classList.add('error');
            if (helpElement) {
                if (!helpElement.classList.contains('error-message')) {
                    // Create error message element
                    const errorElement = document.createElement('div');
                    errorElement.className = 'form-help error-message';
                    errorElement.style.color = '#dc2626';
                    errorElement.textContent = message;
                    input.parentNode.appendChild(errorElement);
                } else {
                    helpElement.textContent = message;
                    helpElement.style.display = 'block';
                }
            }
        }
    }

    // Auto-refresh for status page
    function initAutoRefresh() {
        const statusPage = document.querySelector('.status-content');
        if (statusPage) {
            const refreshInterval = 30000; // 30 seconds
            let refreshTimer;

            function startAutoRefresh() {
                refreshTimer = setInterval(function() {
                    const refreshBtn = document.querySelector('button[onclick*="refreshStatus"]');
                    if (refreshBtn) {
                        window.location.reload();
                    }
                }, refreshInterval);
            }

            // Start auto-refresh for non-completed sessions
            const statusBadge = document.querySelector('.status-badge');
            if (statusBadge && !statusBadge.classList.contains('status-completed')) {
                startAutoRefresh();
            }

            // Stop auto-refresh when page is not visible
            document.addEventListener('visibilitychange', function() {
                if (document.hidden) {
                    clearInterval(refreshTimer);
                } else if (statusBadge && !statusBadge.classList.contains('status-completed')) {
                    startAutoRefresh();
                }
            });
        }
    }

    // Enhanced clipboard functionality
    function initClipboard() {
        // Add copy buttons to code elements
        const codeElements = document.querySelectorAll('code');
        codeElements.forEach(function(code) {
            if (code.textContent.length > 20) { // Only add copy button for longer codes
                const wrapper = document.createElement('div');
                wrapper.style.position = 'relative';
                wrapper.style.display = 'inline-block';
                
                const copyBtn = document.createElement('button');
                copyBtn.textContent = '📋';
                copyBtn.className = 'btn btn-link';
                copyBtn.style.fontSize = '0.8rem';
                copyBtn.style.padding = '0.25rem';
                copyBtn.style.marginLeft = '0.5rem';
                copyBtn.title = 'Copy to clipboard';
                
                copyBtn.addEventListener('click', function() {
                    copyToClipboard(code.textContent, copyBtn);
                });
                
                code.parentNode.insertBefore(wrapper, code);
                wrapper.appendChild(code);
                wrapper.appendChild(copyBtn);
            }
        });
    }

    // Copy text to clipboard with visual feedback
    function copyToClipboard(text, button) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(function() {
                showCopyFeedback(button);
            }).catch(function() {
                fallbackCopyToClipboard(text, button);
            });
        } else {
            fallbackCopyToClipboard(text, button);
        }
    }

    // Fallback copy method for older browsers
    function fallbackCopyToClipboard(text, button) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.left = '-999999px';
        textarea.style.top = '-999999px';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        
        try {
            document.execCommand('copy');
            showCopyFeedback(button);
        } catch (err) {
            console.error('Failed to copy text: ', err);
        }
        
        document.body.removeChild(textarea);
    }

    // Show visual feedback for copy action
    function showCopyFeedback(button) {
        const originalText = button.textContent;
        button.textContent = '✅';
        button.style.color = '#059669';
        
        setTimeout(function() {
            button.textContent = originalText;
            button.style.color = '';
        }, 2000);
    }

    // Form enhancements
    function initFormEnhancements() {
        // Auto-focus first input in forms
        const firstInput = document.querySelector('form input[type="text"], form input[type="url"], form textarea');
        if (firstInput && !firstInput.value) {
            firstInput.focus();
        }

        // Add loading states to forms
        const forms = document.querySelectorAll('form');
        forms.forEach(function(form) {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.setAttribute('data-original-text', submitBtn.textContent);
            }
        });

        // Enhanced textarea auto-resize
        const textareas = document.querySelectorAll('textarea');
        textareas.forEach(function(textarea) {
            textarea.addEventListener('input', function() {
                this.style.height = 'auto';
                this.style.height = (this.scrollHeight) + 'px';
            });
        });
    }

    // Add CSS for enhanced validation
    const style = document.createElement('style');
    style.textContent = `
        .form-input.error {
            border-color: #dc2626;
            box-shadow: 0 0 0 3px rgba(220, 38, 38, 0.1);
        }
        .error-message {
            color: #dc2626 !important;
            margin-top: 0.25rem;
        }
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        .copy-feedback {
            animation: copyPulse 0.3s ease-in-out;
        }
        @keyframes copyPulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); }
        }
    `;
    document.head.appendChild(style);
    
    // Session management using cookies with localStorage as fallback
    function initSessionManagement() {
        console.log('Initializing session management');
        
        // Log the current state for debugging
        console.log('Local storage session ID:', localStorage.getItem('delegator_session_id'));
        console.log('Cookies:', document.cookie);
        
        // Try to get session ID from localStorage as fallback
        const savedSessionId = localStorage.getItem('delegator_session_id');
        if (savedSessionId) {
            console.log('Found session ID in localStorage:', savedSessionId);
            
            // Update form inputs with session ID from localStorage
            document.querySelectorAll('input[name="session_id"]').forEach(input => {
                if (!input.value) {
                    input.value = savedSessionId;
                    console.log('Updated form input with saved session ID:', savedSessionId);
                }
            });
        }
    }
        
        // Add special handler for FQDN form submission 
        const fqdnForm = document.getElementById('fqdn-form');
        if (fqdnForm) {
            console.log('Found FQDN form, adding special handler');
            fqdnForm.addEventListener('submit', function(e) {
                // Check if the session ID is available
                const sessionIdInput = document.getElementById('session_id_input');
                if (!sessionIdInput || !sessionIdInput.value) {
                    // Try to get from localStorage
                    const savedId = localStorage.getItem('delegator_session_id');
                    if (savedId) {
                        console.log('FQDN form: Setting session ID from localStorage:', savedId);
                        if (sessionIdInput) {
                            sessionIdInput.value = savedId;
                        } else {
                            const input = document.createElement('input');
                            input.type = 'hidden';
                            input.name = 'session_id';
                            input.value = savedId;
                            fqdnForm.appendChild(input);
                        }
                    } else {
                        console.warn('No session ID available for FQDN form submission!');
                        e.preventDefault();
                        alert('Session not found. Please restart the onboarding process.');
                    }
                }
            });
        }
        
        // No need to modify links anymore as we're using cookies
        
        // Enhance forms to include session ID from localStorage if not already present or empty
        const forms = document.querySelectorAll('form');
        forms.forEach(function(form) {
            // First, check for empty session inputs and populate from localStorage
            const sessionIdInput = form.querySelector('input[name="session_id"]');
            if (sessionIdInput && !sessionIdInput.value) {
                const savedSessionId = localStorage.getItem('delegator_session_id');
                if (savedSessionId) {
                    console.log('Setting form session ID from localStorage:', savedSessionId);
                    sessionIdInput.value = savedSessionId;
                }
            }
            
            // Then handle form submission
            form.addEventListener('submit', function(e) {
                const sessionIdInput = form.querySelector('input[name="session_id"]');
                if (!sessionIdInput) {
                    // Add session ID if input doesn't exist
                    const savedSessionId = localStorage.getItem('delegator_session_id');
                    if (savedSessionId) {
                        console.log('Adding session ID to form:', savedSessionId);
                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = 'session_id';
                        input.value = savedSessionId;
                        form.appendChild(input);
                    }
                } else if (!sessionIdInput.value) {
                    // Update session ID if input exists but is empty
                    const savedSessionId = localStorage.getItem('delegator_session_id');
                    if (savedSessionId) {
                        console.log('Updating empty session ID in form:', savedSessionId);
                        sessionIdInput.value = savedSessionId;
                    }
                }
                
                // Double-check we have a session ID, or alert user
                const finalSessionInput = form.querySelector('input[name="session_id"]');
                if (!finalSessionInput || !finalSessionInput.value) {
                    console.warn('No session ID available for form submission');
                }
            });
        });
    }

})();