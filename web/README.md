# Web UI for Storacha Delegator

This directory contains the web user interface for the Storacha Delegator service, providing an accessible HTML-based alternative to the command-line interface.

## Features

- **Progressive Web Interface**: Server-side rendered HTML with optional JavaScript enhancements
- **Complete Onboarding Flow**: Step-by-step WSP (Warm Storage Provider) registration
- **Real-time Status Tracking**: Monitor onboarding progress with auto-refresh
- **Mobile-First Design**: Responsive interface that works on all devices
- **Accessibility**: Semantic HTML, keyboard navigation, and screen reader support

## Structure

```
web/
├── handlers/           # Go HTTP handlers for web routes
│   ├── web.go         # Main web handler and utilities
│   └── onboarding.go  # Onboarding flow handlers
├── templates/         # HTML templates
│   ├── base.html      # Base layout with navigation
│   ├── home.html      # Dashboard/home page
│   ├── onboard.html   # Multi-step onboarding flow
│   └── status.html    # Session status page
└── static/           # Static assets
    ├── css/
    │   └── style.css  # Main stylesheet
    └── js/
        └── app.js     # Progressive enhancement JavaScript
```

## Pages

### Dashboard (`/`)
- Service health status
- Quick onboarding start
- Session lookup by ID
- Basic statistics (when available)

### Onboarding Flow (`/onboard`)
**Step 1: DID Registration**
- Enter and verify DID (Decentralized Identifier)
- Download generated delegation file

**Step 2: FQDN Verification**
- Provide storage node URL
- Automatic verification of DID response

**Step 3: Proof Submission**
- Upload delegation proof
- Complete provider registration

**Step 4: Completion**
- Registration confirmation
- Final delegation download

### Session Status (`/onboard/status/{session_id}`)
- Current progress visualization
- Session details and timestamps
- Next step instructions
- Delegation file download

## Technical Details

### Backend Integration
- Reuses existing API handlers and business logic
- Shared models and services with JSON API
- Template rendering with Go's `html/template`
- Static file serving for CSS/JS

### Frontend Architecture
- **HTML-first**: Works without JavaScript
- **Progressive Enhancement**: JavaScript adds UX improvements
- **CSS Grid/Flexbox**: Modern responsive layout
- **Form Validation**: Both client-side and server-side

### Security Features
- Server-side input validation
- CSRF protection ready
- Secure headers
- Input sanitization

## Usage

### Starting the Server
```bash
# Build the project
make build

# Start server with web UI
./bin/delegator server --port 8080

# Access web interface
open http://localhost:8080
```

### API Compatibility
The web UI runs alongside the existing JSON API:
- Web UI: `http://localhost:8080/`
- JSON API: `http://localhost:8080/api/v1/`

## Development

### Adding New Pages
1. Create HTML template in `templates/`
2. Add handler method to appropriate handler file
3. Register route in `internal/api/routes.go`

### Styling Guidelines
- Mobile-first responsive design
- CSS custom properties for theming
- Semantic class names
- Accessibility considerations

### JavaScript Enhancement
- Keep JavaScript optional
- Use vanilla JS (no frameworks)
- Focus on progressive enhancement
- Maintain accessibility

## Browser Support

- **Modern Browsers**: Full feature support
- **Older Browsers**: Core functionality works without JavaScript
- **Mobile**: Responsive design with touch-friendly interface
- **Screen Readers**: Semantic HTML with ARIA labels

## Customization

### Theming
Edit CSS custom properties in `style.css`:
```css
:root {
    --primary-color: #2563eb;
    --background-color: #f8fafc;
    /* ... other variables ... */
}
```

### Templates
Templates use Go's `html/template` package:
- `base.html`: Common layout and navigation
- Page-specific templates extend the base
- Template data passed from handlers

### Validation
Client-side validation enhances UX but server-side validation is authoritative:
- HTML5 form validation
- JavaScript real-time feedback
- Go handler validation