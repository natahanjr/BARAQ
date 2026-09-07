# BARAQ E2E Testing (Playwright)

## Overview

BARAQ uses **Playwright** for end-to-end browser testing of the frontend authentication flows. The test suite validates login, registration, form validation, and backend integration.

## Setup

### Prerequisites
- Node.js 18+
- PostgreSQL running on port 5432
- BARAQ backend running on port 8001

### Installation

```bash
cd frontend
npm install
npx playwright install chromium
```

## Running Tests

```bash
# Run all tests
npm run test:e2e

# Run with UI mode (interactive)
npm run test:e2e:ui

# Run in headed mode (visible browser)
npm run test:e2e:headed
```

## Test Structure

```
frontend/
├── e2e/
│   └── auth.spec.js          # Authentication E2E tests
├── playwright.config.js       # Playwright configuration
└── playwright-report/         # HTML test reports
```

## Test Coverage

### Authentication (17 tests)

| Category | Tests |
|----------|-------|
| Login Page | Rendering, default hints, button states |
| Registration | Mode switching, password validation, account creation |
| Form Validation | Username pattern, password length, required fields |
| Backend Integration | Valid/invalid login, wrong password, registration |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_URL` | `http://localhost:5173` | Frontend URL |
| `E2E_ADMIN_USER` | `admin` | Admin username |
| `E2E_ADMIN_PASS` | `BaraqAdmin2026!` | Admin password |
| `E2E_TEST_USER` | `testuser` | Test user for registration |
| `E2E_TEST_PASS` | `testpassword123` | Test user password |

## Configuration

The Playwright config (`playwright.config.js`) includes:

- **Base URL**: `http://localhost:5173` (Vite dev server)
- **Browser**: Chromium (Desktop Chrome)
- **Web Server**: Auto-starts Vite dev server
- **Retries**: 2 on CI, 0 locally
- **Reporter**: HTML + list

## CI/CD Integration

For CI environments, set:

```bash
export CI=true
export E2E_ADMIN_USER=admin
export E2E_ADMIN_PASS=<secure-password>
```

## Troubleshooting

### Backend not running
Tests that require the backend will automatically skip if `http://localhost:8001/api/health` is unreachable.

### Rate limiting
The backend rate-limits failed login attempts. Wait 90 seconds between test runs if you hit rate limits.

### Database issues
Ensure PostgreSQL is running:
```bash
# Check status
pg_ctl status -D pg/data2

# Start if needed
pg_ctl start -D pg/data2 -l pg/pg_service.log
```
