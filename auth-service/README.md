Auth Service (Node.js/Express) for Keycloak-backed Authentication

Overview
This service validates JWTs issued by Keycloak for Nginx auth_request and exposes a public registration endpoint that creates users via the Keycloak Admin API.

Endpoints
- GET /health: Basic service info and Keycloak configuration
- POST /auth/debug-token: Debug token verification (accepts { token })
- POST /auth/register: Public registration
  - Request body:
    {
      "username?": string,
      "email?": string,
      "password": string,
      "firstName?": string,
      "lastName?": string,
      "attributes?": object,
      "temporaryPassword?": boolean
    }
  - Responses:
    - 201 { success: true, userId }
    - 400 { error }
    - 409 { error: "User already exists" }
    - 500 { error, details }
- GET /auth/validate: Used by Nginx auth_request (expects Authorization: Bearer <JWT>)

Environment Variables
- KEYCLOAK_URL: e.g. https://aistudentchapter.lk/keycloak
- KEYCLOAK_REALM: e.g. master or your app realm
- KEYCLOAK_CLIENT_ID: expected audience in user tokens for /auth/validate
- KEYCLOAK_ADMIN_CLIENT_ID: confidential client used for Admin API (defaults to KEYCLOAK_CLIENT_ID if not set)
- KEYCLOAK_ADMIN_CLIENT_SECRET: client secret for the admin client (required)
- PORT (optional): defaults to 3002

Keycloak Setup (v22+ UI)
1) Create or choose an OIDC client for admin actions
   - Client authentication: ON
   - Service accounts roles: ON
   - Credentials tab: copy Client secret
2) Assign service account roles
   - Service account roles tab → filter by realm-management
   - Assign: manage-users, view-users, query-users
3) You may use the same client for both user tokens and admin calls
   - In this case, leave KEYCLOAK_ADMIN_CLIENT_ID unset; the service will use KEYCLOAK_CLIENT_ID.

Nginx Integration
- Internal validation (already configured): location /auth/validate { internal; proxy_pass http://localhost:3002; }
- Public registration (example):
  location /auth/register {
      proxy_pass http://localhost:3002/auth/register;
      proxy_http_version 1.1;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-Proto $scheme;
  }

Running Locally
1) Export env vars:
   export KEYCLOAK_URL=...
   export KEYCLOAK_REALM=...
   export KEYCLOAK_CLIENT_ID=...
   # Optional if same client for admin
   # export KEYCLOAK_ADMIN_CLIENT_ID=...
   export KEYCLOAK_ADMIN_CLIENT_SECRET=...
2) Run: node auth-service.js

Systemd Deployment
- /etc/systemd/system/auth-service.service example:
  [Service]
  WorkingDirectory=/opt/auth-service
  ExecStart=/usr/bin/node auth-service.js
  Environment=NODE_ENV=production
  Environment=KEYCLOAK_URL=...
  Environment=KEYCLOAK_REALM=...
  Environment=KEYCLOAK_CLIENT_ID=...
  Environment=KEYCLOAK_ADMIN_CLIENT_ID=...
  Environment=KEYCLOAK_ADMIN_CLIENT_SECRET=...
  Restart=always

Security Notes
- Do not hardcode secrets in code or repo.
- Consider disabling /auth/debug-token in production (network restrict or remove).
- Add rate limiting and input validation for /auth/register as needed.
- Enforce TLS end-to-end where possible.

Troubleshooting
- 401 unauthorized_client from token endpoint: client auth off or wrong secret.
- 403 from Admin API: missing realm-management roles on service account.
- 400 invalid username/email: Keycloak validation failed; sanitize inputs.
