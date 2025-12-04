# AI Portal Deployment Guide

This repository contains the deployment configuration for the AI Portal, utilizing a hybrid deployment strategy on a DigitalOcean Droplet.

## 🏗 System Architecture

*   **Keycloak (v26.0.8)**: Deployed as a **native binary** (systemd service) for optimal performance.
    *   **Port**: 8080 (Internal)
    *   **Database**: External DigitalOcean Managed PostgreSQL.
*   **Auth Service**: Deployed as a **Docker container** (systemd service).
    *   **Port**: 3002 (Internal)
*   **Nginx**: Reverse proxy handling SSL termination and routing.
    *   **Port**: 443 (HTTPS)
    *   **SSL**: Let's Encrypt (Certbot).

## 📋 Prerequisites

### Local Machine
*   `rsync`
*   `ssh`

### Remote Server (Ubuntu 24.04)
The deployment script handles most dependencies, but the server requires:
*   **Java 21** (OpenJDK) - *Installed by script*
*   **Docker** - *Installed by script*
*   **Nginx** - *Installed by script*
*   **Certbot** - *Installed by script*

## ⚙️ Configuration

### 1. Environment Variables (`.env`)
Create a `.env` file in the **project root** (same level as `deployment/`). This file **MUST NOT** be committed to Git.

**Template:**
```ini
# Database Configuration (DigitalOcean Managed DB)
KC_DB=postgres
KC_DB_URL="jdbc:postgresql://<DB_HOST>:<DB_PORT>/defaultdb?sslmode=require"
KC_DB_USERNAME=<DB_USER>
KC_DB_PASSWORD=<DB_PASSWORD>

# Keycloak Admin Credentials (Bootstrap)
KC_BOOTSTRAP_ADMIN_USERNAME=admin
KC_BOOTSTRAP_ADMIN_PASSWORD=<STRONG_PASSWORD>

# Keycloak Hostname Settings
KC_HOSTNAME=https://aistudentchapter.lk/keycloak
KC_HOSTNAME_ADMIN=https://aistudentchapter.lk/keycloak

# Proxy & Security
KC_PROXY_HEADERS=xforwarded
KC_SSL_REQUIRED=external
KC_HTTP_ENABLED=true
```

### 2. File Structure
The deployment script expects the following structure locally:
```
AI-Portal-New/
├── .env                    # Secrets file
├── auth-service/           # Node.js Auth Service
├── deployment/
│   ├── nginx/              # Nginx config
│   ├── scripts/            # Deployment scripts
│   ├── services/           # Systemd service files
│   └── keycloak/           # Keycloak Dockerfile (Legacy/Reference)
└── ...
```

## 🚀 Deployment

### Automated Deployment
Use the `remote_deploy.sh` script to deploy everything. This script syncs your local files (including `.env`) to the server and restarts services.

**Usage:**
```bash
./deployment/scripts/remote_deploy.sh <DROPLET_IP> <SSH_KEY_PATH>
```

**Example:**
```bash
./deployment/scripts/remote_deploy.sh 209.38.123.36 ~/.ssh/id_ed25519
```

**What the script does:**
1.  Syncs project files and `.env` to `/opt/ai-portal`.
2.  Installs system dependencies (Java 21, Docker, Nginx, Certbot).
3.  Configures Nginx and obtains SSL certificates.
4.  Downloads and builds Keycloak 26 (if not present).
5.  Builds the `auth-service` Docker image.
6.  Installs and restarts systemd services (`keycloak`, `auth-service`).

## 🛠 Service Management

You can manage the services directly on the server via SSH.

### Keycloak
*   **Status**: `systemctl status keycloak`
*   **Logs**: `journalctl -u keycloak -f`
*   **Restart**: `systemctl restart keycloak`
*   **Location**: `/opt/keycloak`

### Auth Service
*   **Status**: `systemctl status auth-service`
*   **Logs**: `journalctl -u auth-service -f`
*   **Restart**: `systemctl restart auth-service`
*   **Docker Container**: `docker logs -f ai_portal_auth_service`

### Nginx
*   **Status**: `systemctl status nginx`
*   **Logs**: `/var/log/nginx/error.log`
*   **Test Config**: `nginx -t`
*   **Reload**: `systemctl reload nginx`

## 🔗 Endpoints

| Service | Endpoint | URL | Description |
| :--- | :--- | :--- | :--- |
| **Keycloak** | Admin Console | `https://aistudentchapter.lk/keycloak/admin/` | Identity Management |
| **Keycloak** | Discovery | `https://aistudentchapter.lk/keycloak/realms/master/.well-known/openid-configuration` | OIDC Config |
| **Auth Service** | Public Keys | `https://aistudentchapter.lk/auth/public-key-info` | Public Keys (JWKS) |
| **Auth Service** | Register | `https://aistudentchapter.lk/auth/register` | User Registration |
| **Auth Service** | Validate | `https://aistudentchapter.lk/auth/validate` | Internal Token Validation |

## ⚠️ Troubleshooting

### 502 Bad Gateway
*   **Cause**: Keycloak or Auth Service is down.
*   **Fix**: Check logs (`journalctl -u keycloak` or `journalctl -u auth-service`). Ensure Keycloak is listening on port 8080.

### Keycloak "Hostname v1 options [proxy] are still in use"
*   **Cause**: Deprecated `KC_PROXY` env var.
*   **Fix**: Ensure `KC_PROXY` is removed from `.env` and `keycloak.service`. Use `KC_PROXY_HEADERS=xforwarded` instead.

### "No such file or directory" during deployment
*   **Cause**: Variable scope issue in script.
*   **Fix**: Ensure `PROJECT_DIR` is defined inside the remote execution block in `remote_deploy.sh`.
