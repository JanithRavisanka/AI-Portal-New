# AI Portal Deployment

This directory contains the deployment configuration for the AI Portal, including Docker Compose files, Nginx configuration, and deployment scripts.

## Services

The deployment consists of the following services orchestrated via `docker-compose`:

*   **Keycloak**: Identity and Access Management (Port 8080).
    *   Uses an external PostgreSQL database (DigitalOcean Managed DB).
*   **Auth Service**: Node.js service for authentication validation (Port 3002).
*   **Nginx**: Reverse proxy (running on host) routing traffic to these containers.

> **Note**: The Blog API and Frontend services are currently commented out in `docker-compose.yml` and are not part of this specific deployment configuration yet.

## Prerequisites

*   **Docker** and **Docker Compose** installed on the target server.
*   **Nginx** installed on the target server.
*   **SSL Certificates** (Let's Encrypt) set up for `aistudentchapter.lk`.

## Configuration

### Environment Variables

The `docker-compose.yml` file contains the necessary environment variables. Keycloak is configured to connect to the DigitalOcean Managed PostgreSQL database.

**Keycloak Credentials**:
*   Admin Console: `https://aistudentchapter.lk/keycloak/`
*   Initial Admin User: `admin`
*   Initial Admin Password: `admin` (Change this immediately after first login!)

## Deployment

### Using the Deployment Script

A helper script `scripts/remote_deploy.sh` is provided to automate the deployment process.

**Usage**:
```bash
./scripts/remote_deploy.sh <DROPLET_IP> <SSH_KEY_PATH>
```

**Example**:
```bash
./scripts/remote_deploy.sh 192.168.1.1 ~/.ssh/id_rsa
```

This script will:
1.  Sync the project files to the remote server using `rsync`.
2.  SSH into the server.
3.  Rebuild and restart the Docker containers using `docker compose up -d --build`.

### Manual Deployment

1.  Copy the project files to the server.
2.  Navigate to the `deployment` directory.
3.  Run:
    ```bash
    docker compose up -d --build
    ```
4.  Ensure Nginx is configured to proxy requests to the correct ports (see `nginx/aistudentchapter`).
5.  Reload Nginx: `systemctl reload nginx`.

## Directory Structure

*   `docker-compose.yml`: Main Docker orchestration file.
*   `nginx/`: Nginx server block configurations.
*   `scripts/`: Helper scripts for deployment.
*   `services/`: Systemd service files (legacy/reference).
