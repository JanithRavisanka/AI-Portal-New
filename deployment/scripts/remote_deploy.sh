#!/bin/bash

# Check if IP and Key are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <DROPLET_IP> <SSH_KEY_PATH>"
    echo "Example: $0 192.168.1.1 ~/.ssh/id_rsa"
    exit 1
fi

DROPLET_IP=$1
SSH_KEY_PATH=$2
REMOTE_USER="root"
PROJECT_DIR="/opt/ai-portal"
# Determine the absolute path to the project root
# Script is in deployment/scripts/, so we go up two levels
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LOCAL_PROJECT_PATH="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "Deploying from $LOCAL_PROJECT_PATH to $DROPLET_IP..."

# 1. Create remote directory if it doesn't exist
echo "Creating remote directory..."
ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no "$REMOTE_USER@$DROPLET_IP" "mkdir -p $PROJECT_DIR"

# 2. Sync files (excluding node_modules, .git, etc. via rsync)
echo "Syncing files..."
# Ensure trailing slash on source to copy contents, not the directory itself
rsync -avz -e "ssh -i $SSH_KEY_PATH" \
    --exclude 'node_modules' \
    --exclude '.git' \
    --exclude '.next' \
    --exclude '__pycache__' \
    --exclude '.env.local' \
    "$LOCAL_PROJECT_PATH/" "$REMOTE_USER@$DROPLET_IP:$PROJECT_DIR"

# 3. Run Docker Compose on remote
echo "Starting services on remote..."
ssh -i "$SSH_KEY_PATH" "$REMOTE_USER@$DROPLET_IP" << 'EOF'
    PROJECT_DIR="/opt/ai-portal"

    # Install Docker if not present
    if ! command -v docker &> /dev/null; then
        echo "Docker not found. Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        rm get-docker.sh
    fi

    # Install Nginx if not present
    if ! command -v nginx &> /dev/null; then
        echo "Nginx not found. Installing Nginx..."
        apt-get update
        apt-get install -y nginx
    fi

    # Configure Nginx
    echo "Configuring Nginx..."
    cp $PROJECT_DIR/deployment/nginx/aistudentchapter /etc/nginx/sites-available/aistudentchapter
    ln -sf /etc/nginx/sites-available/aistudentchapter /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Install Certbot if not present
    if ! command -v certbot &> /dev/null; then
        echo "Certbot not found. Installing Certbot..."
        apt-get update
        apt-get install -y certbot
    fi

    # Check if SSL certs exist, otherwise obtain them via Certbot
    if [ ! -f /etc/letsencrypt/live/aistudentchapter.lk/fullchain.pem ]; then
        echo "SSL certificates not found. Attempting to obtain with Certbot..."
        
        # Stop Nginx to free up port 80 for standalone challenge
        systemctl stop nginx
        
        # Run Certbot
        # Note: Using --register-unsafely-without-email for automation. 
        # In production, you should provide an email with -m <email>
        certbot certonly --standalone \
            -d aistudentchapter.lk \
            -d www.aistudentchapter.lk \
            --non-interactive \
            --agree-tos \
            --register-unsafely-without-email
            
        if [ ! -f /etc/letsencrypt/live/aistudentchapter.lk/fullchain.pem ]; then
            echo "Error: Certbot failed to obtain certificates. Please check DNS settings."
            exit 1
        fi
    fi

    nginx -t && systemctl reload nginx || systemctl start nginx || echo "Nginx failed to start"

    # Create Docker network if it doesn't exist
    docker network inspect ai_portal_net >/dev/null 2>&1 || docker network create ai_portal_net

    cd $PROJECT_DIR/deployment

    # Install Java 21 (Required for Keycloak 26)
    if ! java -version 2>&1 | grep -q "build 21"; then
        echo "Installing OpenJDK 21..."
        apt-get update
        apt-get install -y openjdk-21-jdk
    fi

    # Install Keycloak 26.0.8
    KEYCLOAK_VERSION="26.0.8"
    KEYCLOAK_DIR="/opt/keycloak"
    
    if [ ! -d "$KEYCLOAK_DIR" ]; then
        echo "Installing Keycloak $KEYCLOAK_VERSION..."
        wget -q https://github.com/keycloak/keycloak/releases/download/$KEYCLOAK_VERSION/keycloak-$KEYCLOAK_VERSION.tar.gz
        tar -xzf keycloak-$KEYCLOAK_VERSION.tar.gz
        mv keycloak-$KEYCLOAK_VERSION $KEYCLOAK_DIR
        rm keycloak-$KEYCLOAK_VERSION.tar.gz
    else
        echo "Keycloak directory exists. Skipping download."
    fi

    # Build Keycloak
    echo "Building Keycloak..."
    # We need to pass build-time vars here for the build command
    export KC_DB=postgres
    
    $KEYCLOAK_DIR/bin/kc.sh build

    # Build Auth Service image
    echo "Building Auth Service image..."
    docker build -t deployment-auth-service:latest ../auth-service

    # Copy service files to systemd directory
    echo "Installing systemd services..."
    cp $PROJECT_DIR/deployment/services/keycloak.service /etc/systemd/system/
    cp $PROJECT_DIR/deployment/services/auth-service.service /etc/systemd/system/

    # Reload systemd and start services
    systemctl daemon-reload
    
    echo "Starting Keycloak..."
    systemctl enable keycloak.service
    systemctl restart keycloak.service

    echo "Starting Auth Service..."
    systemctl enable auth-service.service
    systemctl restart auth-service.service

    # Check status
    systemctl status keycloak.service --no-pager
    systemctl status auth-service.service --no-pager
EOF

echo "Deployment complete!"
