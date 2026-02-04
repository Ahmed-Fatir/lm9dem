#!/bin/bash
set -e

# Database Backup Script for lm9dem
# Adapted from v2-backup.sh logic for container environment
# Usage: ./backup_database.sh <database_name> <output_path>

DATABASE="$1"
OUTPUT_PATH="$2"

if [ -z "$DATABASE" ] || [ -z "$OUTPUT_PATH" ]; then
    echo "Usage: $0 <database_name> <output_path>"
    exit 1
fi

echo "Starting backup for database: $DATABASE"
echo "Output path: $OUTPUT_PATH"

# Configuration from environment (NO DEFAULTS - FAIL FAST)
REMOTE_HOST="${DEPLOYMENT_SERVER_IP:?DEPLOYMENT_SERVER_IP environment variable is required}"
REMOTE_USER="${SSH_USERNAME:?SSH_USERNAME environment variable is required}"
REMOTE_BACKUP_DIR="${REMOTE_BACKUP_DIR:?REMOTE_BACKUP_DIR environment variable is required}"
REMOTE_SCRIPT_DIR="${REMOTE_SCRIPT_DIR:?REMOTE_SCRIPT_DIR environment variable is required}"
NAMESPACE="${NAMESPACE:?NAMESPACE environment variable is required}"
DUMP_FILE="${DATABASE}.dump"

# Function to log messages with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check SSH connectivity
check_ssh_connection() {
    log "Testing SSH connection to $REMOTE_USER@$REMOTE_HOST..."
    if ! ssh -o ConnectTimeout=10 -o BatchMode=yes "$REMOTE_USER@$REMOTE_HOST" "echo 'SSH connection successful'" >/dev/null 2>&1; then
        log "❌ ERROR: Cannot connect to $REMOTE_USER@$REMOTE_HOST"
        log "Please ensure SSH key authentication is set up and host is accessible"
        exit 1
    fi
    log "✅ SSH connection verified"
}

log "Starting backup process for database: $DATABASE"

# Check SSH connectivity first
check_ssh_connection

log "Connecting to remote machine and starting backup process..."

# Execute the backup process on remote machine via SSH (following v2-backup.sh pattern)
ssh "$REMOTE_USER@$REMOTE_HOST" << EOF
    set -e
    
    echo "[REMOTE] Starting backup process for database: $DATABASE"
    
    # Navigate to the script directory
    if [ ! -d "$REMOTE_SCRIPT_DIR" ]; then
        echo "[REMOTE] ❌ ERROR: Script directory $REMOTE_SCRIPT_DIR not found!"
        exit 1
    fi
    
    cd "$REMOTE_SCRIPT_DIR"
    
    # Check if backup script exists
    if [ ! -f "backup-one-db.sh" ]; then
        echo "[REMOTE] ❌ ERROR: backup-one-db.sh script not found in $REMOTE_SCRIPT_DIR"
        exit 1
    fi
    
    # Remove old dump file if it exists
    if [ -f "$REMOTE_BACKUP_DIR/$DUMP_FILE" ]; then
        echo "[REMOTE] Removing old dump file: $REMOTE_BACKUP_DIR/$DUMP_FILE"
        rm -f "$REMOTE_BACKUP_DIR/$DUMP_FILE"
    fi
    
    # Convert database name for Kubernetes (replace underscores with dashes)
    K8S_NAME=\$(echo "$DATABASE" | sed 's/_/-/g')
    
    # Check and remove existing backup job if it exists
    echo "[REMOTE] Checking for existing backup job: backup-\$K8S_NAME"
    if kubectl get job "backup-\$K8S_NAME" -n $NAMESPACE >/dev/null 2>&1; then
        echo "[REMOTE] Found existing backup job, removing it..."
        kubectl delete job "backup-\$K8S_NAME" -n $NAMESPACE --ignore-not-found=true
        echo "[REMOTE] ✅ Old backup job removed successfully"
        sleep 2
    fi
    
    # Run the backup script
    echo "[REMOTE] Running backup script for database: $DATABASE"
    if ! ./backup-one-db.sh "$DATABASE"; then
        echo "[REMOTE] ❌ ERROR: backup-one-db.sh failed for database: $DATABASE"
        exit 1
    fi
    
    # Wait for the backup job to complete
    echo "[REMOTE] Waiting for backup job to complete..."
    
    # Wait for job completion (timeout after 25 minutes for container context)
    TIMEOUT=1500
    ELAPSED=0
    SLEEP_INTERVAL=10
    
    while [ \$ELAPSED -lt \$TIMEOUT ]; do
        JOB_STATUS=\$(kubectl get job "backup-\$K8S_NAME" -n $NAMESPACE -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null || echo "")
        JOB_FAILED=\$(kubectl get job "backup-\$K8S_NAME" -n $NAMESPACE -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}' 2>/dev/null || echo "")
        
        if [ "\$JOB_STATUS" = "True" ]; then
            echo "[REMOTE] ✅ Backup job completed successfully!"
            break
        elif [ "\$JOB_FAILED" = "True" ]; then
            echo "[REMOTE] ❌ Backup job failed!"
            kubectl logs -n $NAMESPACE -l app=\$K8S_NAME-backup --tail=20 2>/dev/null || echo "Failed to get logs"
            exit 1
        fi
        
        sleep \$SLEEP_INTERVAL
        ELAPSED=\$((ELAPSED + SLEEP_INTERVAL))
        
        if [ \$((ELAPSED % 60)) -eq 0 ]; then
            echo "[REMOTE] Still waiting for backup to complete... (\$((ELAPSED / 60)) minutes elapsed)"
        fi
    done
    
    if [ \$ELAPSED -ge \$TIMEOUT ]; then
        echo "[REMOTE] ❌ Backup job timed out after \$((TIMEOUT / 60)) minutes"
        exit 1
    fi
    
    # Verify the dump file was created
    if [ ! -f "$REMOTE_BACKUP_DIR/$DUMP_FILE" ]; then
        echo "[REMOTE] ❌ ERROR: Dump file $REMOTE_BACKUP_DIR/$DUMP_FILE was not created!"
        exit 1
    fi
    
    DUMP_SIZE=\$(ls -lh "$REMOTE_BACKUP_DIR/$DUMP_FILE" | awk '{print \$5}')
    echo "[REMOTE] ✅ Backup file created successfully: $DUMP_FILE (Size: \$DUMP_SIZE)"
EOF

if [ $? -ne 0 ]; then
    log "❌ Remote backup process failed!"
    exit 1
fi

log "Remote backup completed successfully. Copying file to container..."

# Copy the dump file from remote to container
log "Copying $DUMP_FILE from remote machine to container..."

if scp "$REMOTE_USER@$REMOTE_HOST:$REMOTE_BACKUP_DIR/$DUMP_FILE" "$OUTPUT_PATH"; then
    # Get local file size
    LOCAL_SIZE=$(ls -lh "$OUTPUT_PATH" | awk '{print $5}')
    log "✅ File copied successfully to: $OUTPUT_PATH (Size: $LOCAL_SIZE)"
else
    log "❌ Failed to copy dump file from remote machine"
    exit 1
fi

# Clean up remote dump file
log "Cleaning up remote dump file..."
ssh "$REMOTE_USER@$REMOTE_HOST" "rm -f $REMOTE_BACKUP_DIR/$DUMP_FILE" || {
    log "⚠️  Warning: Could not clean up remote dump file (this is not critical)"
}

log "✅ Database backup process completed successfully!"
log "Database: $DATABASE"
log "Local backup file: $OUTPUT_PATH"
log "File size: $(ls -lh "$OUTPUT_PATH" | awk '{print $5}')"
log "Backup completed at: $(date)"