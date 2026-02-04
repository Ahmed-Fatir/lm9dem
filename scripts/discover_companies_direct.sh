#!/bin/bash
# Fast Company Discovery Script - Direct CNPG Connection
# Uses database discovery from app pod + direct SQL queries to CNPG

set -e

# Configuration from environment (NO DEFAULTS)
NAMESPACE="${NAMESPACE:?NAMESPACE environment variable is required}"
CNPG_CONTAINER="${CNPG_CONTAINER:?CNPG_CONTAINER environment variable is required}"
APP_SELECTOR="${APP_SELECTOR:?APP_SELECTOR environment variable is required}"
CNPG_CLUSTER_NAME="${CNPG_CLUSTER_NAME:?CNPG_CLUSTER_NAME environment variable is required}"

# Function to get CNPG replica pod
get_cnpg_replica_pod() {
    # Try to find a replica pod first (lowest load)
    replica_pod=$(kubectl get pods -n "$NAMESPACE" -l "cnpg.io/instanceRole=replica" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -n "$replica_pod" ]; then
        log "Using CNPG replica pod: $replica_pod"
        echo "$replica_pod"
        return
    fi
    
    # Fallback to any CNPG pod if no replica found
    cnpg_pod=$(kubectl get pods -n "$NAMESPACE" -l "cnpg.io/cluster=$CNPG_CLUSTER_NAME" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -n "$cnpg_pod" ]; then
        log "Using CNPG pod: $cnpg_pod"
        echo "$cnpg_pod"
        return
    fi
    
    log "❌ No CNPG pods found"
    exit 1
}

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Function to get company name via direct SQL
get_company_name_sql() {
    local db_name="$1"
    local cnpg_pod="$2"
    
    log "Querying database: $db_name"
    
    # Direct SQL query to CNPG pod
    result=$(kubectl exec -n "$NAMESPACE" "$cnpg_pod" -c "$CNPG_CONTAINER" -- \
        psql -d "$db_name" -c "select name from res_company where id = '1';" \
        -t -A 2>/dev/null || echo "ERROR")
    
    # Parse the result (remove whitespace and empty lines)
    company_name=$(echo "$result" | grep -v "^$" | head -1)
    # Trim leading and trailing whitespace safely
    company_name=$(echo "$company_name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    if [ -z "$company_name" ] || [ "$company_name" = "ERROR" ]; then
        company_name="Unknown"
        log "  ❌ Failed to get company name for $db_name"
    else
        log "  ✅ Found company: $company_name"
    fi
    
    # Output in clean format for parsing
    echo "$db_name:$company_name"
}

# Function to discover databases from app pod
discover_databases_from_app() {
    log "Discovering databases from app pod..."
    
    # Get an app pod name
    app_pod=$(kubectl get pods -n "$NAMESPACE" -l "app=$APP_SELECTOR" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -z "$app_pod" ]; then
        log "❌ No app pod found"
        exit 1
    fi
    
    log "Using app pod: $app_pod"
    
    # Run database discovery in app pod
    databases=$(kubectl exec -n "$NAMESPACE" "$app_pod" -- bash -c '
        cp /etc/odoo/odoo.conf /tmp/odoo.conf
        echo "" >> /tmp/odoo.conf
        echo "db_host = $HOST" >> /tmp/odoo.conf
        echo "db_user = $USER" >> /tmp/odoo.conf
        echo "db_password = $PASSWORD" >> /tmp/odoo.conf
        timeout 30s click-odoo-listdb --config=/tmp/odoo.conf 2>/dev/null | tr "\n" " "
    ' 2>/dev/null || echo "")
    
    if [ -z "$databases" ]; then
        log "❌ Failed to discover databases"
        exit 1
    fi
    
    log "Found $(echo $databases | wc -w) databases"
    echo "$databases"
}

# Main execution
main() {
    log "Starting fast company discovery via CNPG..."
    
    # Check if we have kubectl access
    if ! kubectl version --client &>/dev/null; then
        log "❌ kubectl not found or not configured"
        exit 1
    fi
    
    # Get CNPG replica pod
    cnpg_pod=$(get_cnpg_replica_pod)
    
    # Single database mode for testing
    if [ -n "$1" ]; then
        log "Testing single database: $1"
        get_company_name_sql "$1" "$cnpg_pod"
        return
    fi
    
    # Discover all databases
    databases=$(discover_databases_from_app)
    
    if [ -z "$databases" ]; then
        log "❌ No databases found"
        exit 1
    fi
    
    # Process each database
    total_count=$(echo $databases | wc -w)
    current=0
    
    for db in $databases; do
        if [ -n "$db" ]; then
            current=$((current + 1))
            log "Progress: $current/$total_count"
            get_company_name_sql "$db" "$cnpg_pod"
        fi
    done
    
    log "Company discovery completed for $total_count databases"
}

# Run main function
main "$@"