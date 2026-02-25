#!/bin/bash
# Hybrid Company Discovery Script - cabinet_global + pg_database
# Lists ALL databases, uses cabinet_global name if available, otherwise 'My Company'

set -e

# Configuration from environment (NO DEFAULTS)
NAMESPACE="${NAMESPACE:?NAMESPACE environment variable is required}"
CNPG_CONTAINER="${CNPG_CONTAINER:?CNPG_CONTAINER environment variable is required}"
CNPG_CLUSTER_NAME="${CNPG_CLUSTER_NAME:?CNPG_CLUSTER_NAME environment variable is required}"

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Function to get CNPG replica pod (prefer replica to avoid load on primary)
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

# Main execution
main() {
    log "Starting hybrid company discovery..."
    
    # Check if we have kubectl access
    if ! kubectl version --client &>/dev/null; then
        log "❌ kubectl not found or not configured"
        exit 1
    fi
    
    # Get CNPG replica pod
    cnpg_pod=$(get_cnpg_replica_pod)
    
    # Single query: LEFT JOIN pg_database with experio_cabinet
    # - Lists ALL databases (except system ones)
    # - Uses cabinet name if registered, otherwise 'My Company'
    log "Querying all databases with cabinet_global lookup..."
    
    result=$(kubectl exec -n "$NAMESPACE" "$cnpg_pod" -c "$CNPG_CONTAINER" -- \
        psql -d cabinet_global -t -A -c \
        "SELECT d.datname || ':' || COALESCE(NULLIF(TRIM(c.name), ''), 'My Company') FROM pg_database d LEFT JOIN experio_cabinet c ON c.dbname = d.datname WHERE d.datname NOT IN ('postgres', 'template0', 'template1') ORDER BY d.datname;" \
        2>/dev/null)
    
    if [ -z "$result" ]; then
        log "❌ Failed to query databases or no results"
        exit 1
    fi
    
    # Count results
    total_count=$(echo "$result" | wc -l)
    log "✅ Found $total_count databases with company names"
    
    # Output the results (format: dbname:company_name)
    echo "$result"
    
    log "Company discovery completed for $total_count databases"
}

# Run main function
main "$@"