#!/bin/bash
# scripts/clientManagement/register-clients.sh
# Registers OAuth2 clients from configs/clients.json

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CLIENTS_CONFIG="$PROJECT_ROOT/configs/clients.json"
ENV_FILE="$PROJECT_ROOT/.env.clients"

# Parse command line arguments
USE_LOCAL=false
for arg in "$@"; do
    if [ "$arg" = "--local" ]; then
        USE_LOCAL=true
    fi
done

# Set AUTH_SERVICE_URL based on flag
if [ "$USE_LOCAL" = true ]; then
    AUTH_SERVICE_URL="${AUTH_SERVICE_URL:-http://localhost:8080}"
else
    AUTH_SERVICE_URL="${AUTH_SERVICE_URL:-http://sous-chef-proxy.local}"
fi

# Terminal width for formatting
COLUMNS=$(tput cols 2>/dev/null || echo 80)

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Counters for summary
SUCCESS_COUNT=0
FAILED_COUNT=0
SKIPPED_COUNT=0

# Arrays to store results
declare -a REGISTERED_CLIENTS=()
declare -a FAILED_CLIENTS=()

print_separator() {
    local char="${1:-=}"
    local width="${COLUMNS:-80}"
    printf '%*s\n' "$width" '' | tr ' ' "$char"
}

print_header() {
    local title="$1"
    print_separator "="
    echo -e "${CYAN}${BOLD}$title${NC}"
    print_separator "="
}

print_section() {
    local title="$1"
    echo
    print_separator "-"
    echo -e "${BLUE}$title${NC}"
    print_separator "-"
}

print_status() {
    local status="$1"
    local message="$2"
    if [ "$status" = "ok" ]; then
        echo -e "  ✅ ${GREEN}$message${NC}"
    elif [ "$status" = "warning" ]; then
        echo -e "  ⚠️  ${YELLOW}$message${NC}"
    elif [ "$status" = "error" ]; then
        echo -e "  ❌ ${RED}$message${NC}"
    elif [ "$status" = "info" ]; then
        echo -e "  ℹ️  ${CYAN}$message${NC}"
    elif [ "$status" = "processing" ]; then
        echo -e "  ⚙️  ${MAGENTA}$message${NC}"
    else
        echo -e "  $message"
    fi
}

check_dependencies() {
    local deps_ok=true

    print_section "🔍 Checking Dependencies"

    if ! command -v jq >/dev/null 2>&1; then
        print_status "error" "jq is not installed. Please install it first:"
        echo "    Ubuntu/Debian: sudo apt-get install jq"
        echo "    macOS: brew install jq"
        echo "    RHEL/CentOS: sudo yum install jq"
        deps_ok=false
    else
        print_status "ok" "jq is installed"
    fi

    if ! command -v curl >/dev/null 2>&1; then
        print_status "error" "curl is not installed. Please install it first."
        deps_ok=false
    else
        print_status "ok" "curl is installed"
    fi

    if [ ! -f "$CLIENTS_CONFIG" ]; then
        print_status "error" "Client configuration file not found: $CLIENTS_CONFIG"
        deps_ok=false
    else
        print_status "ok" "Client configuration found: $CLIENTS_CONFIG"
    fi

    if [ "$deps_ok" = false ]; then
        echo
        print_status "error" "Missing dependencies. Exiting."
        exit 1
    fi
}

check_auth_service() {
    print_section "🔗 Checking Auth Service Connection"

    echo -e "  ${CYAN}Auth Service URL:${NC} $AUTH_SERVICE_URL"

    if curl -s -f "$AUTH_SERVICE_URL/api/v1/auth/health" > /dev/null 2>&1; then
        print_status "ok" "Auth service is running and healthy"
        return 0
    else
        print_status "error" "Auth service is not reachable at $AUTH_SERVICE_URL"
        echo
        echo "  Please ensure the auth service is running:"
        echo "    For local development: make run"
        echo "    For deployed service: Check Kubernetes deployment"
        echo
        echo "  To use local auth service:"
        echo "    $0 --local"
        echo
        echo "  Or specify a different URL:"
        echo "    AUTH_SERVICE_URL=http://your-auth-service:8080 $0"
        exit 1
    fi
}

initialize_env_file() {
    print_section "📝 Initializing Credentials File"

    # Backup existing file if it exists
    if [ -f "$ENV_FILE" ]; then
        BACKUP_FILE="${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        mv "$ENV_FILE" "$BACKUP_FILE"
        print_status "info" "Backed up existing credentials to: $(basename "$BACKUP_FILE")"
    fi

    # Create new env file with header
    cat > "$ENV_FILE" << EOF
# OAuth2 Client Credentials for Backend Services
# Generated on $(date)
# Auth Service: $AUTH_SERVICE_URL

EOF

    print_status "ok" "Initialized credentials file: .env.clients"
}

register_client() {
    local client_json="$1"
    local index="$2"
    local total="$3"

    # Extract client details
    local name
    local redirect_uris
    local scopes
    local grant_types
    name=$(echo "$client_json" | jq -r '.name')
    redirect_uris=$(echo "$client_json" | jq -c '.redirect_uris')
    scopes=$(echo "$client_json" | jq -c '.scopes')
    grant_types=$(echo "$client_json" | jq -c '.grant_types')

    echo
    echo -e "${BOLD}[$index/$total] Registering: ${CYAN}$name${NC}"
    print_separator "."

    # Prepare request body
    local request_body
    request_body=$(jq -n \
        --arg name "$name" \
        --argjson redirect_uris "$redirect_uris" \
        --argjson scopes "$scopes" \
        --argjson grant_types "$grant_types" \
        '{
            name: $name,
            redirect_uris: $redirect_uris,
            scopes: $scopes,
            grant_types: $grant_types
        }')

    # Display request details
    print_status "info" "Grant Types: $(echo "$grant_types" | jq -r 'join(", ")')"
    print_status "info" "Scopes: $(echo "$scopes" | jq -r 'join(", ")')"

    # Make API request
    print_status "processing" "Sending registration request..."

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X POST \
        "$AUTH_SERVICE_URL/api/v1/auth/oauth/clients" \
        -H "Content-Type: application/json" \
        -d "$request_body" 2>/dev/null)

    http_code=$(echo "$response" | tail -n1)
    response_body=$(echo "$response" | head -n-1)

    if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
        # Extract credentials
        local client_id
        local client_secret
        client_id=$(echo "$response_body" | jq -r '.id')
        client_secret=$(echo "$response_body" | jq -r '.secret')

        if [ -n "$client_id" ] && [ "$client_id" != "null" ]; then
            print_status "ok" "Successfully registered!"
            echo -e "  ${GREEN}Client ID:${NC}     $client_id"
            echo -e "  ${GREEN}Client Secret:${NC} $client_secret"

            # Save to env file
            local env_name
            env_name=$(echo "$name" | tr '[:lower:]' '[:upper:]' | tr ' ' '_')
            cat >> "$ENV_FILE" << EOF

# $name
${env_name}_CLIENT_ID="$client_id"
${env_name}_CLIENT_SECRET="$client_secret"
EOF

            # Store for summary
            REGISTERED_CLIENTS+=("$name|$client_id")
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            print_status "error" "Invalid response from server"
            echo "  Response: $response_body"
            FAILED_CLIENTS+=("$name|Invalid response")
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    elif [ "$http_code" = "409" ]; then
        print_status "warning" "Client already exists"
        local existing_msg
        existing_msg=$(echo "$response_body" | jq -r '.error // .message // "Client with this name already exists"')
        echo "  $existing_msg"
        FAILED_CLIENTS+=("$name|Already exists")
        SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
    else
        print_status "error" "Registration failed (HTTP $http_code)"
        local error_msg
        error_msg=$(echo "$response_body" | jq -r '.error // .message // "Unknown error"' 2>/dev/null || echo "$response_body")
        echo "  Error: $error_msg"
        FAILED_CLIENTS+=("$name|HTTP $http_code")
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
}

print_summary() {
    print_header "📊 Registration Summary"

    # Status counts
    echo
    echo -e "${BOLD}Results:${NC}"
    echo -e "  ${GREEN}✅ Successful:${NC} $SUCCESS_COUNT"
    echo -e "  ${YELLOW}⚠️  Skipped:${NC}    $SKIPPED_COUNT"
    echo -e "  ${RED}❌ Failed:${NC}     $FAILED_COUNT"

    # Successful registrations table
    if [[ ${#REGISTERED_CLIENTS[@]} -gt 0 ]]; then
        print_section "✅ Successfully Registered Clients"
        printf "%-40s %s\n" "Client Name" "Client ID"
        print_separator "-"
        for client in "${REGISTERED_CLIENTS[@]}"; do
            IFS='|' read -r name id <<< "$client"
            printf "%-40s %s\n" "$name" "$id"
        done
    fi

    # Failed registrations table
    if [[ ${#FAILED_CLIENTS[@]} -gt 0 ]]; then
        print_section "⚠️  Failed/Skipped Registrations"
        printf "%-40s %s\n" "Client Name" "Reason"
        print_separator "-"
        for client in "${FAILED_CLIENTS[@]}"; do
            IFS='|' read -r name reason <<< "$client"
            printf "%-40s %s\n" "$name" "$reason"
        done
    fi

    # Final notes
    print_section "📌 Next Steps"

    if [ $SUCCESS_COUNT -gt 0 ]; then
        echo -e "  ${GREEN}Client credentials saved to:${NC} $ENV_FILE"
        echo
        echo "  To use these credentials in your services:"
        echo "    source $ENV_FILE"
        echo
        echo "  Or in Docker Compose:"
        echo "    env_file:"
        echo "      - .env.clients"
    fi

    if [ $FAILED_COUNT -gt 0 ] || [ $SKIPPED_COUNT -gt 0 ]; then
        echo
        echo -e "  ${YELLOW}Note:${NC} Some clients were not registered."
        echo "  To view existing clients, run:"
        echo "    ./scripts/clientManagement/list-clients.sh"
        echo
        echo "  To delete existing clients, run:"
        echo "    ./scripts/clientManagement/delete-client.sh <client-id>"
    fi
}

show_usage() {
    print_header "📖 Usage"

    echo "Register OAuth2 clients from configs/clients.json"
    echo
    echo -e "${BOLD}Usage:${NC}"
    echo "  $0 [options]"
    echo
    echo -e "${BOLD}Options:${NC}"
    echo "  --local    - Use local auth service (http://localhost:8080)"
    echo "  --help     - Show this help message"
    echo
    echo -e "${BOLD}Default behavior:${NC}"
    echo "  Connects to deployed auth service at http://sous-chef-proxy.local"
    echo
    echo -e "${BOLD}Environment Variables:${NC}"
    echo "  AUTH_SERVICE_URL - Override auth service URL"
    echo
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0                                    # Use deployed service"
    echo "  $0 --local                            # Use local service"
    echo "  AUTH_SERVICE_URL=http://custom:8080 $0  # Use custom URL"
}

main() {
    # Check for help flag
    for arg in "$@"; do
        if [ "$arg" = "--help" ] || [ "$arg" = "-h" ]; then
            show_usage
            exit 0
        fi
    done

    print_header "🚀 OAuth2 Client Registration Tool"

    check_dependencies
    check_auth_service
    initialize_env_file

    print_section "📦 Loading Client Configurations"

    # Count total clients
    local total_clients
    total_clients=$(jq '. | length' "$CLIENTS_CONFIG")
    print_status "info" "Found $total_clients client(s) to register"

    # Register each client
    local index=1
    while IFS= read -r client; do
        register_client "$client" "$index" "$total_clients"
        index=$((index + 1))
    done < <(jq -c '.[]' "$CLIENTS_CONFIG")

    print_summary

    echo
    print_separator "="

    if [ $SUCCESS_COUNT -gt 0 ]; then
        echo -e "${GREEN}${BOLD}🎉 Client registration completed successfully!${NC}"
    elif [ $SKIPPED_COUNT -eq "$total_clients" ]; then
        echo -e "${YELLOW}${BOLD}⚠️  All clients already exist.${NC}"
    else
        echo -e "${RED}${BOLD}❌ Client registration completed with errors.${NC}"
    fi

    print_separator "="
}

# Run main function
main "$@"
