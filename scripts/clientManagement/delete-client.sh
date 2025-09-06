#!/bin/bash
# scripts/clientManagement/delete-client.sh
# Deletes a registered OAuth2 client

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
ENV_FILE="$PROJECT_ROOT/.env.clients"

# Parse command line arguments
USE_LOCAL=false
CLIENT_ID=""
FORCE_DELETE=""
for arg in "$@"; do
    if [ "$arg" = "--local" ]; then
        USE_LOCAL=true
    elif [ "$arg" = "--force" ]; then
        FORCE_DELETE="--force"
    elif [ "$arg" = "--help" ] || [ "$arg" = "-h" ] || [ "$arg" = "help" ]; then
        CLIENT_ID="help"
    elif [ -z "$CLIENT_ID" ] && [[ "$arg" != --* ]]; then
        CLIENT_ID="$arg"
    fi
done

# Set AUTH_SERVICE_URL based on flag
if [ "$USE_LOCAL" = true ]; then
    AUTH_SERVICE_URL="${AUTH_SERVICE_URL:-http://localhost:8080}"
else
    AUTH_SERVICE_URL="${AUTH_SERVICE_URL:-http://auth-service.local}"
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

show_usage() {
    print_header "📖 Usage"

    echo "Delete a registered OAuth2 client from the auth service"
    echo
    echo -e "${BOLD}Usage:${NC}"
    echo "  $0 <client-id> [options]"
    echo
    echo -e "${BOLD}Arguments:${NC}"
    echo "  client-id    - The ID of the client to delete"
    echo
    echo -e "${BOLD}Options:${NC}"
    echo "  --local      - Use local auth service (http://localhost:8080)"
    echo "  --force      - Skip confirmation prompt"
    echo "  --help       - Show this help message"
    echo
    echo -e "${BOLD}Default behavior:${NC}"
    echo "  Connects to deployed auth service at http://auth-service.local"
    echo
    echo -e "${BOLD}Environment Variables:${NC}"
    echo "  AUTH_SERVICE_URL - Override auth service URL"
    echo
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 abc123def456                       # Delete from deployed service"
    echo "  $0 abc123def456 --local               # Delete from local service"
    echo "  $0 abc123def456 --force               # Skip confirmation"
    echo "  $0 abc123def456 --local --force       # Local + skip confirmation"
    echo "  AUTH_SERVICE_URL=http://custom:8080 $0 abc123def456"
    echo
    echo -e "${BOLD}Note:${NC}"
    echo "  To list all clients and get their IDs:"
    echo "    ./scripts/clientManagement/list-clients.sh"
}

check_auth_service() {
    if ! curl -s -f "$AUTH_SERVICE_URL/api/v1/auth/health" > /dev/null 2>&1; then
        print_header "❌ Auth Service Not Available"
        print_status "error" "Auth service is not reachable at $AUTH_SERVICE_URL"
        echo
        echo "  Please ensure the auth service is running:"
        echo "    For local development: make run"
        echo "    For deployed service: Check Kubernetes deployment"
        echo
        echo "  To use local auth service:"
        echo "    $0 $CLIENT_ID --local"
        echo
        echo "  Or specify a different URL:"
        echo "    AUTH_SERVICE_URL=http://your-auth-service:8080 $0 $CLIENT_ID"
        exit 1
    fi
}

fetch_client_details() {
    local client_id="$1"

    print_section "🔍 Fetching Client Details"
    print_status "processing" "Looking up client: $client_id"

    # Try to fetch client details from auth service
    local response=$(curl -s -f "$AUTH_SERVICE_URL/api/v1/auth/oauth/clients/$client_id" 2>/dev/null || echo "{}")

    if [ "$response" = "{}" ] || ! echo "$response" | jq -e '.id' > /dev/null 2>&1; then
        # Client not found in auth service, check env file
        if [ -f "$ENV_FILE" ] && grep -q "$client_id" "$ENV_FILE" 2>/dev/null; then
            print_status "warning" "Client ID found in local credentials file but not in auth service"
            echo "  The client may have already been deleted from the auth service."

            # Extract client name from env file
            local client_name=$(grep -B1 "$client_id" "$ENV_FILE" | head -n1 | sed 's/^# //')
            if [ -n "$client_name" ]; then
                echo -e "  ${CYAN}Client Name:${NC} $client_name"
            fi

            return 1
        else
            print_status "error" "Client not found: $client_id"
            echo
            echo "  To list all registered clients:"
            echo "    ./scripts/clientManagement/list-clients.sh"
            exit 1
        fi
    fi

    # Display client information
    local name=$(echo "$response" | jq -r '.name // "N/A"')
    local grant_types=$(echo "$response" | jq -r '.grant_types // [] | join(", ")')
    local scopes=$(echo "$response" | jq -r '.scopes // [] | join(", ")')

    print_status "ok" "Client found!"
    echo
    echo -e "  ${CYAN}Client ID:${NC}    $client_id"
    echo -e "  ${CYAN}Name:${NC}         $name"
    echo -e "  ${CYAN}Grant Types:${NC}  $grant_types"
    echo -e "  ${CYAN}Scopes:${NC}       $scopes"

    echo "$response"
}

confirm_deletion() {
    local client_json="$1"
    local client_name=$(echo "$client_json" | jq -r '.name // "Unknown"')

    if [ "$FORCE_DELETE" = "--force" ]; then
        return 0
    fi

    print_section "⚠️  Confirmation Required"

    echo -e "${YELLOW}${BOLD}WARNING:${NC} You are about to delete the following client:"
    echo -e "  • Name: ${BOLD}$client_name${NC}"
    echo -e "  • ID:   ${BOLD}$CLIENT_ID${NC}"
    echo
    echo -e "${YELLOW}This action cannot be undone!${NC}"
    echo

    read -p "Are you sure you want to delete this client? (yes/no): " -r confirmation

    if [ "$confirmation" != "yes" ] && [ "$confirmation" != "y" ]; then
        print_status "info" "Deletion cancelled by user"
        exit 0
    fi
}

delete_client() {
    local client_id="$1"

    print_section "🗑️  Deleting Client"
    print_status "processing" "Sending deletion request..."

    # Send DELETE request to auth service
    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X DELETE \
        "$AUTH_SERVICE_URL/api/v1/auth/oauth/clients/$client_id" 2>/dev/null)

    http_code=$(echo "$response" | tail -n1)
    response_body=$(echo "$response" | head -n-1)

    if [ "$http_code" = "204" ] || [ "$http_code" = "200" ]; then
        print_status "ok" "Client successfully deleted from auth service"
        return 0
    elif [ "$http_code" = "404" ]; then
        print_status "warning" "Client not found in auth service (may already be deleted)"
        return 1
    else
        print_status "error" "Failed to delete client (HTTP $http_code)"
        if [ -n "$response_body" ]; then
            local error_msg=$(echo "$response_body" | jq -r '.error // .message // ""' 2>/dev/null || echo "$response_body")
            if [ -n "$error_msg" ]; then
                echo "  Error: $error_msg"
            fi
        fi
        exit 1
    fi
}

remove_from_env_file() {
    local client_id="$1"

    if [ ! -f "$ENV_FILE" ]; then
        return 0
    fi

    print_section "📝 Updating Credentials File"

    # Check if client exists in env file
    if ! grep -q "$client_id" "$ENV_FILE" 2>/dev/null; then
        print_status "info" "Client not found in credentials file"
        return 0
    fi

    # Create backup
    local backup_file="${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$ENV_FILE" "$backup_file"
    print_status "info" "Created backup: $(basename "$backup_file")"

    # Remove client from env file
    # This removes the comment line before the client and the two credential lines
    local temp_file=$(mktemp)
    local skip_next=0
    local found_client=0

    while IFS= read -r line; do
        if [[ $line == *"$client_id"* ]]; then
            found_client=1
            skip_next=2  # Skip this line and the next one (client secret)
            # Also remove the comment line before this
            sed -i '$ d' "$temp_file" 2>/dev/null || true
            continue
        fi

        if [ $skip_next -gt 0 ]; then
            ((skip_next--))
            continue
        fi

        echo "$line" >> "$temp_file"
    done < "$ENV_FILE"

    if [ $found_client -eq 1 ]; then
        mv "$temp_file" "$ENV_FILE"
        print_status "ok" "Removed client credentials from .env.clients"
    else
        rm "$temp_file"
        print_status "info" "Client not found in credentials file"
    fi
}

print_summary() {
    print_header "✅ Deletion Complete"

    echo -e "\n${GREEN}${BOLD}Client successfully deleted!${NC}\n"

    echo -e "  ${CYAN}Client ID:${NC} $CLIENT_ID"
    echo

    print_section "📌 Next Steps"

    echo "  To view remaining clients:"
    echo "    ./scripts/clientManagement/list-clients.sh"
    echo
    echo "  To register new clients:"
    echo "    ./scripts/clientManagement/register-clients.sh"
    echo
    echo "  If you need to restore this client:"
    echo "    Check the backup file in: .env.clients.backup.*"
}

main() {
    # Check for help flag
    if [ -z "$CLIENT_ID" ] || [ "$CLIENT_ID" = "help" ] || [ "$CLIENT_ID" = "-h" ] || [ "$CLIENT_ID" = "--help" ]; then
        show_usage
        exit 0
    fi

    print_header "🗑️  OAuth2 Client Deletion Tool"

    echo -e "\n${CYAN}Auth Service:${NC} $AUTH_SERVICE_URL"
    echo -e "${CYAN}Target Client:${NC} $CLIENT_ID\n"

    # Check auth service connection
    check_auth_service

    # Fetch and display client details
    client_json=$(fetch_client_details "$CLIENT_ID")
    client_found=$?

    if [ $client_found -eq 0 ]; then
        # Client exists in auth service
        confirm_deletion "$client_json"
        delete_client "$CLIENT_ID"
    else
        # Client only exists in local env file
        print_section "⚠️  Local Cleanup Only"
        echo "  The client appears to be already deleted from the auth service."
        echo "  Would you like to remove it from the local credentials file?"
        echo

        if [ "$FORCE_DELETE" != "--force" ]; then
            read -p "Remove from .env.clients? (yes/no): " -r confirmation
            if [ "$confirmation" != "yes" ] && [ "$confirmation" != "y" ]; then
                print_status "info" "Cleanup cancelled by user"
                exit 0
            fi
        fi
    fi

    # Remove from env file
    remove_from_env_file "$CLIENT_ID"

    # Print summary
    print_summary

    print_separator "="
}

# Run main function
main "$@"
