#!/bin/bash
# scripts/clientManagement/list-clients.sh
# Lists all registered OAuth2 clients

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Parse command line arguments
USE_LOCAL=false
FORMAT="table"
for arg in "$@"; do
    if [ "$arg" = "--local" ]; then
        USE_LOCAL=true
    elif [ "$arg" = "table" ] || [ "$arg" = "json" ] || [ "$arg" = "simple" ]; then
        FORMAT="$arg"
    elif [ "$arg" = "help" ] || [ "$arg" = "-h" ] || [ "$arg" = "--help" ]; then
        FORMAT="help"
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
DIM='\033[2m'
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
    else
        echo -e "  $message"
    fi
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
        echo "    $0 --local"
        echo
        echo "  Or specify a different URL:"
        echo "    AUTH_SERVICE_URL=http://your-auth-service:8080 $0"
        exit 1
    fi
}

fetch_clients() {
    # For now, we'll simulate fetching clients since the API endpoint might not exist yet
    # In a real implementation, this would call: GET /api/v1/auth/oauth/clients

    # Check if .env.clients exists to get a list of registered clients
    local ENV_FILE="$PROJECT_ROOT/.env.clients"

    if [ -f "$ENV_FILE" ]; then
        # Parse client IDs from env file
        local clients_json="[]"

        while IFS= read -r line; do
            if [[ $line =~ ^#[[:space:]](.+)$ ]] && [[ ! $line =~ ^#[[:space:]]OAuth2 ]] && [[ ! $line =~ ^#[[:space:]]Generated ]]; then
                local client_name="${BASH_REMATCH[1]}"
            elif [[ $line =~ _CLIENT_ID=\"(.+)\"$ ]]; then
                local client_id="${BASH_REMATCH[1]}"
                if [ -n "$client_name" ]; then
                    # Try to fetch individual client details
                    local client_response=$(curl -s -f "$AUTH_SERVICE_URL/api/v1/auth/oauth/clients/$client_id" 2>/dev/null || echo "{}")

                    if [ "$client_response" != "{}" ] && echo "$client_response" | jq -e '.id' > /dev/null 2>&1; then
                        clients_json=$(echo "$clients_json" | jq ". += [$client_response]")
                    else
                        # Create a minimal client object if API call fails
                        clients_json=$(echo "$clients_json" | jq \
                            --arg name "$client_name" \
                            --arg id "$client_id" \
                            '. += [{
                                id: $id,
                                name: $name,
                                grant_types: ["unknown"],
                                scopes: ["unknown"]
                            }]')
                    fi
                    client_name=""
                fi
            fi
        done < "$ENV_FILE"

        echo "$clients_json"
    else
        echo "[]"
    fi
}

display_table() {
    local clients_json="$1"
    local count=$(echo "$clients_json" | jq '. | length')

    print_header "📋 Registered OAuth2 Clients"

    echo -e "\n${CYAN}Auth Service:${NC} $AUTH_SERVICE_URL"
    echo -e "${CYAN}Total Clients:${NC} $count\n"

    if [ "$count" -eq 0 ]; then
        print_status "warning" "No clients registered yet"
        echo
        echo "  To register clients, run:"
        echo "    ./scripts/clientManagement/register-clients.sh"
        return
    fi

    # Print table header
    printf "${BOLD}%-25s %-38s %-30s %-30s${NC}\n" \
        "Client Name" \
        "Client ID" \
        "Grant Types" \
        "Scopes"
    print_separator "-"

    # Print each client
    local index=0
    while [ $index -lt $count ]; do
        local client=$(echo "$clients_json" | jq -r ".[$index]")
        local name=$(echo "$client" | jq -r '.name // "N/A"' | cut -c1-24)
        local id=$(echo "$client" | jq -r '.id // "N/A"' | cut -c1-37)
        local grant_types=$(echo "$client" | jq -r '.grant_types // [] | join(", ")' | cut -c1-29)
        local scopes=$(echo "$client" | jq -r '.scopes // [] | join(", ")' | cut -c1-29)

        # Alternate row colors for better readability
        if [ $((index % 2)) -eq 0 ]; then
            printf "%-25s %-38s %-30s %-30s\n" \
                "$name" \
                "$id" \
                "$grant_types" \
                "$scopes"
        else
            printf "${DIM}%-25s %-38s %-30s %-30s${NC}\n" \
                "$name" \
                "$id" \
                "$grant_types" \
                "$scopes"
        fi

        ((index++))
    done

    print_section "📝 Client Management Commands"

    echo "  View client details:"
    echo "    $0 json                    # JSON format"
    echo "    $0 simple                  # Simple list"
    echo
    echo "  Register new clients:"
    echo "    ./scripts/clientManagement/register-clients.sh"
    echo
    echo "  Delete a client:"
    echo "    ./scripts/clientManagement/delete-client.sh <client-id>"
}

display_json() {
    local clients_json="$1"
    echo "$clients_json" | jq '.'
}

display_simple() {
    local clients_json="$1"
    local count=$(echo "$clients_json" | jq '. | length')

    print_header "📋 Registered OAuth2 Clients (Simple View)"

    if [ "$count" -eq 0 ]; then
        print_status "warning" "No clients registered"
        return
    fi

    echo
    local index=0
    while [ $index -lt $count ]; do
        local client=$(echo "$clients_json" | jq -r ".[$index]")
        local name=$(echo "$client" | jq -r '.name // "N/A"')
        local id=$(echo "$client" | jq -r '.id // "N/A"')

        echo -e "${BOLD}$((index + 1)). $name${NC}"
        echo -e "   ${DIM}ID: $id${NC}"
        echo

        ((index++))
    done
}

show_usage() {
    print_header "📖 Usage"

    echo "List all registered OAuth2 clients in the auth service"
    echo
    echo -e "${BOLD}Usage:${NC}"
    echo "  $0 [format] [options]"
    echo
    echo -e "${BOLD}Formats:${NC}"
    echo "  table    - Display as formatted table (default)"
    echo "  json     - Output raw JSON"
    echo "  simple   - Simple numbered list"
    echo
    echo -e "${BOLD}Options:${NC}"
    echo "  --local  - Use local auth service (http://localhost:8080)"
    echo "  --help   - Show this help message"
    echo
    echo -e "${BOLD}Default behavior:${NC}"
    echo "  Connects to deployed auth service at http://auth-service.local"
    echo
    echo -e "${BOLD}Environment Variables:${NC}"
    echo "  AUTH_SERVICE_URL - Override auth service URL"
    echo
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0                                    # Table format, deployed service"
    echo "  $0 --local                            # Table format, local service"
    echo "  $0 json                               # JSON format, deployed service"
    echo "  $0 json --local                       # JSON format, local service"
    echo "  AUTH_SERVICE_URL=http://custom:8080 $0  # Custom URL"
}

main() {
    # Check for help flag
    if [ "$FORMAT" = "help" ] || [ "$FORMAT" = "-h" ] || [ "$FORMAT" = "--help" ]; then
        show_usage
        exit 0
    fi

    # Validate format
    if [ "$FORMAT" != "table" ] && [ "$FORMAT" != "json" ] && [ "$FORMAT" != "simple" ]; then
        print_header "❌ Invalid Format"
        print_status "error" "Unknown format: $FORMAT"
        echo
        echo "  Valid formats: table, json, simple"
        echo "  Run '$0 help' for usage information"
        exit 1
    fi

    # Check auth service
    check_auth_service

    # Fetch clients
    local clients_json=$(fetch_clients)

    # Display based on format
    case "$FORMAT" in
        table)
            display_table "$clients_json"
            ;;
        json)
            display_json "$clients_json"
            ;;
        simple)
            display_simple "$clients_json"
            ;;
    esac

    if [ "$FORMAT" = "table" ] || [ "$FORMAT" = "simple" ]; then
        echo
        print_separator "="
    fi
}

# Run main function
main "$@"
