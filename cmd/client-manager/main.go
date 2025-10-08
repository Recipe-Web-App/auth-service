// Package main provides a CLI tool for managing OAuth2 clients in the auth service.
// This tool can register, list, update, and delete clients via the auth service API.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
)

type ClientConfig struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	GrantTypes   []string `json:"grant_types"`
}

type ClientManager struct {
	baseURL string
	client  *http.Client
}

func main() {
	var (
		baseURL    = flag.String("url", "http://localhost:8080", "Auth service base URL")
		configFile = flag.String("config", "", "Path to client configuration file")
		action     = flag.String("action", "register", "Action to perform: register, list, get, delete")
		clientID   = flag.String("client-id", "", "Client ID for get/delete operations")
		name       = flag.String("name", "", "Client name for single registration")
		redirects  = flag.String("redirects", "", "Comma-separated redirect URIs")
		scopes     = flag.String("scopes", "", "Comma-separated scopes")
		grants     = flag.String("grants", "", "Comma-separated grant types")
		batch      = flag.Bool("batch", false, "Register predefined backend services")
	)
	flag.Parse()

	manager := &ClientManager{
		baseURL: *baseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
	}

	switch *action {
	case "register":
		if *batch {
			err := manager.registerBackendServices()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error registering backend services: %v\n", err)
				os.Exit(1)
			}
		} else if *configFile != "" {
			err := manager.registerFromConfig(*configFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error registering from config: %v\n", err)
				os.Exit(1)
			}
		} else if *name != "" {
			config := ClientConfig{
				Name:         *name,
				RedirectURIs: parseStringList(*redirects),
				Scopes:       parseStringList(*scopes),
				GrantTypes:   parseStringList(*grants),
			}
			client, err := manager.registerClient(config)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error registering client: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Client registered successfully:\n")
			printClient(client)
		} else {
			fmt.Fprintf(os.Stderr, "Please specify -name, -config, or -batch for registration\n")
			os.Exit(1)
		}
	case "list":
		fmt.Println("Note: List functionality requires additional API endpoint implementation")
	case "get":
		if *clientID == "" {
			fmt.Fprintf(os.Stderr, "Client ID is required for get operation\n")
			os.Exit(1)
		}
		client, err := manager.getClient(*clientID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting client: %v\n", err)
			os.Exit(1)
		}
		printClient(client)
	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s\n", *action)
		os.Exit(1)
	}
}

func (cm *ClientManager) registerBackendServices() error {
	services := []ClientConfig{
		{
			Name:         "Recipe Service",
			RedirectURIs: []string{"http://recipe-service:8080/callback"},
			Scopes:       []string{"read", "write", "profile"},
			GrantTypes:   []string{"client_credentials"},
		},
		{
			Name:         "User Service",
			RedirectURIs: []string{"http://user-service:8080/callback"},
			Scopes:       []string{"read", "write", "profile", "email"},
			GrantTypes:   []string{"client_credentials"},
		},
		{
			Name:         "Inventory Service",
			RedirectURIs: []string{"http://inventory-service:8080/callback"},
			Scopes:       []string{"read", "write"},
			GrantTypes:   []string{"client_credentials"},
		},
		{
			Name:         "Order Service",
			RedirectURIs: []string{"http://order-service:8080/callback"},
			Scopes:       []string{"read", "write", "profile"},
			GrantTypes:   []string{"client_credentials"},
		},
		{
			Name:         "Payment Service",
			RedirectURIs: []string{"http://payment-service:8080/callback"},
			Scopes:       []string{"read", "write"},
			GrantTypes:   []string{"client_credentials"},
		},
		{
			Name:         "Notification Service",
			RedirectURIs: []string{"http://notification-service:8080/callback"},
			Scopes:       []string{"read", "write", "email"},
			GrantTypes:   []string{"client_credentials"},
		},
		{
			Name:         "Analytics Service",
			RedirectURIs: []string{"http://analytics-service:8080/callback"},
			Scopes:       []string{"read"},
			GrantTypes:   []string{"client_credentials"},
		},
		{
			Name:         "Search Service",
			RedirectURIs: []string{"http://search-service:8080/callback"},
			Scopes:       []string{"read", "write"},
			GrantTypes:   []string{"client_credentials"},
		},
		{
			Name:         "API Gateway",
			RedirectURIs: []string{"http://api-gateway:8080/callback", "http://localhost:3000/callback"},
			Scopes:       []string{"read", "write", "profile", "email", "openid"},
			GrantTypes:   []string{"client_credentials", "authorization_code", "refresh_token"},
		},
	}

	fmt.Printf("Registering %d backend services...\n", len(services))

	for i, service := range services {
		fmt.Printf("[%d/%d] Registering %s...", i+1, len(services), service.Name)
		client, err := cm.registerClient(service)
		if err != nil {
			fmt.Printf(" FAILED: %v\n", err)
			continue
		}
		fmt.Printf(" SUCCESS\n")
		fmt.Printf("  Client ID: %s\n", client.ID)
		fmt.Printf("  Client Secret: %s\n", client.Secret)
		fmt.Println()
	}

	return nil
}

// validateConfigPath validates the config path to prevent directory traversal attacks.
func validateConfigPath(configPath string) error {
	// Clean the path to resolve any . or .. elements
	cleanPath := filepath.Clean(configPath)

	// Ensure the path doesn't contain directory traversal sequences
	if strings.Contains(cleanPath, "..") {
		return errors.New("directory traversal not allowed in config path")
	}

	// Ensure it's a JSON file
	if !strings.HasSuffix(strings.ToLower(cleanPath), ".json") {
		return errors.New("config file must be a JSON file")
	}

	return nil
}

func (cm *ClientManager) registerFromConfig(configPath string) error {
	// Validate and sanitize the config path for security
	if err := validateConfigPath(configPath); err != nil {
		return fmt.Errorf("invalid config path: %w", err)
	}

	// #nosec G304 - configPath is validated above to prevent directory traversal
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var configs []ClientConfig
	if err := json.NewDecoder(file).Decode(&configs); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	fmt.Printf("Registering %d clients from config...\n", len(configs))

	for i, config := range configs {
		fmt.Printf("[%d/%d] Registering %s...", i+1, len(configs), config.Name)
		client, err := cm.registerClient(config)
		if err != nil {
			fmt.Printf(" FAILED: %v\n", err)
			continue
		}
		fmt.Printf(" SUCCESS\n")
		fmt.Printf("  Client ID: %s\n", client.ID)
		fmt.Printf("  Client Secret: %s\n", client.Secret)
		fmt.Println()
	}

	return nil
}

func (cm *ClientManager) registerClient(config ClientConfig) (*models.Client, error) {
	// Set defaults if not provided
	if len(config.Scopes) == 0 {
		config.Scopes = []string{"read", "write"}
	}
	if len(config.GrantTypes) == 0 {
		config.GrantTypes = []string{"client_credentials"}
	}
	if len(config.RedirectURIs) == 0 {
		config.RedirectURIs = []string{"http://localhost:8080/callback"}
	}

	payload, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := cm.client.Post(
		cm.baseURL+"/api/v1/auth/oauth/clients",
		"application/json",
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		var errorResp map[string]string
		if json.Unmarshal(body, &errorResp) == nil {
			return nil, fmt.Errorf("API error: %s", errorResp["error"])
		}
		return nil, fmt.Errorf("API error: %s", string(body))
	}

	var client models.Client
	if err := json.Unmarshal(body, &client); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &client, nil
}

func (cm *ClientManager) getClient(clientID string) (*models.Client, error) {
	resp, err := cm.client.Get(cm.baseURL + "/api/v1/auth/oauth/clients/" + clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errorResp map[string]string
		if json.Unmarshal(body, &errorResp) == nil {
			return nil, fmt.Errorf("API error: %s", errorResp["error"])
		}
		return nil, fmt.Errorf("API error: %s", string(body))
	}

	var client models.Client
	if err := json.Unmarshal(body, &client); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &client, nil
}

func parseStringList(input string) []string {
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}
	return parts
}

func printClient(client *models.Client) {
	fmt.Printf("Client ID: %s\n", client.ID)
	fmt.Printf("Client Secret: %s\n", client.Secret)
	fmt.Printf("Name: %s\n", client.Name)
	fmt.Printf("Redirect URIs: %s\n", strings.Join(client.RedirectURIs, ", "))
	fmt.Printf("Scopes: %s\n", strings.Join(client.Scopes, ", "))
	fmt.Printf("Grant Types: %s\n", strings.Join(client.GrantTypes, ", "))
	fmt.Printf("Active: %v\n", client.IsActive)
	fmt.Printf("Created: %s\n", client.CreatedAt.Format(time.RFC3339))
}
