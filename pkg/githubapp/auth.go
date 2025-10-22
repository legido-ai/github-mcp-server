package githubapp

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v74/github"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
)

// AppAuth holds the GitHub App authentication details
type AppAuth struct {
	appID              int64
	privateKey         string
	installationID     int64
	token              string
	tokenExpiry        time.Time
	tokenMutex         sync.RWMutex
	enterpriseHostname string
}

// NewAppAuth creates a new AppAuth instance from environment variables
func NewAppAuth(enterpriseHostname string) (*AppAuth, error) {
	appIDStr := os.Getenv("GITHUB_APP_ID")
	if appIDStr == "" {
		return nil, fmt.Errorf("GITHUB_APP_ID environment variable not set")
	}

	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid GITHUB_APP_ID: %w", err)
	}

	privateKey := os.Getenv("GITHUB_PRIVATE_KEY")
	if privateKey == "" {
		return nil, fmt.Errorf("GITHUB_PRIVATE_KEY environment variable not set")
	}

	installationIDStr := os.Getenv("GITHUB_INSTALLATION_ID")
	if installationIDStr == "" {
		return nil, fmt.Errorf("GITHUB_INSTALLATION_ID environment variable not set")
	}

	installationID, err := strconv.ParseInt(installationIDStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid GITHUB_INSTALLATION_ID: %w", err)
	}

	auth := &AppAuth{
		appID:              appID,
		privateKey:         privateKey,
		installationID:     installationID,
		enterpriseHostname: enterpriseHostname,
	}

	return auth, nil
}

// GetToken returns a valid installation token, refreshing if necessary
func (a *AppAuth) GetToken() (string, error) {
	a.tokenMutex.RLock()
	token := a.token
	expiry := a.tokenExpiry
	a.tokenMutex.RUnlock()

	// If we have a token that's still valid for at least 10 minutes, return it
	if token != "" && time.Now().Add(10*time.Minute).Before(expiry) {
		return token, nil
	}

	// Otherwise, get a new token
	a.tokenMutex.Lock()
	defer a.tokenMutex.Unlock()

	// Double-check after acquiring the write lock
	if a.token != "" && time.Now().Add(10*time.Minute).Before(a.tokenExpiry) {
		return a.token, nil
	}

	token, expiry, err := a.generateToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate GitHub App installation token: %w", err)
	}

	a.token = token
	a.tokenExpiry = expiry

	return token, nil
}

// generateToken creates a new installation token using the GitHub App credentials
func (a *AppAuth) generateToken() (string, time.Time, error) {
	// Create a JWT token for the GitHub App
	conf := &jwt.Config{
		Email:      fmt.Sprintf("%d", a.appID), // Use app ID as email for identification
		PrivateKey: []byte(a.privateKey),
		Scopes:     []string{}, // No scopes needed for JWT auth
		TokenURL:   "https://api.github.com/app/installations/" + fmt.Sprintf("%d", a.installationID) + "/access_tokens",
		Subject:    fmt.Sprintf("%d", a.installationID),
	}

	// Create an HTTP client with the JWT token
	client := conf.Client(context.Background())

	// Create GitHub client with the JWT token
	ghClient := github.NewClient(client)

	// For enterprise hosts, update the base URL
	if a.enterpriseHostname != "" {
		baseURL := strings.TrimSuffix(a.enterpriseHostname, "/")
		if !strings.HasSuffix(baseURL, "/api/v3") && !strings.Contains(baseURL, "github.com") {
			baseURL += "/api/v3/"
		} else if strings.Contains(baseURL, "ghe.com") {
			baseURL = strings.Replace(baseURL, "https://", "https://api.", 1) + "/"
		} else {
			baseURL += "/"
		}
		ghClient.BaseURL = mustParseURL(baseURL)
	}

	// Create the installation token
	token, _, err := ghClient.Apps.CreateInstallationToken(
		context.Background(),
		a.installationID,
		&github.InstallationTokenOptions{},
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create installation token: %w", err)
	}

	if token.Token == nil {
		return "", time.Time{}, fmt.Errorf("received nil token from GitHub API")
	}

	expiry := time.Time{}
	if token.ExpiresAt != nil {
		expiry = *token.ExpiresAt
	}

	return *token.Token, expiry, nil
}

// GetRESTClient returns a GitHub REST client configured with the installation token
func (a *AppAuth) GetRESTClient(version string) (*github.Client, error) {
	token, err := a.GetToken()
	if err != nil {
		return nil, err
	}

	// Create an OAuth2 token source
	tokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	httpClient := oauth2.NewClient(context.Background(), tokenSource)

	// Create GitHub client
	client := github.NewClient(httpClient)
	client.UserAgent = fmt.Sprintf("github-mcp-server/%s", version)

	// For enterprise hosts, update the base URL
	if a.enterpriseHostname != "" {
		baseURL := strings.TrimSuffix(a.enterpriseHostname, "/")
		if !strings.HasSuffix(baseURL, "/api/v3") && !strings.Contains(baseURL, "github.com") {
			baseURL += "/api/v3/"
		} else if strings.Contains(baseURL, "ghe.com") {
			baseURL = strings.Replace(baseURL, "https://", "https://api.", 1) + "/"
		} else {
			baseURL += "/"
		}
		client.BaseURL = mustParseURL(baseURL)
	}

	return client, nil
}

// GetGraphQLClient returns a GitHub GraphQL client configured with the installation token
func (a *AppAuth) GetGraphQLClient(version string) (*githubv4.Client, error) {
	token, err := a.GetToken()
	if err != nil {
		return nil, err
	}

	// Create an OAuth2 token source
	tokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	httpClient := oauth2.NewClient(context.Background(), tokenSource)

	// Set user agent
	httpClient.Transport = &userAgentTransport{
		transport: httpClient.Transport,
		agent:     fmt.Sprintf("github-mcp-server/%s", version),
	}

	// Construct GraphQL URL based on hostname
	graphqlURL := "https://api.github.com/graphql"
	if a.enterpriseHostname != "" {
		baseURL := strings.TrimSuffix(a.enterpriseHostname, "/")
		if strings.Contains(baseURL, "ghe.com") {
			graphqlURL = strings.Replace(baseURL, "https://", "https://api.", 1) + "/graphql"
		} else if strings.Contains(baseURL, "github.com") {
			graphqlURL = baseURL + "/graphql"
		} else {
			// For GHES
			graphqlURL = baseURL + "/api/graphql"
		}
	}

	return githubv4.NewEnterpriseClient(graphqlURL, httpClient), nil
}

func mustParseURL(s string) *github.URL {
	u, err := github.ParseURL(s)
	if err != nil {
		panic(err)
	}
	return u
}

type userAgentTransport struct {
	transport http.RoundTripper
	agent     string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", t.agent)
	return t.transport.RoundTrip(req)
}