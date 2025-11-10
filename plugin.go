package traefik_plugin_gh_repo_authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	GitHubAPI   string `json:"githubApi"`
	TokenHeader string `json:"tokenHeader"` // Header containing GitHub OAuth token
	CacheTTL    int    `json:"cacheTTL"`    // seconds
	PathPrefix  string `json:"pathPrefix"`
	Debug       bool   `json:"debug"`
}

func CreateConfig() *Config {
	return &Config{
		GitHubAPI:   "https://api.github.com",
		TokenHeader: "X-Auth-Request-Access-Token",
		CacheTTL:    300, // default 5 minutes
		PathPrefix:  "",
		Debug:       false,
	}
}

type cacheEntry struct {
	authorized bool
	expiryTime time.Time
}

type RepoAuthz struct {
	next        http.Handler
	name        string
	githubAPI   string
	tokenHeader string
	client      *http.Client
	cache       map[string]*cacheEntry
	mu          sync.RWMutex
	cacheTTL    time.Duration
	pathPrefix  string
	debug       bool
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.TokenHeader == "" {
		config.TokenHeader = "X-Auth-Request-Access-Token"
	}

	return &RepoAuthz{
		next:        next,
		name:        name,
		githubAPI:   config.GitHubAPI,
		tokenHeader: config.TokenHeader,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		cache:      make(map[string]*cacheEntry),
		cacheTTL:   time.Duration(config.CacheTTL) * time.Second,
		pathPrefix: config.PathPrefix,
		debug:      config.Debug,
	}, nil
}

func (g *RepoAuthz) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	token := req.Header.Get(g.tokenHeader)
	if token == "" {
		g.httpError(rw, req, "Missing GitHub token", http.StatusUnauthorized)
		return
	}

	owner, repo, err := extractOwnerAndRepo(req.URL.Path, g.pathPrefix)
	if err != nil {
		g.httpError(rw, req, fmt.Sprintf("Invalid path, expected <pathPrefix>/<owner>/<repo>/...: %s", err.Error()), http.StatusBadRequest)
		return
	}

	cacheKey := fmt.Sprintf("%s|%s|%s", token, owner, repo)

	// Check cache
	g.mu.RLock()
	entry, ok := g.cache[cacheKey]
	g.mu.RUnlock()
	if ok && time.Now().Before(entry.expiryTime) {
		if entry.authorized {
			g.next.ServeHTTP(rw, req)
		} else {
			g.httpError(rw, req, "Forbidden (cached)", http.StatusForbidden)
		}
		return
	}

	// Not in cache, check GitHub API
	authorized, err := g.checkRepoAccess(g.githubAPI, token, owner, repo)
	if err != nil && !errors.Is(err, ErrGitHubAPIAccessDenied) {
		g.httpError(rw, req, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update cache
	g.mu.Lock()
	g.cache[cacheKey] = &cacheEntry{
		authorized: authorized,
		expiryTime: time.Now().Add(g.cacheTTL),
	}
	g.mu.Unlock()

	if authorized {
		g.next.ServeHTTP(rw, req)
	} else {
		g.httpError(rw, req, err.Error(), http.StatusForbidden)
	}
}

// Write a HTTP error to the response writer. If g.debugMode is set to true the requested response
// will be written, if g.debugMode is false, a generic 404 will be sent
func (g *RepoAuthz) httpError(rw http.ResponseWriter, req *http.Request, error string, code int) {
	os.Stdout.WriteString(error)
	if g.debug {
		h, _ := json.MarshalIndent(req.Header, "", "  ")
		http.Error(rw, fmt.Sprintf("%s\nRequest Headers:\n%s", error, h), code)
		return
	}
	http.Error(rw, "Not Found", http.StatusNotFound)

}

// Extract owner and repository from the request path
func extractOwnerAndRepo(path, prefix string) (string, string, error) {
	if !strings.HasPrefix(path, prefix) {
		return "", "", fmt.Errorf("path is missing prefix %s", prefix)
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, prefix), "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("path too short")
	}
	return parts[0], parts[1], nil
}

var ErrGitHubAPIAccessDenied = errors.New("GitHub API response")

// Check if a token has access to a repository through the GitHub API.
// If the error is ErrGitHubAPIAccessDenied, the request was successful but the GitHub API
// returned 403 or 404
func (g *RepoAuthz) checkRepoAccess(githubApi, token, owner, repo string) (bool, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", githubApi, owner, repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("HTTP request error: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("X-GitHub-Api", "Version: 2022-11-28")

	resp, err := g.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound, http.StatusForbidden:
		return false, fmt.Errorf("%w: %d", ErrGitHubAPIAccessDenied, resp.StatusCode)
	default:
		var githubErr map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&githubErr)
		return false, fmt.Errorf("GitHub API error %d: %v", resp.StatusCode, githubErr)
	}
}
