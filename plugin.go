package traefik_plugin_gh_repo_authz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Config struct {
	GitHubAPI          string `json:"githubApi"`
	TokenHeader        string `json:"tokenHeader"` // Header containing GitHub OAuth token
	CacheTTL           int    `json:"cacheTTL"`    // seconds
	DumpHeadersOnError bool   `json:"dumpHeadersOnError"`
}

func CreateConfig() *Config {
	return &Config{
		GitHubAPI:          "https://api.github.com",
		TokenHeader:        "X-Auth-Request-Access-Token",
		CacheTTL:           300, // default 5 minutes
		DumpHeadersOnError: false,
	}
}

type cacheEntry struct {
	allowed    bool
	expiryTime time.Time
}

type RepoAuthz struct {
	next               http.Handler
	name               string
	githubAPI          string
	tokenHeader        string
	client             *http.Client
	cache              map[string]*cacheEntry
	mu                 sync.RWMutex
	cacheTTL           time.Duration
	dumpHeadersOnError bool
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
		cache:              make(map[string]*cacheEntry),
		cacheTTL:           time.Duration(config.CacheTTL) * time.Second,
		dumpHeadersOnError: config.DumpHeadersOnError,
	}, nil
}

func (g *RepoAuthz) createErrorContent(msg string, req *http.Request) string {
	if !g.dumpHeadersOnError {
		return msg

	}
	h, _ := json.MarshalIndent(req.Header, "", "  ")

	return fmt.Sprintf("%s\nHeaders:\n%v", msg, string(h))
}

func (g *RepoAuthz) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	token := req.Header.Get(g.tokenHeader)
	if token == "" {
		http.Error(rw, g.createErrorContent("Missing GitHub token", req), http.StatusUnauthorized)
		return
	}

	owner, repo, err := extractOwnerAndRepo(req.URL.Path)
	if err != nil {
		http.Error(rw, g.createErrorContent("Invalid path, expected /<owner>/<repo>/...", req), http.StatusBadRequest)
		return
	}

	cacheKey := fmt.Sprintf("%s|%s|%s", token, owner, repo)

	// Check cache
	g.mu.RLock()
	entry, ok := g.cache[cacheKey]
	g.mu.RUnlock()
	if ok && time.Now().Before(entry.expiryTime) {
		if entry.allowed {
			g.next.ServeHTTP(rw, req)
		} else {
			http.Error(rw, g.createErrorContent("Forbidden (cached)", req), http.StatusForbidden)
		}
		return
	}

	// Not in cache, check GitHub API
	authorized, err := g.checkRepoAccess(g.githubAPI, token, owner, repo)
	if err != nil {
		http.Error(rw, g.createErrorContent(fmt.Sprintf("GitHub API error: %v", err), req), http.StatusInternalServerError)
		return
	}

	// Update cache
	g.mu.Lock()
	g.cache[cacheKey] = &cacheEntry{
		allowed:    authorized,
		expiryTime: time.Now().Add(g.cacheTTL),
	}
	g.mu.Unlock()

	if authorized {
		g.next.ServeHTTP(rw, req)
	} else {
		http.Error(rw, g.createErrorContent("Not Found", req), http.StatusNotFound)
	}
}

func extractOwnerAndRepo(path string) (string, string, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("path too short")
	}
	return parts[0], parts[1], nil
}

func (g *RepoAuthz) checkRepoAccess(githubApi, token, owner, repo string) (bool, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", githubApi, owner, repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
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
		return false, nil
	default:
		var githubErr map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&githubErr)
		return false, fmt.Errorf("unexpected status %d: %v", resp.StatusCode, githubErr)
	}
}
