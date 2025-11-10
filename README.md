# Traefik GitHub Repository Authorization Plugin

This repository includes `traefik-plugin-gh-repo-authz`. It is a middleware plugin for
[Traefik](https://doc.traefik.io/traefik/) authorizing access to subdirectories based on access to
GitHub repositories.

When using GitHub for development it can be directly used as an oauth2 provider as well. That way
your hosted application can inherit the permissions already configured in GitHub.

> [!IMPORTANT]
> This Plugin requires the Oauth2 scope `repo` for Oauth2 Apps, GitHub apps were not yet tested

This middleware allows to check whether the user accessing a path under `<owner>/<repo>` has the
permission to access the same repository on GitHub. Internally the plugin caches the permissions to
improve performance and reducing GitHub API calls.

![Plugin setup within traefik](https://raw.githubusercontent.com/jonasehrlich/traefik-plugin-gh-repo-authz/refs/heads/main/assets/plugin-setup.drawio.svg)

## Configuration

The plugin must be added in the
[install configuration](https://doc.traefik.io/traefik/getting-started/configuration-overview/#the-install-configuration)

```yaml
experimental:
  plugins:
    gh-repo-authz-plugin:
      moduleName: github.com/jonasehrlich/traefik-plugin-gh-repo-authz
      version: v0.2.0
```

The middlewares, routing and the plugin itself are configured in the
[routing configuration](https://doc.traefik.io/traefik/getting-started/configuration-overview/#the-routing-configuration).

```yaml
http:
  middlewares:
    oauth2-middleware:
      # This can be anything that handles the oauth2 flow and puts the access token in the response
      #header, e.g. oauth2-proxy with the correct configuration
    gh-repo-authz-middleware:
      plugin:
        # Configuring that the plugin is used for this middleware
        gh-repo-authz-plugin:
          # Plugin configuration options, these are the default values
          # Base URL of the GitHub API
          githubAPI: https://api.github.com
          # Name of the header which contains the access token on the incoming request
          tokenHeader: X-Auth-Request-Access-Token
          # TTL of the cache entries in seconds
          cacheTTL: 300
          # WARNING: Do not set this to true in production. This will:
          # - Dump request headers to the HTTP error response
          # - Expose the GitHub API response
          debug: false

  routers:
    protected-router:
      middlewares: oauth2-middleware,gh-repo-authz-middleware
```
