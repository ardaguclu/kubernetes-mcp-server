package http

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	authenticationv1api "k8s.io/api/authentication/v1"
	"k8s.io/klog/v2"

	"github.com/containers/kubernetes-mcp-server/pkg/mcp"
)

const (
	Audience           = "kubernetes-mcp-server"
	UserInfoContextKey = "UserInfoContextKey"
)

// AuthorizationMiddleware validates the OAuth flow using Kubernetes TokenReview API
func AuthorizationMiddleware(requireOAuth bool, serverURL string, oidcProvider *oidc.Provider, mcpServer *mcp.Server) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == healthEndpoint || r.URL.Path == oauthProtectedResourceEndpoint {
				next.ServeHTTP(w, r)
				return
			}
			if !requireOAuth {
				next.ServeHTTP(w, r)
				return
			}

			audience := Audience
			if serverURL != "" {
				audience = serverURL
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				klog.V(1).Infof("Authentication failed - missing or invalid bearer token: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

				if serverURL == "" {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="Kubernetes MCP Server", audience="%s", error="missing_token"`, audience))
				} else {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="Kubernetes MCP Server", audience="%s"", resource_metadata="%s%s", error="missing_token"`, audience, serverURL, oauthProtectedResourceEndpoint))
				}
				http.Error(w, "Unauthorized: Bearer token required", http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")

			// Validate the token offline for simple sanity check
			// Because missing expected audience and expired tokens must be
			// rejected already.
			claims, err := ParseJWTClaims(token)
			if err == nil && claims != nil {
				err = claims.Validate(audience)
			}
			if err != nil {
				klog.V(1).Infof("Authentication failed - JWT validation error: %s %s from %s, error: %v", r.Method, r.URL.Path, r.RemoteAddr, err)

				if serverURL == "" {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="Kubernetes MCP Server", audience="%s", error="invalid_token"`, audience))
				} else {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="Kubernetes MCP Server", audience="%s"", resource_metadata="%s%s", error="invalid_token"`, audience, serverURL, oauthProtectedResourceEndpoint))
				}
				http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
				return
			}

			if oidcProvider != nil {
				// If OIDC Provider is configured, this token must be validated against it.
				if err := validateTokenWithOIDC(r.Context(), oidcProvider, token, audience); err != nil {
					klog.V(1).Infof("Authentication failed - OIDC token validation error: %s %s from %s, error: %v", r.Method, r.URL.Path, r.RemoteAddr, err)

					if serverURL == "" {
						w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="Kubernetes MCP Server", audience="%s", error="invalid_token"`, audience))
					} else {
						w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="Kubernetes MCP Server", audience="%s"", resource_metadata="%s%s", error="invalid_token"`, audience, serverURL, oauthProtectedResourceEndpoint))
					}
					http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
					return
				}
			}

			// Extract user information from JWT claims (after OIDC validation)
			userInfo, err := extractUserInfoFromClaims(claims)
			if err != nil {
				klog.V(1).Infof("Authentication failed - failed to extract user info from JWT claims: %s %s from %s, error: %v", r.Method, r.URL.Path, r.RemoteAddr, err)
				http.Error(w, "Unauthorized: Invalid token claims", http.StatusUnauthorized)
				return
			}

			// Scopes are likely to be used for authorization.
			scopes := claims.GetScopes()
			klog.V(2).Infof("JWT token validated - User: %s, Scopes: %v", userInfo.Username, scopes)

			// Pass both scopes and user info through context
			ctx := r.Context()
			ctx = context.WithValue(ctx, mcp.TokenScopesContextKey, scopes)
			ctx = context.WithValue(ctx, UserInfoContextKey, userInfo)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

var allSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.EdDSA,
	jose.HS256,
	jose.HS384,
	jose.HS512,
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
}

type JWTClaims struct {
	jwt.Claims
	Scope  string   `json:"scope,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

func (c *JWTClaims) GetScopes() []string {
	if c.Scope == "" {
		return nil
	}
	return strings.Fields(c.Scope)
}

// Validate Checks if the JWT claims are valid and if the audience matches the expected one.
func (c *JWTClaims) Validate(audience string) error {
	return c.Claims.Validate(jwt.Expected{
		AnyAudience: jwt.Audience{audience},
	})
}

func ParseJWTClaims(token string) (*JWTClaims, error) {
	tkn, err := jwt.ParseSigned(token, allSignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}
	claims := &JWTClaims{}
	err = tkn.UnsafeClaimsWithoutVerification(claims)
	return claims, err
}

func validateTokenWithOIDC(ctx context.Context, provider *oidc.Provider, token, audience string) error {
	verifier := provider.Verifier(&oidc.Config{
		ClientID: audience,
	})

	_, err := verifier.Verify(ctx, token)
	if err != nil {
		return fmt.Errorf("JWT token verification failed: %v", err)
	}

	return nil
}

// extractUserInfoFromClaims extracts user information from JWT claims
func extractUserInfoFromClaims(claims *JWTClaims) (*authenticationv1api.UserInfo, error) {
	// Extract username from JWT claims
	username := claims.Subject
	if username == "" {
		return nil, fmt.Errorf("missing subject claim in JWT token")
	}

	// Extract groups from JWT claims
	var groups []string
	if claims.Groups != nil {
		groups = claims.Groups
	}

	// Extract extra information from JWT claims
	extra := make(map[string]authenticationv1api.ExtraValue)
	if claims.Scope != "" {
		extra["scope"] = authenticationv1api.ExtraValue(strings.Fields(claims.Scope))
	}

	userInfo := &authenticationv1api.UserInfo{
		Username: username,
		Groups:   groups,
		Extra:    extra,
	}

	return userInfo, nil
}
