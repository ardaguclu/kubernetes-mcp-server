package mcp

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	authenticationapiv1 "k8s.io/api/authentication/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"github.com/containers/kubernetes-mcp-server/pkg/config"
	internalk8s "github.com/containers/kubernetes-mcp-server/pkg/kubernetes"
	"github.com/containers/kubernetes-mcp-server/pkg/output"
	"github.com/containers/kubernetes-mcp-server/pkg/version"
)

type ContextKey string

const TokenScopesContextKey = ContextKey("TokenScopesContextKey")

type Configuration struct {
	Profile    Profile
	ListOutput output.Output

	StaticConfig *config.StaticConfig
}

func (c *Configuration) isToolApplicable(tool *mcp.Tool) bool {
	if c.StaticConfig.ReadOnly && !tool.Annotations.ReadOnlyHint {
		return false
	}
	if c.StaticConfig.DisableDestructive && ptr.Deref(tool.Annotations.DestructiveHint, false) {
		return false
	}
	if c.StaticConfig.EnabledTools != nil && !slices.Contains(c.StaticConfig.EnabledTools, tool.Name) {
		return false
	}
	if c.StaticConfig.DisabledTools != nil && slices.Contains(c.StaticConfig.DisabledTools, tool.Name) {
		return false
	}
	return true
}

type Server struct {
	configuration *Configuration
	server        *mcp.Server
	enabledTools  []string
	k             *internalk8s.Manager
}

func NewServer(configuration Configuration) (*Server, error) {
	serverImplementation := &mcp.Implementation{
		Name:    version.BinaryName,
		Title:   version.BinaryName,
		Version: version.Version,
	}
	mcpServer := mcp.NewServer(serverImplementation, nil)

	mcpServer.AddReceivingMiddleware(toolCallloggingMiddleware[*mcp.ServerSession])
	if configuration.StaticConfig.RequireOAuth && false { // TODO: Disabled scope auth validation for now
		mcpServer.AddReceivingMiddleware(toolScopedAuthorizationMiddleware)
	}

	s := &Server{
		configuration: &configuration,
		server:        mcpServer,
	}
	if err := s.reloadKubernetesClient(); err != nil {
		return nil, err
	}
	s.k.WatchKubeConfig(s.reloadKubernetesClient)

	return s, nil
}

func (s *Server) reloadKubernetesClient() error {
	k, err := internalk8s.NewManager(s.configuration.StaticConfig)
	if err != nil {
		return err
	}
	s.k = k
	for _, tool := range s.configuration.Profile.GetTools(s) {
		if !s.configuration.isToolApplicable(tool.Tool) {
			continue
		}
		s.server.AddTool(tool.Tool, tool.Handler)
		s.enabledTools = append(s.enabledTools, tool.Tool.Name)
	}
	return nil
}

func (s *Server) ServeStdio() error {
	return mcp.ServeStdio(s.server)
}

func (s *Server) ServeSse(baseUrl string, httpServer *http.Server) *server.SSEServer {
	options := make([]server.SSEOption, 0)
	options = append(options, server.WithSSEContextFunc(contextFunc), server.WithHTTPServer(httpServer))
	if baseUrl != "" {
		options = append(options, server.WithBaseURL(baseUrl))
	}
	return server.NewSSEServer(s.server, options...)
}

func (s *Server) ServeHTTP(httpServer *http.Server) *server.StreamableHTTPServer {
	options := []server.StreamableHTTPOption{
		server.WithHTTPContextFunc(contextFunc),
		server.WithStreamableHTTPServer(httpServer),
		server.WithStateLess(true),
	}
	return server.NewStreamableHTTPServer(s.server, options...)
}

// KubernetesApiVerifyToken verifies the given token with the audience by
// sending an TokenReview request to API Server.
func (s *Server) KubernetesApiVerifyToken(ctx context.Context, token string, audience string) (*authenticationapiv1.UserInfo, []string, error) {
	if s.k == nil {
		return nil, nil, fmt.Errorf("kubernetes manager is not initialized")
	}
	return s.k.VerifyToken(ctx, token, audience)
}

// GetKubernetesAPIServerHost returns the Kubernetes API server host from the configuration.
func (s *Server) GetKubernetesAPIServerHost() string {
	if s.k == nil {
		return ""
	}
	return s.k.GetAPIServerHost()
}

func (s *Server) GetEnabledTools() []string {
	return s.enabledTools
}

func (s *Server) Close() {
	if s.k != nil {
		s.k.Close()
	}
}

func NewTextResult(content string, err error) *mcp.CallToolResult {
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: err.Error(),
				},
			},
		}
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: content,
			},
		},
	}
}

func contextFunc(ctx context.Context, r *http.Request) context.Context {
	// Get the standard Authorization header (OAuth compliant)
	authHeader := r.Header.Get(string(internalk8s.OAuthAuthorizationHeader))
	if authHeader != "" {
		return context.WithValue(ctx, internalk8s.OAuthAuthorizationHeader, authHeader)
	}

	// Fallback to custom header for backward compatibility
	customAuthHeader := r.Header.Get(string(internalk8s.CustomAuthorizationHeader))
	if customAuthHeader != "" {
		return context.WithValue(ctx, internalk8s.OAuthAuthorizationHeader, customAuthHeader)
	}

	return ctx
}

func toolCallloggingMiddleware[S mcp.Session](handler mcp.MethodHandler[S]) mcp.MethodHandler[S] {
	return func(ctx context.Context, s S, method string, params mcp.Params) (result mcp.Result, err error) {
		if method != "callTool" {
			return handler(ctx, s, method, params)
		}

		toolCallParams, ok := params.(*mcp.CallToolParams)
		if !ok {
			klog.Warning("invalid callTool params %s", params)
			return handler(ctx, s, method, params)
		}

		// TODO: Log headers which exists in previous SDK

		defer func() {
			klog.V(5).Infof("callTool call name: %s arguments: %s result: %v", toolCallParams.Name, toolCallParams.Arguments, result)
		}()
		return handler(ctx, s, method, params)
	}
}

func toolScopedAuthorizationMiddleware[S mcp.Session](handler mcp.MethodHandler[S]) mcp.MethodHandler[S] {
	return func(ctx context.Context, s S, method string, params mcp.Params) (result mcp.Result, err error) {
		toolCallParams, ok := params.(*mcp.CallToolParams)
		if !ok {
			klog.Warning("invalid callTool params %s", params)
			return handler(ctx, s, method, params)
		}
		scopes, ok := ctx.Value(TokenScopesContextKey).([]string)
		if !ok {
			return NewTextResult("", fmt.Errorf("authorization failed: Access denied: Tool '%s' requires scope 'mcp:%s' but no scope is available", toolCallParams.Name, toolCallParams.Name)), nil
		}
		if !slices.Contains(scopes, "mcp:"+toolCallParams.Name) && !slices.Contains(scopes, toolCallParams.Name) {
			return NewTextResult("", fmt.Errorf("authorization failed: Access denied: Tool '%s' requires scope 'mcp:%s' but only scopes %s are available", toolCallParams.Name, toolCallParams.Name, scopes)), nil
		}

		return handler(ctx, s, method, params)
	}
}
