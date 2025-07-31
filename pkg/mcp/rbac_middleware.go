package mcp

import (
	"context"
	"fmt"

	authenticationapiv1 "k8s.io/api/authentication/v1"
	"k8s.io/klog/v2"

	"github.com/containers/kubernetes-mcp-server/pkg/kubernetes"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// RBACValidationMiddleware validates RBAC permissions for Kubernetes operations
func RBACValidationMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract user info from context
		userInfo, ok := ctx.Value(UserInfoContextKey).(*authenticationapiv1.UserInfo)
		if !ok || userInfo == nil {
			// No user info available, proceed without RBAC validation
			klog.V(4).Infof("No user info available for RBAC validation, proceeding with tool: %s", ctr.Params.Name)
			return next(ctx, ctr)
		}

		// Add tool arguments to context for validation
		ctxWithArgs := context.WithValue(ctx, "tool_arguments", ctr.Params.Arguments)

		// Validate RBAC permissions based on the tool being called
		if err := validateRBACForTool(ctxWithArgs, ctr.Params.Name, userInfo); err != nil {
			return NewTextResult("", fmt.Errorf("RBAC validation failed for tool '%s': %v", ctr.Params.Name, err)), nil
		}

		return next(ctx, ctr)
	}
}

// validateRBACForTool validates RBAC permissions for specific tools
func validateRBACForTool(ctx context.Context, toolName string, userInfo *authenticationapiv1.UserInfo) error {
	// Get the RBAC requirement for this tool
	requirement, exists := kubernetes.ResourceVerbMapping[toolName]
	if !exists {
		// If no specific RBAC requirement is defined, allow the tool
		klog.V(4).Infof("No RBAC requirement defined for tool: %s, allowing", toolName)
		return nil
	}

	// Extract namespace from tool arguments
	namespace := "default" // Default namespace

	// Get tool arguments from context
	if toolArgs, ok := ctx.Value("tool_arguments").(map[string]interface{}); ok {
		if ns, exists := toolArgs["namespace"]; exists && ns != nil {
			if nsStr, ok := ns.(string); ok && nsStr != "" {
				namespace = nsStr
			}
		}
	}

	// For cluster-scoped resources, use empty namespace
	if requirement.Scope == "cluster" {
		namespace = ""
	}

	klog.V(4).Infof("Validating RBAC for user %s: %s %s in namespace %s",
		userInfo.Username, requirement.Verb, requirement.Resource, namespace)

	// TODO: Implement actual RBAC validation using the RBACValidator
	// This would involve:
	// 1. Getting the base manager from the MCP server
	// 2. Creating an RBACValidator with the manager's config
	// 3. Using ValidateUserAccess to check permissions

	return nil
}
