package mcp

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/utils/ptr"
)

func (s *Server) initHelm() []ToolWithHandler {
	return []ToolWithHandler{
		{
			Tool: &mcp.Tool{
				Annotations: &mcp.ToolAnnotations{
					DestructiveHint: ptr.To(false),
					IdempotentHint:  false,
					OpenWorldHint:   ptr.To(true),
					ReadOnlyHint:    false,
					Title:           "Helm: Install",
				},
				Description: "Install a Helm chart in the current or provided namespace",
				Name:        "helm_install",
				Title:       "Helm: Install",
			},
			Handler: s.helmInstall,
		},
		{
			Tool: &mcp.Tool{
				Annotations: &mcp.ToolAnnotations{
					DestructiveHint: ptr.To(false),
					OpenWorldHint:   ptr.To(true),
					ReadOnlyHint:    true,
					Title:           "Helm: List",
				},
				Description: "List all the Helm releases in the current or provided namespace (or in all namespaces if specified)",
				Name:        "helm_list",
				Title:       "Helm: List",
			},
			Handler: s.helmList,
		},
		{
			Tool: &mcp.Tool{
				Annotations: &mcp.ToolAnnotations{
					DestructiveHint: ptr.To(true),
					IdempotentHint:  true,
					OpenWorldHint:   ptr.To(true),
					ReadOnlyHint:    false,
					Title:           "Helm: Uninstall",
				},
				Description: "Uninstall a Helm release in the current or provided namespace",
				Name:        "helm_uninstall",
				Title:       "Helm: Uninstall",
			},
			Handler: s.helmUninstall,
		},
	}
}

func (s *Server) helmInstall(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[map[string]any]]) (*mcp.CallToolResultFor[any], error) {
	var chart string
	ok := false
	if chart, ok = req.Params.Arguments["chart"].(string); !ok {
		return NewTextResult("", fmt.Errorf("failed to install helm chart, missing argument chart")), nil
	}
	values := map[string]interface{}{}
	if v, ok := req.Params.Arguments["values"].(map[string]interface{}); ok {
		values = v
	}
	name := ""
	if v, ok := req.Params.Arguments["name"].(string); ok {
		name = v
	}
	namespace := ""
	if v, ok := req.Params.Arguments["namespace"].(string); ok {
		namespace = v
	}
	derived, err := s.k.Derived(ctx)
	if err != nil {
		return nil, err
	}
	ret, err := derived.NewHelm().Install(ctx, chart, values, name, namespace)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to install helm chart '%s': %w", chart, err)), nil
	}
	return NewTextResult(ret, err), nil
}

func (s *Server) helmList(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[map[string]any]]) (*mcp.CallToolResultFor[any], error) {
	allNamespaces := false
	if v, ok := req.Params.Arguments["all_namespaces"].(bool); ok {
		allNamespaces = v
	}
	namespace := ""
	if v, ok := req.Params.Arguments["namespace"].(string); ok {
		namespace = v
	}
	derived, err := s.k.Derived(ctx)
	if err != nil {
		return nil, err
	}
	ret, err := derived.NewHelm().List(namespace, allNamespaces)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to list helm releases in namespace '%s': %w", namespace, err)), nil
	}
	return NewTextResult(ret, err), nil
}

func (s *Server) helmUninstall(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[map[string]any]]) (*mcp.CallToolResultFor[any], error) {
	var name string
	ok := false
	if name, ok = req.Params.Arguments["name"].(string); !ok {
		return NewTextResult("", fmt.Errorf("failed to uninstall helm chart, missing argument name")), nil
	}
	namespace := ""
	if v, ok := req.Params.Arguments["namespace"].(string); ok {
		namespace = v
	}
	derived, err := s.k.Derived(ctx)
	if err != nil {
		return nil, err
	}
	ret, err := derived.NewHelm().Uninstall(name, namespace)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to uninstall helm chart '%s': %w", name, err)), nil
	}
	return NewTextResult(ret, err), nil
}
