package mcp

import (
	"context"
	"fmt"

	"github.com/containers/kubernetes-mcp-server/pkg/kubernetes"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/utils/ptr"
)

func (s *Server) initNamespaces() []ToolWithHandler {
	tools := []ToolWithHandler{
		{
			Tool: &mcp.Tool{
				Annotations: &mcp.ToolAnnotations{
					DestructiveHint: ptr.To(false),
					ReadOnlyHint:    true,
					OpenWorldHint:   ptr.To(true),
					Title:           "Namespaces: List",
				},
				Description: "List all the Kubernetes namespaces in the current cluster",
				Name:        "namespaces_list",
				Title:       "Namespaces: List",
			},
			Handler: s.namespacesList},
	}

	if s.k.IsOpenShift(context.Background()) {
		tools = append(tools, ToolWithHandler{
			Tool: &mcp.Tool{
				Annotations: &mcp.ToolAnnotations{
					DestructiveHint: ptr.To(false),
					ReadOnlyHint:    true,
					OpenWorldHint:   ptr.To(true),
					Title:           "Projects: List",
				},
				Description: "List all the OpenShift projects in the current cluster",
				Name:        "projects_list",
				Title:       "Projects: List",
			},
			Handler: s.projectsList,
		})
	}
	return tools
}

func (s *Server) namespacesList(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[map[string]any]]) (*mcp.CallToolResultFor[any], error) {
	derived, err := s.k.Derived(ctx)
	if err != nil {
		return nil, err
	}
	ret, err := derived.NamespacesList(ctx, kubernetes.ResourceListOptions{AsTable: s.configuration.ListOutput.AsTable()})
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to list namespaces: %v", err)), nil
	}
	return NewTextResult(s.configuration.ListOutput.PrintObj(ret)), nil
}

func (s *Server) projectsList(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[map[string]any]]) (*mcp.CallToolResultFor[any], error) {
	derived, err := s.k.Derived(ctx)
	if err != nil {
		return nil, err
	}
	ret, err := derived.ProjectsList(ctx, kubernetes.ResourceListOptions{AsTable: s.configuration.ListOutput.AsTable()})
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to list projects: %v", err)), nil
	}
	return NewTextResult(s.configuration.ListOutput.PrintObj(ret)), nil
}
