package mcp

import (
	"context"
	"fmt"

	"github.com/containers/kubernetes-mcp-server/pkg/output"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/utils/ptr"
)

func (s *Server) initEvents() []ToolWithHandler {
	return []ToolWithHandler{
		{
			Tool: &mcp.Tool{
				Annotations: &mcp.ToolAnnotations{
					DestructiveHint: ptr.To(false),
					OpenWorldHint:   ptr.To(true),
					ReadOnlyHint:    true,
					Title:           "Events: List",
				},
				Description: "List all the Kubernetes events in the current cluster from all namespaces",
				Name:        "events_list",
				Title:       "Events: List",
			},
			Handler: s.eventsList,
		},
	}
}

func (s *Server) eventsList(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[map[string]any]]) (*mcp.CallToolResultFor[any], error) {
	namespace := ""
	if val, ok := req.Params.Arguments["namespace"]; ok {
		namespace = val.(string)
	}
	derived, err := s.k.Derived(ctx)
	if err != nil {
		return nil, err
	}
	eventMap, err := derived.EventsList(ctx, namespace)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to list events in all namespaces: %v", err)), nil
	}
	if len(eventMap) == 0 {
		return NewTextResult("No events found", nil), nil
	}
	yamlEvents, err := output.MarshalYaml(eventMap)
	if err != nil {
		err = fmt.Errorf("failed to list events in all namespaces: %v", err)
	}
	return NewTextResult(fmt.Sprintf("The following events (YAML format) were found:\n%s", yamlEvents), err), nil
}
