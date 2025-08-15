package mcp

import (
	"context"
	"fmt"

	"github.com/containers/kubernetes-mcp-server/pkg/output"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/utils/ptr"
)

func (s *Server) initConfiguration() []ToolWithHandler {
	tools := []ToolWithHandler{
		{
			Tool: &mcp.Tool{
				Annotations: &mcp.ToolAnnotations{
					DestructiveHint: ptr.To(false),
					ReadOnlyHint:    true,
					OpenWorldHint:   ptr.To(true),
					Title:           "Configuration: View",
				},
				Description: "Get the current Kubernetes configuration content as a kubeconfig YAML",
				Name:        "configuration_view",
				Title:       "Configuration: View",
			},
			Handler: s.configurationView},
	}
	return tools
}

func (s *Server) configurationView(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[map[string]any]]) (*mcp.CallToolResultFor[any], error) {
	minify := true
	if val, ok := req.Params.Arguments["minify"]; ok {
		minify = val.(bool)
	}
	ret, err := s.k.ConfigurationView(minify)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to get configuration: %v", err)), nil
	}
	configurationYaml, err := output.MarshalYaml(ret)
	if err != nil {
		err = fmt.Errorf("failed to get configuration: %v", err)
	}
	return NewTextResult(configurationYaml, err), nil
}
