package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

func (s *Server) initHelm() []server.ServerTool {
	return []server.ServerTool{
		{mcp.NewTool("helm_install",
			mcp.WithDescription("Install a Helm chart in the current or provided namespace"),
			mcp.WithString("chart", mcp.Description("Chart reference to install (for example: stable/grafana, oci://ghcr.io/nginxinc/charts/nginx-ingress)"), mcp.Required()),
			mcp.WithObject("values", mcp.Description("Values to pass to the Helm chart (Optional)")),
			mcp.WithString("name", mcp.Description("Name of the Helm release (Optional, random name if not provided)")),
			mcp.WithString("namespace", mcp.Description("Namespace to install the Helm chart in (Optional, current namespace if not provided)")),
			// Tool annotations
			mcp.WithTitleAnnotation("Helm: Install"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(false), // TODO: consider replacing implementation with equivalent to: helm upgrade --install
			mcp.WithOpenWorldHintAnnotation(true),
		), s.helmInstall},
		{mcp.NewTool("helm_list",
			mcp.WithDescription("List all the Helm releases in the current or provided namespace (or in all namespaces if specified)"),
			mcp.WithString("namespace", mcp.Description("Namespace to list Helm releases from (Optional, all namespaces if not provided)")),
			mcp.WithBoolean("all_namespaces", mcp.Description("If true, lists all Helm releases in all namespaces ignoring the namespace argument (Optional)")),
			// Tool annotations
			mcp.WithTitleAnnotation("Helm: List"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithOpenWorldHintAnnotation(true),
		), s.helmList},
		{mcp.NewTool("helm_uninstall",
			mcp.WithDescription("Uninstall a Helm release in the current or provided namespace"),
			mcp.WithString("name", mcp.Description("Name of the Helm release to uninstall"), mcp.Required()),
			mcp.WithString("namespace", mcp.Description("Namespace to uninstall the Helm release from (Optional, current namespace if not provided)")),
			// Tool annotations
			mcp.WithTitleAnnotation("Helm: Uninstall"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(true),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(true),
		), s.helmUninstall},
	}
}

func (s *Server) helmInstall(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var chart string
	ok := false
	if chart, ok = ctr.GetArguments()["chart"].(string); !ok {
		return NewTextResult("", fmt.Errorf("failed to install helm chart, missing argument chart")), nil
	}
	values := map[string]interface{}{}
	if v, ok := ctr.GetArguments()["values"].(map[string]interface{}); ok {
		values = v
	}
	name := ""
	if v, ok := ctr.GetArguments()["name"].(string); ok {
		name = v
	}
	namespace := ""
	if v, ok := ctr.GetArguments()["namespace"].(string); ok {
		namespace = v
	}

	// Pre-flight authorization: Check permissions for all resources that will be created
	if err := s.checkHelmInstallPermissions(ctx, chart, values, name, namespace); err != nil {
		return NewTextResult("", fmt.Errorf("failed to install helm chart '%s': authorization failed: %w", chart, err)), nil
	}

	ret, err := s.k.Derived(ctx).NewHelm().Install(ctx, chart, values, name, namespace)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to install helm chart '%s': %w", chart, err)), nil
	}
	return NewTextResult(ret, err), nil
}

func (s *Server) helmList(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	allNamespaces := false
	if v, ok := ctr.GetArguments()["all_namespaces"].(bool); ok {
		allNamespaces = v
	}
	namespace := ""
	if v, ok := ctr.GetArguments()["namespace"].(string); ok {
		namespace = v
	}

	secretsGVR := &schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}
	if err := s.k.Derived(ctx).CanClientAccess(ctx, secretsGVR, "", namespace, "list", ""); err != nil {
		return NewTextResult("", fmt.Errorf("failed to list helm releases in namespace '%s': authorization failed: %w", namespace, err)), nil
	}

	ret, err := s.k.Derived(ctx).NewHelm().List(namespace, allNamespaces)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to list helm releases in namespace '%s': %w", namespace, err)), nil
	}
	return NewTextResult(ret, err), nil
}

func (s *Server) helmUninstall(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var name string
	ok := false
	if name, ok = ctr.GetArguments()["name"].(string); !ok {
		return NewTextResult("", fmt.Errorf("failed to uninstall helm chart, missing argument name")), nil
	}
	namespace := ""
	if v, ok := ctr.GetArguments()["namespace"].(string); ok {
		namespace = v
	}

	if err := s.checkHelmUninstallPermissions(ctx, name, namespace); err != nil {
		return NewTextResult("", fmt.Errorf("failed to uninstall helm chart '%s': authorization failed: %w", name, err)), nil
	}

	ret, err := s.k.Derived(ctx).NewHelm().Uninstall(name, namespace)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to uninstall helm chart '%s': %w", name, err)), nil
	}
	return NewTextResult(ret, err), nil
}

// checkHelmInstallPermissions performs pre-flight authorization check by rendering templates and checking user permissions
func (s *Server) checkHelmInstallPermissions(ctx context.Context, chart string, values map[string]interface{}, name, namespace string) error {
	renderedManifests, err := s.renderHelmChart(ctx, chart, values, name, namespace)
	if err != nil {
		return fmt.Errorf("failed to render helm chart templates: %w", err)
	}

	return s.checkManifestPermissions(ctx, renderedManifests, namespace, "create")
}

// renderHelmChart renders the Helm chart templates using dry-run mode
func (s *Server) renderHelmChart(ctx context.Context, chart string, values map[string]interface{}, name, namespace string) (string, error) {
	helm := s.k.Derived(ctx).NewHelm()

	renderedManifests, err := helm.RenderTemplateDryRun(ctx, chart, values, name, namespace)
	if err != nil {
		return "", fmt.Errorf("failed to render helm chart templates: %w", err)
	}

	return renderedManifests, nil
}

func (s *Server) checkHelmUninstallPermissions(ctx context.Context, name, namespace string) error {
	helm := s.k.Derived(ctx).NewHelm()
	releaseManifests, err := helm.GetReleaseManifests(name, namespace)
	if err != nil {
		secretsGVR := &schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "secrets",
		}
		return s.k.Derived(ctx).CanClientAccess(ctx, secretsGVR, "", namespace, "delete", "")
	}

	return s.checkManifestPermissions(ctx, releaseManifests, namespace, "delete")
}

// checkManifestPermissions checks if the user has permissions for all resources in the manifests
func (s *Server) checkManifestPermissions(ctx context.Context, manifests, namespace, verb string) error {
	if manifests == "" {
		secretsGVR := &schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "secrets",
		}
		return s.k.Derived(ctx).CanClientAccess(ctx, secretsGVR, "", namespace, verb, "")
	}

	separator := "---"
	manifestList := strings.Split(manifests, separator)

	for _, manifest := range manifestList {
		manifest = strings.TrimSpace(manifest)
		if manifest == "" {
			continue
		}

		var obj unstructured.Unstructured
		if err := yaml.Unmarshal([]byte(manifest), &obj); err != nil {
			return fmt.Errorf("failed to parse manifest: %w", err)
		}

		if obj.Object == nil {
			continue
		}

		gvk := obj.GroupVersionKind()
		resourceNamespace := obj.GetNamespace()
		if resourceNamespace == "" {
			resourceNamespace = namespace
		}

		gvr, err := s.k.Derived(ctx).ResourceFor(&gvk)
		if err != nil {
			return fmt.Errorf("failed to get resource info for %s: %w", gvk.String(), err)
		}

		if err := s.k.Derived(ctx).CanClientAccess(ctx, gvr, obj.GetName(), resourceNamespace, verb, ""); err != nil {
			return fmt.Errorf("insufficient permissions for %s %s/%s in namespace %s: %w", verb, gvk.Kind, obj.GetName(), resourceNamespace, err)
		}
	}

	return nil
}
