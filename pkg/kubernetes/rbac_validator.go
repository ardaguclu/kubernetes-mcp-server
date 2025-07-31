package kubernetes

import (
	"context"
	"fmt"

	authenticationv1api "k8s.io/api/authentication/v1"
	authorizationv1api "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

// RBACValidator validates RBAC permissions using SelfSubjectAccessReview
type RBACValidator struct {
	ssarClient authorizationv1.SelfSubjectAccessReviewInterface
	config     *rest.Config
}

// NewRBACValidator creates a new RBAC validator
func NewRBACValidator(config *rest.Config) (*RBACValidator, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	return &RBACValidator{
		ssarClient: clientset.AuthorizationV1().SelfSubjectAccessReviews(),
		config:     config,
	}, nil
}

// ValidateAccess checks if the user has the specified permission
func (rv *RBACValidator) ValidateAccess(ctx context.Context, resource, verb, namespace, name string) error {
	// Parse resource to determine group and version
	group, version := parseResource(resource)

	review := &authorizationv1api.SelfSubjectAccessReview{
		Spec: authorizationv1api.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1api.ResourceAttributes{
				Namespace: namespace,
				Verb:      verb,
				Group:     group,
				Version:   version,
				Resource:  resource,
				Name:      name,
			},
		},
	}

	result, err := rv.ssarClient.Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create SelfSubjectAccessReview: %w", err)
	}

	if !result.Status.Allowed {
		reason := result.Status.Reason
		if reason == "" {
			reason = "Access denied"
		}
		return fmt.Errorf("access denied: %s", reason)
	}

	klog.V(4).Infof("RBAC validation passed: %s %s in namespace %s", verb, resource, namespace)
	return nil
}

// ValidateUserAccess validates access for a specific user using impersonation
func (rv *RBACValidator) ValidateUserAccess(ctx context.Context, userInfo *authenticationv1api.UserInfo, resource, verb, namespace, name string) error {
	// Create a new config with user impersonation
	userConfig := rest.CopyConfig(rv.config)
	userConfig.Impersonate.UserName = userInfo.Username
	userConfig.Impersonate.Groups = userInfo.Groups
	if userInfo.Extra != nil {
		userConfig.Impersonate.Extra = make(map[string][]string)
		for k, v := range userInfo.Extra {
			userConfig.Impersonate.Extra[k] = v
		}
	}

	// Create a new validator with the user-impersonated config
	userValidator, err := NewRBACValidator(userConfig)
	if err != nil {
		return fmt.Errorf("failed to create user-aware RBAC validator: %w", err)
	}

	return userValidator.ValidateAccess(ctx, resource, verb, namespace, name)
}

// parseResource determines the group and version for a given resource
func parseResource(resource string) (group, version string) {
	// Handle core resources
	switch resource {
	case "pods", "services", "configmaps", "secrets", "namespaces", "nodes":
		return "", "v1"
	case "deployments", "replicasets", "statefulsets", "daemonsets":
		return "apps", "v1"
	case "ingresses":
		return "networking.k8s.io", "v1"
	case "persistentvolumeclaims", "persistentvolumes":
		return "", "v1"
	case "serviceaccounts":
		return "", "v1"
	case "roles", "rolebindings":
		return "rbac.authorization.k8s.io", "v1"
	case "clusterroles", "clusterrolebindings":
		return "rbac.authorization.k8s.io", "v1"
	default:
		// Default to core v1 for unknown resources
		return "", "v1"
	}
}

// ResourceVerbMapping defines the mapping between tools and their required permissions
var ResourceVerbMapping = map[string]struct {
	Resource string
	Verb     string
	Scope    string // "namespace" or "cluster"
}{
	// Pod tools
	"list_pods": {
		Resource: "pods",
		Verb:     "list",
		Scope:    "namespace",
	},
	"pods_list": {
		Resource: "pods",
		Verb:     "list",
		Scope:    "namespace",
	},
	"pods_list_in_namespace": {
		Resource: "pods",
		Verb:     "list",
		Scope:    "namespace",
	},
	"get_pod": {
		Resource: "pods",
		Verb:     "get",
		Scope:    "namespace",
	},
	"pods_get": {
		Resource: "pods",
		Verb:     "get",
		Scope:    "namespace",
	},
	"delete_pod": {
		Resource: "pods",
		Verb:     "delete",
		Scope:    "namespace",
	},
	"pods_delete": {
		Resource: "pods",
		Verb:     "delete",
		Scope:    "namespace",
	},
	"exec_pod": {
		Resource: "pods",
		Verb:     "create",
		Scope:    "namespace",
	},
	"pods_exec": {
		Resource: "pods",
		Verb:     "create",
		Scope:    "namespace",
	},
	"get_pod_logs": {
		Resource: "pods",
		Verb:     "get",
		Scope:    "namespace",
	},
	"pods_log": {
		Resource: "pods",
		Verb:     "get",
		Scope:    "namespace",
	},
	"pods_top": {
		Resource: "pods",
		Verb:     "get",
		Scope:    "namespace",
	},
	"pods_run": {
		Resource: "pods",
		Verb:     "create",
		Scope:    "namespace",
	},

	// Service tools
	"list_services": {
		Resource: "services",
		Verb:     "list",
		Scope:    "namespace",
	},

	// ConfigMap tools
	"list_configmaps": {
		Resource: "configmaps",
		Verb:     "list",
		Scope:    "namespace",
	},
	"get_configmap": {
		Resource: "configmaps",
		Verb:     "get",
		Scope:    "namespace",
	},

	// Secret tools
	"list_secrets": {
		Resource: "secrets",
		Verb:     "list",
		Scope:    "namespace",
	},
	"get_secret": {
		Resource: "secrets",
		Verb:     "get",
		Scope:    "namespace",
	},

	// Namespace tools
	"list_namespaces": {
		Resource: "namespaces",
		Verb:     "list",
		Scope:    "cluster",
	},
	"namespaces_list": {
		Resource: "namespaces",
		Verb:     "list",
		Scope:    "cluster",
	},
	"get_namespace": {
		Resource: "namespaces",
		Verb:     "get",
		Scope:    "cluster",
	},

	// Event tools
	"events_list": {
		Resource: "events",
		Verb:     "list",
		Scope:    "namespace",
	},

	// Helm tools
	"helm_list": {
		Resource: "secrets", // Helm stores releases as secrets
		Verb:     "list",
		Scope:    "namespace",
	},
	"helm_install": {
		Resource: "secrets", // Helm stores releases as secrets
		Verb:     "create",
		Scope:    "namespace",
	},
	"helm_uninstall": {
		Resource: "secrets", // Helm stores releases as secrets
		Verb:     "delete",
		Scope:    "namespace",
	},

	// Resource tools (generic)
	"list_resources": {
		Resource: "pods", // Default to pods for list_resources
		Verb:     "list",
		Scope:    "namespace",
	},
	"resources_list": {
		Resource: "pods", // Default to pods for resources_list
		Verb:     "list",
		Scope:    "namespace",
	},
	"get_resource": {
		Resource: "pods", // Default to pods for get_resource
		Verb:     "get",
		Scope:    "namespace",
	},
	"resources_get": {
		Resource: "pods", // Default to pods for resources_get
		Verb:     "get",
		Scope:    "namespace",
	},
	"delete_resource": {
		Resource: "pods", // Default to pods for delete_resource
		Verb:     "delete",
		Scope:    "namespace",
	},
	"resources_delete": {
		Resource: "pods", // Default to pods for resources_delete
		Verb:     "delete",
		Scope:    "namespace",
	},
	"apply_resource": {
		Resource: "pods", // Default to pods for apply_resource
		Verb:     "create",
		Scope:    "namespace",
	},
	"resources_create_or_update": {
		Resource: "pods", // Default to pods for resources_create_or_update
		Verb:     "create",
		Scope:    "namespace",
	},

	// Configuration tools
	"configuration_view": {
		Resource: "configmaps",
		Verb:     "get",
		Scope:    "namespace",
	},

	// OpenShift specific tools
	"projects_list": {
		Resource: "projects", // OpenShift projects
		Verb:     "list",
		Scope:    "cluster",
	},
}
