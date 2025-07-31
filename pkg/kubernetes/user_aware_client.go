package kubernetes

import (
	"context"
	"fmt"

	authenticationv1api "k8s.io/api/authentication/v1"
	authorizationv1api "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/klog/v2"

	"github.com/containers/kubernetes-mcp-server/pkg/helm"
	"k8s.io/client-go/dynamic"
)

// UserAwareClient wraps a Kubernetes client with user impersonation capabilities
type UserAwareClient struct {
	baseConfig *rest.Config
	userInfo   *authenticationv1api.UserInfo
}

// NewUserAwareClient creates a new user-aware client that will impersonate the given user
func NewUserAwareClient(baseConfig *rest.Config, userInfo *authenticationv1api.UserInfo) *UserAwareClient {
	return &UserAwareClient{
		baseConfig: baseConfig,
		userInfo:   userInfo,
	}
}

// GetConfig returns a REST config with user impersonation
func (uac *UserAwareClient) GetConfig() *rest.Config {
	config := rest.CopyConfig(uac.baseConfig)
	// Add user impersonation
	if uac.userInfo != nil {
		config.Impersonate.UserName = uac.userInfo.Username
		config.Impersonate.Groups = uac.userInfo.Groups
		// Convert ExtraValue to []string for impersonation
		if uac.userInfo.Extra != nil {
			config.Impersonate.Extra = make(map[string][]string)
			for k, v := range uac.userInfo.Extra {
				config.Impersonate.Extra[k] = v
			}
		}

		// Log impersonation details
		klog.V(4).Infof("Creating impersonated config for user: %s, groups: %v",
			uac.userInfo.Username, uac.userInfo.Groups)
	}
	return config
}

// GetUserInfo returns the user information for this client
func (uac *UserAwareClient) GetUserInfo() *authenticationv1api.UserInfo {
	return uac.userInfo
}

// UserAwareManager wraps the Manager to provide user-aware Kubernetes operations
type UserAwareManager struct {
	baseManager *Manager
	userClient  *UserAwareClient
}

// NewUserAwareManager creates a new user-aware manager
func NewUserAwareManager(baseManager *Manager, userInfo *authenticationv1api.UserInfo) *UserAwareManager {
	userClient := NewUserAwareClient(baseManager.cfg, userInfo)

	return &UserAwareManager{
		baseManager: baseManager,
		userClient:  userClient,
	}
}

// GetUserInfo returns the user information
func (uam *UserAwareManager) GetUserInfo() *authenticationv1api.UserInfo {
	return uam.userClient.GetUserInfo()
}

// GetUserAwareAccessControlClientset returns a user-aware access control clientset
func (uam *UserAwareManager) GetUserAwareAccessControlClientset() (*AccessControlClientset, error) {
	userConfig := uam.userClient.GetConfig()
	return NewAccessControlClientset(userConfig, uam.baseManager.staticConfig)
}

// VerifyUserAccess checks if the user has access to a specific resource and action
func (uam *UserAwareManager) VerifyUserAccess(ctx context.Context, resource, verb, namespace, name string) error {
	clientset, err := uam.GetUserAwareAccessControlClientset()
	if err != nil {
		return fmt.Errorf("failed to create user-aware clientset: %w", err)
	}

	// Create a SelfSubjectAccessReview to check permissions
	ssarClient, err := clientset.SelfSubjectAccessReviews()
	if err != nil {
		return fmt.Errorf("failed to create SelfSubjectAccessReview client: %w", err)
	}

	// Parse resource to get group, version, resource
	// This is a simplified version - you might need more sophisticated parsing
	group := ""
	version := "v1"
	resourceName := resource

	// Handle core resources (pods, services, etc.)
	if resource == "pods" || resource == "services" || resource == "configmaps" || resource == "secrets" {
		group = ""
		version = "v1"
	} else {
		// For other resources, you might need to parse the full resource name
		// This is a simplified approach
		group = ""
		version = "v1"
	}

	review := &authorizationv1api.SelfSubjectAccessReview{
		Spec: authorizationv1api.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1api.ResourceAttributes{
				Namespace: namespace,
				Verb:      verb,
				Group:     group,
				Version:   version,
				Resource:  resourceName,
				Name:      name,
			},
		},
	}

	result, err := ssarClient.Create(ctx, review, metav1.CreateOptions{})
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

	klog.V(4).Infof("User %s has %s access to %s/%s in namespace %s",
		uam.userClient.GetUserInfo().Username, verb, resource, name, namespace)

	return nil
}

// GetUserAwareKubernetes returns a user-aware Kubernetes instance
func (uam *UserAwareManager) GetUserAwareKubernetes() *Kubernetes {
	// Create a new manager with user impersonation
	userConfig := uam.userClient.GetConfig()
	userManager := &Manager{
		cfg:          userConfig,
		staticConfig: uam.baseManager.staticConfig,
	}

	// Initialize the user manager with the same configuration as base manager
	// but using the impersonated config
	userManager.clientCmdConfig = uam.baseManager.clientCmdConfig
	userManager.discoveryClient = memory.NewMemCacheClient(uam.baseManager.discoveryClient)
	userManager.accessControlRESTMapper = uam.baseManager.accessControlRESTMapper

	// Create new clients with impersonated config
	var err error
	userManager.accessControlClientSet, err = NewAccessControlClientset(userConfig, uam.baseManager.staticConfig)
	if err != nil {
		// Fallback to base manager if user config fails
		return &Kubernetes{
			manager: uam.baseManager,
		}
	}

	userManager.dynamicClient, err = dynamic.NewForConfig(userConfig)
	if err != nil {
		// Fallback to base manager if user config fails
		return &Kubernetes{
			manager: uam.baseManager,
		}
	}

	return &Kubernetes{
		manager: userManager,
	}
}

// Implement the Manager interface methods for UserAwareManager
func (uam *UserAwareManager) Close() {
	uam.baseManager.Close()
}

func (uam *UserAwareManager) GetAPIServerHost() string {
	return uam.baseManager.GetAPIServerHost()
}

func (uam *UserAwareManager) ToDiscoveryClient() (discovery.CachedDiscoveryInterface, error) {
	// Use the base manager's discovery client but with user impersonation
	userConfig := uam.userClient.GetConfig()
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(userConfig)
	if err != nil {
		return nil, err
	}
	return memory.NewMemCacheClient(discoveryClient), nil
}

func (uam *UserAwareManager) ToRESTMapper() (meta.RESTMapper, error) {
	discoveryClient, err := uam.ToDiscoveryClient()
	if err != nil {
		return nil, err
	}
	return restmapper.NewDeferredDiscoveryRESTMapper(discoveryClient), nil
}

func (uam *UserAwareManager) Derived(ctx context.Context) (*Kubernetes, error) {
	return uam.GetUserAwareKubernetes(), nil
}

func (uam *UserAwareManager) NewHelm() *helm.Helm {
	// Create a user-aware helm instance
	userConfig := uam.userClient.GetConfig()
	// We need to create a user-aware manager for helm
	userManager := &Manager{
		cfg:          userConfig,
		staticConfig: uam.baseManager.staticConfig,
	}
	return helm.NewHelm(userManager)
}
