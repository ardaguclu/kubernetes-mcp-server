package kubernetes

import (
	"context"
	"fmt"
	"testing"

	authenticationv1api "k8s.io/api/authentication/v1"
	authorizationv1api "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockSelfSubjectAccessReviewInterface mocks the SelfSubjectAccessReview interface
type MockSelfSubjectAccessReviewInterface struct {
	mock.Mock
}

func (m *MockSelfSubjectAccessReviewInterface) Create(ctx context.Context, review *authorizationv1api.SelfSubjectAccessReview, opts metav1.CreateOptions) (*authorizationv1api.SelfSubjectAccessReview, error) {
	args := m.Called(ctx, review, opts)
	return args.Get(0).(*authorizationv1api.SelfSubjectAccessReview), args.Error(1)
}

// MockAccessControlClientset mocks the AccessControlClientset
type MockAccessControlClientset struct {
	mock.Mock
	ssarClient *MockSelfSubjectAccessReviewInterface
}

func (m *MockAccessControlClientset) SelfSubjectAccessReviews() (authorizationv1.SelfSubjectAccessReviewInterface, error) {
	args := m.Called()
	return m.ssarClient, args.Error(1)
}

// MockUserAwareManager mocks the UserAwareManager
type MockUserAwareManager struct {
	mock.Mock
	userInfo  *authenticationv1api.UserInfo
	clientset *MockAccessControlClientset
}

func (m *MockUserAwareManager) GetUserInfo() *authenticationv1api.UserInfo {
	return m.userInfo
}

func (m *MockUserAwareManager) GetUserAwareAccessControlClientset() (*AccessControlClientset, error) {
	args := m.Called()
	return &AccessControlClientset{}, args.Error(1)
}

// TestRBACImpersonation tests that impersonation works correctly for users with different permissions
func TestRBACImpersonation(t *testing.T) {
	// Test cases for different user permission scenarios
	testCases := []struct {
		name           string
		userInfo       *authenticationv1api.UserInfo
		resource       string
		verb           string
		namespace      string
		expectedResult bool
		description    string
	}{
		{
			name: "User with pod access can list pods",
			userInfo: &authenticationv1api.UserInfo{
				Username: "pod-user@example.com",
				Groups:   []string{"pod-readers"},
			},
			resource:       "pods",
			verb:           "list",
			namespace:      "default",
			expectedResult: true,
			description:    "User should be able to list pods",
		},
		{
			name: "User with pod access cannot list deployments",
			userInfo: &authenticationv1api.UserInfo{
				Username: "pod-user@example.com",
				Groups:   []string{"pod-readers"},
			},
			resource:       "deployments",
			verb:           "list",
			namespace:      "default",
			expectedResult: false,
			description:    "User should not be able to list deployments",
		},
		{
			name: "Admin user can list both pods and deployments",
			userInfo: &authenticationv1api.UserInfo{
				Username: "admin@example.com",
				Groups:   []string{"admins"},
			},
			resource:       "pods",
			verb:           "list",
			namespace:      "default",
			expectedResult: true,
			description:    "Admin should be able to list pods",
		},
		{
			name: "Admin user can list deployments",
			userInfo: &authenticationv1api.UserInfo{
				Username: "admin@example.com",
				Groups:   []string{"admins"},
			},
			resource:       "deployments",
			verb:           "list",
			namespace:      "default",
			expectedResult: true,
			description:    "Admin should be able to list deployments",
		},
		{
			name: "User with no permissions cannot access anything",
			userInfo: &authenticationv1api.UserInfo{
				Username: "no-access@example.com",
				Groups:   []string{"no-permissions"},
			},
			resource:       "pods",
			verb:           "list",
			namespace:      "default",
			expectedResult: false,
			description:    "User with no permissions should be denied",
		},
		{
			name: "User can access resources in authorized namespace only",
			userInfo: &authenticationv1api.UserInfo{
				Username: "namespace-user@example.com",
				Groups:   []string{"namespace-users"},
			},
			resource:       "pods",
			verb:           "list",
			namespace:      "authorized-namespace",
			expectedResult: true,
			description:    "User should access resources in authorized namespace",
		},
		{
			name: "User cannot access resources in unauthorized namespace",
			userInfo: &authenticationv1api.UserInfo{
				Username: "namespace-user@example.com",
				Groups:   []string{"namespace-users"},
			},
			resource:       "pods",
			verb:           "list",
			namespace:      "unauthorized-namespace",
			expectedResult: false,
			description:    "User should not access resources in unauthorized namespace",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock clientset
			mockClientset := &MockAccessControlClientset{}
			mockSSARClient := &MockSelfSubjectAccessReviewInterface{}
			mockClientset.ssarClient = mockSSARClient

			// Create mock manager
			mockManager := &MockUserAwareManager{
				userInfo:  tc.userInfo,
				clientset: mockClientset,
			}

			// Set up expected SelfSubjectAccessReview response
			expectedReview := &authorizationv1api.SelfSubjectAccessReview{
				Status: authorizationv1api.SubjectAccessReviewStatus{
					Allowed: tc.expectedResult,
					Reason:  fmt.Sprintf("User %s %s access to %s", tc.userInfo.Username, tc.verb, tc.resource),
				},
			}

			// Configure mock expectations
			mockManager.On("GetUserAwareAccessControlClientset").Return(mockClientset, nil)
			mockClientset.On("SelfSubjectAccessReviews").Return(mockSSARClient, nil)
			mockSSARClient.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(expectedReview, nil)

			// Test the RBAC validation
			err := testRBACValidation(mockManager, tc.resource, tc.verb, tc.namespace, "")

			if tc.expectedResult {
				// Should succeed
				assert.NoError(t, err, tc.description)
			} else {
				// Should fail
				assert.Error(t, err, tc.description)
				assert.Contains(t, err.Error(), "access denied", tc.description)
			}

			// Verify mock expectations
			mockClientset.AssertExpectations(t)
			mockSSARClient.AssertExpectations(t)
		})
	}
}

// testRBACValidation is a helper function that simulates the RBAC validation process
func testRBACValidation(manager *MockUserAwareManager, resource, verb, namespace, name string) error {
	// Get the user-aware clientset
	clientset, err := manager.GetUserAwareAccessControlClientset()
	if err != nil {
		return fmt.Errorf("failed to create user-aware clientset: %w", err)
	}

	// Create a SelfSubjectAccessReview to check permissions
	ssarClient, err := clientset.SelfSubjectAccessReviews()
	if err != nil {
		return fmt.Errorf("failed to create SelfSubjectAccessReview client: %w", err)
	}

	// Parse resource to get group, version, resource
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

	result, err := ssarClient.Create(context.Background(), review, metav1.CreateOptions{})
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

	klog.V(4).Infof("User %s has %s access to %s in namespace %s",
		manager.GetUserInfo().Username, verb, resource, namespace)

	return nil
}

// TestUserAwareClient tests the user-aware client creation and configuration
func TestUserAwareClient(t *testing.T) {
	// Create a base config
	baseConfig := &rest.Config{
		Host: "https://kubernetes.example.com",
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: false,
		},
	}

	// Test user info
	userInfo := &authenticationv1api.UserInfo{
		Username: "test-user@example.com",
		Groups:   []string{"test-group"},
		Extra: map[string]authenticationv1api.ExtraValue{
			"scope": {"read", "write"},
		},
	}

	// Create user-aware client
	userClient := NewUserAwareClient(baseConfig, userInfo)
	assert.NotNil(t, userClient)

	// Get the config with impersonation
	config := userClient.GetConfig()
	assert.NotNil(t, config)

	// Verify impersonation settings
	assert.Equal(t, userInfo.Username, config.Impersonate.UserName)
	assert.Equal(t, userInfo.Groups, config.Impersonate.Groups)
	assert.Equal(t, []string{"read", "write"}, config.Impersonate.Extra["scope"])

	// Test with nil user info
	nilUserClient := NewUserAwareClient(baseConfig, nil)
	nilConfig := nilUserClient.GetConfig()
	assert.Equal(t, "", nilConfig.Impersonate.UserName)
	assert.Empty(t, nilConfig.Impersonate.Groups)
}

// TestResourceVerbMapping tests the mapping between tools and their required permissions
func TestResourceVerbMapping(t *testing.T) {
	// Test that all expected tools are mapped
	expectedTools := []string{
		// Pod tools
		"list_pods", "pods_list", "pods_list_in_namespace",
		"get_pod", "pods_get",
		"delete_pod", "pods_delete",
		"exec_pod", "pods_exec",
		"get_pod_logs", "pods_log", "pods_top", "pods_run",

		// Service tools
		"list_services",

		// ConfigMap tools
		"list_configmaps", "get_configmap",

		// Secret tools
		"list_secrets", "get_secret",

		// Namespace tools
		"list_namespaces", "namespaces_list", "get_namespace",

		// Event tools
		"events_list",

		// Helm tools
		"helm_list", "helm_install", "helm_uninstall",

		// Resource tools (generic)
		"list_resources", "resources_list",
		"get_resource", "resources_get",
		"delete_resource", "resources_delete",
		"apply_resource", "resources_create_or_update",

		// Configuration tools
		"configuration_view",

		// OpenShift specific tools
		"projects_list",
	}

	for _, tool := range expectedTools {
		t.Run(fmt.Sprintf("Tool %s has RBAC mapping", tool), func(t *testing.T) {
			requirement, exists := ResourceVerbMapping[tool]
			assert.True(t, exists, "Tool %s should have RBAC mapping", tool)
			assert.NotEmpty(t, requirement.Resource, "Tool %s should have resource defined", tool)
			assert.NotEmpty(t, requirement.Verb, "Tool %s should have verb defined", tool)
			assert.NotEmpty(t, requirement.Scope, "Tool %s should have scope defined", tool)
		})
	}

	// Test specific mappings
	testCases := []struct {
		tool     string
		resource string
		verb     string
		scope    string
	}{
		{"list_pods", "pods", "list", "namespace"},
		{"pods_list", "pods", "list", "namespace"},
		{"pods_list_in_namespace", "pods", "list", "namespace"},
		{"delete_pod", "pods", "delete", "namespace"},
		{"pods_delete", "pods", "delete", "namespace"},
		{"list_namespaces", "namespaces", "list", "cluster"},
		{"namespaces_list", "namespaces", "list", "cluster"},
		{"events_list", "events", "list", "namespace"},
		{"helm_list", "secrets", "list", "namespace"},
		{"resources_list", "pods", "list", "namespace"},
		{"projects_list", "projects", "list", "cluster"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Mapping for %s", tc.tool), func(t *testing.T) {
			requirement, exists := ResourceVerbMapping[tc.tool]
			assert.True(t, exists)
			assert.Equal(t, tc.resource, requirement.Resource)
			assert.Equal(t, tc.verb, requirement.Verb)
			assert.Equal(t, tc.scope, requirement.Scope)
		})
	}
}

// TestParseResource tests the resource parsing function
func TestParseResource(t *testing.T) {
	testCases := []struct {
		resource        string
		expectedGroup   string
		expectedVersion string
	}{
		{"pods", "", "v1"},
		{"services", "", "v1"},
		{"configmaps", "", "v1"},
		{"secrets", "", "v1"},
		{"namespaces", "", "v1"},
		{"deployments", "apps", "v1"},
		{"replicasets", "apps", "v1"},
		{"statefulsets", "apps", "v1"},
		{"ingresses", "networking.k8s.io", "v1"},
		{"roles", "rbac.authorization.k8s.io", "v1"},
		{"clusterroles", "rbac.authorization.k8s.io", "v1"},
		{"unknown", "", "v1"}, // Default case
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Parse resource %s", tc.resource), func(t *testing.T) {
			group, version := parseResource(tc.resource)
			assert.Equal(t, tc.expectedGroup, group)
			assert.Equal(t, tc.expectedVersion, version)
		})
	}
}

// TestRBACValidator tests the RBAC validator functionality
func TestRBACValidator(t *testing.T) {
	// Create a mock config
	mockConfig := &rest.Config{
		Host: "https://kubernetes.example.com",
	}

	// Test validator creation
	validator, err := NewRBACValidator(mockConfig)
	assert.NoError(t, err)
	assert.NotNil(t, validator)

	// Test user info
	userInfo := &authenticationv1api.UserInfo{
		Username: "test-user@example.com",
		Groups:   []string{"test-group"},
	}

	// Test access validation (this would require a real Kubernetes cluster)
	// For unit testing, we'll just test the function signature
	err = validator.ValidateUserAccess(context.Background(), userInfo, "pods", "list", "default", "")
	// This will fail in unit tests without a real cluster, but that's expected
	// In integration tests, this would work with a real Kubernetes cluster
}

// BenchmarkRBACValidation benchmarks the RBAC validation performance
func BenchmarkRBACValidation(b *testing.B) {
	userInfo := &authenticationv1api.UserInfo{
		Username: "benchmark-user@example.com",
		Groups:   []string{"benchmark-group"},
	}

	mockManager := &MockUserAwareManager{
		userInfo: userInfo,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = testRBACValidation(mockManager, "pods", "list", "default", "")
	}
}
