package kubernetes

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	authenticationv1api "k8s.io/api/authentication/v1"
	rbacv1api "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// IntegrationTestConfig holds configuration for integration tests
type IntegrationTestConfig struct {
	KubeconfigPath string
	TestNamespace  string
	TestUsers      []TestUser
}

// TestUser represents a test user with expected permissions
type TestUser struct {
	Username            string
	Groups              []string
	ExpectedPermissions map[string]bool // resource:verb -> expected result
}

// setupTestUsers creates test users and their RBAC permissions
func setupTestUsers(t *testing.T, clientset *kubernetes.Clientset, namespace string) []TestUser {
	// Define test users with different permission levels
	testUsers := []TestUser{
		{
			Username: "pod-user@example.com",
			Groups:   []string{"pod-readers"},
			ExpectedPermissions: map[string]bool{
				"pods:list":        true,
				"pods:get":         true,
				"deployments:list": false,
				"deployments:get":  false,
				"services:list":    false,
				"services:get":     false,
			},
		},
		{
			Username: "admin@example.com",
			Groups:   []string{"admins"},
			ExpectedPermissions: map[string]bool{
				"pods:list":          true,
				"pods:get":           true,
				"pods:delete":        true,
				"deployments:list":   true,
				"deployments:get":    true,
				"deployments:create": true,
				"services:list":      true,
				"services:get":       true,
				"services:create":    true,
			},
		},
		{
			Username: "no-access@example.com",
			Groups:   []string{"no-permissions"},
			ExpectedPermissions: map[string]bool{
				"pods:list":        false,
				"pods:get":         false,
				"deployments:list": false,
				"services:list":    false,
			},
		},
	}

	// Create RBAC resources for each test user
	for _, user := range testUsers {
		createUserRBAC(t, clientset, namespace, user)
	}

	return testUsers
}

// createUserRBAC creates the necessary RBAC resources for a test user
func createUserRBAC(t *testing.T, clientset *kubernetes.Clientset, namespace string, user TestUser) {
	// Create roles based on user permissions
	var rules []rbacv1api.PolicyRule

	// Add rules based on expected permissions
	if user.ExpectedPermissions["pods:list"] || user.ExpectedPermissions["pods:get"] {
		rules = append(rules, rbacv1api.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     getVerbsForResource(user.ExpectedPermissions, "pods"),
		})
	}

	if user.ExpectedPermissions["deployments:list"] || user.ExpectedPermissions["deployments:get"] || user.ExpectedPermissions["deployments:create"] {
		rules = append(rules, rbacv1api.PolicyRule{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     getVerbsForResource(user.ExpectedPermissions, "deployments"),
		})
	}

	if user.ExpectedPermissions["services:list"] || user.ExpectedPermissions["services:get"] || user.ExpectedPermissions["services:create"] {
		rules = append(rules, rbacv1api.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     getVerbsForResource(user.ExpectedPermissions, "services"),
		})
	}

	// Create role
	role := &rbacv1api.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("test-role-%s", user.Username),
			Namespace: namespace,
		},
		Rules: rules,
	}

	_, err := clientset.RbacV1().Roles(namespace).Create(context.Background(), role, metav1.CreateOptions{})
	if err != nil {
		t.Logf("Role already exists or failed to create: %v", err)
	}

	// Create role binding
	roleBinding := &rbacv1api.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("test-rolebinding-%s", user.Username),
			Namespace: namespace,
		},
		RoleRef: rbacv1api.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     role.Name,
		},
		Subjects: []rbacv1api.Subject{
			{
				Kind:     "User",
				Name:     user.Username,
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}

	// Add group subjects
	for _, group := range user.Groups {
		roleBinding.Subjects = append(roleBinding.Subjects, rbacv1api.Subject{
			Kind:     "Group",
			Name:     group,
			APIGroup: "rbac.authorization.k8s.io",
		})
	}

	_, err = clientset.RbacV1().RoleBindings(namespace).Create(context.Background(), roleBinding, metav1.CreateOptions{})
	if err != nil {
		t.Logf("RoleBinding already exists or failed to create: %v", err)
	}
}

// getVerbsForResource extracts verbs for a specific resource from expected permissions
func getVerbsForResource(expectedPermissions map[string]bool, resource string) []string {
	var verbs []string
	for permission, allowed := range expectedPermissions {
		if allowed {
			parts := splitPermission(permission)
			if len(parts) == 2 && parts[0] == resource {
				verbs = append(verbs, parts[1])
			}
		}
	}
	return verbs
}

// splitPermission splits a permission string like "pods:list" into ["pods", "list"]
func splitPermission(permission string) []string {
	// Simple split by colon - in a real implementation, you might want more sophisticated parsing
	// This is a simplified version for testing
	return []string{permission[:len(permission)-5], permission[len(permission)-4:]}
}

// TestRBACImpersonationIntegration tests RBAC impersonation with a real Kubernetes cluster
func TestRBACImpersonationIntegration(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping integration test. Set INTEGRATION_TESTS=true to run")
	}

	// Load kubeconfig
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = clientcmd.RecommendedHomeFile
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err, "Failed to load kubeconfig")

	// Create clientset
	clientset, err := kubernetes.NewForConfig(config)
	require.NoError(t, err, "Failed to create clientset")

	// Create test namespace
	testNamespace := fmt.Sprintf("test-rbac-%d", time.Now().Unix())

	// Clean up namespace after test
	defer func() {
		clientset.CoreV1().Namespaces().Delete(context.Background(), testNamespace, metav1.DeleteOptions{})
	}()

	// Setup test users and their RBAC permissions
	testUsers := setupTestUsers(t, clientset, testNamespace)

	// Create RBAC validator
	validator, err := NewRBACValidator(config)
	require.NoError(t, err, "Failed to create RBAC validator")

	// Test each user's permissions
	for _, user := range testUsers {
		t.Run(fmt.Sprintf("User_%s", user.Username), func(t *testing.T) {
			// Create user info for impersonation
			userInfo := &authenticationv1api.UserInfo{
				Username: user.Username,
				Groups:   user.Groups,
			}

			// Test each expected permission
			for permission, expectedResult := range user.ExpectedPermissions {
				t.Run(fmt.Sprintf("Permission_%s", permission), func(t *testing.T) {
					// Parse permission (e.g., "pods:list" -> resource="pods", verb="list")
					parts := splitPermission(permission)
					require.Len(t, parts, 2, "Invalid permission format: %s", permission)

					resource := parts[0]
					verb := parts[1]

					// Test the permission using impersonation
					err := validator.ValidateUserAccess(context.Background(), userInfo, resource, verb, testNamespace, "")

					if expectedResult {
						// Should succeed
						assert.NoError(t, err, "User %s should have %s permission for %s", user.Username, verb, resource)
					} else {
						// Should fail
						assert.Error(t, err, "User %s should not have %s permission for %s", user.Username, verb, resource)
						if err != nil {
							assert.Contains(t, err.Error(), "access denied", "Error should indicate access denied")
						}
					}
				})
			}
		})
	}
}

// TestUserAwareClientIntegration tests user-aware client with real Kubernetes cluster
func TestUserAwareClientIntegration(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping integration test. Set INTEGRATION_TESTS=true to run")
	}

	// Load kubeconfig
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = clientcmd.RecommendedHomeFile
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err, "Failed to load kubeconfig")

	// Test user info
	userInfo := &authenticationv1api.UserInfo{
		Username: "test-user@example.com",
		Groups:   []string{"test-group"},
		Extra: map[string]authenticationv1api.ExtraValue{
			"scope": {"read", "write"},
		},
	}

	// Create user-aware client
	userClient := NewUserAwareClient(config, userInfo)
	require.NotNil(t, userClient)

	// Get the config with impersonation
	impersonatedConfig := userClient.GetConfig()
	require.NotNil(t, impersonatedConfig)

	// Verify impersonation settings
	assert.Equal(t, userInfo.Username, impersonatedConfig.Impersonate.UserName)
	assert.Equal(t, userInfo.Groups, impersonatedConfig.Impersonate.Groups)
	assert.Equal(t, []string{"read", "write"}, impersonatedConfig.Impersonate.Extra["scope"])

	// Test that the impersonated config can create a clientset
	impersonatedClientset, err := kubernetes.NewForConfig(impersonatedConfig)
	require.NoError(t, err, "Failed to create clientset with impersonated config")

	// Test a simple operation with impersonation
	// This will fail if the user doesn't have permissions, but that's expected
	_, err = impersonatedClientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	// We don't assert on the result here because it depends on the user's actual permissions
	// The important thing is that the impersonation is working correctly
	t.Logf("Impersonated clientset test completed with error: %v", err)
}

// TestTokenReviewIntegration tests token review with real Kubernetes cluster
func TestTokenReviewIntegration(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping integration test. Set INTEGRATION_TESTS=true to run")
	}

	// This test would require a real JWT token from your OIDC provider
	// For now, we'll test the TokenReview API structure
	config, err := clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
	require.NoError(t, err, "Failed to load kubeconfig")

	clientset, err := kubernetes.NewForConfig(config)
	require.NoError(t, err, "Failed to create clientset")

	// Test TokenReview API structure (without a real token)
	tokenReview := &authenticationv1api.TokenReview{
		Spec: authenticationv1api.TokenReviewSpec{
			Token:     "dummy-token",
			Audiences: []string{"kubernetes-mcp-server"},
		},
	}

	// This will fail with a dummy token, but we can verify the API structure
	result, err := clientset.AuthenticationV1().TokenReviews().Create(context.Background(), tokenReview, metav1.CreateOptions{})

	// We expect this to fail with a dummy token, but we can check the structure
	if err != nil {
		t.Logf("TokenReview failed as expected with dummy token: %v", err)
	} else {
		t.Logf("TokenReview result: %+v", result)
	}
}

// BenchmarkRBACValidationIntegration benchmarks RBAC validation with real cluster
func BenchmarkRBACValidationIntegration(b *testing.B) {
	// Skip if not running integration tests
	if os.Getenv("INTEGRATION_TESTS") != "true" {
		b.Skip("Skipping integration benchmark. Set INTEGRATION_TESTS=true to run")
	}

	// Load kubeconfig
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = clientcmd.RecommendedHomeFile
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(b, err, "Failed to load kubeconfig")

	// Create RBAC validator
	validator, err := NewRBACValidator(config)
	require.NoError(b, err, "Failed to create RBAC validator")

	// Test user info
	userInfo := &authenticationv1api.UserInfo{
		Username: "benchmark-user@example.com",
		Groups:   []string{"benchmark-group"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateUserAccess(context.Background(), userInfo, "pods", "list", "default", "")
	}
}
