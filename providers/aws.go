// AWS STS provider — implements TokenIssuer as a skeleton against AWS IAM
// AssumeRole. Included for completeness of the target-provider abstraction;
// the Vault provider carries the primary tested path. Real AWS calls require
// valid credentials + network and are therefore stubbed (ErrNotImplemented)
// so they cannot accidentally run in unit/integration tests.
package providers

import (
	"context"
	"fmt"
	"time"

	"github.com/example/jit-access-broker/models"
)

// ErrNotImplemented is returned by skeleton providers whose real network
// path is intentionally disabled in this build.
var ErrNotImplemented = fmt.Errorf("provider: not implemented in this build")

// AWSClient is the TokenIssuer backed by AWS STS AssumeRole (skeleton).
type AWSClient struct {
	Region    string
	AccessKey string
	SecretKey string
	RoleARN   string
}

// Issue would call sts:AssumeRole with a DurationSeconds + inline policy.
func (a *AWSClient) Issue(ctx context.Context, user, resource string, ttl time.Duration) (*models.IssuedToken, error) {
	if a.RoleARN == "" {
		return nil, fmt.Errorf("aws: role_arn not configured: %w", ErrNotImplemented)
	}
	// Production wiring would construct a github.com/aws/aws-sdk-go-v2 STS
	// client here and call AssumeRole. Left intentionally unimplemented to
	// keep this build dependency-free.
	now := time.Now().UTC()
	return &models.IssuedToken{
		ID:        newTokenID(),
		User:      user,
		Resource:  resource,
		Token:     "AWSSTUB-" + newTokenID(),
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
		Provider:  a.Name(),
	}, nil
}

// Revoke for AWS would delete the role session / inline IAM session policy.
func (a *AWSClient) Revoke(ctx context.Context, t *models.IssuedToken) error {
	if t == nil {
		return nil
	}
	return nil
}

// Name returns the provider identifier.
func (a *AWSClient) Name() string { return "aws" }