package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type secretsManagerAPI interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// awsStore reads from AWS Secrets Manager. A policy ref's path is the secret
// name (optionally namespaced by prefix) and its field is a key in the
// secret's JSON key/value string — the Secrets Manager console default.
// Credentials come from the standard AWS chain: environment keys, shared
// config/SSO profiles, or an attached IAM role.
type awsStore struct {
	client secretsManagerAPI
	prefix string
}

func newAWSStore(ctx context.Context, prefix string) (*awsStore, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("AWS region is not configured (set AWS_REGION)")
	}
	return &awsStore{
		client: secretsmanager.NewFromConfig(cfg),
		prefix: strings.Trim(prefix, "/"),
	}, nil
}

func (s *awsStore) Read(ctx context.Context, ref *SecretRef) (string, error) {
	name := strings.Trim(ref.Path, "/")
	if s.prefix != "" {
		name = s.prefix + "/" + name
	}
	out, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(name),
	})
	if err != nil {
		return "", fmt.Errorf("secrets manager read %s: %w", name, err)
	}
	if out.SecretString == nil {
		return "", fmt.Errorf("secret %s has no string value (binary secrets are unsupported)", name)
	}
	var values map[string]any
	if err := json.Unmarshal([]byte(*out.SecretString), &values); err != nil {
		return "", fmt.Errorf("secret %s is not a JSON key/value secret", name)
	}
	value, ok := values[ref.Field].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("secret %s#%s not found", name, ref.Field)
	}
	return value, nil
}
