package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type fakeSecretsManager struct {
	values map[string]string // secret name -> SecretString
}

func (f *fakeSecretsManager) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	value, ok := f.values[aws.ToString(in.SecretId)]
	if !ok {
		return nil, fmt.Errorf("ResourceNotFoundException")
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(value)}, nil
}

func TestAWSStoreReadsJSONField(t *testing.T) {
	store := &awsStore{
		client: &fakeSecretsManager{values: map[string]string{
			"tinfoil/workloads/hello/demo": `{"value": "hunter2", "other": "x"}`,
		}},
		prefix: "tinfoil",
	}
	value, err := store.Read(context.Background(), &SecretRef{Path: "workloads/hello/demo", Field: "value"})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if value != "hunter2" {
		t.Fatalf("value = %q", value)
	}
}

func TestAWSStoreMissingFieldOrSecret(t *testing.T) {
	store := &awsStore{
		client: &fakeSecretsManager{values: map[string]string{
			"demo": `{"value": "hunter2"}`,
		}},
	}
	if _, err := store.Read(context.Background(), &SecretRef{Path: "demo", Field: "absent"}); err == nil {
		t.Fatal("missing field read succeeded")
	}
	if _, err := store.Read(context.Background(), &SecretRef{Path: "nope", Field: "value"}); err == nil {
		t.Fatal("missing secret read succeeded")
	}
}

func TestAWSStoreRejectsNonJSON(t *testing.T) {
	store := &awsStore{
		client: &fakeSecretsManager{values: map[string]string{"plain": "raw-string"}},
	}
	if _, err := store.Read(context.Background(), &SecretRef{Path: "plain", Field: "value"}); err == nil {
		t.Fatal("non-JSON secret read succeeded")
	}
}
