package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

type fileStore struct {
	values map[string]map[string]string
}

func newFileStore(path string) (*fileStore, error) {
	if path == "" {
		return nil, fmt.Errorf("file secrets path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file secrets: %w", err)
	}
	var values map[string]map[string]string
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("parsing file secrets: %w", err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("file secrets are empty")
	}
	return &fileStore{values: values}, nil
}

func (s *fileStore) Read(_ context.Context, ref *SecretRef) (string, error) {
	fields, ok := s.values[ref.Path]
	if !ok {
		return "", fmt.Errorf("secret path %s not found", ref.Path)
	}
	value := fields[ref.Field]
	if value == "" {
		return "", fmt.Errorf("secret %s#%s not found", ref.Path, ref.Field)
	}
	return value, nil
}
