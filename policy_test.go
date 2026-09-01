package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyMatchAndAuthorize(t *testing.T) {
	policy := testPolicy()
	if !policy.TrustsRepo("org/hello") || policy.TrustsRepo("org/other") {
		t.Fatal("TrustsRepo misclassified a repo")
	}
	name, workload := policy.Match("org/hello", "v1.0.0")
	if workload == nil || name != "hello" {
		t.Fatalf("Match = %q, %v", name, workload)
	}
	if _, w := policy.Match("org/hello", "v0.9.0"); w != nil {
		t.Fatal("unpinned tag matched")
	}

	release, err := workload.Authorize(name, []string{"DEMO_SECRET"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if release["DEMO_SECRET"].Path != "hello/demo" {
		t.Fatalf("release = %v", release)
	}
	if _, err := workload.Authorize(name, []string{"DEMO_SECRET", "OTHER"}); err == nil {
		t.Fatal("unmapped secret ref was authorized")
	}
	if _, err := workload.Authorize(name, nil); err == nil {
		t.Fatal("empty request was authorized")
	}
}

func TestLoadPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	content := `workloads:
  hello:
    repo: org/hello
    tag: v1.0.0
    domain: hello.example.com
    secrets:
      A: {path: p, field: f}
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if policy.Workloads["hello"].Domain != "hello.example.com" {
		t.Fatalf("policy = %#v", policy.Workloads["hello"])
	}
}

func TestLoadPolicyRejectsIncomplete(t *testing.T) {
	cases := map[string]string{
		"no workloads":   "workloads: {}",
		"no repo":        "workloads:\n  w:\n    tag: v1\n    domain: d\n    secrets:\n      A: {path: p, field: f}",
		"no tag":         "workloads:\n  w:\n    repo: org/x\n    domain: d\n    secrets:\n      A: {path: p, field: f}",
		"no domain":      "workloads:\n  w:\n    repo: org/x\n    tag: v1\n    secrets:\n      A: {path: p, field: f}",
		"no secrets":     "workloads:\n  w:\n    repo: org/x\n    tag: v1\n    domain: d",
		"bad secret ref": "workloads:\n  w:\n    repo: org/x\n    tag: v1\n    domain: d\n    secrets:\n      A: {path: p}",
		"duplicate pin":  "workloads:\n  a:\n    repo: org/x\n    tag: v1\n    domain: d\n    secrets:\n      A: {path: p, field: f}\n  b:\n    repo: org/x\n    tag: v1\n    domain: d\n    secrets:\n      B: {path: q, field: f}",
	}
	for name, content := range cases {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(path); err == nil {
			t.Errorf("%s: invalid policy loaded", name)
		} else if strings.Contains(err.Error(), "reading policy") {
			t.Errorf("%s: unexpected read error: %v", name, err)
		}
	}
}
