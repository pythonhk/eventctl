package main

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

var (
	canonicalUsesLine = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*([^\s#]+)(?:\s+#.*)?$`)
	pinnedActionRef   = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$`)
)

type workflowScanner struct {
	usesCount    int
	failureCount int
}

func (scanner *workflowScanner) report(path string, node *yaml.Node, format string, values ...any) {
	message := fmt.Sprintf(format, values...)
	fmt.Fprintf(os.Stderr, "%s:%d:%d: %s\n", path, node.Line, node.Column, message)
	scanner.failureCount++
}

func (scanner *workflowScanner) checkUses(path string, lines []string, key, value *yaml.Node) {
	scanner.usesCount++
	if key.Line < 1 || key.Line > len(lines) {
		scanner.report(path, key, "could not locate uses key in workflow source")
		return
	}

	lineMatch := canonicalUsesLine.FindStringSubmatch(lines[key.Line-1])
	if len(lineMatch) != 2 || value.Kind != yaml.ScalarNode || lineMatch[1] != value.Value {
		scanner.report(path, key, "action reference must use one canonical block-style uses line")
		return
	}

	actionRef := value.Value
	if strings.HasPrefix(actionRef, "./") {
		return
	}
	if !pinnedActionRef.MatchString(actionRef) {
		scanner.report(path, value, "action is not pinned to a full commit SHA: %s", actionRef)
	}
}

func resolveAlias(node *yaml.Node) *yaml.Node {
	seen := make(map[*yaml.Node]struct{})
	for node != nil && node.Kind == yaml.AliasNode && node.Alias != nil {
		if _, exists := seen[node]; exists {
			return node
		}
		seen[node] = struct{}{}
		node = node.Alias
	}
	return node
}

func (scanner *workflowScanner) walk(path string, lines []string, node *yaml.Node) {
	if node.Kind == yaml.MappingNode {
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			value := node.Content[index+1]
			resolvedKey := resolveAlias(key)
			if resolvedKey != nil && resolvedKey.Kind == yaml.ScalarNode && resolvedKey.Value == "uses" {
				scanner.checkUses(path, lines, key, value)
			}
			scanner.walk(path, lines, key)
			scanner.walk(path, lines, value)
		}
		return
	}
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		scanner.walk(path, lines, node.Alias)
		return
	}
	for _, child := range node.Content {
		scanner.walk(path, lines, child)
	}
}

func (scanner *workflowScanner) scanFile(path string) error {
	source, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(source), "\n")
	decoder := yaml.NewDecoder(bytes.NewReader(source))
	for {
		var document yaml.Node
		err = decoder.Decode(&document)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		scanner.walk(path, lines, &document)
	}
}

func run(workflowDir string) int {
	scanner := &workflowScanner{}
	err := filepath.WalkDir(workflowDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		extension := strings.ToLower(filepath.Ext(path))
		if extension != ".yml" && extension != ".yaml" {
			return nil
		}
		if err := scanner.scanFile(path); err != nil {
			return fmt.Errorf("parse workflow %s: %w", path, err)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if scanner.usesCount == 0 {
		fmt.Fprintf(os.Stderr, "no action references found under %s\n", workflowDir)
		return 1
	}
	if scanner.failureCount != 0 {
		return 1
	}
	fmt.Printf("verified %d action references are commit-pinned\n", scanner.usesCount)
	return 0
}

func main() {
	workflowDir := ".github/workflows"
	if len(os.Args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: check-action-pins [workflow-directory]")
		os.Exit(2)
	}
	if len(os.Args) == 2 {
		workflowDir = os.Args[1]
	}
	info, err := os.Stat(workflowDir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "workflow directory not found: %s\n", workflowDir)
		os.Exit(1)
	}
	os.Exit(run(workflowDir))
}
