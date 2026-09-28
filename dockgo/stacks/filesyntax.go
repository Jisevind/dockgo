package stacks

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// File kinds addressable by the editor. They select both the syntax checker and
// which slice of the Stack the index refers to.
const (
	FileKindCompose = "compose"
	FileKindEnv     = "env"
)

// SyntaxError is a single syntax problem, positioned for an editor gutter.
type SyntaxError struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

// SyntaxResult is the outcome of a syntax check.
type SyntaxResult struct {
	Valid  bool          `json:"valid"`
	Errors []SyntaxError `json:"errors"`
}

// dotEnvAssignment matches KEY=VALUE with an optional `export ` prefix. Keys
// follow the conventional POSIX subset Docker Compose accepts.
var dotEnvAssignment = regexp.MustCompile(`^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=`)

// ValidateSyntax checks content for the given file kind. It is a syntax check
// only: it never touches the filesystem and never runs docker. Semantic
// validation happens separately via Validate.
func ValidateSyntax(kind string, content string) SyntaxResult {
	switch kind {
	case FileKindCompose:
		return validateComposeSyntax(content)
	case FileKindEnv:
		return validateEnvSyntax(content)
	default:
		return SyntaxResult{
			Valid:  false,
			Errors: []SyntaxError{{Line: 1, Column: 1, Message: fmt.Sprintf("unsupported file kind: %s", kind)}},
		}
	}
}

func validateComposeSyntax(content string) SyntaxResult {
	if strings.TrimSpace(content) == "" {
		return SyntaxResult{Valid: true}
	}

	var decoded any
	if err := yaml.Unmarshal([]byte(content), &decoded); err != nil {
		return SyntaxResult{Valid: false, Errors: []SyntaxError{yamlSyntaxError(err)}}
	}
	return SyntaxResult{Valid: true}
}

// yamlSyntaxError reduces the several error shapes yaml.v3 can return to one
// positioned syntax error.
func yamlSyntaxError(err error) SyntaxError {
	var typeErr *yaml.TypeError
	if ok := asTypeError(err, &typeErr); ok && len(typeErr.Errors) > 0 {
		line, column := parseYAMLPosition(typeErr.Errors[0])
		return SyntaxError{Line: line, Column: column, Message: typeErr.Errors[0]}
	}

	message := err.Error()
	line, column := parseYAMLPosition(message)
	return SyntaxError{Line: line, Column: column, Message: message}
}

func asTypeError(err error, target **yaml.TypeError) bool {
	if te, ok := err.(*yaml.TypeError); ok {
		*target = te
		return true
	}
	return false
}

// parseYAMLPosition extracts "line N: ..." / "line N, column M" from a yaml.v3
// message. Unknown positions fall back to line 1 so the editor always has a
// place to anchor the marker.
var yamlPosition = regexp.MustCompile(`line (\d+)(?:, column (\d+))?`)

func parseYAMLPosition(message string) (int, int) {
	match := yamlPosition.FindStringSubmatch(message)
	if match == nil {
		return 1, 1
	}

	line := 1
	if _, err := fmt.Sscanf(match[1], "%d", &line); err != nil || line < 1 {
		line = 1
	}

	column := 1
	if match[2] != "" {
		if _, err := fmt.Sscanf(match[2], "%d", &column); err != nil || column < 1 {
			column = 1
		}
	}
	return line, column
}

func validateEnvSyntax(content string) SyntaxResult {
	result := SyntaxResult{Valid: true}

	for index, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !dotEnvAssignment.MatchString(line) {
			result.Valid = false
			result.Errors = append(result.Errors, SyntaxError{
				Line:    index + 1,
				Column:  1,
				Message: "expected KEY=VALUE",
			})
		}
	}

	return result
}
