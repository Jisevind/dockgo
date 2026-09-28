package stacks

import "testing"

func TestValidateSyntaxCompose(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantValid  bool
		wantLine   int
		wantSubstr string
	}{
		{name: "valid", content: "services:\n  web:\n    image: nginx\n", wantValid: true},
		{name: "empty document is valid", content: "", wantValid: true},
		{
			name:       "tab indentation is invalid",
			content:    "services:\n\tweb:\n\t\timage: nginx\n",
			wantValid:  false,
			wantSubstr: "line",
		},
		{
			name:       "unclosed mapping",
			content:    "services:\n  web: [\n",
			wantValid:  false,
			wantSubstr: "line",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateSyntax(FileKindCompose, tc.content)
			if got.Valid != tc.wantValid {
				t.Fatalf("Valid = %v, want %v (errors=%+v)", got.Valid, tc.wantValid, got.Errors)
			}
			if !tc.wantValid {
				if len(got.Errors) == 0 {
					t.Fatal("Errors is empty for invalid content")
				}
				if got.Errors[0].Line < 1 {
					t.Fatalf("first error Line = %d, want >= 1", got.Errors[0].Line)
				}
			}
		})
	}
}

func TestValidateSyntaxEnv(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantValid bool
		wantLine  int
	}{
		{name: "assignments", content: "TZ=Europe/Stockholm\nPUID=1000\n", wantValid: true},
		{name: "comments and blanks", content: "# a comment\n\nTZ=UTC\n", wantValid: true},
		{name: "export prefix", content: "export TZ=UTC\n", wantValid: true},
		{name: "empty value is allowed", content: "EMPTY=\n", wantValid: true},
		{name: "missing separator", content: "TZ=UTC\nNOT_AN_ASSIGNMENT\n", wantValid: false, wantLine: 2},
		{name: "leading digit in key", content: "1BAD=value\n", wantValid: false, wantLine: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateSyntax(FileKindEnv, tc.content)
			if got.Valid != tc.wantValid {
				t.Fatalf("Valid = %v, want %v (errors=%+v)", got.Valid, tc.wantValid, got.Errors)
			}
			if !tc.wantValid && tc.wantLine > 0 && got.Errors[0].Line != tc.wantLine {
				t.Fatalf("first error Line = %d, want %d", got.Errors[0].Line, tc.wantLine)
			}
		})
	}
}

func TestValidateSyntaxUnknownKindIsRejected(t *testing.T) {
	if got := ValidateSyntax("nonsense", "x"); got.Valid {
		t.Fatal("Valid = true for an unknown kind, want false")
	}
}
