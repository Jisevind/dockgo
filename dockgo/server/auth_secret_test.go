package server

import "testing"

func TestAuthSecretFromEnv(t *testing.T) {
	t.Setenv("AUTH_SECRET", "")
	if _, err := authSecretFromEnv(); err == nil {
		t.Fatal("authSecretFromEnv() error = nil, want error for unset AUTH_SECRET")
	}

	t.Setenv("AUTH_SECRET", "   ")
	if _, err := authSecretFromEnv(); err == nil {
		t.Fatal("authSecretFromEnv() error = nil, want error for blank AUTH_SECRET")
	}

	t.Setenv("AUTH_SECRET", "  stable-secret  ")
	secret, err := authSecretFromEnv()
	if err != nil {
		t.Fatalf("authSecretFromEnv() error = %v", err)
	}
	if secret != "stable-secret" {
		t.Fatalf("authSecretFromEnv() = %q, want %q", secret, "stable-secret")
	}
}
