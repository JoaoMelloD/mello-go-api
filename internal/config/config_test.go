package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestLoadValidConfig(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 32))
	t.Setenv("SECRET_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))))
	t.Setenv("JWT_EXPIRATION_MINUTES", "30")
	t.Setenv("APP_ENV", "production")
	t.Setenv("ALLOWED_ORIGINS", "https://app.example.com, https://app.example.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got := string(cfg.JWTSecret); got != strings.Repeat("a", 32) {
		t.Fatalf("JWTSecret = %q", got)
	}
	if cfg.JWTExpiration != 30*time.Minute {
		t.Fatalf("JWTExpiration = %s", cfg.JWTExpiration)
	}
	if cfg.AppEnv != "production" {
		t.Fatalf("AppEnv = %q", cfg.AppEnv)
	}
	if len(cfg.AllowedOrigins) != 1 || cfg.AllowedOrigins[0] != "https://app.example.com" {
		t.Fatalf("AllowedOrigins = %#v", cfg.AllowedOrigins)
	}
}

func TestLoadRejectsWeakSecrets(t *testing.T) {
	t.Setenv("JWT_SECRET", "short")
	t.Setenv("SECRET_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))))

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want weak JWT_SECRET error")
	}
}

func TestLoadRejectsInvalidEncryptionKey(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 32))
	t.Setenv("SECRET_ENCRYPTION_KEY", "not-base64")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want invalid SECRET_ENCRYPTION_KEY error")
	}
}

func TestLoadRejectsUnsafeJWTExpiration(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 32))
	t.Setenv("SECRET_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))))
	t.Setenv("JWT_EXPIRATION_MINUTES", "1")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want unsafe JWT_EXPIRATION_MINUTES error")
	}
}

func TestLoadRejectsWildcardCORS(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 32))
	t.Setenv("SECRET_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))))
	t.Setenv("ALLOWED_ORIGINS", "*")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want wildcard ALLOWED_ORIGINS error")
	}
}
