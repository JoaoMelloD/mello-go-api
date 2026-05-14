package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultJWTExpirationMinutes = 60
	minJWTExpirationMinutes     = 5
	maxJWTExpirationMinutes     = 1440

	DefaultJWTIssuer   = "mello-go-api"
	DefaultJWTAudience = "mello-go-api-users"
)

type Config struct {
	AppEnv              string
	JWTSecret           []byte
	JWTExpiration       time.Duration
	JWTIssuer           string
	JWTAudience         string
	SecretEncryptionKey []byte
	AllowedOrigins      []string
}

func Load() (Config, error) {
	jwtSecret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if len([]byte(jwtSecret)) < 32 {
		return Config{}, fmt.Errorf("JWT_SECRET deve ter pelo menos 32 bytes")
	}

	encryptionKeyText := strings.TrimSpace(os.Getenv("SECRET_ENCRYPTION_KEY"))
	encryptionKey, err := base64.StdEncoding.DecodeString(encryptionKeyText)
	if err != nil || len(encryptionKey) != 32 {
		return Config{}, fmt.Errorf("SECRET_ENCRYPTION_KEY deve ser base64 de 32 bytes")
	}

	expirationMinutes, err := parseJWTExpiration(os.Getenv("JWT_EXPIRATION_MINUTES"))
	if err != nil {
		return Config{}, err
	}

	allowedOrigins, err := parseAllowedOrigins(os.Getenv("ALLOWED_ORIGINS"))
	if err != nil {
		return Config{}, err
	}

	return Config{
		AppEnv:              strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV"))),
		JWTSecret:           []byte(jwtSecret),
		JWTExpiration:       time.Duration(expirationMinutes) * time.Minute,
		JWTIssuer:           DefaultJWTIssuer,
		JWTAudience:         DefaultJWTAudience,
		SecretEncryptionKey: encryptionKey,
		AllowedOrigins:      allowedOrigins,
	}, nil
}

func parseJWTExpiration(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultJWTExpirationMinutes, nil
	}

	expirationMinutes, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("JWT_EXPIRATION_MINUTES deve ser numérico")
	}

	if expirationMinutes < minJWTExpirationMinutes || expirationMinutes > maxJWTExpirationMinutes {
		return 0, fmt.Errorf("JWT_EXPIRATION_MINUTES deve estar entre %d e %d", minJWTExpirationMinutes, maxJWTExpirationMinutes)
	}

	return expirationMinutes, nil
}

func parseAllowedOrigins(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	parts := strings.Split(value, ",")
	origins := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))

	for _, part := range parts {
		origin := strings.TrimSpace(part)
		if origin == "" {
			continue
		}
		if origin == "*" {
			return nil, fmt.Errorf("ALLOWED_ORIGINS não pode usar wildcard")
		}
		if _, found := seen[origin]; found {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}

	return origins, nil
}
