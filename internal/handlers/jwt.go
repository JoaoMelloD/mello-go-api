package handlers

import (
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTClaims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

func getJWTSecret() []byte {
	return []byte(os.Getenv("JWT_SECRET"))
}

func getJWTExpiration() time.Duration {
	expirationText := os.Getenv("JWT_EXPIRATION_MINUTES")

	expirationMinutes, err := strconv.Atoi(expirationText)
	if err != nil || expirationMinutes <= 0 {
		expirationMinutes = 60
	}

	return time.Duration(expirationMinutes) * time.Minute
}

func GenerateJWT(userID int) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(getJWTExpiration())),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(getJWTSecret())
}

func ValidateJWT(tokenString string) (int, bool) {
	claims := &JWTClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return getJWTSecret(), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	if err != nil || !token.Valid {
		return 0, false
	}

	return claims.UserID, true
}
