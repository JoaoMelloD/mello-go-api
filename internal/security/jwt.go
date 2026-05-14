package security

import (
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTClaims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	secret     []byte
	expiration time.Duration
	issuer     string
	audience   string
}

func NewJWTManager(secret []byte, expiration time.Duration, issuer string, audience string) *JWTManager {
	return &JWTManager{
		secret:     append([]byte(nil), secret...),
		expiration: expiration,
		issuer:     issuer,
		audience:   audience,
	}
}

func (m *JWTManager) Generate(userID int) (string, error) {
	now := time.Now()
	subject := strconv.Itoa(userID)

	claims := JWTClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    m.issuer,
			Audience:  jwt.ClaimStrings{m.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(m.expiration)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

func (m *JWTManager) Validate(tokenString string) (int, bool) {
	claims := &JWTClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return m.secret, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience(m.audience),
	)

	if err != nil || !token.Valid {
		return 0, false
	}

	if claims.UserID <= 0 || claims.Subject != strconv.Itoa(claims.UserID) {
		return 0, false
	}

	return claims.UserID, true
}
