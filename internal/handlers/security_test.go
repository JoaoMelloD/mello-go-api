package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mello-go-api/internal/config"
	"mello-go-api/internal/security"
	"mello-go-api/internal/store"

	"github.com/golang-jwt/jwt/v5"
)

const testJWTSecret = "0123456789abcdef0123456789abcdef"

type testApp struct {
	handler http.Handler
	store   *store.Store
}

func newTestApp(t *testing.T, loginLimit int) testApp {
	t.Helper()

	appStore := store.NewStore()
	jwtManager := security.NewJWTManager([]byte(testJWTSecret), time.Hour, config.DefaultJWTIssuer, config.DefaultJWTAudience)
	secretCipher, err := security.NewSecretCipher([]byte("abcdef0123456789abcdef0123456789"))
	if err != nil {
		t.Fatalf("NewSecretCipher() error = %v", err)
	}

	mux := http.NewServeMux()
	userHandler := NewUserHandler(
		appStore,
		jwtManager,
		security.NewRateLimiter(loginLimit, 15*time.Minute),
		security.NewRateLimiter(100, time.Hour),
	)
	secretHandler := NewSecretHandler(
		appStore,
		jwtManager,
		secretCipher,
		security.NewRateLimiter(100, time.Minute),
	)

	mux.HandleFunc("/api/register", userHandler.Register)
	mux.HandleFunc("/api/login", userHandler.Login)
	mux.HandleFunc("/api/secrets", secretHandler.Create)
	mux.HandleFunc("/api/secrets/", secretHandler.GetByID)

	return testApp{
		handler: SecurityHeadersMiddleware(false)(mux),
		store:   appStore,
	}
}

func TestSecretAuthorizationAndEncryption(t *testing.T) {
	app := newTestApp(t, 100)

	tokenA := registerAndLogin(t, app.handler, "Alice", "alice@example.com", "strong-password-1")
	tokenB := registerAndLogin(t, app.handler, "Bob", "bob@example.com", "strong-password-2")

	createBody := `{"title":"Banco","secret_content":"ultra-secret-value"}`
	createResponse := doJSON(app.handler, http.MethodPost, "/api/secrets", createBody, tokenA)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", createResponse.Code, createResponse.Body.String())
	}
	if strings.Contains(createResponse.Body.String(), "ultra-secret-value") {
		t.Fatal("POST /api/secrets leaked secret_content")
	}

	storedSecret, found := app.store.FindSecretByID(1)
	if !found {
		t.Fatal("secret was not stored")
	}
	if storedSecret.SecretCiphertext == "" || storedSecret.SecretNonce == "" {
		t.Fatal("secret was not encrypted in store")
	}
	if strings.Contains(storedSecret.SecretCiphertext, "ultra-secret-value") {
		t.Fatal("store ciphertext contains plaintext")
	}

	noTokenResponse := doJSON(app.handler, http.MethodGet, "/api/secrets/1", "", "")
	if noTokenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("GET without token status = %d", noTokenResponse.Code)
	}
	if got := noTokenResponse.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	otherUserResponse := doJSON(app.handler, http.MethodGet, "/api/secrets/1", "", tokenB)
	if otherUserResponse.Code != http.StatusNotFound {
		t.Fatalf("GET as other user status = %d, body = %s", otherUserResponse.Code, otherUserResponse.Body.String())
	}

	ownerResponse := doJSON(app.handler, http.MethodGet, "/api/secrets/1", "", tokenA)
	if ownerResponse.Code != http.StatusOK {
		t.Fatalf("GET as owner status = %d, body = %s", ownerResponse.Code, ownerResponse.Body.String())
	}

	var secretResponse SecretResponse
	if err := json.NewDecoder(ownerResponse.Body).Decode(&secretResponse); err != nil {
		t.Fatalf("Decode owner response error = %v", err)
	}
	if secretResponse.SecretContent != "ultra-secret-value" {
		t.Fatalf("SecretContent = %q", secretResponse.SecretContent)
	}
}

func TestInvalidAndExpiredJWTsAreRejected(t *testing.T) {
	app := newTestApp(t, 100)

	expiredToken := signTestToken(t, jwt.SigningMethodHS256, time.Now().Add(-time.Hour))
	expiredResponse := doJSON(app.handler, http.MethodGet, "/api/secrets/1", "", expiredToken)
	if expiredResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expired token status = %d", expiredResponse.Code)
	}

	wrongAlgorithmToken := signTestToken(t, jwt.SigningMethodHS512, time.Now().Add(time.Hour))
	wrongAlgorithmResponse := doJSON(app.handler, http.MethodGet, "/api/secrets/1", "", wrongAlgorithmToken)
	if wrongAlgorithmResponse.Code != http.StatusUnauthorized {
		t.Fatalf("wrong algorithm token status = %d", wrongAlgorithmResponse.Code)
	}
}

func TestValidationAndRateLimit(t *testing.T) {
	app := newTestApp(t, 1)

	wrongContentType := httptest.NewRecorder()
	wrongContentTypeRequest := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewBufferString(`{}`))
	wrongContentTypeRequest.Header.Set("Content-Type", "text/plain")
	app.handler.ServeHTTP(wrongContentType, wrongContentTypeRequest)
	if wrongContentType.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("wrong content-type status = %d", wrongContentType.Code)
	}

	unknownField := doJSON(app.handler, http.MethodPost, "/api/register", `{"name":"A","email":"a@example.com","password":"strong-password","role":"admin"}`, "")
	if unknownField.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d", unknownField.Code)
	}

	shortPassword := doJSON(app.handler, http.MethodPost, "/api/register", `{"name":"A","email":"a@example.com","password":"short"}`, "")
	if shortPassword.Code != http.StatusBadRequest {
		t.Fatalf("short password status = %d", shortPassword.Code)
	}

	largeName := `{"name":"` + strings.Repeat("a", 9<<10) + `","email":"large@example.com","password":"strong-password"}`
	largeBody := doJSON(app.handler, http.MethodPost, "/api/register", largeName, "")
	if largeBody.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body status = %d", largeBody.Code)
	}

	registerOnly(t, app.handler, "Carol", "carol@example.com", "strong-password-3")

	firstLoginFailure := doJSON(app.handler, http.MethodPost, "/api/login", `{"email":"carol@example.com","password":"wrong-password"}`, "")
	if firstLoginFailure.Code != http.StatusUnauthorized {
		t.Fatalf("first login failure status = %d", firstLoginFailure.Code)
	}

	secondLoginFailure := doJSON(app.handler, http.MethodPost, "/api/login", `{"email":"carol@example.com","password":"wrong-password"}`, "")
	if secondLoginFailure.Code != http.StatusTooManyRequests {
		t.Fatalf("second login failure status = %d", secondLoginFailure.Code)
	}
	if secondLoginFailure.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After header missing")
	}
}

func registerAndLogin(t *testing.T, handler http.Handler, name string, email string, password string) string {
	t.Helper()

	registerOnly(t, handler, name, email, password)

	loginBody := `{"email":"` + email + `","password":"` + password + `"}`
	loginResponse := doJSON(handler, http.MethodPost, "/api/login", loginBody, "")
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", loginResponse.Code, loginResponse.Body.String())
	}

	var response LoginResponse
	if err := json.NewDecoder(loginResponse.Body).Decode(&response); err != nil {
		t.Fatalf("Decode login response error = %v", err)
	}
	if response.Token == "" {
		t.Fatal("login response token is empty")
	}

	return response.Token
}

func registerOnly(t *testing.T, handler http.Handler, name string, email string, password string) {
	t.Helper()

	registerBody := `{"name":"` + name + `","email":"` + email + `","password":"` + password + `"}`
	registerResponse := doJSON(handler, http.MethodPost, "/api/register", registerBody, "")
	if registerResponse.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", registerResponse.Code, registerResponse.Body.String())
	}
}

func doJSON(handler http.Handler, method string, path string, body string, token string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}

	request := httptest.NewRequest(method, path, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func signTestToken(t *testing.T, method jwt.SigningMethod, expiresAt time.Time) string {
	t.Helper()

	claims := jwt.MapClaims{
		"user_id": 1,
		"sub":     "1",
		"iss":     config.DefaultJWTIssuer,
		"aud":     config.DefaultJWTAudience,
		"iat":     time.Now().Unix(),
		"exp":     expiresAt.Unix(),
	}

	token, err := jwt.NewWithClaims(method, claims).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	return token
}
