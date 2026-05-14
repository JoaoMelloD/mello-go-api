package handlers

import (
	"log"
	"mello-go-api/internal/models"
	"mello-go-api/internal/security"
	"mello-go-api/internal/store"
	"net/http"
	"net/mail"
	"strings"
)

const authRequestMaxBytes = 8 << 10

type UserHandler struct {
	store           *store.Store
	jwtManager      *security.JWTManager
	loginLimiter    *security.RateLimiter
	registerLimiter *security.RateLimiter
}

type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type UserResponse struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func NewUserHandler(store *store.Store, jwtManager *security.JWTManager, loginLimiter *security.RateLimiter, registerLimiter *security.RateLimiter) *UserHandler {
	return &UserHandler{
		store:           store,
		jwtManager:      jwtManager,
		loginLimiter:    loginLimiter,
		registerLimiter: registerLimiter,
	}
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Método não permitido")
		return
	}

	ip := clientIP(r)
	if ok, retryAfter := h.registerLimiter.Allow(rateLimitKey("register", ip)); !ok {
		log.Printf("security_event=rate_limited endpoint=register ip=%s", ip)
		writeRateLimit(w, retryAfter)
		return
	}

	var request RegisterRequest
	if !decodeJSON(w, r, &request, authRequestMaxBytes) {
		return
	}

	name, email, password, err := validateRegisterRequest(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	_, found := h.store.FindUserByEmail(email)
	if found {
		writeError(w, http.StatusConflict, "E-mail já cadastrado")
		return
	}

	hashedPassword, err := HashPassword(password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Erro ao processar senha")
		return
	}

	createdUser := h.store.CreateUser(models.User{
		Name:     name,
		Email:    email,
		Password: hashedPassword,
	})

	response := UserResponse{
		ID:    createdUser.ID,
		Name:  createdUser.Name,
		Email: createdUser.Email,
	}

	writeJSON(w, http.StatusCreated, response)
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Método não permitido")
		return
	}

	var request LoginRequest
	if !decodeJSON(w, r, &request, authRequestMaxBytes) {
		return
	}

	email := normalizeEmail(request.Email)
	ip := clientIP(r)
	rateEmail := email
	if rateEmail == "" {
		rateEmail = "invalid"
	}
	if ok, retryAfter := h.loginLimiter.Allow(rateLimitKey("login", ip, rateEmail)); !ok {
		log.Printf("security_event=rate_limited endpoint=login ip=%s", ip)
		writeRateLimit(w, retryAfter)
		return
	}

	if !isValidEmail(email) {
		writeError(w, http.StatusBadRequest, "E-mail inválido")
		return
	}

	user, found := h.store.FindUserByEmail(email)
	if !found {
		log.Printf("security_event=login_failed reason=user_not_found ip=%s", ip)
		writeError(w, http.StatusUnauthorized, "Credenciais inválidas")
		return
	}

	if !CheckPassword(user.Password, request.Password) {
		log.Printf("security_event=login_failed reason=invalid_password ip=%s", ip)
		writeError(w, http.StatusUnauthorized, "Credenciais inválidas")
		return
	}

	token, err := h.jwtManager.Generate(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Erro ao gerar token")
		return
	}

	response := LoginResponse{
		Token: token,
	}

	writeJSON(w, http.StatusOK, response)
}

func validateRegisterRequest(request RegisterRequest) (string, string, string, error) {
	name := strings.TrimSpace(request.Name)
	if name == "" || len(name) > 120 {
		return "", "", "", validationError("Nome inválido")
	}

	email := normalizeEmail(request.Email)
	if !isValidEmail(email) {
		return "", "", "", validationError("E-mail inválido")
	}

	password := request.Password
	passwordLength := len([]byte(password))
	if passwordLength < 12 || passwordLength > 72 {
		return "", "", "", validationError("Senha deve ter entre 12 e 72 caracteres")
	}

	return name, email, password, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func isValidEmail(email string) bool {
	if email == "" || len(email) > 254 {
		return false
	}

	parsed, err := mail.ParseAddress(email)
	return err == nil && parsed.Address == email
}

type validationError string

func (e validationError) Error() string {
	return string(e)
}
