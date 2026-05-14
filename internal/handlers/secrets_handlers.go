package handlers

import (
	"log"
	"mello-go-api/internal/models"
	"mello-go-api/internal/security"
	"mello-go-api/internal/store"
	"net/http"
	"strconv"
	"strings"
)

const (
	secretRequestMaxBytes = 64 << 10
	maxSecretContentBytes = 10 << 10
	maxSecretTitleLength  = 120
)

type SecretHandler struct {
	store        *store.Store
	jwtManager   *security.JWTManager
	secretCipher *security.SecretCipher
	rateLimiter  *security.RateLimiter
}

type CreateSecretRequest struct {
	Title         string `json:"title"`
	SecretContent string `json:"secret_content"`
}

type SecretMetadataResponse struct {
	ID     int    `json:"id"`
	UserID int    `json:"user_id"`
	Title  string `json:"title"`
}

type SecretResponse struct {
	ID            int    `json:"id"`
	UserID        int    `json:"user_id"`
	Title         string `json:"title"`
	SecretContent string `json:"secret_content"`
}

func NewSecretHandler(store *store.Store, jwtManager *security.JWTManager, secretCipher *security.SecretCipher, rateLimiter *security.RateLimiter) *SecretHandler {
	return &SecretHandler{
		store:        store,
		jwtManager:   jwtManager,
		secretCipher: secretCipher,
		rateLimiter:  rateLimiter,
	}
}

func (h *SecretHandler) getUserIDFromToken(r *http.Request) (int, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return 0, false
	}

	fields := strings.Fields(authHeader)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return 0, false
	}

	return h.jwtManager.Validate(fields[1])
}

func (h *SecretHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Método não permitido")
		return
	}

	ip := clientIP(r)
	userID, ok := h.getUserIDFromToken(r)
	if !ok {
		log.Printf("security_event=invalid_token endpoint=create_secret ip=%s", ip)
		writeError(w, http.StatusUnauthorized, "Token inválido ou ausente")
		return
	}

	if ok, retryAfter := h.rateLimiter.Allow(rateLimitKey("secrets", strconv.Itoa(userID), ip)); !ok {
		log.Printf("security_event=rate_limited endpoint=create_secret user_id=%d ip=%s", userID, ip)
		writeRateLimit(w, retryAfter)
		return
	}

	var request CreateSecretRequest
	if !decodeJSON(w, r, &request, secretRequestMaxBytes) {
		return
	}

	title, content, err := validateCreateSecretRequest(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ciphertext, nonce, err := h.secretCipher.EncryptString(content)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Erro ao proteger segredo")
		return
	}

	createdSecret := h.store.CreateSecret(models.Secret{
		UserID:           userID,
		Title:            title,
		SecretCiphertext: ciphertext,
		SecretNonce:      nonce,
	})

	writeJSON(w, http.StatusCreated, SecretMetadataResponse{
		ID:     createdSecret.ID,
		UserID: createdSecret.UserID,
		Title:  createdSecret.Title,
	})
}

func (h *SecretHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Método não permitido")
		return
	}

	ip := clientIP(r)
	userID, ok := h.getUserIDFromToken(r)
	if !ok {
		log.Printf("security_event=invalid_token endpoint=get_secret ip=%s", ip)
		writeError(w, http.StatusUnauthorized, "Token inválido ou ausente")
		return
	}

	if ok, retryAfter := h.rateLimiter.Allow(rateLimitKey("secrets", strconv.Itoa(userID), ip)); !ok {
		log.Printf("security_event=rate_limited endpoint=get_secret user_id=%d ip=%s", userID, ip)
		writeRateLimit(w, retryAfter)
		return
	}

	idText := strings.TrimPrefix(r.URL.Path, "/api/secrets/")
	if idText == "" {
		writeError(w, http.StatusBadRequest, "ID do segredo é obrigatório")
		return
	}

	id, err := strconv.Atoi(idText)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ID inválido")
		return
	}

	secret, found := h.store.FindSecretByID(id)
	if !found || secret.UserID != userID {
		if found {
			log.Printf("security_event=access_denied endpoint=get_secret user_id=%d secret_id=%d ip=%s", userID, id, ip)
		}
		writeError(w, http.StatusNotFound, "Segredo não encontrado")
		return
	}

	content, err := h.secretCipher.DecryptString(secret.SecretCiphertext, secret.SecretNonce)
	if err != nil {
		log.Printf("security_event=secret_decrypt_failed secret_id=%d", secret.ID)
		writeError(w, http.StatusInternalServerError, "Erro ao carregar segredo")
		return
	}

	writeJSON(w, http.StatusOK, SecretResponse{
		ID:            secret.ID,
		UserID:        secret.UserID,
		Title:         secret.Title,
		SecretContent: content,
	})
}

func validateCreateSecretRequest(request CreateSecretRequest) (string, string, error) {
	title := strings.TrimSpace(request.Title)
	if title == "" || len(title) > maxSecretTitleLength {
		return "", "", validationError("Título inválido")
	}

	if request.SecretContent == "" || len([]byte(request.SecretContent)) > maxSecretContentBytes {
		return "", "", validationError("Conteúdo secreto inválido")
	}

	return title, request.SecretContent, nil
}
