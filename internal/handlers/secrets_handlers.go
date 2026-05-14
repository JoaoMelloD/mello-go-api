package handlers

import (
	"encoding/json"
	"mello-go-api/internal/models"
	"mello-go-api/internal/store"
	"net/http"
	"strconv"
	"strings"
)

type SecretHandler struct {
	store *store.Store
}

type CreateSecretRequest struct {
	Title         string `json:"title"`
	SecretContent string `json:"secret_content"`
}

func NewSecretHandler(store *store.Store) *SecretHandler {
	return &SecretHandler{
		store: store,
	}
}

func getUserIDFromToken(r *http.Request) (int, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return 0, false
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return 0, false
	}

	return ValidateJWT(tokenString)
}

func (h *SecretHandler) Create(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := getUserIDFromToken(r)
	if !ok {
		http.Error(w, "Token inválido ou ausente", http.StatusUnauthorized)
		return
	}

	var request CreateSecretRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}

	secret := models.Secret{
		UserID:        userID,
		Title:         request.Title,
		SecretContent: request.SecretContent,
	}

	createdSecret := h.store.CreateSecret(secret)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdSecret)

}

func (h *SecretHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	idText := strings.TrimPrefix(r.URL.Path, "/api/secrets/")
	if idText == "" {
		http.Error(w, "ID do segredo é obrigatório", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idText)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	secret, found := h.store.FindSecretByID(id)
	if !found {
		http.Error(w, "Segredo não encontrado", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(secret)
}
