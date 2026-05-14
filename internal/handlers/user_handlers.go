package handlers

import (
	"encoding/json"
	"mello-go-api/internal/models"
	"mello-go-api/internal/store"
	"net/http"
)

type UserHandler struct {
	store *store.Store
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

func NewUserHandler(store *store.Store) *UserHandler {
	return &UserHandler{
		store: store,
	}
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	var user models.User

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}

	_, found := h.store.FindUserByEmail(user.Email)
	if found {
		http.Error(w, "E-mail já cadastrado", http.StatusConflict)
		return
	}

	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		http.Error(w, "Erro ao processar senha", http.StatusInternalServerError)
		return
	}

	user.Password = hashedPassword

	createdUser := h.store.CreateUser(user)

	response := UserResponse{
		ID:    createdUser.ID,
		Name:  createdUser.Name,
		Email: createdUser.Email,
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Método Não Permitido", http.StatusMethodNotAllowed)
		return
	}

	var request LoginRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}

	user, found := h.store.FindUserByEmail(request.Email)
	if !found {
		http.Error(w, "Credenciais Inválidas", http.StatusUnauthorized)
		return
	}

	if !CheckPassword(user.Password, request.Password) {
		http.Error(w, "Credenciais Inválidas", http.StatusUnauthorized)
		return
	}

	token, err := GenerateJWT(user.ID)
	if err != nil {
		http.Error(w, "Erro ao gerar token", http.StatusInternalServerError)
		return
	}

	response := LoginResponse{
		Token: token,
	}

	json.NewEncoder(w).Encode(response)

}
