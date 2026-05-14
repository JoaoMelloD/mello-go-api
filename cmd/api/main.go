package main

import (
	"encoding/json"
	"fmt"
	"log"
	"mello-go-api/internal/handlers"
	"mello-go-api/internal/store"
	"net/http"

	"github.com/joho/godotenv"
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]string{
		"status": "ok",
	}

	json.NewEncoder(w).Encode(response)
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Println("Arquivo .env não encontrado")
	}
	mux := http.NewServeMux()

	appStore := store.NewStore()
	userHandler := handlers.NewUserHandler(appStore)
	secretHandler := handlers.NewSecretHandler(appStore)

	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/register", userHandler.Register)
	mux.HandleFunc("/api/login", userHandler.Login)
	mux.HandleFunc("/api/secrets", secretHandler.Create)
	mux.HandleFunc("/api/secrets/", secretHandler.GetByID)

	fmt.Println("Servidor rodando em http://localhost:8080")

	err = http.ListenAndServe(":8080", mux)
	if err != nil {
		fmt.Println("Erro ao iniciar servidor:", err)
	}
}
