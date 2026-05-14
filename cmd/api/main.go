package main

import (
	"encoding/json"
	"log"
	"mello-go-api/internal/config"
	"mello-go-api/internal/handlers"
	"mello-go-api/internal/security"
	"mello-go-api/internal/store"
	"net/http"
	"os"
	"time"

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
	if !loadEnv() {
		log.Println("Arquivo .env não encontrado")
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Configuração inválida: %v", err)
	}

	jwtManager := security.NewJWTManager(cfg.JWTSecret, cfg.JWTExpiration, cfg.JWTIssuer, cfg.JWTAudience)
	secretCipher, err := security.NewSecretCipher(cfg.SecretEncryptionKey)
	if err != nil {
		log.Fatalf("Configuração inválida: %v", err)
	}

	mux := http.NewServeMux()

	appStore := store.NewStore()
	userHandler := handlers.NewUserHandler(
		appStore,
		jwtManager,
		security.NewRateLimiter(5, 15*time.Minute),
		security.NewRateLimiter(10, time.Hour),
	)
	secretHandler := handlers.NewSecretHandler(
		appStore,
		jwtManager,
		secretCipher,
		security.NewRateLimiter(60, time.Minute),
	)

	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/register", userHandler.Register)
	mux.HandleFunc("/api/login", userHandler.Login)
	mux.HandleFunc("/api/secrets", secretHandler.Create)
	mux.HandleFunc("/api/secrets/", secretHandler.GetByID)

	handler := handlers.SecurityHeadersMiddleware(cfg.AppEnv == "production")(mux)
	handler = handlers.CORSMiddleware(cfg.AllowedOrigins)(handler)

	server := &http.Server{
		Addr:              ":8080",
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Println("Servidor rodando em http://localhost:8080")
	log.Fatal(server.ListenAndServe())
}

func loadEnv() bool {
	for _, path := range []string{".env", "../.env", "../../.env"} {
		if _, err := os.Stat(path); err != nil {
			continue
		}

		if err := godotenv.Load(path); err != nil {
			log.Printf("Erro ao carregar %s: %v", path, err)
			return false
		}

		return true
	}

	return false
}
