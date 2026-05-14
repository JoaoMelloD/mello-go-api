package models

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"-"`
}

type Secret struct {
	ID               int    `json:"id"`
	UserID           int    `json:"user_id"`
	Title            string `json:"title"`
	SecretCiphertext string `json:"-"`
	SecretNonce      string `json:"-"`
}
