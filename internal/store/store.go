package store

import (
	"mello-go-api/internal/models"
	"sync"
)

type Store struct {
	mu           sync.RWMutex
	users        map[int]models.User
	secrets      map[int]models.Secret
	nextUserID   int
	nextSecretID int
}

func NewStore() *Store {
	return &Store{
		users:        make(map[int]models.User),
		secrets:      make(map[int]models.Secret),
		nextUserID:   1,
		nextSecretID: 1,
	}
}

func (s *Store) CreateUser(user models.User) models.User {
	s.mu.Lock()
	defer s.mu.Unlock()

	user.ID = s.nextUserID

	s.users[user.ID] = user

	s.nextUserID++

	return user
}

func (s *Store) FindUserByEmail(email string) (models.User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.Email == email {
			return user, true
		}
	}

	return models.User{}, false
}

func (s *Store) CreateSecret(secret models.Secret) models.Secret {
	s.mu.Lock()
	defer s.mu.Unlock()

	secret.ID = s.nextSecretID

	s.secrets[secret.ID] = secret
	s.nextSecretID++

	return secret
}

func (s *Store) FindSecretByID(id int) (models.Secret, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secret, found := s.secrets[id]
	return secret, found
}
