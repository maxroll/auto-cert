package secrets

type SecretBackend interface {
	GetSecret() *Secret
	CreateSecret(payload *Secret) *Secret
	UpdateSecret(payload *Secret) *Secret
	Close()
}

type User struct {
	Email      string `json:"email"`
	PrivateKey string `json:"private_key"`
}

type Secret struct {
	PrivateKey  string   `json:"private_key"`
	Certificate string   `json:"certificate"`
	User        User     `json:"user"`
	Hostnames   []string `json:"hostnames"`
}
