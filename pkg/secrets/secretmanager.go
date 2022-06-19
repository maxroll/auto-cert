package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

type SecretManagerConfig struct {
	SecretId  string
	UseLatest bool
	ProjectId string
	Version   string
}

type SecretManagerBackend struct {
	config *SecretManagerConfig
	ctx    context.Context
	client *secretmanager.Client
}

func (s *SecretManagerBackend) GetName(includeVersion bool) string {
	version := "latest"

	if s.config.UseLatest != true && s.config.Version != "" {
		version = s.config.Version
	}

	secretName := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", s.config.ProjectId, s.config.SecretId, version)

	if !includeVersion {
		secretName = fmt.Sprintf("projects/%s/secrets/%s", s.config.ProjectId, s.config.SecretId)
	}

	return secretName
}

func (s *SecretManagerBackend) GetSecret() *Secret {
	accessRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: s.GetName(true),
	}

	// Call the API.
	result, err := s.client.AccessSecretVersion(s.ctx, accessRequest)
	if err != nil {
		log.Println(err)
		return nil
	}

	var secret *Secret

	err = json.Unmarshal(result.Payload.Data, &secret)

	if err != nil {
		log.Fatalf("Could not unmarshal secret data (%v)", result.Payload.Data)
	}

	return secret
}

func (s *SecretManagerBackend) CreateSecret(payload *Secret) *Secret {

	createSecretReq := &secretmanagerpb.CreateSecretRequest{
		Parent:   fmt.Sprintf("projects/%s", s.config.ProjectId),
		SecretId: s.config.SecretId,
		Secret: &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	}

	secret, err := s.client.CreateSecret(s.ctx, createSecretReq)
	if err != nil {
		log.Fatalf("failed to create secret: %v", err)
	}

	data, err := json.Marshal(payload)

	if err != nil {
		log.Fatalf("Error while trying to marshal payload: %v", payload)
	}

	// Build the request.
	addSecretVersionReq := &secretmanagerpb.AddSecretVersionRequest{
		Parent: secret.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: data,
		},
	}

	_, err = s.client.AddSecretVersion(s.ctx, addSecretVersionReq)
	if err != nil {
		log.Fatalf("failed to add secret version: %v", err)
	}

	return payload

}

func (s *SecretManagerBackend) UpdateSecret(payload *Secret) *Secret {

	data, err := json.Marshal(payload)

	if err != nil {
		log.Fatalf("Error while trying to marshal payload: %v", payload)
	}

	currentReq := &secretmanagerpb.GetSecretVersionRequest{
		Name: s.GetName(true),
	}

	version, err := s.client.GetSecretVersion(s.ctx, currentReq)

	if err != nil {
		log.Fatalf("failed to get secret version: %v", err)
	}

	req := &secretmanagerpb.AddSecretVersionRequest{
		Parent: s.GetName(false),
		Payload: &secretmanagerpb.SecretPayload{
			Data: data,
		},
	}

	// delete the old secret
	_, err = s.client.AddSecretVersion(s.ctx, req)
	if err != nil {
		log.Fatalf("Failed to update secret: %v", err)
	}

	deleteReq := &secretmanagerpb.DisableSecretVersionRequest{
		Name: version.Name,
	}

	if _, err := s.client.DisableSecretVersion(s.ctx, deleteReq); err != nil {
		log.Fatalf("failed to disable secret version: %v", err)
	}

	return payload
}

func (s *SecretManagerBackend) Close() {
	s.client.Close()
}

func NewSecretManagerSecretBackend(ctx context.Context, config *SecretManagerConfig) SecretBackend {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("failed to setup client: %v", err)
	}

	return &SecretManagerBackend{config, ctx, client}
}
