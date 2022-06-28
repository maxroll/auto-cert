package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/platform/config/env"
	cloudflare "github.com/go-acme/lego/v4/providers/dns/cloudflare"
	_ "github.com/joho/godotenv/autoload"
	"github.com/maxroll/auto-cert/pkg/requestor"
	"github.com/maxroll/auto-cert/pkg/runner"
	"github.com/maxroll/auto-cert/pkg/secrets"
)

func main() {

	log.Println("Starting autocert...")
	ctx := context.Background()

	secretBackendName := env.GetOrDefaultString("AUTOCERT_SECRET_BACKEND", "secretmanager")
	secretName := env.GetOrDefaultString("AUTOCERT_SECRET_NAME", "")
	email := env.GetOrDefaultString("AUTOCERT_EMAIL", "")
	providerName := env.GetOrDefaultString("AUTOCERT_PROVIDER", "cloudflare")
	hostnamesEnv := env.GetOrDefaultString("AUTOCERT_HOSTNAMES", "")
	forceRenew := env.GetOrDefaultBool("AUTOCERT_FORCE_RENEW", false)
	runnersEnv := env.GetOrDefaultString("AUTOCERT_RUNNERS", "")

	if secretBackendName == "" {
		log.Fatalf("env var AUTOCERT_SECRET_BACKEND not set")
	}

	if secretName == "" {
		log.Fatalf("env var AUTOCERT_SECRET_NAME not set")
	}

	if hostnamesEnv == "" {
		log.Fatalf("env var AUTOCERT_HOSTNAMES not set")
	}

	if runnersEnv == "" {
		log.Fatalf("env var AUTOCERT_RUNNERS not set")
	}

	var secretBackend secrets.SecretBackend
	var certRequestor *requestor.Requestor
	var user *requestor.AcmeUser

	hostnames := strings.Split(hostnamesEnv, ",")
	runners := strings.Split(runnersEnv, ",")

	log.Printf("Hostnames set: %s", hostnames)
	log.Printf("Runners set: %s", runners)

	runnerManager, err := runner.NewRunnerManager(runners)

	if err != nil {
		log.Fatalf("Error loading runners: %s", err.Error())
	}

	if secretBackendName == "secretmanager" {
		config := &secrets.SecretManagerConfig{
			UseLatest: true,
			ProjectId: env.GetOrDefaultString("SECRETMANAGER_GOOGLE_PROJECT_ID", ""),
			SecretId:  secretName,
		}

		secretBackend = secrets.NewSecretManagerSecretBackend(ctx, config)

		defer secretBackend.Close()
	} else {
		log.Fatalf("Invalid secrets backend: %s", secretBackendName)
	}

	secret := secretBackend.GetSecret()
	var certificate *requestor.Certificate

	if secret == nil {
		log.Println("User does not exist, creating new private key")
		user = certRequestor.GenerateUserKeys(email)
	} else {
		userPrivateKey, err := requestor.LoadPrivateKey([]byte(secret.User.PrivateKey))

		if err != nil {
			log.Fatalf("Could not load private key: %v", err)
		}

		user = requestor.CreateUser(secret.User.Email, userPrivateKey, true)
	}

	requestorConfig := requestor.Config{
		AcmeURL: env.GetOrDefaultString("AUTOCERT_ACME_URL", "https://acme-staging-v02.api.letsencrypt.org/directory"),
	}

	if providerName == "cloudflare" {
		cloudflareConfig := &cloudflare.Config{}

		provider, err := cloudflare.NewDNSProvider()

		if err != nil {
			log.Fatalf("Could not create cloudflare provider: %v", err)
		}

		certRequestor, err = requestor.NewRequestor(user, provider, cloudflareConfig, requestorConfig, requestor.DNS)

		if err != nil {
			log.Fatalf("Creating requestor failed: %v", err.Error())
		}
	} else {
		log.Fatalf("Invalid acme provider: %s", providerName)
	}

	if certRequestor == nil {
		log.Fatalf("Invalid requestor provider set: %s", providerName)
	}

	if secret != nil {
		certificate = &requestor.Certificate{
			Certificate: []byte(secret.Certificate),
			PrivateKey:  []byte(secret.PrivateKey),
		}

		//check validity
		if certificate != nil {
			block, _ := pem.Decode([]byte(certificate.Certificate))
			if block == nil {
				log.Fatalln("failed to parse certificate PEM")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Fatalf("failed to parse certificate: %v", err.Error())
			}

			if forceRenew {
				log.Println("Forcibly renewing certificate")
			}

			if cert.NotAfter.Sub(time.Now()) >= time.Hour*72 && !forceRenew {

				log.Printf("Validaty left: %d days", int(cert.NotAfter.Sub(time.Now()).Hours())/24)
				log.Printf("Current certicate valid until: %s. No need to renew", cert.NotAfter)
				os.Exit(0)
			} else {
				log.Println("Renewing certificate")

				certificate, err := certRequestor.RenewCertificate(user, hostnames, certificate.PrivateKey)

				if err != nil {
					log.Fatalf("Failed to renew certificate: %v", err.Error())
				}

				secretBackend.UpdateSecret(&secrets.Secret{
					Certificate: string(certificate.Certificate),
					PrivateKey:  string(certificate.PrivateKey),
					User:        secret.User,
					Hostnames:   hostnames,
				})

				log.Println("Certificate renewed successfully")
				runnerManager.Run(hostnames, certificate)
			}
		}

	} else {

		// request new certificate
		certificate, err := certRequestor.GenerateCertificate(user, hostnames)

		if err != nil {
			log.Fatalf("Failed to request certificate: %v", err)
		}

		userKeyBytes := requestor.GetPrivateKeyBytes(user.GetPrivateKey())
		secretBackend.CreateSecret(&secrets.Secret{
			Certificate: string(certificate.Certificate),
			PrivateKey:  string(certificate.PrivateKey),
			User: secrets.User{
				Email:      email,
				PrivateKey: string(userKeyBytes),
			},
			Hostnames: hostnames,
		})

		log.Printf("Done requesting cerficate for %s", hostnames)

		runnerManager.Run(hostnames, certificate)
	}

}
