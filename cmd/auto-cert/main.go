package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/platform/config/env"
	cloudflare "github.com/go-acme/lego/v4/providers/dns/cloudflare"
	_ "github.com/joho/godotenv/autoload"
	"github.com/maxroll/auto-cert/pkg/requestor"
	"github.com/maxroll/auto-cert/pkg/runner"
	"github.com/maxroll/auto-cert/pkg/secrets"
)

type Config struct {
	email         string
	providerName  string
	hostnames     []string
	forceRenew    bool
	runnerManager *runner.RunnerManager
	secretBackend secrets.SecretBackend
	secret        *secrets.Secret
	requestor     *requestor.Requestor
	user          *requestor.AcmeUser
	ctx           context.Context
}

func main() {

	log.Println("Starting autocert...")
	ctx := context.Background()

	secretBackendName := env.GetOrDefaultString("AUTOCERT_SECRET_BACKEND", "secretmanager")
	secretName := env.GetOrDefaultString("AUTOCERT_SECRET_NAME", "")
	email := env.GetOrDefaultString("AUTOCERT_EMAIL", "")
	providerName := env.GetOrDefaultString("AUTOCERT_PROVIDER", "cloudflare")
	hostnamesEnv := env.GetOrDefaultString("AUTOCERT_HOSTNAMES", "")
	forceRenew := env.GetOrDefaultBool("AUTOCERT_FORCE_RENEW", false)
	listenerMode := env.GetOrDefaultBool("AUTOCERT_LISTENER_MODE", false)
	listenerPort := env.GetOrDefaultInt("AUTOCERT_LISTENER_PORT", 8080)
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

	secretBackendConfig := &secrets.SecretManagerConfig{
		UseLatest: true,
		ProjectId: env.GetOrDefaultString("SECRETMANAGER_GOOGLE_PROJECT_ID", ""),
		SecretId:  secretName,
	}

	secretBackend = secrets.NewSecretManagerSecretBackend(ctx, secretBackendConfig)
	secret := secretBackend.GetSecret()

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

	config := &Config{
		email:         email,
		providerName:  providerName,
		hostnames:     hostnames,
		forceRenew:    forceRenew,
		runnerManager: runnerManager,
		secretBackend: secretBackend,
		secret:        secret,
		requestor:     certRequestor,
		user:          user,
		ctx:           ctx,
	}

	if listenerMode {
		log.Printf("Starting auto-cert in listener mode on port %d", listenerPort)

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "OK")
		})
		http.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
			execute(config)

			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "OK")
		})
		err := http.ListenAndServe(fmt.Sprintf(":%d", listenerPort), nil)

		if err != nil {
			log.Fatalf("HTTP listener failed: %s", err.Error())
		}
	} else {
		execute(config)
	}
}

func execute(config *Config) {

	if config.secretBackend.Name() == "secretmanager" {
		defer config.secretBackend.Close()
	} else {
		log.Fatalf("Invalid secrets backend: %s", config.secretBackend.Name())
	}

	var certificate *requestor.Certificate

	if config.secret != nil {
		certificate = &requestor.Certificate{
			Certificate: []byte(config.secret.Certificate),
			PrivateKey:  []byte(config.secret.PrivateKey),
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

			if config.forceRenew {
				log.Println("Forcibly renewing certificate")
			}

			if cert.NotAfter.Sub(time.Now()) >= time.Hour*72 && !config.forceRenew {

				log.Printf("Validaty left: %d days", int(cert.NotAfter.Sub(time.Now()).Hours())/24)
				log.Printf("Current certicate valid until: %s. No need to renew", cert.NotAfter)
				return
			} else {
				log.Println("Renewing certificate")

				certificate, err := config.requestor.RenewCertificate(config.user, config.hostnames, certificate.PrivateKey)

				if err != nil {
					log.Fatalf("Failed to renew certificate: %v", err.Error())
				}

				config.secretBackend.UpdateSecret(&secrets.Secret{
					Certificate: string(certificate.Certificate),
					PrivateKey:  string(certificate.PrivateKey),
					User:        config.secret.User,
					Hostnames:   config.hostnames,
				})

				log.Println("Certificate renewed successfully")
				config.runnerManager.Run(config.hostnames, certificate)
			}
		}

	} else {

		// request new certificate
		certificate, err := config.requestor.GenerateCertificate(config.user, config.hostnames)

		if err != nil {
			log.Fatalf("Failed to request certificate: %v", err)
		}

		userKeyBytes := requestor.GetPrivateKeyBytes(config.user.GetPrivateKey())
		config.secretBackend.CreateSecret(&secrets.Secret{
			Certificate: string(certificate.Certificate),
			PrivateKey:  string(certificate.PrivateKey),
			User: secrets.User{
				Email:      config.email,
				PrivateKey: string(userKeyBytes),
			},
			Hostnames: config.hostnames,
		})

		log.Printf("Done requesting cerficate for %s", config.hostnames)

		config.runnerManager.Run(config.hostnames, certificate)
	}
}
