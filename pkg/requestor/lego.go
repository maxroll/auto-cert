package requestor

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type AcmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
	exists       bool
}

func (u *AcmeUser) GetEmail() string {
	return u.Email
}
func (u AcmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

type Config struct {
	AcmeURL string
}

type Requestor struct {
	client       *lego.Client
	Provider     challenge.Provider
	solverConfig interface{}
	config       Config
	method       RequestorMethod
}

type RequestorMethod string

const (
	DNS  RequestorMethod = "dns01"
	HTTP RequestorMethod = "http01"
)

func NewRequestor(user *AcmeUser, provider challenge.Provider, solverConfig interface{}, requestorConfig Config, method RequestorMethod) (*Requestor, error) {

	config := lego.NewConfig(user)
	config.CADirURL = requestorConfig.AcmeURL
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	if user.exists {
		// load account by key
		reg, err := client.Registration.ResolveAccountByKey()
		if err != nil {
			return nil, err
		}

		user.Registration = reg
	} else {

		// register a new account
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, err
		}
		user.Registration = reg

	}

	if method == DNS {
		err = client.Challenge.SetDNS01Provider(provider)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("Other methods are not yet implemented")
	}

	return &Requestor{client, provider, solverConfig, requestorConfig, method}, nil
}

func CreateUser(email string, privateKey crypto.PrivateKey, exists bool) *AcmeUser {
	return &AcmeUser{Email: email, key: privateKey, exists: exists}
}

func (r *Requestor) GenerateUserKeys(email string) *AcmeUser {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	user := CreateUser(email, privateKey, false)

	return user
}

func (r *Requestor) RenewCertificate(user *AcmeUser, hostnames []string, privateKey []byte) (*Certificate, error) {

	parsed, err := certcrypto.ParsePEMPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	request := certificate.ObtainRequest{
		Domains:    hostnames,
		Bundle:     true,
		PrivateKey: parsed,
	}

	certificates, err := r.client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	return &Certificate{
		PrivateKey:  privateKey,
		Certificate: certificates.Certificate,
	}, nil

}

func (r *Requestor) GenerateCertificate(user *AcmeUser, hostnames []string) (*Certificate, error) {

	request := certificate.ObtainRequest{
		Domains: hostnames,
		Bundle:  true,
	}
	certificates, err := r.client.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}

	return &Certificate{
		PrivateKey:  certificates.PrivateKey,
		Certificate: certificates.Certificate,
	}, nil
}
