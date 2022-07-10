package runner

import (
	"fmt"
	"log"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/maxroll/auto-cert/pkg/requestor"
	"github.com/maxroll/auto-cert/pkg/util"
)

const (
	stackPathApiUrl = "https://gateway.stackpath.com"
)

type CertificateInput struct {
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
	CaBundle    string `json:"caBundle"`
}

type CertificateResult struct {
	PageInfo     PageInfo      `json:"pageInfo"`
	Certificates []Certificate `json:"results"`
}
type PageInfo struct {
	TotalCount      string `json:"totalCount"`
	HasPreviousPage bool   `json:"hasPreviousPage"`
	HasNextPage     bool   `json:"hasNextPage"`
	EndCursor       string `json:"endCursor"`
}
type Certificate struct {
	ID                      string    `json:"id"`
	Fingerprint             string    `json:"fingerprint"`
	CommonName              string    `json:"commonName"`
	Issuer                  string    `json:"issuer"`
	CaBundle                string    `json:"caBundle"`
	Trusted                 bool      `json:"trusted"`
	ExpirationDate          time.Time `json:"expirationDate"`
	CreateDate              time.Time `json:"createDate"`
	UpdateDate              time.Time `json:"updateDate"`
	SubjectAlternativeNames []string  `json:"subjectAlternativeNames"`
	Status                  string    `json:"status"`
	ProviderManaged         bool      `json:"providerManaged"`
}

type StackPathAPI struct {
	config *StackPathConfig
	token  *Token
	client *resty.Client
}

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type TokenInput struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
}

func newStackPathAPI(config *StackPathConfig) (*StackPathAPI, error) {
	client := resty.New()

	client.SetHeader("Accept", "application/json")
	client.SetHeader("Content-Type", "application/json")

	resp, err := client.R().
		SetBody(TokenInput{config.ClientId, config.ClientSecret, "client_credentials"}).
		SetResult(&Token{}).
		Post(fmt.Sprintf("%s/identity/v1/oauth2/token", stackPathApiUrl))

	if err != nil || resp.StatusCode() != 200 {
		return nil, fmt.Errorf("[StackPath] Could not fetch bearer token (%s)", resp.Request.URL)
	}

	token := resp.Result().(*Token)
	client.SetAuthToken(token.AccessToken)

	return &StackPathAPI{config, token, client}, nil
}

func (s *StackPathAPI) ListCertificates() (*CertificateResult, error) {
	resp, err := s.client.R().
		SetResult(&CertificateResult{}).
		Get(fmt.Sprintf("%s/cdn/v1/stacks/%s/certificates?page_request.filter=%s", stackPathApiUrl, s.config.StackId, "status%3D%22ACTIVE%22"))

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("Failed to list certificates for Stack %s (%s)", s.config.StackId, string(resp.Body()))
	}

	return resp.Result().(*CertificateResult), nil
}

func (s *StackPathAPI) AddCertificates(certificate *requestor.Certificate) error {

	bundle, err := util.SplitCerts(certificate)

	if err != nil {
		return err
	}

	resp, err := s.client.R().
		SetBody(CertificateInput{
			Certificate: string(bundle.Certificate),
			Key:         string(certificate.PrivateKey),
			CaBundle:    string(bundle.CaBundle),
		}).
		Post(fmt.Sprintf("%s/cdn/v1/stacks/%s/certificates", stackPathApiUrl, s.config.StackId))

	if err != nil {
		return err
	}

	log.Printf("Response code: %d", resp.StatusCode())

	if resp.StatusCode() != 200 {
		return fmt.Errorf(string(resp.Body()))
	}

	return nil
}

func (s *StackPathAPI) UpdateCertificates(certId string, certificate *requestor.Certificate) error {

	bundle, err := util.SplitCerts(certificate)

	if err != nil {
		return err
	}

	resp, err := s.client.R().
		SetBody(CertificateInput{
			Certificate: string(bundle.Certificate),
			Key:         string(certificate.PrivateKey),
			CaBundle:    string(bundle.CaBundle),
		}).
		Put(fmt.Sprintf("%s/cdn/v1/stacks/%s/certificates/%s", stackPathApiUrl, s.config.StackId, certId))

	if err != nil {
		return err
	}

	if resp.StatusCode() != 200 {
		return fmt.Errorf(string(resp.Body()))
	}

	return nil
}
