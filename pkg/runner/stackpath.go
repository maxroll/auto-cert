package runner

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/maxroll/auto-cert/pkg/requestor"
	"github.com/maxroll/auto-cert/pkg/util"
)

type StackPathConfig struct {
	ClientId     string
	ClientSecret string
	StackId      string
	SiteId       string
}

type StackPathRunner struct {
	config *StackPathConfig
	context.Context
	*StackPathAPI
	*sync.WaitGroup
}

func NewStackPathRunner() (*StackPathRunner, error) {
	config := &StackPathConfig{
		ClientId:     env.GetOrDefaultString("STACKPATH_API_CLIENT_ID", ""),
		ClientSecret: env.GetOrDefaultString("STACKPATH_API_CLIENT_SECRET", ""),
		StackId:      env.GetOrDefaultString("STACKPATH_STACK_ID", ""),
		SiteId:       env.GetOrDefaultString("STACKPATH_SITE_ID", ""),
	}

	client, err := newStackPathAPI(config)

	if err != nil {
		return nil, err
	}

	return &StackPathRunner{config, context.Background(), client, nil}, nil
}

func (r *StackPathRunner) Exec(hostnames []string, certificate *requestor.Certificate) error {
	log.Printf("[StackPath Runner] Updating certificate in StackPath")

	if certificate == nil {
		return fmt.Errorf("No certificate available")
	}

	certs, err := r.StackPathAPI.ListCertificates()

	if err != nil {
		return err
	}

	certId := ""

	for _, cert := range certs.Certificates {
		if util.StringSlicesEqual(cert.SubjectAlternativeNames, hostnames) {
			certId = cert.ID
			break
		}
	}

	if certId != "" {
		log.Println("[StackPath Runner] Cert for these hostnames already exists, updating...")

		err = r.StackPathAPI.UpdateCertificates(certId, certificate)

		if err != nil {
			return fmt.Errorf("[StackPath Runner] Failed to update certificate %s: %s", certId, err.Error())
		}

		log.Println("[StackPath Runner] Certificate updated")

	} else {

		err := r.StackPathAPI.AddCertificates(certificate)

		if err != nil {
			return fmt.Errorf("[StackPath Runner] Failed to add certificate to stack: %s", err.Error())
		}

		log.Println("[StackPath Runner] Certificate created")
	}

	log.Println("[StackPath Runner] StackPath runner finished!")

	return nil

}
