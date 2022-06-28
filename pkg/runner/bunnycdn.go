package runner

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/maxroll/auto-cert/pkg/requestor"
	bunny "github.com/simplesurance/bunny-go"
)

type Config struct {
	PullZoneId int64
	ApiKey     string
}

type BunnyCDNRunner struct {
	config *Config
	*bunny.Client
	context.Context
	*sync.WaitGroup
}

func NewBunnyCDNRunner() *BunnyCDNRunner {
	config := &Config{
		PullZoneId: int64(env.GetOrDefaultInt("BUNNYCDN_PULL_ZONE_ID", 0)),
		ApiKey:     env.GetOrDefaultString("BUNNYCDN_API_KEY", ""),
	}

	client := bunny.NewClient(config.ApiKey)

	return &BunnyCDNRunner{config, client, context.Background(), nil}
}

func (r *BunnyCDNRunner) Exec(waitGroup *sync.WaitGroup, hostnames []string, certificate *requestor.Certificate) error {
	log.Printf("[BunnyCDN Runner] Updating certificate in BunnyCDN")

	if certificate == nil {
		return fmt.Errorf("No certificate available")
	}

	if waitGroup == nil {
		return fmt.Errorf("No waitgroup set")
	}

	// check if the pull zone exists
	pz, err := r.Client.PullZone.Get(context.Background(), r.config.PullZoneId)
	if err != nil {
		return fmt.Errorf("Could not get pull zone: %v", err.Error())
	}

	for _, hostname := range hostnames {

		exists := false
		for _, bunnyHostname := range pz.Hostnames {
			if *bunnyHostname.Value == hostname {
				exists = true
			}
		}

		if !exists {
			return fmt.Errorf("Hostname %s missing, add hostname first", hostname)
		}

		log.Printf("[BunnyCDN Runner] Adding custom certificate for hostname %s", hostname)

		cert := &bunny.PullZoneAddCustomCertificateOptions{
			Hostname:       hostname,
			Certificate:    certificate.Certificate,
			CertificateKey: certificate.PrivateKey,
		}

		err = r.Client.PullZone.AddCustomCertificate(r.Context, r.config.PullZoneId, cert)

		if err != nil {
			return err
		}
	}

	log.Println("[BunnyCDN Runner] BunnyCDN runner finished!")
	waitGroup.Done()

	return nil

}
