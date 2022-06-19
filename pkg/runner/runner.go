package runner

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/maxroll/auto-cert/pkg/requestor"
	"github.com/maxroll/auto-cert/pkg/secrets"
)

type Runner interface {
	Exec(hostnames []string, certificate *requestor.Certificate) error
}

type Bootstrap struct {
	SecretBackend secrets.SecretBackend
	DnsProvider   challenge.Provider
	Runner        Runner
}
