package runner

import (
	"fmt"
	"sync"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/maxroll/auto-cert/pkg/requestor"
	"github.com/maxroll/auto-cert/pkg/secrets"
)

type Runner interface {
	Exec(waitGroup *sync.WaitGroup, hostnames []string, certificate *requestor.Certificate) error
}

type Bootstrap struct {
	SecretBackend secrets.SecretBackend
	DnsProvider   challenge.Provider
	Runner        Runner
}

type RunnerManager struct {
	Runners []Runner
	*sync.WaitGroup
}

func NewRunnerManager(runners []string) (*RunnerManager, error) {
	waitGroup := &sync.WaitGroup{}

	var runnerInstances []Runner

	for _, runnerName := range runners {
		if runnerName == "bunnycdn" {
			runnerInstances = append(runnerInstances, NewBunnyCDNRunner())
		} else {
			return nil, fmt.Errorf("Unknown runner: %s", runnerName)
		}
	}

	waitGroup.Add(len(runners))

	return &RunnerManager{runnerInstances, waitGroup}, nil
}

func (r *RunnerManager) Run(hostnames []string, certificate *requestor.Certificate) {
	for _, runner := range r.Runners {
		go runner.Exec(r.WaitGroup, hostnames, certificate)
	}
	r.WaitGroup.Wait()
}
