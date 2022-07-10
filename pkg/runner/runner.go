package runner

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/maxroll/auto-cert/pkg/requestor"
	"github.com/maxroll/auto-cert/pkg/secrets"
	"golang.org/x/sync/errgroup"
)

type Runner interface {
	Exec(hostnames []string, certificate *requestor.Certificate) error
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
		} else if runnerName == "stackpath" {
			runner, err := NewStackPathRunner()

			if err != nil {
				return nil, err
			}

			runnerInstances = append(runnerInstances, runner)
		} else {
			return nil, fmt.Errorf("Unknown runner: %s", runnerName)
		}
	}

	waitGroup.Add(len(runners))

	return &RunnerManager{runnerInstances, waitGroup}, nil
}

func (r *RunnerManager) Run(hostnames []string, certificate *requestor.Certificate) {
	ctx := context.Background()

	errs, ctx := errgroup.WithContext(ctx)

	for _, runner := range r.Runners {
		execRunner := runner
		errs.Go(func() error {
			return execRunner.Exec(hostnames, certificate)
		})
	}

	err := errs.Wait()

	if err != nil {
		log.Printf("Runner failed: %s", err.Error())
	}
}
