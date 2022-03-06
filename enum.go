package sneak

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

var (
	Container   string = "container"
	VirtMachine        = "vm"
)

type Enumerator struct {
	Hostname *string `json:"hostname"`
	EnvType  *string `json:"env"`
	Results  map[string]string
}

// Creates a new Enumerator, populates with inital recon,
// and prepare to build from SSRF checks.
func StartEnum() *Enumerator {

	var hostname *string
	host, err := os.Hostname()
	if err != nil {
		hostname = nil
	} else {
		hostname = &host
	}

	// check for Docker by control groups
	var envtype *string
	b, err := ioutil.ReadFile("/proc/1/cgroup")
	if err != nil {
		envtype = nil
	} else if strings.Contains(string(b), "docker") {
		envtype = &Container
	} else {
		envtype = &VirtMachine
	}

	return &Enumerator{
		Hostname: hostname,
		EnvType:  envtype,
	}
}

// Test for SSRF against either a single specified cloud provider,
// or enumerate all for juicy information.
func (e *Enumerator) CheckCloud(specific *string) error {

	metadata := GetMetadataEndpoints()

	if specific != nil && *specific != "" {
		provider := *specific
		action, ok := metadata[provider]
		if !ok {
			return errors.New("specified cloud provider not found")
		}

		// test for specific provider and error handle
		if !action.CheckLitmus() {
			return errors.New("specified cloud provider does not have metadata endpoint exposed")
		}
	}

	// test for each available metadata endpoint
	for provider, action := range metadata {
		fmt.Printf("Testing %s\n", provider)

		// skip if litmus test for provider fails
		if !action.CheckLitmus() {
			fmt.Printf("Cannot reach metadata endpoint for %s\n", provider)
			continue
		}

		// if we're good, exploit and recover metadata
		if err := action.Exploit(); err != nil {
			fmt.Printf("Cannot exploit for cloud provider %s. Reason: %s\n", provider, err)
			continue
		}
	}
	return nil
}

func (e *Enumerator) CheckNet() {

}

// Enumerates global environment variables for secrets and URLs, and
// additionally checks for dotenvs on disk.
func (e *Enumerator) CheckEnv() {

}

// Outputs results to stdout, or in the case of blind test, send back
// results to an attacker-controlled webhook.
func (e *Enumerator) Export(webhook *string) {

}