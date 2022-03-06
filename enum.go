package sneak

import (
	"encoding/json"
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
	Hostname string                  `json:"hostname"`
	EnvType  string                  `json:"env"`
	Results  map[string]*SsrfResults `json:"ssrf_results"`
}

// Creates a new Enumerator, populates with inital recon,
// and prepare to build from SSRF checks.
func StartEnum() *Enumerator {

	var hostname string
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "none"
	}

	// check for Docker by control groups
	var envtype string
	b, err := ioutil.ReadFile("/proc/1/cgroup")
	if err != nil {
		envtype = VirtMachine
	} else if strings.Contains(string(b), "docker") {
		envtype = Container
	} else {
		envtype = VirtMachine
	}

	return &Enumerator{
		Hostname: hostname,
		EnvType:  envtype,
		Results: map[string]*SsrfResults{
			"cloud": nil,
			"net":   nil,
			"env":   nil,
		},
	}
}

// Test for SSRF against either a single specified cloud provider,
// or enumerate all for juicy information.
func (e *Enumerator) CheckCloud(specific *string) error {
	metadata := GetMetadataEndpoints()

	// if specified, test only for the specific cloud provider
	if specific != nil && *specific != "" {
		provider := *specific
		action, ok := metadata[provider]
		if !ok {
			return errors.New("specified cloud provider not found")
		}
		if !action.CheckLitmus() {
			return errors.New("specified cloud provider does not have metadata endpoint exposed")
		}

		// if we're good, exploit and recover metadata
		results := action.Exploit()
		e.Results["cloud"] = &results
		return nil
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
		results := action.Exploit()
		e.Results["cloud"] = &results
		break
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
	jsonified, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		panic(err)
	}

	if webhook != nil || *webhook != "" {
		// TODO
	}
	fmt.Printf("%s\n", string(jsonified))
}
