package main

import (
	"os"

	"github.com/cybercrit/cybercrit/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
