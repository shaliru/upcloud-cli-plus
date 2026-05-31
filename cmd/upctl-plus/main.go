package main

import (
	"os"

	"github.com/shaliru/upcloud-cli-plus/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
