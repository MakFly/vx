package main

import (
	"os"

	"github.com/MakFly/vx/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
