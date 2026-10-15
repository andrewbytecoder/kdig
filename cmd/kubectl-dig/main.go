package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/andrewbytecoder/kdig/pkg/cli"
	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		var statusError *diagnostic.StatusError
		if errors.As(err, &statusError) {
			os.Exit(statusError.Code)
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
