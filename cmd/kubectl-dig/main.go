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
		if statusError, ok := errors.AsType[*diagnostic.StatusError](err); ok {
			os.Exit(statusError.Code)
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
