package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/andrewbytecoder/kdig/pkg/cli"
	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.NewRootCommand().ExecuteContext(ctx); err != nil {
		if statusError, ok := errors.AsType[*diagnostic.StatusError](err); ok {
			os.Exit(statusError.Code)
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
