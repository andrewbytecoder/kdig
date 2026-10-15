package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootCommandWithoutSubcommandShowsHelp(t *testing.T) {
	command := NewRootCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	for _, expected := range []string{"Available Commands:", "amtool", "metallb", "prometheus"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("help output does not contain %q:\n%s", expected, output.String())
		}
	}
	if command.Flags().Lookup("metallb-namespace") != nil || command.Flags().Lookup("prometheus-namespace") != nil {
		t.Fatal("service-specific flags must not be registered on the root command")
	}
}
