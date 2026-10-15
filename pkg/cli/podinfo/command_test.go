package podinfo

import (
	"testing"

	"github.com/andrewbytecoder/kdig/pkg/cli/common"
)

func TestDefaultOptions(t *testing.T) {
	options := NewOptions()
	if options.Namespace != "default" {
		t.Fatalf("Namespace = %q, want default", options.Namespace)
	}
	if options.Username != "root" {
		t.Fatalf("Username = %q, want root", options.Username)
	}
	if options.Password != "" {
		t.Fatalf("Password = %q, want empty", options.Password)
	}
	if options.SSHPort != 22 {
		t.Fatalf("SSHPort = %d, want 22", options.SSHPort)
	}
}

func TestCommandAcceptsNamespaceOnlyMode(t *testing.T) {
	command := NewCommand(common.NewOptions(), NewOptions())
	if err := command.Args(command, []string{}); err != nil {
		t.Fatalf("Args() rejected namespace-only mode: %v", err)
	}
	if err := command.Args(command, []string{"api-0"}); err != nil {
		t.Fatalf("Args() rejected single-pod mode: %v", err)
	}
}
