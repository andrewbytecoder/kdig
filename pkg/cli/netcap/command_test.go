package netcap

import (
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	options := NewOptions()
	if options.Namespace != "default" || options.Username != "root" || options.SSHPort != 22 {
		t.Fatalf("unexpected SSH defaults: %#v", options)
	}
	if options.Interface != "any" || options.Duration != 30*time.Second {
		t.Fatalf("unexpected capture defaults: %#v", options)
	}
}

func TestValidateRequiresPod(t *testing.T) {
	options := NewOptions()
	options.InsecureSkipHostKey = true
	if err := options.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want missing pod error")
	}
}
