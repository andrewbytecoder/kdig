package podinfo

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestHostKeyCallbackAcceptsNewAndRejectsChangedKey(t *testing.T) {
	knownHostsFile := filepath.Join(t.TempDir(), ".ssh", "known_hosts")
	runner := &sshRunner{options: SSHOptions{KnownHostsFile: knownHostsFile}}
	callback, err := runner.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}
	firstKey := generatePublicKey(t)
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}

	if err := callback("192.0.2.10:22", remote, firstKey); err != nil {
		t.Fatalf("callback rejected new host key: %v", err)
	}
	contents, err := os.ReadFile(knownHostsFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(contents), knownhosts.Normalize("192.0.2.10:22")) {
		t.Fatalf("known_hosts does not contain normalized address:\n%s", contents)
	}

	reloaded, err := runner.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback() reload error = %v", err)
	}
	if err := reloaded("192.0.2.10:22", remote, firstKey); err != nil {
		t.Fatalf("callback rejected known host key: %v", err)
	}
	if err := reloaded("192.0.2.10:22", remote, generatePublicKey(t)); err == nil {
		t.Fatal("callback accepted a changed host key")
	}
}

func generatePublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}
	return publicKey
}
