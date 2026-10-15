package podinfo

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

type SSHOptions struct {
	Username            string
	Password            string
	IdentityFile        string
	KnownHostsFile      string
	InsecureSkipHostKey bool
	Timeout             time.Duration
}

type sshRunner struct {
	options SSHOptions
}

func NewSSHRunner(options SSHOptions) RemoteRunner {
	return &sshRunner{options: options}
}

func (runner *sshRunner) Run(ctx context.Context, address string, command string) (string, error) {
	if runner.options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, runner.options.Timeout)
		defer cancel()
	}
	config, agentConnection, err := runner.clientConfig()
	if err != nil {
		return "", err
	}
	if agentConnection != nil {
		defer agentConnection.Close()
	}

	dialer := net.Dialer{Timeout: runner.options.Timeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w", address, err)
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, config)
	if err != nil {
		connection.Close()
		return "", fmt.Errorf("SSH handshake with %s: %w", address, err)
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("create SSH session: %w", err)
	}
	defer session.Close()

	type result struct {
		output []byte
		err    error
	}
	resultChannel := make(chan result, 1)
	go func() {
		output, runErr := session.CombinedOutput(command)
		resultChannel <- result{output: output, err: runErr}
	}()

	select {
	case <-ctx.Done():
		client.Close()
		return "", ctx.Err()
	case commandResult := <-resultChannel:
		if commandResult.err != nil {
			return string(commandResult.output), fmt.Errorf("run %q: %w: %s", command, commandResult.err, string(commandResult.output))
		}
		return string(commandResult.output), nil
	}
}

func (runner *sshRunner) clientConfig() (*ssh.ClientConfig, net.Conn, error) {
	authMethods, agentConnection, err := runner.authMethods()
	if err != nil {
		if agentConnection != nil {
			agentConnection.Close()
		}
		return nil, nil, err
	}
	hostKeyCallback, err := runner.hostKeyCallback()
	if err != nil {
		if agentConnection != nil {
			agentConnection.Close()
		}
		return nil, nil, err
	}
	return &ssh.ClientConfig{
		User:            runner.options.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         runner.options.Timeout,
	}, agentConnection, nil
}

func (runner *sshRunner) authMethods() ([]ssh.AuthMethod, net.Conn, error) {
	if runner.options.Password != "" {
		return []ssh.AuthMethod{ssh.Password(runner.options.Password)}, nil, nil
	}

	authMethods := make([]ssh.AuthMethod, 0)
	var agentConnection net.Conn
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		connection, err := net.Dial("unix", socket)
		if err == nil {
			agentConnection = connection
			authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(connection).Signers))
		}
	}

	identityFiles := []string{runner.options.IdentityFile}
	if runner.options.IdentityFile == "" {
		if home, err := os.UserHomeDir(); err == nil {
			identityFiles = []string{
				filepath.Join(home, ".ssh", "id_ed25519"),
				filepath.Join(home, ".ssh", "id_ecdsa"),
				filepath.Join(home, ".ssh", "id_rsa"),
			}
		}
	}
	for _, identityFile := range identityFiles {
		if identityFile == "" {
			continue
		}
		key, err := os.ReadFile(identityFile)
		if err != nil {
			if runner.options.IdentityFile != "" {
				return nil, agentConnection, fmt.Errorf("read identity file %s: %w", identityFile, err)
			}
			continue
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			if runner.options.IdentityFile != "" {
				return nil, agentConnection, fmt.Errorf("parse identity file %s: %w", identityFile, err)
			}
			continue
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if len(authMethods) == 0 {
		return nil, agentConnection, errors.New("no SSH authentication method available; provide --password, --identity-file, or SSH_AUTH_SOCK")
	}
	return authMethods, agentConnection, nil
}

func (runner *sshRunner) hostKeyCallback() (ssh.HostKeyCallback, error) {
	if runner.options.InsecureSkipHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if runner.options.KnownHostsFile == "" {
		return nil, errors.New("known_hosts file is required unless insecure host key checking is enabled")
	}
	callback, err := knownhosts.New(runner.options.KnownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts file %s: %w", runner.options.KnownHostsFile, err)
	}
	return callback, nil
}
