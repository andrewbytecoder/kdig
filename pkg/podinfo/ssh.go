package podinfo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

var knownHostsMutex sync.Mutex

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

type StreamRunner interface {
	RemoteRunner
	Stream(ctx context.Context, address string, command string, stdout io.Writer) (string, error)
}

func NewSSHRunner(options SSHOptions) RemoteRunner {
	return &sshRunner{options: options}
}

func NewSSHStreamRunner(options SSHOptions) StreamRunner {
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

func (runner *sshRunner) Stream(ctx context.Context, address string, command string, stdout io.Writer) (string, error) {
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

	var stderr strings.Builder
	session.Stdout = stdout
	session.Stderr = &stderr
	resultChannel := make(chan error, 1)
	go func() {
		resultChannel <- session.Run(command)
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGINT)
		select {
		case <-resultChannel:
		case <-time.After(2 * time.Second):
			client.Close()
			<-resultChannel
		}
		return stderr.String(), ctx.Err()
	case runErr := <-resultChannel:
		if runErr != nil {
			return stderr.String(), fmt.Errorf("run %q: %w", command, runErr)
		}
		return stderr.String(), nil
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
	if err := ensureKnownHostsFile(runner.options.KnownHostsFile); err != nil {
		return nil, err
	}
	callback, err := knownhosts.New(runner.options.KnownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts file %s: %w", runner.options.KnownHostsFile, err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := callback(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyError *knownhosts.KeyError
		if !errors.As(err, &keyError) || len(keyError.Want) > 0 {
			return err
		}
		return acceptNewHostKey(runner.options.KnownHostsFile, hostname, remote, key)
	}, nil
}

func ensureKnownHostsFile(path string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create known_hosts directory %s: %w", directory, err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("create known_hosts file %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close known_hosts file %s: %w", path, err)
	}
	return nil
}

func acceptNewHostKey(path string, hostname string, remote net.Addr, key ssh.PublicKey) error {
	knownHostsMutex.Lock()
	defer knownHostsMutex.Unlock()

	callback, err := knownhosts.New(path)
	if err != nil {
		return fmt.Errorf("reload known_hosts file %s: %w", path, err)
	}
	if err := callback(hostname, remote, key); err == nil {
		return nil
	} else {
		var keyError *knownhosts.KeyError
		if !errors.As(err, &keyError) || len(keyError.Want) > 0 {
			return err
		}
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open known_hosts file %s: %w", path, err)
	}
	defer file.Close()
	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
	if _, err := fmt.Fprintln(file, line); err != nil {
		return fmt.Errorf("save host key for %s: %w", hostname, err)
	}
	return nil
}
