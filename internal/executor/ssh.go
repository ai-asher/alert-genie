package executor

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHExecutor executes commands on remote hosts via SSH.
type SSHExecutor struct {
	targets map[string]*sshTarget
	logger  *slog.Logger
}

type sshTarget struct {
	name       string
	host       string
	port       int
	user       string
	signer     ssh.Signer
	bastionCfg *bastionConfig
}

type bastionConfig struct {
	host   string
	user   string
	signer ssh.Signer
}

type SSHTargetConfig struct {
	Name           string
	Host           string
	Port           int
	User           string
	PrivateKeyPath string
	BastionHost    string
	BastionUser    string
	BastionKeyPath string
}

func NewSSHExecutor(targets []SSHTargetConfig, logger *slog.Logger) (*SSHExecutor, error) {
	tMap := make(map[string]*sshTarget, len(targets))

	for _, tc := range targets {
		keyData, err := os.ReadFile(tc.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read key for %s: %w", tc.Name, err)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse key for %s: %w", tc.Name, err)
		}

		t := &sshTarget{
			name:   tc.Name,
			host:   tc.Host,
			port:   tc.Port,
			user:   tc.User,
			signer: signer,
		}

		if tc.BastionHost != "" {
			bastionKey, err := os.ReadFile(tc.BastionKeyPath)
			if err != nil {
				return nil, fmt.Errorf("read bastion key for %s: %w", tc.Name, err)
			}
			bastionSigner, err := ssh.ParsePrivateKey(bastionKey)
			if err != nil {
				return nil, fmt.Errorf("parse bastion key for %s: %w", tc.Name, err)
			}
			t.bastionCfg = &bastionConfig{
				host:   tc.BastionHost,
				user:   tc.BastionUser,
				signer: bastionSigner,
			}
		}

		tMap[tc.Name] = t
	}

	return &SSHExecutor{targets: tMap, logger: logger}, nil
}

func (e *SSHExecutor) Type() CommandType {
	return CommandTypeSSH
}

func (e *SSHExecutor) Execute(ctx context.Context, cmd Command) (*ExecutionResult, error) {
	target, ok := e.targets[cmd.Target]
	if !ok {
		return &ExecutionResult{
			CommandID: cmd.ID,
			Success:   false,
			Error:     fmt.Sprintf("unknown SSH target %q", cmd.Target),
		}, fmt.Errorf("unknown SSH target %q", cmd.Target)
	}

	start := time.Now()

	e.logger.Info("executing ssh command",
		"target", cmd.Target,
		"host", target.host,
		"command", cmd.Command,
	)

	client, err := e.connect(ctx, target)
	if err != nil {
		return &ExecutionResult{
			CommandID: cmd.ID,
			Success:   false,
			Error:     fmt.Sprintf("ssh connect: %v", err),
			Duration:  time.Since(start),
		}, nil
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return &ExecutionResult{
			CommandID: cmd.ID,
			Success:   false,
			Error:     fmt.Sprintf("ssh session: %v", err),
			Duration:  time.Since(start),
		}, nil
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Run with context cancellation
	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmd.Command)
	}()

	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL)
		return &ExecutionResult{
			CommandID: cmd.ID,
			Success:   false,
			Error:     "command timed out",
			Duration:  time.Since(start),
			ExitCode:  -1,
		}, nil
	case err := <-done:
		duration := time.Since(start)
		output := truncateOutput(stdout.String(), 10240)
		errStr := truncateOutput(stderr.String(), 10240)

		result := &ExecutionResult{
			CommandID: cmd.ID,
			Duration:  duration,
			Output:    output,
		}

		if err != nil {
			result.Success = false
			result.Error = errStr
			if exitErr, ok := err.(*ssh.ExitError); ok {
				result.ExitCode = exitErr.ExitStatus()
			} else {
				result.ExitCode = -1
			}
		} else {
			result.Success = true
			result.ExitCode = 0
		}
		return result, nil
	}
}

func (e *SSHExecutor) DryRun(_ context.Context, cmd Command) error {
	if _, ok := e.targets[cmd.Target]; !ok {
		return fmt.Errorf("unknown SSH target %q", cmd.Target)
	}
	if cmd.Command == "" {
		return fmt.Errorf("empty command")
	}
	return nil
}

func (e *SSHExecutor) connect(ctx context.Context, target *sshTarget) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            target.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(target.signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", target.host, target.port)

	if target.bastionCfg != nil {
		return e.connectViaBastion(ctx, target, config, addr)
	}

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", addr, err)
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

func (e *SSHExecutor) connectViaBastion(_ context.Context, target *sshTarget, targetConfig *ssh.ClientConfig, targetAddr string) (*ssh.Client, error) {
	bastionConfig := &ssh.ClientConfig{
		User:            target.bastionCfg.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(target.bastionCfg.signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	bastionAddr := fmt.Sprintf("%s:22", target.bastionCfg.host)
	bastionClient, err := ssh.Dial("tcp", bastionAddr, bastionConfig)
	if err != nil {
		return nil, fmt.Errorf("dial bastion %s: %w", bastionAddr, err)
	}

	conn, err := bastionClient.Dial("tcp", targetAddr)
	if err != nil {
		bastionClient.Close()
		return nil, fmt.Errorf("dial target via bastion: %w", err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, targetConfig)
	if err != nil {
		conn.Close()
		bastionClient.Close()
		return nil, fmt.Errorf("ssh handshake via bastion: %w", err)
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}
