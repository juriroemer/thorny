package handler

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"go.yaml.in/yaml/v4"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

type SshHandlerConfig struct {
	Version   string `yaml:"version"`
	ServerCfg ssh.ServerConfig
}

func (c *SshHandlerConfig) Validate() error {
	if c.Version == "" {
		return fmt.Errorf("ssh version required")
	}
	return nil
}

type SshHandlerPlugin struct {
}

func (SshHandlerPlugin) Name() string {
	return "ssh_handler"
}

func (SshHandlerPlugin) Protocol() string {
	return "ssh"
}

type SshHandlerInstance struct {
	cfg      SshHandlerConfig
	listener net.Listener
	logger   *slog.Logger
}

func (SshHandlerPlugin) New(config HandlerConfig, listener net.Listener, logger *slog.Logger) (HandlerInstance, error) {
	instance := SshHandlerInstance{
		listener: listener,
		logger: logger.With(
			slog.String("protocol", "ssh"),
		),
	}

	if err := instance.loadSshConfig(config); err != nil {
		return nil, err
	}

	return &instance, nil
}

func (sh *SshHandlerInstance) loadSshConfig(raw HandlerConfig) error {
	cfg := &SshHandlerConfig{}
	fmt.Println(raw)
	valuesRaw := raw["values"]
	fmt.Println(valuesRaw)
	valuesYaml, _ := yaml.Marshal(valuesRaw)
	fmt.Println(valuesYaml)

	if err := yaml.Unmarshal(valuesYaml, cfg); err != nil {
		return err
	}
	fmt.Println(cfg)

	if err := cfg.Validate(); err != nil {
		return err
	}

	cfg.ServerCfg = ssh.ServerConfig{
		// Remove to disable password auth.
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			fmt.Printf("Trying to login as %s with PW %s\n", c.User(), string(pass))

			if c.User() == "admin" && string(pass) == "password" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
		ServerVersion: fmt.Sprintf("SSH-2.0-%s", cfg.Version),
	}

	private, err := sh.loadSshPrivKey()
	cfg.ServerCfg.AddHostKey(private)

	sh.cfg = *cfg

	return err
}

func loadSigner(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

// TODO refactor into something nicer
func (sh *SshHandlerInstance) loadSshPrivKey() (ssh.Signer, error) {
	private, err := loadSigner("id_ed25519")
	if err != nil {
		slog.Warn("Failed to load private key: ", "error", err)
		slog.Warn("Generating new private key")
		private, err := sh.genSshPrivKey()
		return private, err
	}

	return private, nil
}

func (sh *SshHandlerInstance) genSshPrivKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("unable to generate key pair")
	}

	// Encode private key as PKCS#8 since ed25519 doesn't use PKCS#1
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal private key")
	}
	privPem := &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}
	if err := os.WriteFile("id_ed25519", pem.EncodeToMemory(privPem), 0600); err != nil {
		return nil, fmt.Errorf("unable to write private key to disc")
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to create signer from private key")
	}
	slog.Info("new private key generated and written to file")
	return signer, nil
}

func (sh *SshHandlerInstance) Serve() {
	// Accept connections in a loop and handle each concurrently.
	for {
		nConn, err := sh.listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection: %v", err)
			return
		}

		go sh.handleConn(nConn)
	}
}

// handleConn performs the SSH handshake and services channels/requests
// for a single net.Conn. It's safe to run concurrently for multiple
// accepted connections.
func (sh *SshHandlerInstance) handleConn(nConn net.Conn) {
	defer nConn.Close()

	conn, chans, reqs, err := ssh.NewServerConn(nConn, &sh.cfg.ServerCfg)
	if err != nil {
		log.Printf("failed to handshake: %v", err)
		return
	}
	log.Printf("logged in user %s", conn.User())

	var wg sync.WaitGroup

	// Service global out-of-band requests for this connection.
	wg.Add(1)
	go func() {
		ssh.DiscardRequests(reqs)
		wg.Done()
	}()

	// Service channels for this connection.
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}

		// Handle channel requests (e.g. "shell").
		wg.Add(1)
		go func(in <-chan *ssh.Request) {
			defer wg.Done()
			for req := range in {
				switch req.Type {
				case "pty-req":
					// parse payload if you need terminal settings
					if req.WantReply {
						req.Reply(true, nil)
					}
				case "shell":
					if req.WantReply {
						req.Reply(true, nil)
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						term := terminal.NewTerminal(channel, "> ")
						defer channel.Close()
						for {
							line, err := term.ReadLine()
							if err != nil {
								break
							}
							fmt.Println(line)
							term.Write([]byte(line + "\r\n"))
						}
					}()
				case "exec":
					if req.WantReply {
						req.Reply(true, nil)
					}
					// read req.Payload for command and handle it
				default:
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}
		}(requests)

	}

	wg.Wait()
	conn.Close()
}

type SshSession struct {
	logger        *slog.Logger
	start         time.Time
	clientIp      string
	port          int
	loginAttempts int // orL: attemptsLogin bool ?
	password      string
	duration      time.Duration
	numMessages   int
	// cert attempt?
	// session / channel types

	// close IF loginAttempted?
}
