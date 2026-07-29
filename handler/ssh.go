package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.yaml.in/yaml/v4"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// SSH config struct
type SshHandlerConfig struct {
	Version      string `yaml:"version"`
	MessageLimit int    `yaml:"message_limit"`
	IdEd25519    string `yaml:"id_ed25519"`
	IdRsa        string `yaml:"id_rsa"`
	IdEcdsa      string `yaml:"id_ecdsa"`
	ServerCfg    ssh.ServerConfig
}

// Validate validates the SSH config
func (c *SshHandlerConfig) Validate() error {
	if c.Version == "" {
		return fmt.Errorf("ssh version required")
	}
	if c.MessageLimit <= 0 {
		c.MessageLimit = 10 // default to 10 messages if not specified
	}
	return nil
}

// SSH handler struct
type SshHandlerPlugin struct {
}

// Name returns the handlers name
func (SshHandlerPlugin) Name() string {
	return "ssh_handler"
}

// Name returns the name of the protocol the handlers implements
func (SshHandlerPlugin) Protocol() string {
	return "ssh"
}

// The SSH handler instance struct
type SshHandlerInstance struct {
	name     string
	cfg      SshHandlerConfig
	listener net.Listener
	logger   *slog.Logger
}

// Name returns the handler name, wraps SshHandlerPlugin.Name()
func (s *SshHandlerInstance) Name() string { return s.name }

// New creates a new handler plugin instance
func (SshHandlerPlugin) New(config HandlerConfig, listener net.Listener, logger *slog.Logger) (HandlerInstance, error) {
	instance := SshHandlerInstance{
		name:     SshHandlerPlugin{}.Name(),
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

// loadLdapConfig loads/parses the LDAP config from yaml
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

	// Set defaults for key paths if not provided
	if cfg.IdEd25519 == "" {
		cfg.IdEd25519 = "id_ed25519"
	}
	if cfg.IdRsa == "" {
		cfg.IdRsa = "id_rsa"
	}
	if cfg.IdEcdsa == "" {
		cfg.IdEcdsa = "id_ecdsa"
	}

	sh.cfg = *cfg

	// Configure SSH server
	cfg.ServerCfg = ssh.ServerConfig{
		ServerVersion: fmt.Sprintf("SSH-2.0-%s", cfg.Version),
		NoClientAuth:  false, // Allow client auth (password callback will handle)
	}

	// Load ed25519 host key (generate if missing)
	if edKey, edErr := sh.loadEd25519PrivKey(); edErr == nil {
		cfg.ServerCfg.AddHostKey(edKey)
	} else {
		slog.Warn("Failed to load/generate ed25519 host key", "error", edErr)
	}

	// Load rsa host key (generate if missing)
	if rsaKey, rsaErr := sh.loadRsaPrivKey(); rsaErr == nil {
		cfg.ServerCfg.AddHostKey(rsaKey)
	} else {
		slog.Warn("Failed to load/generate RSA host key", "error", rsaErr)
	}

	// Load ECDSA host key (generate if missing)
	if ecdsaKey, ecdsaErr := sh.loadEcdsaPrivKey(); ecdsaErr == nil {
		cfg.ServerCfg.AddHostKey(ecdsaKey)
	} else {
		slog.Warn("Failed to load/generate ECDSA host key", "error", ecdsaErr)
	}

	// Broaden algorithm support for scanners/older clients
	cfg.ServerCfg.Ciphers = []string{
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-cbc", "3des-cbc", "chacha20-poly1305@openssh.com",
	}
	cfg.ServerCfg.KeyExchanges = []string{
		"curve25519-sha256",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group-exchange-sha256",
	}
	cfg.ServerCfg.MACs = []string{
		"hmac-sha2-256", "hmac-sha1", "umac-64-etm@openssh.com",
	}

	sh.cfg = *cfg

	return nil
}

// loadSigner loads provate keys
func loadSigner(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

// loadEd25519PrivKey attempts to load id_ed25519, generating a new one if missing.
func (sh *SshHandlerInstance) loadEd25519PrivKey() (ssh.Signer, error) {
	private, err := loadSigner(sh.cfg.IdEd25519)
	if err != nil {
		private, err = sh.genEd25519PrivKey()
		return private, err
	}

	return private, nil
}

// genEd25519PrivKey generates and saves id_ed25519 private keys to disc
func (sh *SshHandlerInstance) genEd25519PrivKey() (ssh.Signer, error) {
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

	if dir := filepath.Dir(sh.cfg.IdEd25519); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("unable to create parent dir for ed25519 key: %v", err)
		}
	}
	if err := os.WriteFile(sh.cfg.IdEd25519, pem.EncodeToMemory(privPem), 0600); err != nil {
		return nil, fmt.Errorf("unable to write private key to disc: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to create signer from private key")
	}
	slog.Info("new ed25519 private key generated and written to file")
	return signer, nil
}

// loadRsaPrivKey attempts to load id_rsa, generating a new one if missing.
func (sh *SshHandlerInstance) loadRsaPrivKey() (ssh.Signer, error) {
	private, err := loadSigner(sh.cfg.IdRsa)
	if err != nil {
		private, err = sh.genRsaPrivKey()
		return private, err
	}
	return private, nil
}

// genRsaPrivKey generates and saves rsa private keys to disc
func (sh *SshHandlerInstance) genRsaPrivKey() (ssh.Signer, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("unable to generate RSA key pair")
	}

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}

	if dir := filepath.Dir(sh.cfg.IdRsa); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("unable to create parent dir for rsa key: %v", err)
		}
	}
	if err := os.WriteFile(sh.cfg.IdRsa, pem.EncodeToMemory(privPem), 0600); err != nil {
		return nil, fmt.Errorf("unable to write RSA private key to disk: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to create RSA signer from private key")
	}
	slog.Info("new RSA private key generated and written to file")
	return signer, nil
}

// loadEcdsaPrivKey attempts to load id_ecdsa, generating a new one if missing.
func (sh *SshHandlerInstance) loadEcdsaPrivKey() (ssh.Signer, error) {
	private, err := loadSigner(sh.cfg.IdEcdsa)
	if err != nil {
		private, err = sh.genEcdsaPrivKey()
		return private, err
	}
	return private, nil
}

// genEcdsaPrivKey generates and saves id_ecdsa private keys to disc
func (sh *SshHandlerInstance) genEcdsaPrivKey() (ssh.Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("unable to generate ECDSA key pair")
	}

	// Marshal EC private key
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal ECDSA private key: %v", err)
	}
	privPem := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}

	if dir := filepath.Dir(sh.cfg.IdEcdsa); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("unable to create parent dir for ecdsa key: %v", err)
		}
	}
	if err := os.WriteFile(sh.cfg.IdEcdsa, pem.EncodeToMemory(privPem), 0600); err != nil {
		return nil, fmt.Errorf("unable to write ECDSA private key to disk: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to create ECDSA signer from private key")
	}
	slog.Info("new ecdsa private key generated and written to file")
	return signer, nil
}

// bannerConn replays an initial buffer on Read() then delegates to the
// underlying net.Conn for subsequent reads. Used to read the client
// identification banner before handing the connection to the SSH parser.
type bannerConn struct {
	net.Conn
	buf []byte
	off int
}

// Read reads initial buffer to extract SSH client banner
func (b *bannerConn) Read(p []byte) (int, error) {
	if b.off < len(b.buf) {
		n := copy(p, b.buf[b.off:])
		b.off += n
		return n, nil
	}
	return b.Conn.Read(p)
}

// Serves handles incoming connections
func (sh *SshHandlerInstance) Serve(ctx context.Context, wg *sync.WaitGroup) {
	acceptChan := make(chan net.Conn, 1)
	var acceptWg sync.WaitGroup

	acceptWg.Add(1)
	go func() {
		defer acceptWg.Done()
		for {
			conn, err := sh.listener.Accept()
			if err != nil {
				log.Println("[SSH] Listener Goroutine ended")
				return
			}
			acceptChan <- conn
		}
	}()

	// Monitor context cancellation
	defer func() {
		sh.listener.Close()
		acceptWg.Wait() // wait for accept goroutine to exit
		wg.Done()       // then signal parent that Serve is done
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("[SSH] no longer serving")
			return // triggers defer and also ends go routine above
		case conn := <-acceptChan:
			go sh.handleConn(ctx, conn)
		}
	}
}

// handleConn performs the SSH handshake and services channels/requests
// for a single net.Conn.
func (sh *SshHandlerInstance) handleConn(ctx context.Context, nConn net.Conn) {
	defer nConn.Close()

	// Parse client IP and port
	clientAddr := nConn.RemoteAddr().String()
	clientIP, clientPortStr, _ := net.SplitHostPort(clientAddr)
	clientPort := 0
	if p, err := strconv.Atoi(clientPortStr); err == nil {
		clientPort = p
	}

	// Initialize session for logging
	sess := &SshSession{
		start:      time.Now(),
		clientIP:   clientIP,
		clientPort: clientPort,
		logger:     sh.logger,
		messages:   make([]string, 0),
	}

	// Defer logging of session when connection ends
	defer func() {
		sess.duration = time.Since(sess.start)
		sess.logger.Info("ssh_session_end",
			slog.Int64("ts", sess.start.Unix()),
			slog.String("client_ip", sess.clientIP),
			slog.Int("client_port", sess.clientPort),
			slog.Int("messages_count", sess.messageCount),
			slog.String("client_banner", sess.clientBanner),
			slog.String("disconnect_reason", sess.disconnectReason),
			slog.String("username", sess.loginUsername),
			slog.String("password", sess.loginPassword),
			slog.Bool("login_attempted", sess.loginAttempted),
			slog.Bool("command_attempted", sess.commandAttempted),
			slog.String("command_type", sess.commandType),
			slog.String("command_data", sess.commandData),
			slog.Int("channels_opened", sess.channelsOpened),
			slog.Any("messages", sess.messages),
			slog.Duration("duration", sess.duration),
		)
	}()

	// Set idle timeout to prevent hanging connections
	idleTimeout := 2 * time.Minute
	nConn.SetReadDeadline(time.Now().Add(idleTimeout))

	// Read client identification line (client banner) without consuming
	// bytes needed by the SSH handshake. We'll read up to CRLF (\r\n)
	// or until a small limit and then wrap the connection so the
	// previously-read bytes are replayed for the SSH library.
	var bannerBuf []byte
	const maxBanner = 1024
	tmp := make([]byte, 1)
	for len(bannerBuf) < maxBanner {
		n, err := nConn.Read(tmp)
		if n > 0 {
			bannerBuf = append(bannerBuf, tmp[:n]...)
			bl := len(bannerBuf)
			if bl >= 2 && bannerBuf[bl-2] == '\r' && bannerBuf[bl-1] == '\n' {
				break
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			break
		}
	}

	// Store banner string in session for logging
	if len(bannerBuf) > 0 {
		sess.clientBanner = strings.TrimRight(string(bannerBuf), "\r\n")
	}

	// If we read some banner bytes, wrap the connection so those bytes
	// are replayed to the SSH library on the first Read().
	wrappedConn := net.Conn(nConn)
	if len(bannerBuf) > 0 {
		wrappedConn = &bannerConn{Conn: nConn, buf: bannerBuf, off: 0}
	}

	// Create a custom ServerConfig with password callback that captures credentials
	serverConfig := sh.cfg.ServerCfg
	serverConfig.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		// Capture credentials in session
		sess.loginAttempted = true
		sess.loginUsername = c.User()
		sess.loginPassword = string(pass)

		log.Printf("[SSH] Login attempt: %s with password %s", c.User(), string(pass))

		// All credentials are accepted
		return nil, nil
	}

	conn, chans, reqs, err := ssh.NewServerConn(wrappedConn, &serverConfig)
	if err != nil {
		// Handle different handshake error types for better diagnostics
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			sess.disconnectReason = "handshake_timeout"
			log.Printf("[SSH] Handshake timeout from %s", clientIP)
		} else if errors.Is(err, syscall.ECONNRESET) || strings.Contains(err.Error(), "connection reset by peer") {
			sess.disconnectReason = "client_disconnect_during_handshake"
			log.Printf("[SSH] Client %s reset connection during handshake: %v", clientIP, err)
		} else if strings.Contains(err.Error(), "unmarshal error for field Language") {
			// Some scanners send malformed disconnect messages
			// Example error: Handshake failed from [IP]: ssh: unmarshal error for field Language of type disconnectMsg
			// NOTE: Client is probably sending faulty Language attribute, but we know we are trying to unmarshal a `disconnectMsg`,
			// so the client is clearly disconnecting
			// https://cs.opensource.google/go/x/crypto/+/master:ssh/messages.go;l=40?q=disconnectMsg&ss=go%2Fx%2Fcrypto
			// RFC: https://datatracker.ietf.org/doc/html/rfc4253#section-11.1
			// matching issue https://github.com/jaksi/sshesame/issues/8
			sess.disconnectReason = "client_disconnect_during_handshake_malformatted"
			log.Printf("[SSH] Client %s sent malformed disconnect during handshake: %v", clientIP, err)
		} else if err.Error() == "EOF" {
			sess.disconnectReason = "client_disconnect_during_handshake"
			log.Printf("[SSH] Client %s disconnected during handshake (EOF)", clientIP)
		} else {
			sess.disconnectReason = "handshake_error"
			log.Printf("[SSH] Handshake failed from %s: %v", clientIP, err)
		}
		return
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		ssh.DiscardRequests(reqs)
		wg.Done()
	}()

	// Service channels for connection.
	for {
		select {
		case <-ctx.Done():
			sess.disconnectReason = "context_cancelled"
			log.Println("[SSH] Connection shutdown via context")
			return
		case newChannel, ok := <-chans:
			if !ok {
				// Connection closed (client dropped connection)
				sess.disconnectReason = "client_disconnect"
				return
			}
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				sess.disconnectReason = "channel_accept_error"
				log.Printf("[SSH] Could not accept channel: %v", err)
				continue
			}

			sess.channelsOpened++

			// Handle channel requests (e.g. "shell").
			wg.Add(1)
			go func(in <-chan *ssh.Request, ch ssh.Channel) {
				defer wg.Done()
				for req := range in {
					switch req.Type {
					case "pty-req":
						// Accept PTY request
						if req.WantReply {
							req.Reply(true, nil)
						}
					case "shell":
						// Client requested shell - accept and wait for commands
						sess.commandType = "shell"
						if req.WantReply {
							req.Reply(true, nil)
						}

						// Read commands from shell in a loop
						prompt_symbol := "$"
						if sess.loginUsername == "root" {
							prompt_symbol = "#"
						}
						term := terminal.NewTerminal(ch, fmt.Sprintf("%s@srv01:~%s ", sess.loginUsername, prompt_symbol)) // TODO better: use the actual username thats 'logged in'
						for {
							line, err := term.ReadLine()
							if err != nil {
								if sess.messageCount > 0 {
									sess.disconnectReason = "shell_session_ended"
								} else {
									sess.disconnectReason = "shell_no_command"
								}
								log.Printf("[SSH] %s shell session ended", sess.clientIP)
								ch.Close()
								conn.Close()
								return
							}

							if line == "" {
								continue
							}

							// Handle exit command
							if line == "exit" || line == "logout" {
								sess.disconnectReason = "exit_command"
								term.Write([]byte("logout\r\n"))
								ch.Close()
								conn.Close()
								return
							}

							// Track message
							sess.commandAttempted = true
							sess.messageCount++
							sess.messages = append(sess.messages, line)
							log.Printf("[SSH] %s shell command: %s", sess.clientIP, line)

							// Send static response
							term.Write([]byte("bash: command not found\r\n"))

							// Check message limit
							if sess.messageCount >= sh.cfg.MessageLimit {
								sess.disconnectReason = "message_limit_reached"
								log.Printf("[SSH] %s reached message limit (%d)", sess.clientIP, sh.cfg.MessageLimit)
								ch.Close()
								conn.Close()
								return
							}
						}
					case "exec":
						// Client attempted to execute a command - log it and close connection immediately
						sess.commandAttempted = true
						sess.commandType = "exec"
						sess.commandData = string(req.Payload)
						sess.disconnectReason = "exec_requested"
						if req.WantReply {
							req.Reply(true, nil)
						}
						
						log.Printf("[SSH] %s attempted exec: %s", sess.clientIP, sess.commandData)
						conn.Close()
						return
					case "subsystem":
						// Client requested subsystem (sftp, etc) - log and close connection immediately
						sess.commandAttempted = true
						sess.commandType = "subsystem"
						sess.commandData = string(req.Payload)
						sess.disconnectReason = "subsystem_requested"
						if req.WantReply {
							req.Reply(false, nil)
						}
						
						log.Printf("[SSH] %s attempted subsystem: %s", sess.clientIP, sess.commandData)
						conn.Close()
						return
					default:
						if req.WantReply {
							req.Reply(false, nil)
						}
					}
				}
			}(requests, channel)

		}
	}
}

type SshSession struct {
	start        time.Time
	duration     time.Duration
	clientIP     string
	clientPort   int
	logger       *slog.Logger
	clientBanner string

	loginAttempted bool
	loginUsername  string
	loginPassword  string

	commandAttempted bool
	commandType      string // "shell", "exec", "subsystem", etc.
	commandData      string // command data for exec and subsystem
	channelsOpened   int
	messageCount     int
	messages         []string // shell messages

	disconnectReason string
}
