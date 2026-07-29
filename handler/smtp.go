package handler

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.yaml.in/yaml/v4"

	"github.com/juriroemer/thorny/lib"
)

// SMTP config struct
type SmtpHandlerConfig struct {
}

// SMTP handler struct
type SmtpHandlerPlugin struct {
}

// Name returns the handlers name
func (SmtpHandlerPlugin) Name() string {
	return "smtp_handler"
}

// Name returns the name of the protocol the handlers implements
func (SmtpHandlerPlugin) Protocol() string {
	return "smtp"
}

// The SMTP handler instance struct
type SmtpHandlerInstance struct {
	name     string
	cfg      SmtpHandlerConfig // TODO remove cfg if not necessary
	listener net.Listener
	logger   *slog.Logger
}

// Name returns the handler name, wraps SmtpHandlerPlugin.Name()
func (s *SmtpHandlerInstance) Name() string { return s.name }

// New creates a new handler plugin instance
func (SmtpHandlerPlugin) New(config HandlerConfig, listener net.Listener, logger *slog.Logger) (HandlerInstance, error) {
	cfg, err := SmtpHandlerPlugin{}.parseConfig(config)
	if err != nil {
		return nil, err
	}
	return &SmtpHandlerInstance{
		name:     SmtpHandlerPlugin{}.Name(),
		cfg:      *cfg,
		listener: listener,
		logger: logger.With(
			slog.String("protocol", "smtp"),
		),
	}, nil
}

// parseConfig parses the yaml SMTP config part
func (SmtpHandlerPlugin) parseConfig(config HandlerConfig) (*SmtpHandlerConfig, error) {
	// Handle missing or empty config blocks.
	if config == nil {
		return &SmtpHandlerConfig{}, nil
	}

	var cfg SmtpHandlerConfig
	b, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return &SmtpHandlerConfig{}, nil
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Serves handles incoming connections
func (sh *SmtpHandlerInstance) Serve(ctx context.Context, wg *sync.WaitGroup) {
	acceptChan := make(chan net.Conn, 1)

	// Load TLS certificate for STARTTLS from typed TLS config in context.
	var tlsConfig *tls.Config
	if v := ctx.Value(lib.CtxTlsUserConfig); v != nil {
		if tconf, ok := v.(*lib.TlsUserConfig); ok {
			cert, err := tls.LoadX509KeyPair(tconf.CertPath, tconf.KeyPath)
			if err != nil {
				log.Printf("[SMTP] Failed to load TLS certificate from %s / %s: %v", tconf.CertPath, tconf.KeyPath, err)
			} else {
				tlsConfig = &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS10,
					MaxVersion:   tls.VersionTLS11,
				}
			}
		}
	}

	// accept connections
	go func() {
		for {
			conn, err := sh.listener.Accept()
			if err != nil {
				log.Println("[SMTP] ENDING LISTENER GOROUTINE")
				return
			}
			acceptChan <- conn
		}
	}()

	// Monitor context cancellation
	defer func() {
		sh.listener.Close()
		wg.Done()
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("[SMTP] No longer serving")
			return // triggers defer and also ends go routine above
		case conn := <-acceptChan:
			go sh.handleConn(ctx, conn, tlsConfig)
		}
	}
}

// handleConn handles a individual SMTP connections
func (hh *SmtpHandlerInstance) handleConn(ctx context.Context, conn net.Conn, tlsConfig *tls.Config) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[SMTP] Connection from %s", clientAddr)

	// Parse client IP and port
	clientIP, clientPortStr, _ := net.SplitHostPort(clientAddr)
	clientPort := 0
	if p, err := strconv.Atoi(clientPortStr); err == nil {
		clientPort = p
	}

	// Initialize session struct  for logging/metadata
	sess := &SmtpSession{
		start:          time.Now(),
		clientIP:       clientIP,
		clientPort:     clientPort,
		clientHostname: "",
		recipients:     []string{},
		commands:       []string{},
		allHeaders:     make(map[string]string),
	}

	// Defer structured logging of captured session data when connection ends
	defer func() {
		sess.duration = time.Since(sess.start)
		hh.logger.Info("smtp_session_end",
			slog.Int64("ts", sess.start.Unix()),
			slog.String("client_ip", sess.clientIP),
			slog.Int("client_port", sess.clientPort),
			slog.String("disconnect_reason", sess.disconnectReason),
			slog.String("client_hostname", sess.clientHostname),
			slog.Bool("tls_used", sess.tlsUsed),
			slog.Bool("tls_tested", sess.tlsTested),
			slog.String("tls_version", sess.tlsVersion),
			slog.String("tls_cipher", sess.tlsCipherSuite),
			slog.String("auth_user", sess.authUser),
			slog.String("auth_pass", sess.authPass),
			slog.String("auth_mechanism", sess.authMechanism),
			slog.String("sender", sess.sender),
			slog.Any("recipients", sess.recipients),
			slog.String("subject", sess.subject),
			slog.String("date", sess.dateHeader),
			slog.Any("headers", sess.allHeaders),
			slog.Int("body_len", len(sess.messageBody)),
			slog.String("body", sess.messageBody),
			slog.Int("data_size", len(sess.rawData)),
			slog.Any("commands", sess.commands),
			slog.Duration("duration", sess.duration),
		)
	}()

	// Set 2-minute idle timeout
	conn.SetDeadline(time.Now().Add(2 * time.Minute))

	// SMTP banner
	writeLine(conn, "220 nsec.uni-muenster.de ESMTP Postfix")

	reader := bufio.NewReader(conn)
	state := "INIT" // SMTP state machine
	var mailFrom string
	var rcptTo []string
	tlsActive := false
	authUser := ""

	for {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		lineBytes, err := reader.ReadBytes('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if shutdown requested
				select {
				case <-ctx.Done():
					sess.disconnectReason = "context_cancelled"
					log.Println("[SMTP] Session shutdown via context")
					return
				default:
					continue
				}
			}
			// EOF or real error
			if errors.Is(err, syscall.ECONNRESET) || strings.Contains(err.Error(), "connection reset by peer") {
				sess.disconnectReason = "client_disconnect"
				log.Printf("[SMTP] Client disconnected (RST) from %s: %v", clientAddr, err)
			} else if err.Error() == "EOF" || strings.Contains(err.Error(), "EOF") {
				sess.disconnectReason = "client_disconnect"
			} else {
				sess.disconnectReason = "read_error"
				log.Printf("[SMTP] Connection error from %s: %v", clientAddr, err)
			}
			break
		}

		// Reset deadline after successful read
		conn.SetReadDeadline(time.Time{})
		conn.SetDeadline(time.Now().Add(2 * time.Minute))

		line := strings.TrimSpace(string(lineBytes))
		log.Printf("[SMTP] %s >> %s", clientAddr, line)

		arg := ""
		var cmd string
		if i := strings.Index(line, " "); i > -1 {
			arg = strings.TrimSpace(line[i+1:])
			cmd = strings.ToUpper(line[:i])
		} else {
			cmd = strings.ToUpper(line)
		}

		// Handle SMTP commands
		switch cmd {
		case "EHLO":
			sess.commands = append(sess.commands, line)
			state = "HELO_RECEIVED"
			// Capture FQHN
			sess.clientHostname = arg
			writeLine(conn, "250-nsec.uni-muenster.de")
			writeLine(conn, "250-PIPELINING")
			writeLine(conn, "250-SIZE 35882577")
			if !tlsActive {
				writeLine(conn, "250-STARTTLS")
			}
			writeLine(conn, "250-AUTH LOGIN PLAIN")
			writeLine(conn, "250-ENHANCEDSTATUSCODES")
			writeLine(conn, "250-8BITMIME")
			writeLine(conn, "250 DSN")

		case "HELO":
			sess.commands = append(sess.commands, line)
			state = "HELO_RECEIVED"
			// Capture FQHN
			sess.clientHostname = arg
			writeLine(conn, "250 OK")

		case "VRFY":
			// Do not reveal user existence; standard privacy-preserving response
			sess.commands = append(sess.commands, line)
			writeLine(conn, "252 2.5.2 Cannot VRFY user, but will accept message and attempt delivery")

		case "EXPN":
			// Respond that mailing list expansion is disabled
			sess.commands = append(sess.commands, line)
			writeLine(conn, "502 5.5.1 Command not supported")

		case "MAIL":
			// Starts Mail sending
			sess.commands = append(sess.commands, line)
			if state == "INIT" {
				writeLine(conn, "503 5.5.1 Error: need HELO or EHLO first")
				break
			}
			// Parse MAIL FROM:<address>
			if !strings.HasPrefix(strings.ToUpper(arg), "FROM:") {
				writeLine(conn, "501 5.5.4 Syntax: MAIL FROM:<address>")
				break
			}
			mailFrom = strings.TrimSpace(arg[5:])
			sess.sender = mailFrom
			state = "MAIL_RECEIVED"

			sender := mailFrom
			if !strings.Contains(sender, "<") {
				sender = "<" + sender + ">"
			}
			writeLine(conn, fmt.Sprintf("250 2.1.0 Originator %s ok", sender))

		case "RCPT":
			// Set receiver
			sess.commands = append(sess.commands, line)
			if state != "MAIL_RECEIVED" && state != "RCPT_RECEIVED" {
				writeLine(conn, "503 5.5.1 Error: need MAIL command")
				break
			}
			// Parse RCPT TO:<address>
			if !strings.HasPrefix(strings.ToUpper(arg), "TO:") {
				writeLine(conn, "501 5.5.4 Syntax: RCPT TO:<address>")
				break
			}
			rcpt := strings.TrimSpace(arg[3:])
			rcptTo = append(rcptTo, rcpt)
			sess.recipients = append(sess.recipients, rcpt)
			state = "RCPT_RECEIVED"

			recip := rcpt
			if !strings.Contains(recip, "<") {
				recip = "<" + recip + ">"
			}
			writeLine(conn, fmt.Sprintf("250 2.1.5 Recipient %s ok", recip))

		case "DATA":
			// Log Email data
			sess.commands = append(sess.commands, line)
			if state != "RCPT_RECEIVED" {
				writeLine(conn, "503 5.5.1 Error: need RCPT command")
				break
			}
			writeLine(conn, "354 End data with <CR><LF>.<CR><LF>")
			body, err := readSmtpData(reader)
			if err != nil {
				sess.disconnectReason = "data_read_error"
				log.Printf("[SMTP] Data read error: %v", err)
				return
			}
			// Capture raw data and parse headers/body
			sess.rawData = body
			headers, msgBody := parseEmailContent(body)
			sess.allHeaders = headers
			sess.messageBody = msgBody
			sess.subject = headers["Subject"]
			sess.dateHeader = headers["Date"]
			log.Printf("[SMTP] Message from %s | MAIL=%s | RCPT=%v\nBody:\n%s\n---END---",
				clientAddr, mailFrom, rcptTo, body)
			// Generate random queue ID
			queueID := strings.ToUpper(strings.ReplaceAll(time.Now().Format("20060102150405"), "", "")) + "A1B2C"
			writeLine(conn, "250 2.0.0 Ok: queued as "+queueID)
			// Reset for next message
			mailFrom = ""
			rcptTo = nil
			state = "HELO_RECEIVED"

		case "STARTTLS":
			sess.commands = append(sess.commands, line)
			// Mark that client initiated a TLS upgrade attempt
			sess.tlsTested = true
			if tlsActive {
				writeLine(conn, "503 5.5.1 Error: TLS already active")
				break
			}
			if tlsConfig == nil || len(tlsConfig.Certificates) == 0 {
				writeLine(conn, "454 4.7.0 TLS not available")
				break
			}
			writeLine(conn, "220 2.0.0 Ready to start TLS")
			// Upgrade connection to TLS encryption
			tlsConn := tls.Server(conn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				errStr := err.Error()
				if strings.Contains(errStr, "client offered only unsupported versions") || strings.Contains(errStr, "unsupported versions") {
					sess.disconnectReason = "tls_unsupported_client_versions"
					log.Printf("[SMTP] TLS handshake failed (unsupported client versions) from %s: %v", clientAddr, err)
				} else {
					sess.disconnectReason = "tls_handshake_error"
					log.Printf("[SMTP] TLS handshake failed from %s: %v", clientAddr, err)
				}
				return
			}
			conn = tlsConn
			reader = bufio.NewReader(conn)
			tlsActive = true
			sess.tlsUsed = true
			// Capture TLS version and cipher suite
			tlsState := tlsConn.ConnectionState()
			sess.tlsVersion = tlsVersionString(tlsState.Version)
			sess.tlsCipherSuite = tls.CipherSuiteName(tlsState.CipherSuite)
			log.Printf("[SMTP] TLS established from %s", clientAddr)
			// After STARTTLS, client must re-send EHLO/HELO
			state = "INIT"

		case "AUTH":
			// Handle simple LOGIN AUTH (Username/Password)
			sess.commands = append(sess.commands, line)
			if state == "INIT" {
				writeLine(conn, "503 5.5.1 Error: need HELO or EHLO first")
				break
			}
			if !strings.HasPrefix(strings.ToUpper(arg), "LOGIN") {
				writeLine(conn, "504 5.5.4 Unsupported AUTH mechanism")
				break
			}
			sess.authMechanism = "LOGIN"
			// Prompt for username
			writeLine(conn, "334 VXNlcm5hbWU6") // "Username:" in b64

			// Read username
			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			userBytes, err := reader.ReadBytes('\n')
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					sess.disconnectReason = "auth_username_timeout"
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				sess.disconnectReason = "auth_read_error"
				writeLine(conn, "501 5.5.2 Invalid syntax")
				break
			}
			conn.SetReadDeadline(time.Time{})
			conn.SetDeadline(time.Now().Add(2 * time.Minute))

			userEncoded := strings.TrimSpace(string(userBytes))
			userDecoded, err := base64.StdEncoding.DecodeString(userEncoded)
			if err != nil {
				writeLine(conn, "501 5.5.2 Invalid base64")
				break
			}
			authUser = string(userDecoded)
			sess.authUser = authUser

			// Password prompt
			writeLine(conn, "334 UGFzc3dvcmQ6") // "Password:" in b64

			// Read password
			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			passBytes, err := reader.ReadBytes('\n')
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					sess.disconnectReason = "auth_password_timeout"
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				sess.disconnectReason = "auth_read_error"
				writeLine(conn, "501 5.5.2 Invalid syntax")
				break
			}
			conn.SetReadDeadline(time.Time{})
			conn.SetDeadline(time.Now().Add(2 * time.Minute))

			passEncoded := strings.TrimSpace(string(passBytes))
			passDecoded, err := base64.StdEncoding.DecodeString(passEncoded)
			if err != nil {
				writeLine(conn, "501 5.5.2 Invalid base64")
				break
			}
			authPass := string(passDecoded)
			sess.authPass = authPass

			log.Printf("[SMTP] AUTH LOGIN from %s | username=%s password=%s", clientAddr, authUser, authPass)

			writeLine(conn, "235 2.7.0 Authentication successful")

		case "QUIT":
			// Handles graceful quitting
			sess.commands = append(sess.commands, line)
			sess.disconnectReason = "quit_command"
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			conn.Write([]byte("221 2.0.0 Bye\r\n"))
			conn.Close()
			return

		case "NOOP":
			sess.commands = append(sess.commands, line)
			writeLine(conn, "250 OK")

		case "RSET":
			// Resets SMTP state machine
			sess.commands = append(sess.commands, line)
			if state == "INIT" {
				writeLine(conn, "503 5.5.1 Error: need HELO or EHLO first")
				break
			}
			mailFrom = ""
			rcptTo = nil
			state = "HELO_RECEIVED"
			writeLine(conn, "250 2.0.0 Ok")

		case "HELP":
			sess.commands = append(sess.commands, line)
			writeLine(conn, "214-HELO EHLO MAIL RCPT DATA RSET NOOP QUIT")
			writeLine(conn, "214 STARTTLS AUTH PLAIN LOGIN")

		default:
			// Default fallback
			sess.commands = append(sess.commands, line)
			writeLine(conn, "502 5.5.2 Error: command not recognized")
		}
	}
}

type SmtpSession struct {
	start          time.Time
	clientIP       string
	clientPort     int
	clientHostname string
	tlsUsed        bool
	tlsTested      bool
	tlsVersion     string
	tlsCipherSuite string
	duration       time.Duration

	sender      string
	recipients  []string
	rawData     string
	subject     string
	dateHeader  string
	messageBody string
	allHeaders  map[string]string

	authUser      string
	authPass      string
	authMechanism string

	commands []string

	disconnectReason string
}

// readSmtpData parses DATA bodies
func readSmtpData(reader *bufio.Reader) (string, error) {
	var lines []string
	for {
		lineBytes, err := reader.ReadBytes('\n')
		if err != nil {
			return "", err
		}
		line := strings.TrimSpace(string(lineBytes))
		if line == "." {
			break
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n"), nil
}

// parseEmailContent splits SMTP DATA content into headers and body.
func parseEmailContent(data string) (map[string]string, string) {
	headers := make(map[string]string)
	lines := strings.Split(data, "\n")

	// Collect header lines until blank line
	var headerLines []string
	i := 0
	for ; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) == "" {
			i++
			break
		}
		headerLines = append(headerLines, l)
	}

	// Merge folded headers
	var merged []string
	for _, hl := range headerLines {
		if strings.HasPrefix(hl, " ") || strings.HasPrefix(hl, "\t") {
			if len(merged) > 0 {
				merged[len(merged)-1] = merged[len(merged)-1] + " " + strings.TrimSpace(hl)
			}
			continue
		}
		merged = append(merged, hl)
	}

	for _, h := range merged {
		if idx := strings.Index(h, ":"); idx > -1 {
			key := strings.TrimSpace(h[:idx])
			val := strings.TrimSpace(h[idx+1:])
			headers[key] = val
		}
	}

	body := strings.Join(lines[i:], "\n")
	return headers, body
}

// writeLine writes a line to a connection
func writeLine(conn net.Conn, s string) {
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte(s + "\r\n"))
}

// tlsVersionString converts TLS version constant to human readable string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}
