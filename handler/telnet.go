package handler

import (
	"bufio"
	"context"
	"log"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"go.yaml.in/yaml/v4"
)

type TelnetHandlerConfig struct {
	MessageLimit int `yaml:"message_limit"`
}

func (c *TelnetHandlerConfig) Validate() error {
	if c.MessageLimit <= 0 {
		c.MessageLimit = 10 // default to 10 messages if not specified
	}
	return nil
}

type TelnetHandlerPlugin struct {
}

func (TelnetHandlerPlugin) Name() string {
	return "telnet_handler"
}

func (TelnetHandlerPlugin) Protocol() string {
	return "telnet"
}

type TelnetHandlerInstance struct {
	name     string
	cfg      TelnetHandlerConfig
	listener net.Listener
	logger   *slog.Logger
}

func (t *TelnetHandlerInstance) Name() string { return t.name }

func (TelnetHandlerPlugin) New(config HandlerConfig, listener net.Listener, logger *slog.Logger) (HandlerInstance, error) {
	instance := TelnetHandlerInstance{
		name:     TelnetHandlerPlugin{}.Name(),
		listener: listener,
		logger: logger.With(
			slog.String("protocol", "telnet"),
		),
	}

	if err := instance.loadTelnetConfig(config); err != nil {
		return nil, err
	}

	return &instance, nil
}

func (th *TelnetHandlerInstance) loadTelnetConfig(raw HandlerConfig) error {
	cfg := &TelnetHandlerConfig{}
	valuesRaw := raw["values"]
	valuesYaml, _ := yaml.Marshal(valuesRaw)

	if err := yaml.Unmarshal(valuesYaml, cfg); err != nil {
		return err
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	th.cfg = *cfg

	return nil
}

func (th *TelnetHandlerInstance) Serve(ctx context.Context, wg *sync.WaitGroup) {
	acceptChan := make(chan net.Conn, 1)
	var acceptWg sync.WaitGroup

	acceptWg.Add(1)
	go func() {
		defer acceptWg.Done()
		for {
			conn, err := th.listener.Accept()
			if err != nil {
				log.Println("[TELNET] ERROR/ENDING LISTENER GOROUTINE")
				return
			}
			acceptChan <- conn
		}
	}()

	defer func() {
		th.listener.Close()
		acceptWg.Wait()
		wg.Done()
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("[TELNET] ENDING SERVE")
			return
		case conn := <-acceptChan:
			go th.handleConn(ctx, conn)
		}
	}
}

// handleConn accepts a telnet connection, reads and logs messages,
// and disconnects after message limit or idle timeout.
func (th *TelnetHandlerInstance) handleConn(ctx context.Context, nConn net.Conn) {
	defer nConn.Close()

	// Parse client IP and port
	clientAddr := nConn.RemoteAddr().String()
	clientIP, clientPortStr, _ := net.SplitHostPort(clientAddr)
	clientPort := 0
	if p, err := strconv.Atoi(clientPortStr); err == nil {
		clientPort = p
	}

	// Initialize session for logging
	sess := &TelnetSession{
		start:      time.Now(),
		clientIP:   clientIP,
		clientPort: clientPort,
		logger:     th.logger,
		messages:   make([]string, 0),
	}

	// Defer structured logging of session when connection ends
	defer func() {
		sess.duration = time.Since(sess.start)
		sess.logger.Info("telnet_session_end",
			slog.Int64("ts", sess.start.Unix()),
			slog.String("client_ip", sess.clientIP),
			slog.Int("client_port", sess.clientPort),
			slog.Int("messages_count", sess.messageCount),
			slog.Any("messages", sess.messages),
			slog.String("username", sess.loginUsername),
			slog.String("password", sess.loginPassword),
			slog.String("disconnect_reason", sess.disconnectReason),
			slog.Duration("duration", sess.duration),
		)
	}()

	// Send a familiar login banner and prompt
	banner := "Debian GNU/Linux 11 \n\n"
	nConn.Write([]byte(banner))
	nConn.Write([]byte("srv01 login: "))

	// Set up idle timeout
	idleTimeout := 2 * time.Minute
	nConn.SetReadDeadline(time.Now().Add(idleTimeout))

	// Read messages from client with simple login/password prompt first
	scanner := bufio.NewScanner(nConn)
	state := "await_username"
	for {
		select {
		case <-ctx.Done():
			sess.disconnectReason = "context_cancelled"
			log.Println("[TELNET] Connection shutdown via context")
			return
		default:
			// Update read deadline before each read to handle idle timeout
			nConn.SetReadDeadline(time.Now().Add(idleTimeout))

			if scanner.Scan() {
				line := scanner.Text()

				switch state {
				case "await_username":
					// Capture username and prompt for password next
					sess.messageCount++
					sess.messages = append(sess.messages, line)
					sess.loginUsername = line
					nConn.Write([]byte("Password: "))
					state = "await_password"
					continue
				case "await_password":
					// Capture password, accept login, show prompt, and wait for first command
					sess.messageCount++
					sess.messages = append(sess.messages, line)
					sess.loginPassword = line
					nConn.Write([]byte("\r\nWelcome to Debian GNU/Linux 11\r\n"))
					nConn.Write([]byte("srv01:~$ "))
					state = "await_cmd"
					continue
				case "await_cmd":
					// Count and log post-login commands only
					sess.messageCount++
					sess.messages = append(sess.messages, line)

					// Handle exit command
					if line == "exit" || line == "logout" {
						sess.disconnectReason = "exit_command"
						nConn.Write([]byte("logout\r\n"))
						return
					}

					// Minimal shell-like response
					nConn.Write([]byte("bash: command not found\r\n"))
					nConn.Write([]byte("srv01:~$ "))
				default:
					// Generic echo for any unexpected state
					nConn.Write([]byte(line))
				}

				// Check if message limit reached
				if sess.messageCount >= th.cfg.MessageLimit {
					sess.disconnectReason = "message_limit_reached"
					log.Printf("[TELNET] %s reached message limit (%d)", sess.clientIP, th.cfg.MessageLimit)
					return
				}
			} else {
				// Scanner failed or connection closed
				if scanner.Err() != nil {
					netErr := scanner.Err()
					if netErr, ok := netErr.(net.Error); ok && netErr.Timeout() {
						sess.disconnectReason = "idle_timeout"
						log.Printf("[TELNET] %s idle timeout", sess.clientIP)
					} else {
						// RST / broken pipe disconnect by client
						sess.disconnectReason = "read_error"
						log.Printf("[TELNET] %s read error: %v", sess.clientIP, scanner.Err())
					}
				} else {
					// EOF disconnect by client
					sess.disconnectReason = "client_disconnect"
					log.Printf("[TELNET] %s disconnected", sess.clientIP)
				}
				return
			}
		}
	}
}

type TelnetSession struct {
	start            time.Time
	duration         time.Duration
	clientIP         string
	clientPort       int
	logger           *slog.Logger
	messageCount     int
	messages         []string
	disconnectReason string
	// Login capture
	loginUsername string
	loginPassword string
}
