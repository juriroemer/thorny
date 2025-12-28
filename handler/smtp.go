package handler

import (
	"bufio"
	"log"
	"log/slog"
	"net"
	"strings"
	"time"

	"go.yaml.in/yaml/v4"
)

type SmtpHandlerConfig struct {
}

type SmtpHandlerPlugin struct {
}

func (SmtpHandlerPlugin) Name() string {
	return "smtp_handler"
}

func (SmtpHandlerPlugin) Protocol() string {
	return "smtp"
}

type SmtpHandlerInstance struct {
	cfg      SmtpHandlerConfig // TODO remove cfg if not necessary
	listener net.Listener
	logger   *slog.Logger
}

func (SmtpHandlerPlugin) New(config HandlerConfig, listener net.Listener, logger *slog.Logger) (HandlerInstance, error) {
	cfg, err := SmtpHandlerPlugin{}.parseConfig(config)
	if err != nil {
		return nil, err
	}
	return &SmtpHandlerInstance{
		cfg:      *cfg,
		listener: listener,
		logger: logger.With(
			slog.String("protocol", "smtp"),
		),
	}, nil
}

func (SmtpHandlerPlugin) parseConfig(config HandlerConfig) (*SmtpHandlerConfig, error) {
	return &SmtpHandlerConfig{}, nil

	var cfg SmtpHandlerConfig
	b, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (hh *SmtpHandlerInstance) Serve() {
	//http.HandleFunc("/", serveHTTP)
	// go log.Fatal(http.ListenAndServe(":8080", nil))

	log.Printf("Starting fake SMTP server on %s\n", hh.listener.Addr().String())
	for {
		conn, err := hh.listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleSMTP(conn)
	}
}

func handleSMTP(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[SMTP] Connection from %s", clientAddr)

	// SMTP banner
	writeLine(conn, "220 example.com ESMTP FakeServer")

	reader := bufio.NewScanner(conn)
	state := "INIT"
	var mailFrom string
	var rcptTo []string

	for reader.Scan() {
		line := reader.Text()
		log.Printf("[SMTP] %s >> %s", clientAddr, line)

		cmd := strings.ToUpper(line)
		arg := ""
		if i := strings.Index(cmd, " "); i > -1 {
			arg = strings.TrimSpace(line[i+1:])
			cmd = cmd[:i]
		}

		switch cmd { // TODO make this check "startswith"
		case "EHLO", "HELO":
			// TODO log fqdn
			writeLine(conn, "250-example.com greets you") // TODO make this config option
			writeLine(conn, "250-SIZE 35882577")
			writeLine(conn, "250-8BITMIME")
			writeLine(conn, "250-ENHANCEDSTATUSCODES")
			writeLine(conn, "250 STARTTLS") // appear legit // TODO ?

		case "MAIL":
			// TODO log Sender
			mailFrom = arg
			writeLine(conn, "250 OK")

		case "RCPT":
			// TODO log RCPT
			rcptTo = append(rcptTo, arg)
			writeLine(conn, "250 OK")

		case "DATA":
			// TODO log mail contents?
			writeLine(conn, "354 End data with <CR><LF>.<CR><LF>")
			state = "DATA"
			body, err := readSmtpData(reader)
			if err != nil {
				log.Printf("[SMTP] Data read error: %v", err)
				return
			}
			log.Printf("[SMTP] Message from %s | MAIL=%s | RCPT=%v\nBody:\n%s\n---END---",
				clientAddr, mailFrom, rcptTo, body)
			writeLine(conn, "250 OK queued as 12345")
			state = "INIT"

		case "QUIT":
			writeLine(conn, "221 Bye")
			return

		case "NOOP":
			writeLine(conn, "250 OK")

		case "RSET":
			mailFrom = ""
			rcptTo = nil
			state = "INIT"
			writeLine(conn, "250 OK")

		default:
			if state == "DATA" {
				// should never reach here (handled in readSMTPData)
				continue
			}
			// Default fallback for unexpected commands
			writeLine(conn, "502 Command not implemented")
		}
	}

	if err := reader.Err(); err != nil {
		log.Printf("[SMTP] Connection error from %s: %v", clientAddr, err)
	}
}

type SmtpSession struct {
	FQDN string // fully qualified domain name

	tlsActive bool
	logger    *slog.Logger
	start     time.Time
	client_ip string
	port      int
	tlsUsed   bool
	duration  time.Duration
	numMessages int

	// nur sinnvoll, wenn nicht nach bestimmter anzahl an messages geclosed wird:
	// commands []string
	// state     string // bis wohin geht client?

	// Close IF kompletter Mailversand durchgespielt?
}

func readSmtpData(scanner *bufio.Scanner) (string, error) {
	var lines []string
	for scanner.Scan() {
		l := scanner.Text()
		if l == "." {
			break
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n"), scanner.Err()
}

func writeLine(conn net.Conn, s string) {
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte(s + "\r\n"))
}
