package handler

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	// NOTE used go-asn1-ber/asn1-ber because go-ldap/ldap/v3 uses it.
	// 			standard lib "asn1" might be better, offers Marshaling

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/juriroemer/thorny/lib"
)

// StartTLS error type
var errStartTLS = errors.New("starttls negotiated")

// LDAP config struct
type LdapHandlerConfig struct {
}

// Validate validates the handler config
func (c *LdapHandlerConfig) Validate() error {
	return nil
}

// LDAP handler struct
type LdapHandlerPlugin struct {
}

// Name returns the handlers name
func (LdapHandlerPlugin) Name() string {
	return "ldap_handler"
}

// Name returns the name of the protocol the handlers implements
func (LdapHandlerPlugin) Protocol() string {
	return "ldap"
}

// The LDAP handler instance struct
type LdapHandlerInstance struct {
	name     string
	cfg      LdapHandlerConfig
	listener net.Listener
	logger   *slog.Logger
}

// Name returns the handler name, wraps LdapHandlerPlugin.Name()
func (l *LdapHandlerInstance) Name() string { return l.name }

// New creates a new handler plugin instance
func (LdapHandlerPlugin) New(config HandlerConfig, listener net.Listener, logger *slog.Logger) (HandlerInstance, error) {
	instance := LdapHandlerInstance{
		name:     LdapHandlerPlugin{}.Name(),
		listener: listener,
		logger: logger.With(
			slog.String("protocol", "ldap"),
		),
	}
	fmt.Println("[LDAP] New instance")

	if err := instance.loadLdapConfig(config); err != nil {
		fmt.Println("[LDAP] Config error")
		return nil, err
	}

	return &instance, nil
}

// loadLdapConfig loads the LDAP config (currently empty)
func (lh *LdapHandlerInstance) loadLdapConfig(raw HandlerConfig) error {
	cfg := LdapHandlerConfig{}
	lh.cfg = cfg

	return nil
}

// Serves handles incoming connections
func (lh *LdapHandlerInstance) Serve(ctx context.Context, wg *sync.WaitGroup) {
	var tlsConfig *tls.Config
	if v := ctx.Value(lib.CtxTlsUserConfig); v != nil {
		if tconf, ok := v.(*lib.TlsUserConfig); ok {
			cert, err := tls.LoadX509KeyPair(tconf.CertPath, tconf.KeyPath)
			if err != nil {
				log.Printf("[LDAP] Failed to load TLS certificate from %s / %s: %v", tconf.CertPath, tconf.KeyPath, err)
			} else {
				tlsConfig = &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS10,
					MaxVersion:   tls.VersionTLS11,
				}
			}
		}
	}

	fmt.Println("[LDAP] TLS loaded")

	acceptChan := make(chan net.Conn, 1)
	var acceptWg sync.WaitGroup // local WaitGroup for internal goroutines

	acceptWg.Add(1)

	// accept connections
	go func() {
		defer acceptWg.Done()
		for {
			conn, err := lh.listener.Accept()
			if err != nil {
				log.Println("[LDAP] Listener Goroutine ended")
				return
			}
			acceptChan <- conn
		}
	}()

	// Monitor context cancellation
	defer func() {
		lh.listener.Close()
		acceptWg.Wait() // wait for accept goroutine to exit
		wg.Done()       // then signal parent that Serve is done
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("[LDAP] No longer serving")
			return // triggers defer and also ends go routine above
		case conn := <-acceptChan:
			go lh.handleConn(ctx, conn, tlsConfig)
		}
	}
}

// handleConn handles a individual LDAP connections
func (lh *LdapHandlerInstance) handleConn(ctx context.Context, rawConn net.Conn, tlsConfig *tls.Config) {

	// Parse client IP and port
	clientAddr := rawConn.RemoteAddr().String()
	clientIP, clientPortStr, _ := net.SplitHostPort(clientAddr)
	clientPort := 0
	if p, err := strconv.Atoi(clientPortStr); err == nil {
		clientPort = p
	}

	// Creates session logger
	connLogger := lh.logger.With(
		slog.String("client_ip", clientIP),
		slog.Int("client_port", clientPort),
	)

	// Initialize session struct for logging/metadata
	sess := NewLdapSession(connLogger, rawConn)

	defer func() {
		sess.Close()
		rawConn.Close()
	}()

	idleTimeout := 2 * time.Minute

	// Connection loop
	for {
		select {
		case <-ctx.Done():
			sess.disconnectReason = "context_cancelled"
			return
		default:
			// Set read deadline for idle timeout
			rawConn.SetReadDeadline(time.Now().Add(idleTimeout))

			// Read packets, handle disconnects
			packet, err := ber.ReadPacket(sess.conn)

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Check if it's shutdown or idle timeout
					select {
					case <-ctx.Done():
						sess.disconnectReason = "context_cancelled"
						slog.Info("[LDAP] connection shutdown during idle")
						return
					default:
						sess.disconnectReason = "idle_timeout"
						slog.Info("L[LDAP]t")
						return
					}
				}
				// Connection closed / read error
				sess.disconnectReason = "client_disconnect"
				slog.Info("[LDAP] client disconnected")
				return
			}

			sess.numMessages += 1

			// Handle malformated packets
			if len(packet.Children) < 2 {
				continue
			}

			// Get message type
			msgId := packet.Children[0].Value.(int64)
			op := packet.Children[1]

			err = sess.dispatch(msgId, op, tlsConfig)
			if err == errStartTLS {
				continue
			}
			if err == io.EOF {
				sess.disconnectReason = "unbind_requested"
				return
			}
			if err != nil {
				sess.disconnectReason = "dispatch_error"
				return
			}
		}
	}
}

// LdapSession holds the log for a single session
type LdapSession struct {
	conn             net.Conn
	tlsActive        bool
	logger           *slog.Logger
	start            time.Time
	port             int
	tlsUsed          bool
	tlsVersion       string
	tlsCipherSuite   string
	tlsServerName    string
	authAttempted    bool
	loginDN          string
	password         string
	searchAttempted  bool
	duration         time.Duration
	numMessages      int
	bindAttempts     int
	disconnectReason string
}

// NewLdapSession constructs an LdapSession
func NewLdapSession(l *slog.Logger, rawConn net.Conn) LdapSession {
	return LdapSession{
		conn:            rawConn,
		tlsActive:       false,
		logger:          l,
		start:           time.Now(),
		tlsUsed:         false,
		bindAttempts:    0,
		authAttempted:   false,
		loginDN:         "",
		password:        "",
		searchAttempted: false,
		numMessages:     1,
	}
}

// Close runs when a LDAP session finishes, writes the log line to the log file
func (s *LdapSession) Close() {
	s.logger.Info("ldap_session_end",
		slog.Int64("ts", s.start.Unix()),
		slog.Bool("tls", s.tlsUsed),
		slog.String("tls_version", s.tlsVersion),
		slog.String("tls_cipher", s.tlsCipherSuite),
		slog.String("tls_sni", s.tlsServerName),
		slog.Int("bind_attempts", s.bindAttempts),
		slog.Bool("auth_attempted", s.authAttempted),
		slog.String("login_dn", s.loginDN),
		slog.String("password", s.password),
		slog.Bool("search_attempted", s.searchAttempted),
		slog.String("disconnect_reason", s.disconnectReason),
		slog.Int64("duration_ms", time.Since(s.start).Milliseconds()),
		slog.Int("num_messages", s.numMessages),
	)
}

// dispatch identifies LDAP message types and handles them if they are implemented
func (s *LdapSession) dispatch(msgId int64, op *ber.Packet, tlsConfig *tls.Config) error {
	switch op.Tag {
	// BindRequest [APPLICATION 0]
	// https://ldapwiki.com/wiki/Wiki.jsp?page=Bind%20Request
	case ber.Tag(ldap.ApplicationBindRequest):
		s.bindAttempts += 1
		s.handleBind(msgId, op)

		// UnbindRequest [APPLICATION 2]
		// https://ldapwiki.com/wiki/Wiki.jsp?page=Unbind%20Request
	case ber.Tag(ldap.ApplicationUnbindRequest):
		s.disconnectReason = "unbind_requested"
		slog.Info("\nLDAP unbind requested")
		return io.EOF

		// SearchRequest [APPLICATION 3]
		// https://ldapwiki.com/wiki/Wiki.jsp?page=SearchRequest
	case ber.Tag(ldap.ApplicationSearchRequest):
		s.searchAttempted = true
		s.handleSearch(msgId, op)

		// ExtendedRequest [APPLICATION 23]
		// https://ldapwiki.com/wiki/Wiki.jsp?page=Extended%20Request
	case ber.Tag(ldap.ApplicationExtendedRequest):
		return s.handleExtendedRequest(msgId, op, tlsConfig)

		// Send operationsError response
	default:
		s.sendOperationsError(msgId)
	}

	return nil
}

// Sends OperationsError for LDAP Messages that are not implemented.
func (s *LdapSession) sendOperationsError(msgId int64) {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgId, "messageID"))

	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(5), nil, "SearchResultDone")

	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldap.LDAPResultOperationsError, "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "error", "diagnosticMessage"))

	msg.AppendChild(resp)
	s.conn.Write(msg.Bytes())
}

// handleBind handles Bind requests
func (s *LdapSession) handleBind(msgId int64, op *ber.Packet) {
	// Send LDAPResultOperationsError = 1 response if not enough arguments
	if len(op.Children) < 3 {
		s.sendBindResponse(msgId, ldap.LDAPResultOperationsError)
		return
	}

	version := op.Children[0].Value.(int64)
	dn := op.Children[1].Value.(string)

	var password string

	auth := op.Children[2]
	fmt.Println(auth.Data.String())

	// if AuthenticationChoice == simple auth
	if auth.Tag == ber.Tag(0) {
		password = auth.Data.String()
		s.loginDN = dn
		s.password = password
		s.authAttempted = true
	}

	fmt.Printf("[LDAP] BIND version=%d dn=%q password=%q\n", version, dn, password)

	// Send ResultSuccess, accept everything
	s.sendBindResponse(msgId, ldap.LDAPResultSuccess)
}

// sendBindResponse sends the response for a bind request
func (s *LdapSession) sendBindResponse(msgId int64, resultCode int64) {
	resp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, "nil", "LDAPMessage")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgId, "messageID"))

	bindResp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "BindResponse")
	bindResp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, resultCode, "resultCode"))
	bindResp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	bindResp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))

	resp.AppendChild(bindResp)
	s.conn.Write(resp.Bytes())
}

// handleSearch handles search requests
func (s *LdapSession) handleSearch(msgId int64, op *ber.Packet) {
	fmt.Println("SEARCH")
	// Send LDAPResultOperationsError = 1 response if not enough arguments
	if len(op.Children) < 7 {
		s.sendSearchDone(msgId, ldap.LDAPResultOperationsError)
		return
	}

	baseDn := op.Children[0].Value.(string)
	scope := op.Children[1].Value.(int64)
	filter := op.Children[6].Data

	fmt.Printf("[LDAP] SEARCH base=%q scope=%d filter=%v\n", baseDn, scope, filter)
	// If this is a RootDSE query (base="", scope=base object), return RootDSE
	if baseDn == "" && scope == 0 {
		s.sendRootDSE(msgId)
		s.sendSearchDone(msgId, ldap.LDAPResultSuccess)
		return
	}

	s.sendSearchEntry(msgId)
	s.sendSearchDone(msgId, ldap.LDAPResultSuccess)
}

// sendSearchEntry sends a hardcoded Search Entry Response
func (s *LdapSession) sendSearchEntry(msgId int64) {
	// TODO make this a config option?
	fakeSearchEntry := "uid=admin,dc=example,dc=com"

	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgId, "messageID"))

	// Search result
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "SearchResultEntry")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		fakeSearchEntry, "objectName"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")

	attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
	attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "type"))

	values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
	values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "admin", "value"))

	attr.AppendChild(values)
	attrs.AppendChild(attr)

	entry.AppendChild(attrs)
	msg.AppendChild(entry)

	s.conn.Write(msg.Bytes())
}

// sendRootDSE returns a minimal, plausible RootDSE so nmap can fingerprint
// the server as OpenLDAP. This is not exhaustive, just enough for -sV and
// ldap-rootdse to report a recognizable vendor/version.
func (s *LdapSession) sendRootDSE(msgId int64) {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgId, "messageID"))

	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "SearchResultEntry")
	// RootDSE has empty DN
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "objectName"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")

	// helper to append attribute with one or more values
	addAttr := func(name string, values ...string) {
		attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
		for _, v := range values {
			vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
		}
		attr.AppendChild(vals)
		attrs.AppendChild(attr)
	}

	// Typical values seen on OpenLDAP
	// if anyone wants to use this in the future, it should be moved to the LDAP config
	// so that it can be set in the yaml file
	addAttr("namingContexts", "dc=example,dc=com")
	addAttr("supportedLDAPVersion", "3")
	addAttr("supportedSASLMechanisms", "PLAIN", "LOGIN", "ANONYMOUS")
	addAttr("supportedExtension", "1.3.6.1.4.1.1466.20037") // StartTLS OID
	addAttr("vendorName", "OpenLDAP")
	addAttr("vendorVersion", "2.5.13")

	entry.AppendChild(attrs)
	msg.AppendChild(entry)

	s.conn.Write(msg.Bytes())
}

// sendSearchDone sends a search done message, to indicate to the client that there will be no more search results
func (s *LdapSession) sendSearchDone(msgID int64, resultCode int64) {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "messageID"))

	done := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultDone, nil, "SearchResultDone")
	done.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, resultCode, "resultCode"))
	done.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	done.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))

	msg.AppendChild(done)
	s.conn.Write(msg.Bytes())
}

// handleExtendedRequest handles extension requests, in this case STARTTLS
// upgrades the connection to TLS encryption
func (s *LdapSession) handleExtendedRequest(msgId int64, op *ber.Packet, tlsConfig *tls.Config) error {
	// Send LDAPResultOperationsError = 1 response if no Request OID is given
	if len(op.Children) == 0 {
		s.sendExtendedResponse(msgId, ldap.LDAPResultOperationsError, "")
		return nil
	}

	oid := op.Children[0].Data.String()
	fmt.Println(oid)

	// Sends error if extended request was not STARTTLS
	if oid != "1.3.6.1.4.1.1466.20037" {
		s.sendExtendedResponse(msgId, ldap.LDAPResultProtocolError, "")
		return nil
	}

	slog.Info("LDAP StartTLS requested")
	s.tlsUsed = true

	if s.tlsActive {
		s.sendExtendedResponse(msgId, ldap.LDAPResultOperationsError, "")
		return nil
	}

	// Send success response
	s.sendExtendedResponse(msgId, ldap.LDAPResultSuccess, "")

	// Upgrade connection to TLS
	tlsConn := tls.Server(s.conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		slog.Error("TLS handshake failed: ", "err", err)
		return nil
	}

	s.conn = tlsConn
	s.tlsActive = true
	// Capture TLS parameters
	tlsState := tlsConn.ConnectionState()
	s.tlsVersion = tlsVersionString(tlsState.Version)
	s.tlsCipherSuite = tls.CipherSuiteName(tlsState.CipherSuite)
	s.tlsServerName = tlsState.ServerName
	s.tlsUsed = true

	return errStartTLS
}

// sendExtendedResponse sends a response to an extension request
func (s *LdapSession) sendExtendedResponse(msgId int64, resultCode int64, oid string) {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgId, "messageID"))

	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedResponse, nil, "ExtendedResponse")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, resultCode, "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))

	if oid != "" {
		resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, oid, "responseName"))
	}

	msg.AppendChild(resp)
	s.conn.Write(msg.Bytes())
}
