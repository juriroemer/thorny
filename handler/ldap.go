package handler

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"time"

	// NOTE used go-asn1-ber/asn1-ber because go-ldap/ldap/v3 uses it. standard lib "asn1" might be better, offers Marshaling?
	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

type LdapHandlerConfig struct {
}

func (c *LdapHandlerConfig) Validate() error {
	return nil
}

type LdapHandlerPlugin struct {
}

func (LdapHandlerPlugin) Name() string {
	return "ldap_handler"
}

func (LdapHandlerPlugin) Protocol() string {
	return "ldap"
}

type LdapHandlerInstance struct {
	cfg      LdapHandlerConfig
	listener net.Listener
	logger   *slog.Logger
}

func (LdapHandlerPlugin) New(config HandlerConfig, listener net.Listener, logger *slog.Logger) (HandlerInstance, error) {
	instance := LdapHandlerInstance{
		listener: listener,
		logger: logger.With(
			slog.String("protocol", "ldap"),
		),
	}
	fmt.Println("NEW LDAP INSTANCE")

	if err := instance.loadLdapConfig(config); err != nil {
		fmt.Println("LDAP CONFIG ERROR")
		return nil, err
	}

	return &instance, nil
}

// TODO add search response from config
func (lh *LdapHandlerInstance) loadLdapConfig(raw HandlerConfig) error {
	cfg := LdapHandlerConfig{}
	lh.cfg = cfg

	return nil
}

func (lh *LdapHandlerInstance) Serve() {
	// Accept connections in a loop and handle each concurrently.
	fmt.Println("SERVE")
	cert, err := tls.LoadX509KeyPair("./cert/cert.pem", "./cert/key.pem")
	if err != nil {
		fmt.Println("SERVE panic")
		panic(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	fmt.Println("TLS LOADED")

	for {
		nConn, err := lh.listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection: %v", err)
		}
		fmt.Println("accepting ldap")
		go lh.handleConn(nConn, tlsConfig)
	}
}

func (lh *LdapHandlerInstance) handleConn(rawConn net.Conn, tlsConfig *tls.Config) {
	fmt.Println("HANDLECON")

	connLogger := lh.logger.With("client_ip", rawConn.RemoteAddr().String())
	sess := NewLdapSession(connLogger, rawConn)

	defer func() {
		sess.Close()
		rawConn.Close()
	}()

	for {
		packet, err := ber.ReadPacket(sess.conn)
		fmt.Printf("new Message with id %d ", sess.numMessages)
		sess.numMessages += 1

		if err != nil {
			slog.Info("LDAP client disconnected")
			return
		}

		// TODO
		if len(packet.Children) < 2 {
			fmt.Println("SHORT PACKAGE")
			continue
		}

		msgId := packet.Children[0].Value.(int64)
		op := packet.Children[1]

		err = sess.dispatch(msgId, op, tlsConfig)
		if err == errStartTLS {
			continue
		}
		if err != nil {
			return
		}
	}
}

type LdapSession struct {
	conn            net.Conn
	tlsActive       bool
	logger          *slog.Logger
	start           time.Time
	port            int
	tlsUsed         bool
	authAttempted   bool
	passwordLen     int
	searchAttempted bool
	duration        time.Duration
	numMessages     int // ohne serverseitiges closing
	bindAttempts    int // ohne serverseitiges closing

	// close if
	// authAttempted && searchAttempted
	// OR
	// authAttempted ?
}

func NewLdapSession(l *slog.Logger, rawConn net.Conn) LdapSession {
	return LdapSession{
		conn:            rawConn,
		tlsActive:       false,
		logger:          l,
		start:           time.Now(),
		tlsUsed:         false,
		bindAttempts:    0,
		authAttempted:   false,
		passwordLen:     0,
		searchAttempted: false,
		numMessages:     1,
	}
}

func (s *LdapSession) Close() {
	s.logger.Info("",
		slog.String("start", s.start.String()),
		slog.Bool("tls", s.tlsUsed),
		slog.Int("bind_attempts", s.bindAttempts),
		slog.Bool("auth_attempted", s.authAttempted),
		slog.Int("pass_len", s.passwordLen),
		slog.Bool("search_attempted", s.searchAttempted),
		slog.Int64("duration_ms", time.Since(s.start).Milliseconds()),
		slog.Int("num_messages", s.numMessages),
	)
}

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

var errStartTLS = errors.New("starttls negotiated")

// Sends OperationsError for Messages that are not implemented.
// OPTION match not implemented Messages to their errors and send the correct error. this one uses SearchResultDone
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
		s.passwordLen = len(password)
		s.authAttempted = true
	}

	// TODO
	fmt.Printf("LDAP BIND version=%d dn=%q password=%q\n", version, dn, password)

	// Send ResultSuccess, accept everything
	s.sendBindResponse(msgId, ldap.LDAPResultSuccess)
}

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

func (s *LdapSession) handleSearch(msgId int64, op *ber.Packet) {
	fmt.Println("SEARCH")
	// Send LDAPResultOperationsError = 1 response if not enough arguments
	if len(op.Children) < 7 {
		s.sendSearchDone(msgId, ldap.LDAPResultOperationsError)
		return
	}

	baseDn := op.Children[0].Value.(string)
	scope := op.Children[1].Value.(int64)
	filter := op.Children[6].Data // TODO parse recursive filters?

	fmt.Printf("LDAP SEARCH base=%q scope=%d filter=%v\n", baseDn, scope, filter)

	s.sendSearchEntry(msgId)
	s.sendSearchDone(msgId, ldap.LDAPResultSuccess)
}

// Sends a hardcoded Search Entry Response
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

func (s *LdapSession) handleExtendedRequest(msgId int64, op *ber.Packet, tlsConfig *tls.Config) error {
	// Send LDAPResultOperationsError = 1 response if no Request OID is given
	if len(op.Children) == 0 {
		s.sendExtendedResponse(msgId, ldap.LDAPResultOperationsError, "")
		return nil
	}

	oid := op.Children[0].Data.String()
	fmt.Println(oid)

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

	// send success response
	s.sendExtendedResponse(msgId, ldap.LDAPResultSuccess, "")

	tlsConn := tls.Server(s.conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		slog.Error("TLS handshake failed: ", "err", err)
		return nil
	}

	s.conn = tlsConn
	s.tlsActive = true
	slog.Info("LDAP TLS established")

	return errStartTLS
}

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
