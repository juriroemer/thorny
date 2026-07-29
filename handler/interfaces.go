package handler

// capability interfaces (small interfaces)

// For handlers that emulate a specific software version
type VersionProvider interface {
	GetVersion() string
}

// For handlers that use Headers, e.g. http
type HeaderProvider interface {
	GetHeaders() map[string]string
}
