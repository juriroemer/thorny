package handler

// capability interfaces (small interfaces)
type VersionProvider interface {
	GetVersion() string
}

type HeaderProvider interface {
	GetHeaders() map[string]string
}
