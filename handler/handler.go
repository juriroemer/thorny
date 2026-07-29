package handler

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
)

type Handlers = map[int]CfgHandler
type HandlerConfig = map[string]any

// The interface all handler plugins must implement
type HandlerPlugin interface {
	Name() string
	New(config HandlerConfig,
		listener net.Listener,
		logger *slog.Logger) (HandlerInstance, error)
}

// Config handler struct
type CfgHandler struct {
	Name   string        `yaml:"name"`
	Config HandlerConfig `yaml:"config"`
}

// The interface handler instances implement
type HandlerInstance interface {
	Name() string
	Serve(context.Context, *sync.WaitGroup)
}

// The registry that holds the handler plugins
type HandlerRegistry struct {
	handlerPlugins map[string]HandlerPlugin
	active         map[int]HandlerInstance
}

// NewHandlerRegistry constructs a HandlerRegistry
func NewHandlerRegistry() *HandlerRegistry {
	return &HandlerRegistry{
		handlerPlugins: make(map[string]HandlerPlugin),
		active:         make(map[int]HandlerInstance),
	}
}

// Init registers all available handlers
func (f *HandlerRegistry) Init() error {
	//f.Register(HttpHandlerPlugin{})
	f.Register(SmtpHandlerPlugin{})
	f.Register(SshHandlerPlugin{})
	f.Register(LdapHandlerPlugin{})
	f.Register(TelnetHandlerPlugin{})
	return nil
}

// Register registers individual handler plugins
func (f *HandlerRegistry) Register(p HandlerPlugin) {
	f.handlerPlugins[p.Name()] = p
}

// Derigister removes a handler plugin from the handler registry
func (f *HandlerRegistry) Deregister(name string) {
	delete(f.handlerPlugins, name)
}

// Activate initiualizes a new handler instance with its configuration, listener and logger
func (r *HandlerRegistry) Activate(port int, f CfgHandler, listener net.Listener, logger *slog.Logger) error {
	plugin := r.handlerPlugins[f.Name]

	fmt.Printf("activating %s on port %d\n", f.Name, port)

	instance, err := plugin.New(f.Config, listener, logger)
	if err != nil {
		panic(err)
	}
	r.active[port] = instance
	return nil
}

// ServeAll makes all active handlers serve connections
func (f *HandlerRegistry) ServeAll(ctx context.Context, wg *sync.WaitGroup) {
	fmt.Println("Serve all")
	for port, h := range f.active {
		fmt.Printf("Serve %s on port %d\n", h.Name(), port)
		wg.Add(1)
		go h.Serve(ctx, wg)
	}
}
