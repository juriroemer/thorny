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
type HandlerPlugin interface {
	Name() string
	New(config HandlerConfig,
		listener net.Listener,
		logger *slog.Logger) (HandlerInstance, error)
}

type CfgHandler struct {
	Name   string        `yaml:"name"`
	Config HandlerConfig `yaml:"config"`
}

type HandlerInstance interface {
	Name() string
	Serve(context.Context, *sync.WaitGroup)
}

type HandlerRegistry struct {
	handlerPlugins map[string]HandlerPlugin
	active         map[int]HandlerInstance
}

func NewHandlerRegistry() *HandlerRegistry {
	return &HandlerRegistry{
		handlerPlugins: make(map[string]HandlerPlugin),
		active:         make(map[int]HandlerInstance),
	}
}

func (f *HandlerRegistry) Init() error {
	//f.Register(HttpHandlerPlugin{})
	f.Register(SmtpHandlerPlugin{})
	f.Register(SshHandlerPlugin{})
	f.Register(LdapHandlerPlugin{})
	f.Register(TelnetHandlerPlugin{})
	return nil
}

func (f *HandlerRegistry) Register(p HandlerPlugin) {
	f.handlerPlugins[p.Name()] = p
}

func (f *HandlerRegistry) Deregister(name string) {
	delete(f.handlerPlugins, name)
}

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

func (f *HandlerRegistry) ServeAll(ctx context.Context, wg *sync.WaitGroup) {
	fmt.Println("Serve all")
	for port, h := range f.active {
		fmt.Printf("Serve %s on port %d\n", h.Name(), port)
		wg.Add(1)
		go h.Serve(ctx, wg)
	}
}
