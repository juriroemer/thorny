package handler

import (
	"fmt"
	"log/slog"
	"net"
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
	Serve()
}

type HandlerRegistry struct {
	handlerPlugins map[string]HandlerPlugin
	active         map[string]HandlerInstance
}

func NewHandlerRegistry() *HandlerRegistry {
	return &HandlerRegistry{
		handlerPlugins: make(map[string]HandlerPlugin),
		active:         make(map[string]HandlerInstance),
	}
}

func (f *HandlerRegistry) Init() error {
	//f.Register(HttpHandlerPlugin{})
	f.Register(SmtpHandlerPlugin{})
	f.Register(SshHandlerPlugin{})
	f.Register(LdapHandlerPlugin{})
	return nil
}

func (f *HandlerRegistry) Register(p HandlerPlugin) {
	f.handlerPlugins[p.Name()] = p
}

func (f *HandlerRegistry) Deregister(name string) {
	delete(f.handlerPlugins, name)
}

func (r *HandlerRegistry) Activate(f CfgHandler, listener net.Listener, logger *slog.Logger) error {
	plugin := r.handlerPlugins[f.Name]

	fmt.Println("activating %s", f.Name)

	instance, err := plugin.New(f.Config, listener, logger)
	if err != nil {
		panic(err)
	}
	r.active[f.Name] = instance
	return nil
}

func (f *HandlerRegistry) ServeAll() {
	fmt.Println("Serve all")
	for i, h := range f.active {
		fmt.Println("Serve %d", i)
		go h.Serve()
	}
}
