package handler

import "net"

type Handlers = map[int]CfgHandler
type HandlerConfig = map[string]any
type HandlerPlugin interface {
	Name() string
	New(config HandlerConfig, l net.Listener) (HandlerInstance, error)
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
	f.Register(HttpHandlerPlugin{})
	f.Register(SmtpHandlerPlugin{})
	return nil
}

func (f *HandlerRegistry) Register(p HandlerPlugin) {
	f.handlerPlugins[p.Name()] = p
}

func (f *HandlerRegistry) Deregister(name string) {
	delete(f.handlerPlugins, name)
}

func (r *HandlerRegistry) Activate(f CfgHandler, l net.Listener) error {
	plugin := r.handlerPlugins[f.Name]

	instance, err := plugin.New(f.Config, l)
	if err != nil {
		panic(err)
	}

	r.active[f.Name] = instance
	return nil
}

func (f *HandlerRegistry) ServeAll() {
	for _, h := range f.active {
		h.Serve()
	}
}
