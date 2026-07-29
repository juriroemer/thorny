package handler

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v4"
)

// This handler was ultimatively not used or required, as the thesis scope changed
// It can serve http templates, `http_templates/nginx.tmpl` emulates a nginx welcome page
// Included for completeness

type HttpHandlerConfig struct {
	Template string         `yaml:"template"`
	Values   TemplateConfig `yaml:"values"`
}

type HttpHandlerPlugin struct {
}

func (HttpHandlerPlugin) Name() string {
	return "http_handler"
}

func (h *HttpHandlerInstance) Name() string { return h.name }

type HttpHandlerInstance struct {
	cfg       HttpHandlerConfig
	listener  net.Listener
	templates map[string]func() TemplateConfig
	logger    *slog.Logger
	name      string
}

type TemplateConfig interface {
	Validate() error
}

func (HttpHandlerPlugin) New(config HandlerConfig, l net.Listener, logger *slog.Logger) (HandlerInstance, error) {

	instance := HttpHandlerInstance{
		listener:  l,
		templates: make(map[string]func() TemplateConfig),
		logger:    logger,
		name:      HttpHandlerPlugin{}.Name(),
	}

	// register templates
	instance.RegisterTemplate("nginx", NginxTemplateFactory())

	if err := instance.loadHTTPConfig(config); err != nil {
		return nil, err
	}

	return &instance, nil
}

func (hh *HttpHandlerInstance) loadHTTPConfig(raw HandlerConfig) error {
	templateName := raw["template"].(string)
	factory := hh.templates[templateName]
	if factory == nil {
		return fmt.Errorf("unknown template: %s", templateName)
	}
	cfg := factory()

	valuesRaw := raw["values"]
	valuesYaml, _ := yaml.Marshal(valuesRaw)

	if err := yaml.Unmarshal(valuesYaml, cfg); err != nil {
		return err
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	hh.cfg = HttpHandlerConfig{
		Template: templateName,
		Values:   cfg,
	}
	return nil
}

func (hh *HttpHandlerInstance) RegisterTemplate(id string, tf func() TemplateConfig) {
	hh.templates[id] = tf
}

func (hh *HttpHandlerInstance) Serve(ctx context.Context, wg *sync.WaitGroup) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", hh.Handler())
	go func() {
		if err := http.Serve(hh.listener, mux); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
}

func (hh *HttpHandlerInstance) Handler() http.HandlerFunc {
	cfg := hh.cfg

	return func(w http.ResponseWriter, r *http.Request) {
		// use capability interface for version
		if vp, ok := cfg.Values.(VersionProvider); ok {
			// TODO generalize this - Should Header Providers write their own Headers? `VersionProvider.CustomizeHeaders(w.Header())`
			w.Header().Set("Server", fmt.Sprintf("nginx/%s", vp.GetVersion()))
		}

		slog.Info(r.RequestURI)
		// strip and add additional headers from config
		if hp, ok := cfg.Values.(HeaderProvider); ok {
			for k, v := range hp.GetHeaders() {
				k_stripped := strings.ReplaceAll(k, " ", "-")
				if k != k_stripped {
					slog.Warn(fmt.Sprintf("Whitespace found in nginx header, replaced '%s' with '%s'. Please check your config.", k, k_stripped))
				}
				w.Header().Set(k_stripped, v)
			}
		}

		//remove default headers
		w.Header()["Content-Type"] = nil
		// When the Content-Length Header is not set, http.ResponseWriter will set `Transfer-Encoding: chunked`,
		// https://www.dolthub.com/blog/2022-03-09-debugging-http-body-read-behavior/#conclusion
		// if the response is larger than the chunking buffer size. The buffer size can be increased:
		// https://stackoverflow.com/questions/68778961/how-to-configure-the-buffer-size-for-http-responsewriter
		// -> TODO decide the buffer size should be increased (to something larger than the response)
		// to suppress both the Content-Length and Transfer-Encoding Headers, as the nginx welcome page sends neither
		w.Header()["Content-Length"] = nil

		// populate template
		tmplFile := fmt.Sprintf("./handler/http_templates/%s.tmpl", cfg.Template)
		tmpl, err := template.ParseFiles(tmplFile)
		if err != nil {
			panic(err)
		}

		// write template to response writer
		if err := tmpl.Execute(w, make(map[string]string)); err != nil {
			panic(err)
		}
	}
}

func formattedTimeMinus20() string {
	t := time.Now().UTC().Add(-20 * time.Minute)
	t = t.In(time.FixedZone("GMT", 0))
	return t.Format(time.RFC1123)
}
