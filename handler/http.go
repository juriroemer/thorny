package handler

import (
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"go.yaml.in/yaml/v4"
)

var http_instance HttpHandlerInstance // TODO replace with closure / anonymous function in HandleFunc

type HttpHandlerConfig struct {
	Template string `yaml:"template"`
	Values   nginx  `yaml:"values"`
}

type nginx struct {
	Version string            `yaml:"version"`
	Headers map[string]string `yaml:"headers"`
}

type HttpHandlerPlugin struct {
}

func (HttpHandlerPlugin) Name() string {
	return "http_handler"
}

type HttpHandlerInstance struct {
	cfg      HttpHandlerConfig
	listener net.Listener
}

func (HttpHandlerPlugin) New(config HandlerConfig, l net.Listener) (HandlerInstance, error) {
	cfg, err := HttpHandlerPlugin{}.parseConfig(config)
	if err != nil {
		return nil, err
	}

	http_instance = HttpHandlerInstance{
		cfg:      *cfg,
		listener: l,
	}
	return &http_instance, nil
}

func (HttpHandlerPlugin) parseConfig(config HandlerConfig) (*HttpHandlerConfig, error) {
	var cfg HttpHandlerConfig
	b, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (hh *HttpHandlerInstance) Listen() {
	// BUG
	http.HandleFunc("/", serveHTTP)
	go log.Fatal(http.Serve(hh.listener, nil))
}

// TODO extend templates to headers, so they aren't set here anymore -> “config subtype registry”
func serveHTTP(w http.ResponseWriter, r *http.Request) {
	n := http_instance.cfg

	// set nginx default headers
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Etag", "6969")
	w.Header().Set("Last-Modified", formattedTimeMinus20())
	w.Header().Set("Server", fmt.Sprintf("nginx/%s", n.Values.Version))

	slog.Info(r.RequestURI)
	// strip and add additional headers from config
	for k, v := range n.Values.Headers {
		k_stripped := strings.ReplaceAll(k, " ", "-")
		if k != k_stripped {
			slog.Warn(fmt.Sprintf("Whitespace found in nginx header, replaced '%s' with '%s'. Please check your config.", k, k_stripped))
		}
		w.Header().Set(k_stripped, v)
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
	tmplFile := fmt.Sprintf("./handler/http_templates/%s.tmpl", n.Template)
	tmpl, err := template.ParseFiles(tmplFile)
	if err != nil {
		panic(err)
	}

	// write template to response writer
	err = tmpl.Execute(w, make(map[string]string)) // n.values
	if err != nil {
		panic(err)
	}
}

func formattedTimeMinus20() string {
	t := time.Now().UTC().Add(-20 * time.Minute)
	t = t.In(time.FixedZone("GMT", 0))
	return t.Format(time.RFC1123)
}
