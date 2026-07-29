package handler

import "fmt"

// Not used in the final thesis, included for completeness
// Holds instance attributes for the http handler nginx template

func NginxTemplateFactory() func() TemplateConfig {
	return func() TemplateConfig {
		return &NginxConfig{
			Headers: map[string]string{
				"Etag":          "6969",
				"Connection":    "keep-alive",
				"Last-Modified": formattedTimeMinus20(),
			},
		}
	}
}

// NginxConfig holds configuration for the nginx template
type NginxConfig struct {
	Version string            `yaml:"version"`
	Headers map[string]string `yaml:"headers"`
}

func (c *NginxConfig) Validate() error {
	if c.Version == "" {
		return fmt.Errorf("nginx version required")
	}
	return nil
}

// implement capability interfaces for NginxConfig
func (c *NginxConfig) GetVersion() string {
	return c.Version
}

func (c *NginxConfig) GetHeaders() map[string]string {
	return c.Headers
}
