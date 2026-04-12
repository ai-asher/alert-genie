package topology

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type staticProvider struct {
	services map[string]*ServiceTopology
}

type topologyFile struct {
	Services []ServiceTopology `yaml:"services"`
}

// NewStaticProvider loads topology from a YAML file.
func NewStaticProvider(path string) (Provider, error) {
	if path == "" {
		return &staticProvider{services: make(map[string]*ServiceTopology)}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read topology file: %w", err)
	}

	var tf topologyFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("parse topology file: %w", err)
	}

	services := make(map[string]*ServiceTopology, len(tf.Services))
	for i := range tf.Services {
		svc := &tf.Services[i]
		services[strings.ToLower(svc.ServiceName)] = svc
	}

	return &staticProvider{services: services}, nil
}

func (p *staticProvider) Get(serviceName string) *ServiceTopology {
	return p.services[strings.ToLower(serviceName)]
}
