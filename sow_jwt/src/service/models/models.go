package models

// KeysConfig contains configuration for auto api services
type KeysConfig struct {
	Private, Public string
}

// ServiceConfig contains configurations for grpc service.
type ServiceConfig struct {
	Network string // Service network
	Port    string // Service port
}
