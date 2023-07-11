package config

import (
	"github.com/namsral/flag"
)

type Config struct {
	/* gRPC */
	GrpcAddress string
	/* JWT method */
	Method string
	/* HMAC secret */
	Secret string
	/* RSA algorithm */
	PrivateKeyDir string
}

func NewConfig() *Config {
	config := &Config{}
	/* gRPC */
	flag.StringVar(&config.GrpcAddress, "grpc-address", "0.0.0.0:5304", "gRPC address and port for inter-service communications")
	/* JWT method */
	flag.StringVar(&config.Method, "method", "hmac", "")
	/* HMAC secret */
	flag.StringVar(&config.Secret, "secret", "example", "")
	/* RSA algorithm */
	flag.StringVar(&config.PrivateKeyDir, "private-key", "./keys/app.rsa", "")

	/* parse config from envs or config files */
	flag.Parse()
	return config
}
