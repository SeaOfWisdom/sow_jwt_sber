package main

import (
	"fmt"
	"net"
	"time"

	"github.com/SeaOfWisdom/sow_jwt/src/config"
	jwt "github.com/SeaOfWisdom/sow_jwt/src/service"
	pb "github.com/SeaOfWisdom/sow_proto/jwt-srv"
	"github.com/sirupsen/logrus"

	"google.golang.org/grpc"
)

func main() {
	cfg := config.NewConfig()
	logger := createLogger()

	listener, err := net.Listen("tcp", cfg.GrpcAddress)
	if err != nil {
		logger.Fatalf(err.Error(), fmt.Sprintf("start to listen on %s", cfg.GrpcAddress))
	}
	grpcServer := grpc.NewServer([]grpc.ServerOption{}...)
	pb.RegisterJwtServiceServer(grpcServer, jwt.CreateJWTService(logger, cfg))

	logger.Infof("Start sow-jwt service\n")
	grpcServer.Serve(listener)
}

func createLogger() *logrus.Logger {
	// init logrus logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: time.RFC822,
	})

	// set logger level
	lvl := "debug"
	level, err := logrus.ParseLevel(lvl)
	if err != nil {
		logger.WithFields(logrus.Fields{"level": lvl}).Fatalf("Parse logger's level: ", err.Error())
	}
	logger.SetLevel(level)
	return logger
}
