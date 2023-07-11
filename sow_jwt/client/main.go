package main

import (
	"context"
	"fmt"
	"log"

	pb "github.com/SeaOfWisdom/sow_proto/jwt-srv"

	"google.golang.org/grpc"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	conn, err := grpc.Dial("localhost:5304", []grpc.DialOption{grpc.WithInsecure()}...)
	failOnError(err, "Geo-service. While connetion client")
	defer conn.Close()

	cli := pb.NewJwtServiceClient(conn)

	reqG := pb.TokenBody{Iss: "pp-lib", Sub: "8b4a701c-578d-436c-a0c7-44a45c29e809", Role: 1, Status: "active"}
	responseG, err := cli.GenerateJWT(context.Background(), &reqG)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(responseG.Token)

	reqD := pb.Token{Token: responseG.Token}
	responseD, err := cli.DecodeJWT(context.Background(), &reqD)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(responseD.Body)
}
