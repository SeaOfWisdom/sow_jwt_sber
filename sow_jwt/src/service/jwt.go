package jwt

import (
	"context"
	"crypto/rsa"
	"fmt"
	"io/ioutil"

	"github.com/SeaOfWisdom/sow_jwt/src/config"
	pb "github.com/SeaOfWisdom/sow_proto/jwt-srv"
	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
)

// AutoSRV is main service
type AutoSRV struct {
	pb.UnimplementedJwtServiceServer
	secret, method string
	private        *rsa.PrivateKey
	public         *rsa.PublicKey
	logger         *logrus.Logger
}

// CreateJWTService creates and reads keys for auto service
// returns service
func CreateJWTService(logger *logrus.Logger, cfg *config.Config) *AutoSRV {
	a := &AutoSRV{logger: logger}
	// reate keys
	if cfg.Method == "rsa" {
		a.method = "rsa"
		a.private, a.public = a.readKeys(cfg.PrivateKeyDir)
	} else if cfg.Method == "hmac" {
		a.method = "hmac"
		a.secret = cfg.Secret
	} else {
		a.logger.WithFields(logrus.Fields{"CreateJWTService": "wrong method"}).Fatalf("wrong method: %s", cfg.Method)
		return nil
	}

	return a
}

// GenerateJWT ...
func (a *AutoSRV) GenerateJWT(ctx context.Context, in *pb.TokenBody) (*pb.Token, error) {
	a.logger.WithFields(logrus.Fields{"GenerateJWT": "Request"}).Debugf("%s %s\n", in.GetIss(), in.GetSub())

	if a.method == "hmac" {
		return a.generateJWTHMAC(in)
	} else if a.method == "rsa" {
		return a.generateJWTRSA(in)
	}
	a.logger.WithFields(logrus.Fields{"GenerateJWT": "Wrong service method"}).Debugf("Service method = %s\n", a.method)
	return nil, fmt.Errorf("wrong method in service == %s", a.method)
}

// DecodeJWT ...
func (a *AutoSRV) DecodeJWT(ctx context.Context, in *pb.Token) (*pb.DecodeResp, error) {
	a.logger.WithFields(logrus.Fields{"DecodeJWT": "Request"}).Debugln(in.GetToken())

	if a.method == "hmac" {
		return a.decodeJWTHMAC(in)
	} else if a.method == "rsa" {
		return a.decodeJWTRSA(in)
	} else {
		a.logger.WithFields(logrus.Fields{"GenerateJWT": "Wrong service method"}).Debugf("Service method = %s\n", a.method)
		return nil, fmt.Errorf("Wrong method in service == %s", a.method)
	}
}

func (a *AutoSRV) readKeys(privKeyPath string) (*rsa.PrivateKey, *rsa.PublicKey) {
	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		a.logger.WithFields(logrus.Fields{"readKeys": "Read privKey"}).Fatalf(err.Error())
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		a.logger.WithFields(logrus.Fields{"readKeys": "Parse privKey"}).Fatalf(err.Error())
	}

	return signKey, &signKey.PublicKey
}
