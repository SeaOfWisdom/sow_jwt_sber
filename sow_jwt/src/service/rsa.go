package jwt

import (
	"fmt"
	"time"

	pb "github.com/SeaOfWisdom/sow_proto/jwt-srv"
	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
)

func (a *AutoSRV) generateJWTRSA(in *pb.TokenBody) (*pb.Token, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	// The "exp" (expiration time) claim identifies the expiration time on
	// or after which the JWT MUST NOT be accepted for processing.
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	//  The "iat" (issued at) claim identifies the time at which the JWT was issued.
	claims["iat"] = time.Now().Unix()
	//The "iss" (issuer) claim identifies the principal that issued the JWT.
	claims["iss"] = in.Iss
	// The "sub" (subject) claim identifies the principal that is the subject of the JWT.
	claims["sub"] = in.Sub
	claims["role"] = in.Role
	claims["status"] = in.Status

	tokenString, err := token.SignedString(a.private)
	if err != nil {
		a.logger.WithFields(logrus.Fields{"GenerateJWT": "Token signed by private key(RSA)"}).Errorln(err)
		return nil, fmt.Errorf("Something went wrong while signing token: %s", err.Error())
	}

	return &pb.Token{
		Token: tokenString,
	}, nil
}

func (a *AutoSRV) decodeJWTRSA(in *pb.Token) (*pb.DecodeResp, error) {
	token, err := jwt.Parse(in.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return a.public, nil
	})

	if err != nil {
		a.logger.WithFields(logrus.Fields{"DecodeJWT": "Parse token(RSA)"}).Errorln(err)
		return &pb.DecodeResp{Valid: false, Token: in.Token}, err
	}

	bodyT := pb.TokenBody{}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims["role"] != nil {
			bodyT.Role = claims["role"].(int64)
		}
		if claims["iss"] != nil {
			bodyT.Iss = claims["iss"].(string)
		}
		if claims["sub"] != nil {
			bodyT.Sub = claims["sub"].(string)
		}
		if claims["status"] != nil {
			bodyT.Status = claims["status"].(string)
		}
	} else {
		return &pb.DecodeResp{Valid: false, Token: in.Token}, nil
	}

	if token.Valid {
		return &pb.DecodeResp{Valid: true, Token: in.Token, Body: &bodyT}, nil
	}

	return &pb.DecodeResp{Valid: false, Token: in.Token}, nil
}
