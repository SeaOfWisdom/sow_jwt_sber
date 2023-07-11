package jwt

import (
	"fmt"
	"time"

	pb "github.com/SeaOfWisdom/sow_proto/jwt-srv"
	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
)

func (a *AutoSRV) generateJWTHMAC(in *pb.TokenBody) (*pb.Token, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp":          time.Now().Add(time.Hour * 24).Unix(),
		"iat":          time.Now().Unix(),
		"iss":          in.Iss,
		"sub":          in.Sub,
		"role":         in.Role,
		"web3_address": in.Web3Address,
		"language":     in.Language,
	})

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
	claims["web3_address"] = in.Web3Address
	claims["language"] = in.Language
	claims["status"] = in.Status

	tokenString, err := token.SignedString([]byte(a.secret))
	if err != nil {
		a.logger.WithFields(logrus.Fields{"GenerateJWT": "Token signed by token(HMAC)"}).Errorln(err)
		return nil, fmt.Errorf("something went wrong while signing token: %s", err.Error())
	}

	return &pb.Token{
		Token: tokenString,
	}, nil
}

func (a *AutoSRV) decodeJWTHMAC(in *pb.Token) (*pb.DecodeResp, error) {
	token, err := jwt.Parse(in.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("there was an error")
		}
		return []byte(a.secret), nil
	})

	if err != nil {
		a.logger.WithFields(logrus.Fields{"DecodeJWT": "Parse token(HMAC)"}).Errorln(err)
		return &pb.DecodeResp{Valid: false, Token: in.Token}, err
	}

	bodyT := pb.TokenBody{}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims["web3_address"] != nil {
			bodyT.Web3Address = claims["web3_address"].(string)
		}
		if claims["language"] != nil {
			bodyT.Language = claims["language"].(string)
		}
		if claims["role"] != nil {
			bodyT.Role = int64(claims["role"].(float64))
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
