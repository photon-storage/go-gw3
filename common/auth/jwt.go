package auth

import (
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

var errDecodeJWT = errors.New("decode JWT failure")

// Claims contain the auth data that share between servers.
type Claims struct {
	AccountID uint64 `json:"id"`
	Provider  string `json:"provider"`
	Username  string `json:"username"`
	Perm      uint64 `json:"perm"`
	Debug     string `json:"debug,omitempty"`
	jwt.RegisteredClaims
}

// NewClaimsFromJWT validates jwt string and converts it to claims.
func NewClaimsFromJWT(cipherJWT string, secret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(cipherJWT, &Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return secret, nil
		},
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errDecodeJWT
	}

	return claims, nil
}

// GenerateJWT converts the claims to the jwt string.
func (c *Claims) GenerateJWT(secret []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS512, c).SignedString(secret)
}

// ExtractDebug extracts debug data as kv pairs.
func (c *Claims) ExtractDebug() map[string]string {
	m := map[string]string{}
	kvs := strings.Split(c.Debug, ";")
	for _, kv := range kvs {
		parts := strings.Split(kv, "=")
		if len(parts) != 2 {
			continue
		}
		m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	return m
}
