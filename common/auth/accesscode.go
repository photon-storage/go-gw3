package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	acPrefix = "1f"
	acLen    = 10
)

var (
	ErrAccessCodeNotFound = errors.New("access code not found")
)

func GenAccessCode() string {
	token := make([]byte, (acLen-len(acPrefix))/2)
	rand.Read(token)
	return "1f" + hex.EncodeToString(token)
}

func HasAccessCodePrefix(str string) bool {
	return strings.HasPrefix(str, acPrefix)
}

func ExtractLeadingAccessCode(str string) (string, string, error) {
	if len(str) < acLen || !strings.HasPrefix(str, acPrefix) {
		return "", "", ErrAccessCodeNotFound
	}
	return str[:acLen], str[acLen:], nil
}
