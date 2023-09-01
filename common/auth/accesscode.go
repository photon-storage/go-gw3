package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	acPrefix = "1"
	acLen    = 7
)

var (
	ErrAccessCodeNotFound = errors.New("access code not found")
)

// Common CID in b36 encoding is usually 56 bytes.
// The max length for a domain label is 63 bytes.
// With 1 byte prefix identifier, it leaves 6 bytes for access code.
// A hex encoding allows actual 3 bytes of data: 2^24 = 16M variations.
func GenAccessCode() string {
	token := make([]byte, (acLen-len(acPrefix))/2)
	rand.Read(token)
	return acPrefix + hex.EncodeToString(token)
}

func AccessCodeLen() int {
	return acLen
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
