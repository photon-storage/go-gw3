package net

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	HashLen    = 16
	DomainName = "gtw3.io"
)

func GW3Hostname(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	h := hex.EncodeToString(sum[:])
	return fmt.Sprintf("%s.%s", h[:HashLen], DomainName)
}
