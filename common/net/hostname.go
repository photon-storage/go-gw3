package net

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func GW3Hostname(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	h := hex.EncodeToString(sum[:])
	return fmt.Sprintf("%s.gw3.io", h[:16])
}
