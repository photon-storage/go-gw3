package crypto_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/photon-storage/go-common/testing/require"
	"github.com/photon-storage/go-gw3/common/auth"
)

func TestGen(t *testing.T) {
	t.Skip()

	for i := 0; i < 10; i++ {
		sk, _, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
		require.NoError(t, err)

		str, err := auth.EncodeSk(sk)
		require.NoError(t, err)
		fmt.Printf("%v\n", str)

		str, err = auth.EncodePk(sk.GetPublic())
		require.NoError(t, err)
		fmt.Printf("%v\n", str)
	}
}
