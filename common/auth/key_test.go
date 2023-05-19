package auth_test

import (
	"crypto/rand"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/photon-storage/go-common/testing/require"

	"github.com/photon-storage/go-gw3/common/auth"
)

func TestKeyEncode(t *testing.T) {
	sk, pk, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	str, err := auth.EncodePk(pk)
	require.NoError(t, err)
	pk1, err := auth.DecodePk(str)
	require.NoError(t, err)
	require.True(t, pk.Equals(pk1))

	str, err = auth.EncodeSk(sk)
	require.NoError(t, err)
	sk1, err := auth.DecodeSk(str)
	require.NoError(t, err)
	require.True(t, sk.Equals(sk1))
}
