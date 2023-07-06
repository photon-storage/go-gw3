package auth

import (
	"testing"

	"github.com/photon-storage/go-common/testing/require"
)

func TestJWT(t *testing.T) {
	origin := &Claims{
		AccountID: 996,
		Provider:  "mock_provider",
		Username:  "mock_name",
		Perm:      31,
		Debug:     "k0=v0; k1= v1",
	}

	secert := []byte("ICU")
	jwt, err := origin.GenerateJWT(secert)
	require.NoError(t, err)
	got, err := NewClaimsFromJWT(jwt, secert)
	require.NoError(t, err)
	require.DeepEqual(t, origin, got)

	kvs := got.ExtractDebug()
	require.Equal(t, 2, len(kvs))
	require.Equal(t, "v0", kvs["k0"])
	require.Equal(t, "v1", kvs["k1"])
}
