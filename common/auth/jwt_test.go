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
	}

	secert := []byte("ICU")
	jwt, err := origin.GenerateJWT(secert)
	require.NoError(t, err)
	got, err := NewClaimsFromJWT(jwt, secert)
	require.NoError(t, err)
	require.DeepEqual(t, origin, got)
}
