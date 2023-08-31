package auth_test

import (
	"testing"

	"github.com/photon-storage/go-common/testing/require"

	"github.com/photon-storage/go-gw3/common/auth"
)

func TestAccessCode(t *testing.T) {
	ac := auth.GenAccessCode()
	t.Logf("access code = %v\n", ac)

	s0, s1, err := auth.ExtractLeadingAccessCode(ac)
	require.NoError(t, err)
	require.Equal(t, ac, s0)
	require.Equal(t, "", s1)

	s0, s1, err = auth.ExtractLeadingAccessCode(ac + "abcdef")
	require.NoError(t, err)
	require.Equal(t, ac, s0)
	require.Equal(t, "abcdef", s1)

	_, _, err = auth.ExtractLeadingAccessCode("123456789abcdef123")
	require.ErrorIs(t, auth.ErrAccessCodeNotFound, err)
	_, _, err = auth.ExtractLeadingAccessCode("1fabc")
	require.ErrorIs(t, auth.ErrAccessCodeNotFound, err)
}
