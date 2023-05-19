package http_test

import (
	"fmt"
	"testing"

	"github.com/photon-storage/go-common/testing/require"

	"github.com/photon-storage/go-gw3/common/http"
)

func TestArgs(t *testing.T) {
	for c := 1; c <= 256; c *= 2 {
		a0 := http.NewArgs()
		for i := 0; i < c; i++ {
			a0.SetParam(
				fmt.Sprintf("param_%v", i),
				fmt.Sprintf("param_val_%v", i),
			)
			a0.SetHeader(
				fmt.Sprintf("header_%v", i),
				fmt.Sprintf("header_val_%v", i),
			)
			a0.SetArg(
				fmt.Sprintf("arg_%v", i),
				fmt.Sprintf("arg_val_%v", i),
			)
		}

		enc := a0.Encode()
		fmt.Printf("[%v] Encoded value: %v, size %v\n", c, enc, len(enc))

		a1, err := http.DecodeArgs(enc)
		require.NoError(t, err)
		require.Equal(t, c, a1.NumParams())
		require.Equal(t, c, a1.NumHeaders())
		require.Equal(t, c, a1.NumArgs())
		for i := 0; i < c; i++ {
			require.Equal(t,
				fmt.Sprintf("param_val_%v", i),
				a1.GetParam(fmt.Sprintf("param_%v", i)),
			)
			require.Equal(t,
				fmt.Sprintf("header_val_%v", i),
				a1.GetHeader(fmt.Sprintf("header_%v", i)),
			)
			require.Equal(t,
				fmt.Sprintf("arg_val_%v", i),
				a1.GetArg(fmt.Sprintf("arg_%v", i)),
			)
		}
		require.Equal(t, enc, a1.Encode())
	}
}
