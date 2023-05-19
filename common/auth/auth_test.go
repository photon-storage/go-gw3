package auth_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	gohttp "net/http"
	"testing"
	"time"

	crypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/photon-storage/go-common/testing/require"

	"github.com/photon-storage/go-gw3/common/auth"
	"github.com/photon-storage/go-gw3/common/http"
)

func TestSign(t *testing.T) {
	url := "/url/to/request"
	sk0, pk0, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	_, pk1, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "ok",
			run: func(t *testing.T) {
				r, err := gohttp.NewRequest(
					"PUT",
					url,
					bytes.NewReader([]byte("request body")),
				)
				require.NoError(t, err)

				a := http.NewArgs().
					SetParam("x-p3-parameter1", "parameter1").
					SetParam("x-p3-parameter2", "parameter2").
					SetParam("x-p3-parameter3", "parameter3").
					SetArg(http.ArgP3Unixtime,
						fmt.Sprintf("%v", time.Now().Unix()),
					).
					SetArg(http.ArgP3Node, "localhost:8080")

				require.NoError(t, auth.SignRequest(r, a, sk0))
				require.NoError(t, auth.VerifyRequest(r, pk0))
			},
		},
		{
			name: "verification failure",
			run: func(t *testing.T) {
				r, err := gohttp.NewRequest(
					"PUT",
					url,
					bytes.NewReader([]byte("request body")),
				)
				require.NoError(t, err)

				a := http.NewArgs().
					SetParam("x-p3-parameter1", "parameter1").
					SetParam("x-p3-parameter2", "parameter2").
					SetParam("x-p3-parameter3", "parameter3").
					SetArg(http.ArgP3Unixtime,
						fmt.Sprintf("%v", time.Now().Unix()),
					).
					SetArg(http.ArgP3Node, "localhost:8080")

				require.NoError(t, auth.SignRequest(r, a, sk0))
				require.ErrorIs(t,
					auth.ErrReqSigFailure,
					auth.VerifyRequest(r, pk1))
			},
		},
		{
			name: "missing timestamp",
			run: func(t *testing.T) {
				r, err := gohttp.NewRequest(
					"PUT",
					url,
					bytes.NewReader([]byte("request body")),
				)
				require.NoError(t, err)

				a := http.NewArgs().
					SetParam("x-p3-parameter1", "parameter1").
					SetParam("x-p3-parameter2", "parameter2").
					SetParam("x-p3-parameter3", "parameter3").
					SetArg(http.ArgP3Node, "localhost:8080")

				require.ErrorIs(t,
					auth.ErrReqDateMissing,
					auth.SignRequest(r, a, sk0))
			},
		},
		{
			name: "timestamp too old",
			run: func(t *testing.T) {
				r, err := gohttp.NewRequest(
					"PUT",
					url,
					bytes.NewReader([]byte("request body")),
				)
				require.NoError(t, err)

				a := http.NewArgs().
					SetParam("x-p3-parameter1", "parameter1").
					SetParam("x-p3-parameter2", "parameter2").
					SetParam("x-p3-parameter3", "parameter3").
					SetArg(http.ArgP3Unixtime,
						fmt.Sprintf("%v", time.Now().Add(-20*time.Minute).Unix()),
					).
					SetArg(http.ArgP3Node, "localhost:8080")

				require.ErrorIs(t,
					auth.ErrReqDateTooOld,
					auth.SignRequest(r, a, sk0))
			},
		},
		{
			name: "missing node",
			run: func(t *testing.T) {
				r, err := gohttp.NewRequest(
					"PUT",
					url,
					bytes.NewReader([]byte("request body")),
				)
				require.NoError(t, err)

				a := http.NewArgs()
				a.SetParam("x-p3-parameter1", "parameter1")
				a.SetParam("x-p3-parameter2", "parameter2")
				a.SetParam("x-p3-parameter3", "parameter3")
				a.SetArg(http.ArgP3Unixtime,
					fmt.Sprintf("%v", time.Now().Unix()),
				)

				require.ErrorIs(t,
					auth.ErrReqNodeMissing,
					auth.SignRequest(r, a, sk0))
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}
