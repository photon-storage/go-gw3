package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	gohttp "net/http"
	"strconv"
	"strings"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/photon-storage/go-gw3/common/http"
)

// Predefined errors for auth.
var (
	ErrReqDateMissing  = errors.New("request date missing")
	ErrReqDateObsolete = errors.New("request date obsolete")
	ErrReqNodeMissing  = errors.New("request node missing")
	ErrReqSigExists    = errors.New("request signature parameter already exists")
	ErrReqSigMissing   = errors.New("request signature parameter missing")
	ErrReqSigFailure   = errors.New("request signature verification failure")
)

// SignRequest is a API authentication scheme similar to AWS S3.
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/RESTAuthentication.html
func SignRequest(
	r *gohttp.Request,
	args *http.Args,
	sk libp2pcrypto.PrivKey,
) error {
	if _, err := ValidateTimestamp(args, 5*time.Second); err != nil {
		return err
	}

	if err := ValidateNode(args); err != nil {
		return err
	}

	query := r.URL.Query()
	if query.Get(http.ParamP3Sig) != "" {
		return ErrReqSigExists
	}

	p3Args := args.Encode()

	sig, err := SignBase64(
		[]byte(GenStringToSign(
			r.Method,
			r.Host,
			CanonicalizeURI(r.URL.Path),
			p3Args,
		)),
		sk,
	)
	if err != nil {
		return fmt.Errorf("error signing request: %w", err)
	}

	query.Set(http.ParamP3Args, p3Args)
	query.Set(http.ParamP3Sig, sig)
	r.URL.RawQuery = query.Encode()

	return nil
}

// VerifyRequest is used to verify the auth by decoding by the public key.
func VerifyRequest(r *gohttp.Request, pk libp2pcrypto.PubKey) error {
	sig := r.URL.Query().Get(http.ParamP3Sig)
	if sig == "" {
		return ErrReqSigMissing
	}

	return VerifySigBase64(
		GenStringToSign(
			r.Method,
			r.Host,
			CanonicalizeURI(r.URL.Path),
			r.URL.Query().Get(http.ParamP3Args),
		),
		sig,
		pk,
	)
}

func SignBase64(data []byte, sk libp2pcrypto.PrivKey) (string, error) {
	sig, err := sk.Sign(data)
	if err != nil {
		return "", fmt.Errorf("error signing request: %w", err)
	}

	return base64.URLEncoding.EncodeToString(sig), nil
}

func VerifySigBase64(data, sig string, pk libp2pcrypto.PubKey) error {
	decSig, err := base64.URLEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("error decoding signature: %w", err)
	}

	ok, err := pk.Verify([]byte(data), decSig)
	if err != nil {
		return fmt.Errorf("error verifying signature: %w", err)
	}

	if !ok {
		return ErrReqSigFailure
	}

	return nil
}

func GenStringToSign(method, host, uri, arg string) string {
	return method + "\n" + host + "\n" + uri + "\n" + arg
}

func CanonicalizeURI(path string) string {
	parts := strings.Split(path, "/")
	var vals []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		vals = append(vals, part)
	}

	return "/" + strings.Join(vals, "/")
}

func ValidateTimestamp(
	args *http.Args,
	tolerance time.Duration,
) (time.Time, error) {
	var ts time.Time
	utime := args.GetArg(http.ArgP3Unixtime)
	if utime != "" {
		v, err := strconv.ParseInt(utime, 10, 64)
		if err != nil {
			return time.Time{},
				fmt.Errorf("error parsing x-p3-unixtime parameter: %w", err)
		}
		ts = time.Unix(v, 0)
	}

	if ts.IsZero() {
		return time.Time{}, ErrReqDateMissing
	}
	if time.Since(ts).Abs() > tolerance {
		return time.Time{}, ErrReqDateObsolete
	}

	return ts, nil
}

func ValidateNode(args *http.Args) error {
	node := args.GetArg(http.ArgP3Node)
	if node == "" {
		return ErrReqNodeMissing
	}
	return nil
}
