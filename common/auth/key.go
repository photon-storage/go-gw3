package auth

import (
	"encoding/base64"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
)

func EncodePk(pk libp2pcrypto.PubKey) (string, error) {
	bytes, err := libp2pcrypto.MarshalPublicKey(pk)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

func DecodePk(str string) (libp2pcrypto.PubKey, error) {
	bytes, err := base64.URLEncoding.DecodeString(str)
	if err != nil {
		bytes, err = base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, err
		}
	}

	return libp2pcrypto.UnmarshalPublicKey(bytes)
}

func EncodeSk(sk libp2pcrypto.PrivKey) (string, error) {
	bytes, err := libp2pcrypto.MarshalPrivateKey(sk)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

func DecodeSk(str string) (libp2pcrypto.PrivKey, error) {
	bytes, err := base64.URLEncoding.DecodeString(str)
	if err != nil {
		bytes, err = base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, err
		}
	}

	return libp2pcrypto.UnmarshalPrivateKey(bytes)
}
