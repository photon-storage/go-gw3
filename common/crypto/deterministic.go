package crypto

import (
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/photon-storage/go-gw3/common/auth"
)

var (
	pregens = [10]libp2pcrypto.PrivKey{
		// Dev - starbase key
		// CAESIHnUcGM7CitSdYMLIFMEoy1yQy8dAE7rtKJDJ5kQybXd
		toE225519("CAESQGw2ew4pJo+Afsgmzv4VGnYehtQhAF7ZFxImnB5eXhpHedRwYzsKK1J1gwsgUwSjLXJDLx0ATuu0okMnmRDJtd0="),
		// Dev - falcon key
		// CAESIHCp/6a6fHbSvpS3e64J545mB1wUnKJ8TPDrgqwSHmqY
		toE225519("CAESQOiMDZG28QD6UTZjXsT4sRgWf4iKYIA5y+wNibdp4OQMcKn/prp8dtK+lLd7rgnnjmYHXBSconxM8OuCrBIeapg="),
		// CAESIJ3vdUtmgwODmeXfi4Zjz0CqiPcKRQXOC7LE/zWz86Ll
		toE225519("CAESQEH/3VJ/6PD7082l+dh9HTYft0imJYe7tL0si+XLThJvne91S2aDA4OZ5d+LhmPPQKqI9wpFBc4LssT/NbPzouU="),
		// CAESILeHbNQfeb7LcRrRF1BonC34fctUvsj+NMnw7BUe1eRk
		toE225519("CAESQEaEU9wLtwKCMWEiyJnxriaeq44+K4QzLaMm11IPRgAZt4ds1B95vstxGtEXUGicLfh9y1S+yP40yfDsFR7V5GQ="),
		// CAESILpfSfwMWTFVwuvzCEdLHJusPglLk5Kxs6vUxIRb8gXP
		toE225519("CAESQCvbyfLebahB6oDrrl4P9X/TlgTB3Ba8MTJ2/VdLdpQVul9J/AxZMVXC6/MIR0scm6w+CUuTkrGzq9TEhFvyBc8="),
		// CAESIMqS1aMIUB8xAMp7oW35r/BKNcKcSuBlIg6zybf4u2LN
		toE225519("CAESQAu66+uoU240Bav8O+JxRhLE9A5a8njmddk6NvNMIhQLypLVowhQHzEAynuhbfmv8Eo1wpxK4GUiDrPJt/i7Ys0="),
		// CAESID6qlnnthvNfFO5BlQvJTqI/8a1Qz2Ct29laAn5985dq
		toE225519("CAESQEQPVEJwEyHwbOx2KD8dGEZH3POPsJdP0onZR5fxk1YzPqqWee2G818U7kGVC8lOoj/xrVDPYK3b2VoCfn3zl2o="),
		// CAESIF1RAvxILcIXDxatqhJyZiSd8REtpH/BffHcXvsweCG0
		toE225519("CAESQB22r4h3IPPtbLh6aVuLMWI0Ry7N5SiFiEH0zt0ZyfVyXVEC/EgtwhcPFq2qEnJmJJ3xES2kf8F98dxe+zB4IbQ="),
		// CAESIEjfdCD11oQjPoi+qlDrGxEjdQIPOtBLBvUrobtU1LkW
		toE225519("CAESQDvZTk5j4NGhl5MkUNnJDkaLQqnqUcSMDggUjL80oETeSN90IPXWhCM+iL6qUOsbESN1Ag860EsG9Suhu1TUuRY="),
		// CAESIAaH5mgIv1e3kLKJ8uKs2AR6Z/YDP+EdaPdc/0ucg94L
		toE225519("CAESQB9O3gYqKWcBVJ/fV9mRelQr89vg9Rtob+j8USQEn9frBofmaAi/V7eQsony4qzYBHpn9gM/4R1o91z/S5yD3gs="),
	}
)

func toE225519(str string) libp2pcrypto.PrivKey {
	sk, err := auth.DecodeSk(str)
	if err != nil {
		panic(err)
	}

	return sk
}

type convertibleInt interface {
	int | int8 | uint8 | int16 | uint16 | int32 | uint32 | int64 | uint64
}

func PregenEd25519[T convertibleInt](idx T) libp2pcrypto.PrivKey {
	n := int(idx)
	if n > len(pregens) {
		panic("index is larger than pre-genenerated size")
	}
	return pregens[n]
}
