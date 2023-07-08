package http

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"sort"

	"github.com/klauspost/compress/gzip"
)

// Standard Param/Header names.
const (
	// HTTP headers & params used for requesting APIs from external sources.
	HeaderAuthorization  = "Authorization"
	HeaderP3JWTToken     = "X-JWT-Token"
	HeaderP3AccessKey    = "X-Access-Key"
	HeaderP3AccessSecret = "X-Access-Secret"
	HeaderP3AccessSig    = "X-Access-Signature"

	ParamP3Unixtime = "ts"
	ParamP3Size     = "size"
	ParamP3Boundary = "boundary"
	ParamP3AuthOnly = "auth-only"

	// Args used for communicating between internal services (encoded in args).
	ArgP3Node      = "arg-node"
	ArgP3Size      = "arg-size"
	ArgP3AcctID    = "arg-a-id"
	ArgP3BillingID = "arg-b-id"
	ArgP3Unixtime  = "arg-unix"

	// Params generated by internal sources and pass to other starbase services.
	ParamP3Args = "sargs"
	ParamP3Sig  = "ssig"
	ParamP3Pk   = "spk"

	// IPFS native params.
	ParamIPFSArg      = "arg"
	ParamIPFSKey      = "key"
	ParamIPFSProgress = "progress"
	ParamIPFSType     = "type"
	ParamIPFSFormat   = "format"
	ParamIPFSFileName = "filename"
	ParamIPFSPinRoots = "pin-roots"
)

type Args struct {
	Params  map[string]string `json:"p"`
	Headers map[string]string `json:"h"`
	Args    map[string]string `json:"a"`
}

type kv struct {
	K string `json:"k"`
	V string `json:"v"`
}

type sortedArgs struct {
	Params  []*kv `json:"p"`
	Headers []*kv `json:"h"`
	Args    []*kv `json:"a"`
}

func NewArgs() *Args {
	return &Args{
		Params:  map[string]string{},
		Headers: map[string]string{},
		Args:    map[string]string{},
	}
}

func DecodeArgs(v string) (*Args, error) {
	dec, err := base64.URLEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}

	r, err := gzip.NewReader(bytes.NewReader(dec))
	if err != nil {
		return nil, err
	}
	dec, err = io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var sorted sortedArgs
	if err := json.Unmarshal(dec, &sorted); err != nil {
		return nil, err
	}

	params := map[string]string{}
	for _, pair := range sorted.Params {
		params[pair.K] = pair.V
	}
	headers := map[string]string{}
	for _, pair := range sorted.Headers {
		headers[pair.K] = pair.V
	}
	args := map[string]string{}
	for _, pair := range sorted.Args {
		args[pair.K] = pair.V
	}

	return &Args{
		Params:  params,
		Headers: headers,
		Args:    args,
	}, nil
}

func (a *Args) NumParams() int {
	return len(a.Params)
}

func (a *Args) NumHeaders() int {
	return len(a.Headers)
}

func (a *Args) NumArgs() int {
	return len(a.Args)
}

func (a *Args) SetParam(k, v string) *Args {
	a.Params[k] = v
	return a
}

func (a *Args) GetParam(k string) string {
	return a.Params[k]
}

func (a *Args) SetHeader(k, v string) *Args {
	a.Headers[k] = v
	return a
}

func (a *Args) GetHeader(k string) string {
	return a.Headers[k]
}

func (a *Args) SetArg(k, v string) *Args {
	a.Args[k] = v
	return a
}

func (a *Args) GetArg(k string) string {
	return a.Args[k]
}

func (a *Args) Encode() string {
	var sorted sortedArgs
	for k, v := range a.Params {
		sorted.Params = append(sorted.Params, &kv{
			K: k,
			V: v,
		})
	}
	for k, v := range a.Headers {
		sorted.Headers = append(sorted.Headers, &kv{
			K: k,
			V: v,
		})
	}
	for k, v := range a.Args {
		sorted.Args = append(sorted.Args, &kv{
			K: k,
			V: v,
		})
	}

	sort.SliceStable(sorted.Params, func(i, j int) bool {
		return sorted.Params[i].K < sorted.Params[j].K
	})
	sort.SliceStable(sorted.Headers, func(i, j int) bool {
		return sorted.Headers[i].K < sorted.Headers[j].K
	})
	sort.SliceStable(sorted.Args, func(i, j int) bool {
		return sorted.Args[i].K < sorted.Args[j].K
	})

	enc, err := json.Marshal(sorted)
	if err != nil {
		panic(err)
	}

	b := new(bytes.Buffer)
	w := gzip.NewWriter(b)
	if _, err := w.Write(enc); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b.Bytes())
}
