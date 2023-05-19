package reporting

type AuthReq struct {
	Method string `json:"m"`
	URI    string `json:"u"`
	Args   string `json:"a"`
	Sig    string `json:"s"`
}

type LogV1 struct {
	Version int `json:"ver"`

	Req AuthReq `json:"r"`

	CidSize int   `json:"sz"`
	Ingress int   `json:"i"`
	Egress  int   `json:"e"`
	At      int64 `json:"at"`
}
