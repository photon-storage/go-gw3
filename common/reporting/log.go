package reporting

type AuthReq struct {
	Method string `json:"m"`
	Host   string `json:"h"`
	URI    string `json:"u"`
	Args   string `json:"a"`
	Sig    string `json:"s"`
}

type LogV1 struct {
	Version int `json:"ver"`

	Req AuthReq `json:"r"`

	InProgress  bool  `json:"ipr"`
	PinnedBytes int   `json:"sz"`
	PinnedCount int   `json:"cnt"`
	Ingress     int   `json:"i"`
	Egress      int   `json:"e"`
	At          int64 `json:"at"`
}
