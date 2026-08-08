package buildinfo

const (
	Protocol = "eventctl/v2"
)

var (
	Version = "0.2.0-dev"
	Commit  = "dev"
)

type Info struct {
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Protocol string `json:"protocol"`
}

func Current() Info { return Info{Version, Commit, Protocol} }
