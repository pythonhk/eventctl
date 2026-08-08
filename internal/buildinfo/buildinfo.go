package buildinfo

const (
	Version = "0.1.0"
	Commit  = "dev"
)

type Info struct {
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Protocol string `json:"protocol"`
}

func Current() Info { return Info{Version, Commit, "eventctl/v1"} }
