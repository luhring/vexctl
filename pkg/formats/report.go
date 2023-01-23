package formats

type Normalized struct {
	Matches []Match
	Distro  string
}

type Match struct {
	Package       Package
	Vulnerability Vulnerability
}

type Package struct {
	Name              string
	Version           string
	Type              string
	OriginPackageName string
	Locations         []string
}

type Vulnerability struct {
	ID          string
	Severity    string
	URL         string
	Description string
}

type Format interface {
	Normalized() Normalized
}
