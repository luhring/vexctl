package grypejson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/openvex/vexctl/pkg/formats"
)

type Format struct {
	wrapped models.Document
}

func Parse(input io.Reader) (Format, error) {
	dec := json.NewDecoder(input)
	d := new(models.Document)
	err := dec.Decode(d)
	if err != nil {
		return Format{}, fmt.Errorf("unable to parse Grype JSON data: %w", err)
	}

	return Format{
		wrapped: *d,
	}, nil
}

func (f Format) Normalized() formats.Normalized {
	matches := make([]formats.Match, 0, len(f.wrapped.Matches))
	for _, m := range f.wrapped.Matches {
		matches = append(matches, normalizeMatch(m))
	}

	normalized := formats.Normalized{
		Matches: matches,
		Distro:  f.wrapped.Distro.Name,
	}

	return normalized
}

func normalizeMatch(m models.Match) formats.Match {
	return formats.Match{
		Package: formats.Package{
			Name:              m.Artifact.Name,
			Version:           m.Artifact.Version,
			Type:              string(m.Artifact.Type),
			OriginPackageName: getOriginPackageName(m.Artifact),
			Locations:         getPackageLocations(m.Artifact),
		},
		Vulnerability: formats.Vulnerability{
			ID:          m.Vulnerability.ID,
			Severity:    m.Vulnerability.Severity,
			URL:         m.Vulnerability.DataSource,
			Description: m.Vulnerability.Description,
		},
	}
}

func getOriginPackageName(p models.Package) string {
	if len(p.Upstreams) >= 1 {
		return p.Upstreams[0].Name
	}

	return ""
}

func getPackageLocations(p models.Package) []string {
	locations := make([]string, 0, len(p.Locations))

	for _, l := range p.Locations {
		locations = append(locations, l.RealPath)
	}

	return locations
}
