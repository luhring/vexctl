/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package ctl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	gosarif "github.com/owenrumney/go-sarif/sarif"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/release-utils/util"

	"github.com/openvex/go-vex/pkg/sarif"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/openvex/vexctl/pkg/attestation"
)

const IntotoPayloadType = "application/vnd.in-toto+json"

type Implementation interface {
	ApplySingleVEX(*sarif.Report, *vex.VEX) (*sarif.Report, error)
	SortDocuments([]*vex.VEX) []*vex.VEX
	OpenVexData(Options, []string) ([]*vex.VEX, error)
	Sort(docs []*vex.VEX) []*vex.VEX
	AttestationBytes(*attestation.Attestation) ([]byte, error)
	Attach(context.Context, *attestation.Attestation, string) error
	SourceType(uri string) (string, error)
	ReadImageAttestations(context.Context, Options, string) ([]*vex.VEX, error)
	Merge(context.Context, *MergeOptions, []*vex.VEX) (*vex.VEX, error)
	LoadFiles(context.Context, []string) ([]*vex.VEX, error)
}

type defaultVexCtlImplementation struct{}

var cveRegexp regexp.Regexp

func init() {
	cveRegexp = *regexp.MustCompile(`^(CVE-\d+-\d+)`)
}

func (impl *defaultVexCtlImplementation) SortDocuments(docs []*vex.VEX) []*vex.VEX {
	return vex.SortDocuments(docs)
}

func (impl *defaultVexCtlImplementation) ApplySingleVEX(report *sarif.Report, vexDoc *vex.VEX) (*sarif.Report, error) {
	newReport := *report
	logrus.Infof("VEX document contains %d statements", len(vexDoc.Statements))
	logrus.Infof("+%v Runs: %d\n", report, len(report.Runs))
	// Search for negative VEX statements, that is those that cancel a CVE
	for i := range report.Runs {
		newResults := []*gosarif.Result{}
		logrus.Infof("Inspecting run #%d containing %d results", i, len(report.Runs[i].Results))
		for _, res := range report.Runs[i].Results {
			// Normalize the CVE IDs
			m := cveRegexp.FindStringSubmatch(*res.RuleID)
			if len(m) != 2 {
				logrus.Errorf(
					"Invalid rulename in sarif report, expected CVE identifier, got %s",
					*res.RuleID,
				)
				newResults = append(newResults, res)
				continue
			}
			id := m[1]
			// TODO: Trim rule ID to CVE as Grype adds junk to the CVE ID
			statement := vexDoc.StatementFromID(id)
			logrus.Infof("Checking %s", id)
			if statement != nil {
				logrus.Infof("Statement is for %s and status is %s", statement.Vulnerability, statement.Status)
				if statement.Status == vex.StatusNotAffected ||
					statement.Status == vex.StatusFixed {
					logrus.Infof("Found VEX Statement for %s: %s", id, statement.Status)
					continue
				}
			}
			newResults = append(newResults, res)
		}
		newReport.Runs[i].Results = newResults
	}
	return &newReport, nil
}

// OpenVexData returns a set of vex documents from the paths received
func (impl *defaultVexCtlImplementation) OpenVexData(opts Options, paths []string) ([]*vex.VEX, error) {
	vexes := []*vex.VEX{}
	for _, path := range paths {
		var v *vex.VEX
		var err error
		switch opts.Format {
		case "vex", "json", "":
			v, err = vex.OpenJSON(path)
		case "yaml":
			v, err = vex.OpenYAML(path)
		case "csaf":
			v, err = vex.OpenCSAF(path, opts.Products)
		}
		if err != nil {
			return nil, fmt.Errorf("opening document: %w", err)
		}
		vexes = append(vexes, v)
	}
	return vexes, nil
}

func (impl *defaultVexCtlImplementation) Sort(docs []*vex.VEX) []*vex.VEX {
	return vex.SortDocuments(docs)
}

func (impl *defaultVexCtlImplementation) AttestationBytes(att *attestation.Attestation) ([]byte, error) {
	var b bytes.Buffer
	if err := att.ToJSON(&b); err != nil {
		return nil, fmt.Errorf("serializing attestation to json: %w", err)
	}
	return b.Bytes(), nil
}

func (impl *defaultVexCtlImplementation) Attach(ctx context.Context, att *attestation.Attestation, imageRef string) error {
	env := ssldsse.Envelope{}
	regOpts := options.RegistryOptions{}
	remoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("getting OCI remote options: %w", err)
	}

	var b bytes.Buffer
	if err := att.ToJSON(&b); err != nil {
		return fmt.Errorf("getting attestation JSON")
	}
	decoder := json.NewDecoder(&b)
	for decoder.More() {
		if err := decoder.Decode(&env); err != nil {
			return err
		}

		payload, err := json.Marshal(env)
		if err != nil {
			return err
		}

		if env.PayloadType != IntotoPayloadType {
			return fmt.Errorf("invalid payloadType %s on envelope. Expected %s", env.PayloadType, types.IntotoPayloadType)
		}

		ref, err := name.ParseReference(imageRef)
		if err != nil {
			return err
		}
		digest, err := ociremote.ResolveDigest(ref, remoteOpts...)
		if err != nil {
			return err
		}
		// Overwrite "ref" with a digest to avoid a race where we use a tag
		// multiple times, and it potentially points to different things at
		// each access.
		ref = digest //nolint:ineffassign

		opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
		att, err := static.NewAttestation(payload, opts...)
		if err != nil {
			return err
		}

		se, err := ociremote.SignedEntity(digest, remoteOpts...)
		if err != nil {
			return err
		}

		newSE, err := mutate.AttachAttestationToEntity(se, att)
		if err != nil {
			return err
		}

		// Publish the signatures associated with this entity
		err = ociremote.WriteAttestations(digest.Repository, newSE, remoteOpts...)
		if err != nil {
			return err
		}
	}

	return nil
}

// SourceType returns a string indicating what kind of vex
// source a URI points to
func (impl *defaultVexCtlImplementation) SourceType(uri string) (string, error) {
	if util.Exists(uri) {
		return "file", nil
	}

	_, err := name.ParseReference(uri)
	if err == nil {
		return "image", nil
	}

	return "", errors.New("unable to resolve the vex source location")
}

// DownloadAttestation
func (impl *defaultVexCtlImplementation) ReadImageAttestations(
	ctx context.Context, opts Options, refString string,
) (vexes []*vex.VEX, err error) {
	// Parsae the image reference
	ref, err := name.ParseReference(refString)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference: %w", err)
	}
	regOpts := options.RegistryOptions{}
	remoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting OCI remote options: %w", err)
	}
	payloads, err := cosign.FetchAttestationsForReference(ctx, ref, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("fetching attached attestation: %w", err)
	}
	vexes = []*vex.VEX{}
	for _, dssePayload := range payloads {
		vexData, err := impl.ReadSignedVEX(dssePayload)
		if err != nil {
			return nil, fmt.Errorf("opening dsse payload: %w", err)
		}
		vexes = append(vexes, vexData)
	}
	return vexes, nil
}

// ReadSignedVEX returns the vex data inside a signed envelope
func (impl *defaultVexCtlImplementation) ReadSignedVEX(dssePayload cosign.AttestationPayload) (*vex.VEX, error) {
	if dssePayload.PayloadType != IntotoPayloadType {
		logrus.Info("Signed envelope does not contain an in-toto attestation")
		return nil, nil
	}

	data, err := base64.StdEncoding.DecodeString(dssePayload.PayLoad)
	if err != nil {
		return nil, fmt.Errorf("decoding signed attestation: %w", err)
	}
	fmt.Printf("%s\n", string(data))

	// Unmarshall the attestation
	att := &attestation.Attestation{}
	if err := json.Unmarshal(data, att); err != nil {
		return nil, fmt.Errorf("unmarshalling attestation JSON: %w", err)
	}

	if att.PredicateType != vex.TypeURI {
		return nil, nil
	}

	return &att.Predicate, nil
}

type MergeOptions struct {
	DocumentID      string   // ID to use in the new document
	Author          string   // Author to use in the new document
	AuthorRole      string   // Role of the document author
	Products        []string // Product IDs to consider
	Vulnerabilities []string // IDs of vulnerabilities to merge
}

// Merge combines the statements from a number of documents into
// a new one, preserving time context from each of them.
func (impl *defaultVexCtlImplementation) Merge(
	_ context.Context, mergeOpts *MergeOptions, docs []*vex.VEX,
) (*vex.VEX, error) {
	if len(docs) == 0 {
		return nil, fmt.Errorf("at least one vex document is required to merge")
	}

	docID := mergeOpts.DocumentID
	// If no document id is specified we compute a
	// deterministic ID using the merged docs
	if docID == "" {
		ids := []string{}
		for i, d := range docs {
			if d.ID == "" {
				ids = append(ids, fmt.Sprintf("VEX-DOC-%d", i))
			} else {
				ids = append(ids, d.ID)
			}
		}

		sort.Strings(ids)
		h := sha256.New()
		h.Write([]byte(strings.Join(ids, ":")))
		// Hash the sorted IDs list
		docID = fmt.Sprintf("merged-vex-%x", h.Sum(nil))
	}
	now := time.Now()
	newDoc := &vex.VEX{
		Metadata: vex.Metadata{
			ID:         docID, // TODO
			Author:     mergeOpts.Author,
			AuthorRole: mergeOpts.AuthorRole,
			Timestamp:  &now,
		},
	}

	t, err := vex.DateFromEnv()
	if err != nil {
		return nil, fmt.Errorf("reading date from env: %w", err)
	}

	if t != nil {
		newDoc.Metadata.Timestamp = t
	}

	ss := []vex.Statement{}

	iProds := map[string]struct{}{}
	iVulns := map[string]struct{}{}
	for _, id := range mergeOpts.Products {
		iProds[id] = struct{}{}
	}
	for _, id := range mergeOpts.Vulnerabilities {
		iVulns[id] = struct{}{}
	}

	for _, doc := range docs {
	LOOP_STATEMENTS:
		for _, s := range doc.Statements { //nolint:gocritic // this IS supposed to copy
			if len(iProds) > 0 {
				for _, pid := range s.Products {
					if _, ok := iProds[pid]; !ok {
						continue LOOP_STATEMENTS
					}
				}
			}

			if len(iVulns) > 0 {
				if _, ok := iProds[s.Vulnerability]; !ok {
					continue LOOP_STATEMENTS
				}
			}

			// If statement does not have a timestamp, cascade
			// the timestamp down from the document.
			// See https://github.com/chainguard-dev/vex/issues/49
			if s.Timestamp == nil {
				if doc.Timestamp == nil {
					return nil, errors.New("unable to cascade timestamp from doc to timeless statement")
				}
				s.Timestamp = doc.Timestamp
			}

			ss = append(ss, s)
		}
	}

	vex.SortStatements(ss, *newDoc.Metadata.Timestamp)

	newDoc.Statements = ss

	return newDoc, nil
}

// LoadFiles loads multiple vex files from disk
func (impl *defaultVexCtlImplementation) LoadFiles(
	_ context.Context, filePaths []string,
) ([]*vex.VEX, error) {
	vexes := make([]*vex.VEX, len(filePaths))
	for i, path := range filePaths {
		doc, err := vex.Load(path)
		if err != nil {
			return nil, fmt.Errorf("error loading file: %w", err)
		}
		vexes[i] = doc
	}
	return vexes, nil
}
