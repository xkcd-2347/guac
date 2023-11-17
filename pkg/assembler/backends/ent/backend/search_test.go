//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build integration

package backend

import (
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

var p5 = &model.PkgInputSpec{
	Type:      p4.Type,
	Namespace: p4.Namespace,
	Name:      p4.Name,
	Version:   ptrfrom.String("3.0.4"),
}

var p5out = &model.Package{
	Type: p4out.Type,
	Namespaces: []*model.PackageNamespace{{
		Namespace: p4out.Namespaces[0].Namespace,
		Names: []*model.PackageName{{
			Name: p4out.Namespaces[0].Names[0].Name,
			Versions: []*model.PackageVersion{{
				Version:    p4out.Namespaces[0].Names[0].Versions[0].Version,
				Qualifiers: []*model.PackageQualifier{},
			}},
		}},
	}},
}

var p6 = &model.PkgInputSpec{
	Type:    p2.Type,
	Name:    p2.Name,
	Version: ptrfrom.String("3.0.4"),
}

func (s *Suite) Test_FindSoftware() {
	b, err := GetBackend(s.Client)
	s.NoError(err)

	for _, p := range []*model.PkgInputSpec{p1, p2, p3} {
		if _, err := b.IngestPackage(s.Ctx, *p); err != nil {
			s.NoError(err)
		}
	}

	for _, src := range []*model.SourceInputSpec{s1, s2} {
		if _, err := b.IngestSource(s.Ctx, *src); err != nil {
			s.NoError(err)
		}
	}

	for _, art := range []*model.ArtifactInputSpec{a1} {
		if _, err := b.IngestArtifact(s.Ctx, art); err != nil {
			s.NoError(err)
		}
	}

	// Find a package
	results, err := b.FindSoftware(s.Ctx, "tensor")
	s.NoError(err)

	if diff := cmp.Diff([]model.PackageSourceOrArtifact{p1out, p2out, p3out}, results, ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}

	// Find a source
	results, err = b.FindSoftware(s.Ctx, "bobs")
	s.NoError(err)

	if diff := cmp.Diff([]model.PackageSourceOrArtifact{s2out}, results, ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}

	// Find an artifact
	results, err = b.FindSoftware(s.Ctx, "6bbb0da")
	s.NoError(err)

	if diff := cmp.Diff([]model.PackageSourceOrArtifact{a1out}, results, ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}

	// Find with empty query
	results, err = b.FindSoftware(s.Ctx, "")
	s.NoError(err)

	if diff := cmp.Diff([]model.PackageSourceOrArtifact{}, results, ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}
}

func (s *Suite) Test_FindTopLevelPackagesRelatedToVulnerability() {
	type IsDependency struct {
		P1 model.PkgInputSpec
		P2 model.PkgInputSpec
		MF model.MatchFlags
		ID model.IsDependencyInputSpec
	}
	type HasSBOM struct {
		Sub model.PackageOrArtifactInput
		HS  model.HasSBOMInputSpec
	}
	type CertifyVEXStatement struct {
		Sub  model.PackageOrArtifactInput
		Vuln model.VulnerabilityInputSpec
		In   model.VexStatementInputSpec
	}
	type CertifyVuln struct {
		Pkg         *model.PkgInputSpec
		Vuln        *model.VulnerabilityInputSpec
		CertifyVuln *model.ScanMetadataInput
	}
	tests := []struct {
		name                  string
		InPkg                 []*model.PkgInputSpec
		InIsDependency        []IsDependency
		InHasSBOM             []HasSBOM
		InVulnerability       []*model.VulnerabilityInputSpec
		InCertifyVexStatement []CertifyVEXStatement
		InCertifyVuln         []CertifyVuln
		query                 string
		want                  [][]model.Node
		wantErr               bool
	}{
		{
			name:  "Happy Path - VEX",
			InPkg: []*model.PkgInputSpec{p1, p4, p5},
			// p1 is a dependency ONLY of p4
			InIsDependency: []IsDependency{
				{
					P1: *p4,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			// both p4 and p5 are top level packages, i.e. with an SBOM
			InHasSBOM: []HasSBOM{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p4,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p5,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			InVulnerability: []*model.VulnerabilityInputSpec{{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			}},
			// vulnerability relates to p1
			InCertifyVexStatement: []CertifyVEXStatement{{
				Sub: model.PackageOrArtifactInput{
					Package: p1,
				},
				Vuln: model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				In: model.VexStatementInputSpec{
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			}},
			query: "cve-2019-13110",
			want: [][]model.Node{{
				&model.CertifyVEXStatement{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type: "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{
							{VulnerabilityID: "cve-2019-13110"},
						},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
				p1out,
				&model.IsDependency{
					Package:           p4out,
					DependencyPackage: p1out,
					DependencyType:    model.DependencyTypeUnknown,
					Justification:     "test justification",
				},
				p5out,
			}},
			wantErr: false,
		},
		{
			name:  "Happy Path - Vuln",
			InPkg: []*model.PkgInputSpec{p1, p4, p5},
			// p1 is a dependency ONLY of p4
			InIsDependency: []IsDependency{
				{
					P1: *p4,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			// both p4 and p5 are top level packages, i.e. with an SBOM
			InHasSBOM: []HasSBOM{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p4,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p5,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			InVulnerability: []*model.VulnerabilityInputSpec{{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			}},
			// vulnerability relates to p1
			InCertifyVuln: []CertifyVuln{{
				Pkg: p1,
				Vuln: &model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				CertifyVuln: &model.ScanMetadataInput{
					Collector:      "test collector",
					Origin:         "test origin",
					ScannerVersion: "v1.0.0",
					ScannerURI:     "test scanner uri",
					DbVersion:      "2023.01.01",
					DbURI:          "test db uri",
					TimeScanned:    testdata.T1,
				},
			}},
			query: "cve-2019-13110",
			want: [][]model.Node{{
				&model.CertifyVuln{
					Package: p1out,
					Vulnerability: &model.Vulnerability{
						Type: "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{
							{VulnerabilityID: "cve-2019-13110"},
						},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
				p1out,
				&model.IsDependency{
					Package:           p4out,
					DependencyPackage: p1out,
					DependencyType:    model.DependencyTypeUnknown,
					Justification:     "test justification",
				},
				p5out,
			}},
			wantErr: false,
		},
		{
			name:  "No package with SBOM found",
			InPkg: []*model.PkgInputSpec{p1, p4, p5},
			// p1 is a dependency ONLY of p4
			InIsDependency: []IsDependency{
				{
					P1: *p4,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			InHasSBOM: []HasSBOM{},
			InVulnerability: []*model.VulnerabilityInputSpec{{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			}},
			// vulnerability relates to p1
			InCertifyVuln: []CertifyVuln{{
				Pkg: p1,
				Vuln: &model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				CertifyVuln: &model.ScanMetadataInput{
					Collector:      "test collector",
					Origin:         "test origin",
					ScannerVersion: "v1.0.0",
					ScannerURI:     "test scanner uri",
					DbVersion:      "2023.01.01",
					DbURI:          "test db uri",
					TimeScanned:    testdata.T1,
				},
			}},
			query:   "cve-2019-13110",
			want:    [][]model.Node{},
			wantErr: false,
		},
		{
			name:  "VEX exclude not affected",
			InPkg: []*model.PkgInputSpec{p1, p4, p5},
			// p1 is a dependency ONLY of p4
			InIsDependency: []IsDependency{
				{
					P1: *p4,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			// both p4 and p5 are top level packages, i.e. with an SBOM
			InHasSBOM: []HasSBOM{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p4,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p5,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			InVulnerability: []*model.VulnerabilityInputSpec{{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			}},
			// vulnerability relates to p1
			InCertifyVexStatement: []CertifyVEXStatement{{
				Sub: model.PackageOrArtifactInput{
					Package: p1,
				},
				Vuln: model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				In: model.VexStatementInputSpec{
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			}, {
				Sub: model.PackageOrArtifactInput{
					Package: p4,
				},
				Vuln: model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				In: model.VexStatementInputSpec{
					Status:           model.VexStatusNotAffected,
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			}},
			query: "cve-2019-13110",
			want: [][]model.Node{{
				&model.CertifyVEXStatement{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type: "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{
							{VulnerabilityID: "cve-2019-13110"},
						},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
				p1out,
				&model.IsDependency{
					Package:           p4out,
					DependencyPackage: p1out,
					DependencyType:    model.DependencyTypeUnknown,
					Justification:     "test justification",
				},
				p5out,
			}},
			wantErr: false,
		},
	}
	ctx := s.Ctx
	for _, tt := range tests {
		s.Run(tt.name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}

			_, err = b.IngestPackages(ctx, tt.InPkg)
			if err != nil {
				t.Fatalf("did not get expected ingest error, %v", err)
			}
			if err != nil {
				return
			}

			for _, isDependency := range tt.InIsDependency {
				_, err := b.IngestDependency(ctx, isDependency.P1, isDependency.P2, isDependency.MF, isDependency.ID)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			for _, hasSBOM := range tt.InHasSBOM {
				_, err := b.IngestHasSbom(ctx, hasSBOM.Sub, hasSBOM.HS)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			_, err = b.IngestVulnerabilities(ctx, tt.InVulnerability)
			if err != nil {
				t.Fatalf("did not get expected ingest error, %v", err)
			}
			if err != nil {
				return
			}

			for _, vexStatement := range tt.InCertifyVexStatement {
				_, err := b.IngestVEXStatement(ctx, vexStatement.Sub, vexStatement.Vuln, vexStatement.In)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			for _, vuln := range tt.InCertifyVuln {
				_, err := b.IngestCertifyVuln(ctx, *vuln.Pkg, *vuln.Vuln, *vuln.CertifyVuln)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			got, err := b.FindTopLevelPackagesRelatedToVulnerability(ctx, tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindTopLevelPackagesRelatedToVulnerability error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) Test_FindVulnerability() {
	type IsDependency struct {
		P1 model.PkgInputSpec
		P2 model.PkgInputSpec
		MF model.MatchFlags
		ID model.IsDependencyInputSpec
	}
	type HasMetadata struct {
		Sub model.PackageSourceOrArtifactInput
		PMT *model.MatchFlags
		HM  model.HasMetadataInputSpec
	}
	type HasSBOM struct {
		Sub model.PackageOrArtifactInput
		HS  model.HasSBOMInputSpec
	}
	type CertifyVEXStatement struct {
		Sub  model.PackageOrArtifactInput
		Vuln model.VulnerabilityInputSpec
		In   model.VexStatementInputSpec
	}
	type CertifyVuln struct {
		Pkg         *model.PkgInputSpec
		Vuln        *model.VulnerabilityInputSpec
		CertifyVuln *model.ScanMetadataInput
	}
	tests := []struct {
		name                  string
		InPkg                 []*model.PkgInputSpec
		InIsDependency        []IsDependency
		InHasMetadata         []HasMetadata
		InHasSBOM             []HasSBOM
		InVulnerability       []*model.VulnerabilityInputSpec
		InCertifyVexStatement []CertifyVEXStatement
		InCertifyVuln         []CertifyVuln
		query                 string
		want                  []model.CertifyVulnOrCertifyVEXStatement
		wantErr               bool
	}{
		{
			name:  "Happy Path - VEX",
			InPkg: []*model.PkgInputSpec{p1, p6, p5},
			// p1 is a dependency ONLY of p6
			InIsDependency: []IsDependency{
				{
					P1: *p6,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			InHasMetadata: []HasMetadata{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
			},
			// both p6 and p5 are top level packages, i.e. with an SBOM
			InHasSBOM: []HasSBOM{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p6,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p5,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			InVulnerability: []*model.VulnerabilityInputSpec{{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			}},
			// vulnerability relates to p1
			InCertifyVexStatement: []CertifyVEXStatement{{
				Sub: model.PackageOrArtifactInput{
					Package: p1,
				},
				Vuln: model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				In: model.VexStatementInputSpec{
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			}},
			query: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
			want: []model.CertifyVulnOrCertifyVEXStatement{
				&model.CertifyVEXStatement{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type: "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{
							{VulnerabilityID: "cve-2019-13110"},
						},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
			wantErr: false,
		},
		{
			name:  "Happy Path - Vuln",
			InPkg: []*model.PkgInputSpec{p1, p6, p5},
			// p1 is a dependency ONLY of p6
			InIsDependency: []IsDependency{
				{
					P1: *p6,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			InHasMetadata: []HasMetadata{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
			},
			// both p6 and p5 are top level packages, i.e. with an SBOM
			InHasSBOM: []HasSBOM{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p6,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p5,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			InVulnerability: []*model.VulnerabilityInputSpec{{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			}},
			// vulnerability relates to p1
			InCertifyVuln: []CertifyVuln{{
				Pkg: p1,
				Vuln: &model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				CertifyVuln: &model.ScanMetadataInput{
					Collector:      "test collector",
					Origin:         "test origin",
					ScannerVersion: "v1.0.0",
					ScannerURI:     "test scanner uri",
					DbVersion:      "2023.01.01",
					DbURI:          "test db uri",
					TimeScanned:    testdata.T1,
				},
			}},
			query: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
			want: []model.CertifyVulnOrCertifyVEXStatement{
				&model.CertifyVuln{
					Package: p1out,
					Vulnerability: &model.Vulnerability{
						Type: "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{
							{VulnerabilityID: "cve-2019-13110"},
						},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "No package with SBOM found",
			query:   helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
			wantErr: true,
		},
		{
			name:  "VEX exclude not affected",
			InPkg: []*model.PkgInputSpec{p1, p6, p5},
			// p1 is a dependency ONLY of p6
			InIsDependency: []IsDependency{
				{
					P1: *p6,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			InHasMetadata: []HasMetadata{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
			},
			// both p6 and p5 are top level packages, i.e. with an SBOM
			InHasSBOM: []HasSBOM{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p6,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p5,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			InVulnerability: []*model.VulnerabilityInputSpec{{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			}},
			// vulnerability relates to p1
			InCertifyVexStatement: []CertifyVEXStatement{{
				Sub: model.PackageOrArtifactInput{
					Package: p1,
				},
				Vuln: model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				In: model.VexStatementInputSpec{
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			}, {
				Sub: model.PackageOrArtifactInput{
					Package: p6,
				},
				Vuln: model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				In: model.VexStatementInputSpec{
					Status:           model.VexStatusNotAffected,
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			}},
			query: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
			want: []model.CertifyVulnOrCertifyVEXStatement{
				&model.CertifyVEXStatement{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type: "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{
							{VulnerabilityID: "cve-2019-13110"},
						},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
			wantErr: false,
		},
	}
	ctx := s.Ctx
	for _, tt := range tests {
		s.Run(tt.name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}

			_, err = b.IngestPackages(ctx, tt.InPkg)
			if err != nil {
				t.Fatalf("did not get expected ingest error, %v", err)
			}
			if err != nil {
				return
			}

			for _, isDependency := range tt.InIsDependency {
				_, err := b.IngestDependency(ctx, isDependency.P1, isDependency.P2, isDependency.MF, isDependency.ID)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			for _, hasMetadata := range tt.InHasMetadata {
				_, err := b.IngestHasMetadata(ctx, hasMetadata.Sub, hasMetadata.PMT, hasMetadata.HM)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			for _, hasSBOM := range tt.InHasSBOM {
				_, err := b.IngestHasSbom(ctx, hasSBOM.Sub, hasSBOM.HS)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			_, err = b.IngestVulnerabilities(ctx, tt.InVulnerability)
			if err != nil {
				t.Fatalf("did not get expected ingest error, %v", err)
			}
			if err != nil {
				return
			}

			for _, vexStatement := range tt.InCertifyVexStatement {
				_, err := b.IngestVEXStatement(ctx, vexStatement.Sub, vexStatement.Vuln, vexStatement.In)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			for _, vuln := range tt.InCertifyVuln {
				_, err := b.IngestCertifyVuln(ctx, *vuln.Pkg, *vuln.Vuln, *vuln.CertifyVuln)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			got, err := b.FindVulnerability(ctx, tt.query, nil, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindTopLevelPackagesRelatedToVulnerability error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) Test_FindVulnerabilityCPE() {
	type IsDependency struct {
		P1 model.PkgInputSpec
		P2 model.PkgInputSpec
		MF model.MatchFlags
		ID model.IsDependencyInputSpec
	}
	type HasMetadata struct {
		Sub model.PackageSourceOrArtifactInput
		PMT *model.MatchFlags
		HM  model.HasMetadataInputSpec
	}
	type HasSBOM struct {
		Sub model.PackageOrArtifactInput
		HS  model.HasSBOMInputSpec
	}
	type CertifyVEXStatement struct {
		Sub  model.PackageOrArtifactInput
		Vuln model.VulnerabilityInputSpec
		In   model.VexStatementInputSpec
	}
	type CertifyVuln struct {
		Pkg         *model.PkgInputSpec
		Vuln        *model.VulnerabilityInputSpec
		CertifyVuln *model.ScanMetadataInput
	}
	tests := []struct {
		name                  string
		InPkg                 []*model.PkgInputSpec
		InIsDependency        []IsDependency
		InHasMetadata         []HasMetadata
		InHasSBOM             []HasSBOM
		InVulnerability       []*model.VulnerabilityInputSpec
		InCertifyVexStatement []CertifyVEXStatement
		InCertifyVuln         []CertifyVuln
		query                 string
		want                  []model.CertifyVulnOrCertifyVEXStatement
		wantErr               bool
	}{
		{
			name:  "Happy Path - VEX",
			InPkg: []*model.PkgInputSpec{p1, p6, p5},
			// p1 is a dependency ONLY of p6
			InIsDependency: []IsDependency{
				{
					P1: *p6,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			InHasMetadata: []HasMetadata{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "cpe",
						Value: "cpe:/o:redhat:enterprise_linux:7::server",
					},
				},
			},
			// both p6 and p5 are top level packages, i.e. with an SBOM
			InHasSBOM: []HasSBOM{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p6,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p5,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			InVulnerability: []*model.VulnerabilityInputSpec{{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			}},
			// vulnerability relates to p1
			InCertifyVexStatement: []CertifyVEXStatement{{
				Sub: model.PackageOrArtifactInput{
					Package: p1,
				},
				Vuln: model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				In: model.VexStatementInputSpec{
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			}},
			query: "cpe:/o:redhat:enterprise_linux:7::server",
			want: []model.CertifyVulnOrCertifyVEXStatement{
				&model.CertifyVEXStatement{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type: "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{
							{VulnerabilityID: "cve-2019-13110"},
						},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
			wantErr: false,
		},
		{
			name:  "Happy Path - Vuln",
			InPkg: []*model.PkgInputSpec{p1, p6, p5},
			// p1 is a dependency ONLY of p6
			InIsDependency: []IsDependency{
				{
					P1: *p6,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			InHasMetadata: []HasMetadata{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "cpe",
						Value: "cpe:/o:redhat:enterprise_linux:7::server",
					},
				},
			},
			// both p6 and p5 are top level packages, i.e. with an SBOM
			InHasSBOM: []HasSBOM{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p6,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p5,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			InVulnerability: []*model.VulnerabilityInputSpec{{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			}},
			// vulnerability relates to p1
			InCertifyVuln: []CertifyVuln{{
				Pkg: p1,
				Vuln: &model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				CertifyVuln: &model.ScanMetadataInput{
					Collector:      "test collector",
					Origin:         "test origin",
					ScannerVersion: "v1.0.0",
					ScannerURI:     "test scanner uri",
					DbVersion:      "2023.01.01",
					DbURI:          "test db uri",
					TimeScanned:    testdata.T1,
				},
			}},
			query: "cpe:/o:redhat:enterprise_linux:7::server",
			want: []model.CertifyVulnOrCertifyVEXStatement{
				&model.CertifyVuln{
					Package: p1out,
					Vulnerability: &model.Vulnerability{
						Type: "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{
							{VulnerabilityID: "cve-2019-13110"},
						},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "No package with SBOM found",
			query:   "cpe:/o:redhat:enterprise_linux:7::server",
			wantErr: true,
		},
	}
	ctx := s.Ctx
	for _, tt := range tests {
		s.Run(tt.name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}

			_, err = b.IngestPackages(ctx, tt.InPkg)
			if err != nil {
				t.Fatalf("did not get expected ingest error, %v", err)
			}
			if err != nil {
				return
			}

			for _, isDependency := range tt.InIsDependency {
				_, err := b.IngestDependency(ctx, isDependency.P1, isDependency.P2, isDependency.MF, isDependency.ID)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			for _, hasMetadata := range tt.InHasMetadata {
				_, err := b.IngestHasMetadata(ctx, hasMetadata.Sub, hasMetadata.PMT, hasMetadata.HM)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			for _, hasSBOM := range tt.InHasSBOM {
				_, err := b.IngestHasSbom(ctx, hasSBOM.Sub, hasSBOM.HS)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			_, err = b.IngestVulnerabilities(ctx, tt.InVulnerability)
			if err != nil {
				t.Fatalf("did not get expected ingest error, %v", err)
			}
			if err != nil {
				return
			}

			for _, vexStatement := range tt.InCertifyVexStatement {
				_, err := b.IngestVEXStatement(ctx, vexStatement.Sub, vexStatement.Vuln, vexStatement.In)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			for _, vuln := range tt.InCertifyVuln {
				_, err := b.IngestCertifyVuln(ctx, *vuln.Pkg, *vuln.Vuln, *vuln.CertifyVuln)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			got, err := b.FindVulnerabilityCPE(ctx, tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindTopLevelPackagesRelatedToVulnerability error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
func (s *Suite) Test_FindVulnerabilitySbomURI() {
	type IsDependency struct {
		P1 model.PkgInputSpec
		P2 model.PkgInputSpec
		MF model.MatchFlags
		ID model.IsDependencyInputSpec
	}
	type HasMetadata struct {
		Sub model.PackageSourceOrArtifactInput
		PMT *model.MatchFlags
		HM  model.HasMetadataInputSpec
	}
	type HasSBOM struct {
		Sub model.PackageOrArtifactInput
		HS  model.HasSBOMInputSpec
	}
	type CertifyVEXStatement struct {
		Sub  model.PackageOrArtifactInput
		Vuln model.VulnerabilityInputSpec
		In   model.VexStatementInputSpec
	}
	type CertifyVuln struct {
		Pkg         *model.PkgInputSpec
		Vuln        *model.VulnerabilityInputSpec
		CertifyVuln *model.ScanMetadataInput
	}
	tests := []struct {
		name                  string
		InPkg                 []*model.PkgInputSpec
		InIsDependency        []IsDependency
		InHasMetadata         []HasMetadata
		InHasSBOM             []HasSBOM
		InVulnerability       []*model.VulnerabilityInputSpec
		InCertifyVexStatement []CertifyVEXStatement
		InCertifyVuln         []CertifyVuln
		query                 string
		want                  []model.CertifyVulnOrCertifyVEXStatement
		wantErr               bool
	}{
		{
			name:  "Happy Path - VEX",
			InPkg: []*model.PkgInputSpec{p1, p6, p5},
			// p1 is a dependency ONLY of p6
			InIsDependency: []IsDependency{
				{
					P1: *p6,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			InHasMetadata: []HasMetadata{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "cpe",
						Value: "cpe:/o:redhat:enterprise_linux:7::server",
					},
				},
			},
			// both p6 and p5 are top level packages, i.e. with an SBOM
			InHasSBOM: []HasSBOM{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p6,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri 1",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p5,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri 2",
					},
				},
			},
			InVulnerability: []*model.VulnerabilityInputSpec{{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			}},
			// vulnerability relates to p1
			InCertifyVexStatement: []CertifyVEXStatement{{
				Sub: model.PackageOrArtifactInput{
					Package: p1,
				},
				Vuln: model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				In: model.VexStatementInputSpec{
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			}},
			query: "test uri 1",
			want: []model.CertifyVulnOrCertifyVEXStatement{
				&model.CertifyVEXStatement{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type: "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{
							{VulnerabilityID: "cve-2019-13110"},
						},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
			wantErr: false,
		},
		{
			name:  "Happy Path - Vuln",
			InPkg: []*model.PkgInputSpec{p1, p6, p5},
			// p1 is a dependency ONLY of p6
			InIsDependency: []IsDependency{
				{
					P1: *p6,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			InHasMetadata: []HasMetadata{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "topLevelPackage",
						Value: helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "cpe",
						Value: "cpe:/o:redhat:enterprise_linux:7::server",
					},
				},
			},
			// both p6 and p5 are top level packages, i.e. with an SBOM
			InHasSBOM: []HasSBOM{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p6,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri 1",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p5,
					},
					HS: model.HasSBOMInputSpec{
						URI: "test uri 2",
					},
				},
			},
			InVulnerability: []*model.VulnerabilityInputSpec{{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			}},
			// vulnerability relates to p1
			InCertifyVuln: []CertifyVuln{{
				Pkg: p1,
				Vuln: &model.VulnerabilityInputSpec{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				CertifyVuln: &model.ScanMetadataInput{
					Collector:      "test collector",
					Origin:         "test origin",
					ScannerVersion: "v1.0.0",
					ScannerURI:     "test scanner uri",
					DbVersion:      "2023.01.01",
					DbURI:          "test db uri",
					TimeScanned:    testdata.T1,
				},
			}},
			query: "test uri 1",
			want: []model.CertifyVulnOrCertifyVEXStatement{
				&model.CertifyVuln{
					Package: p1out,
					Vulnerability: &model.Vulnerability{
						Type: "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{
							{VulnerabilityID: "cve-2019-13110"},
						},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "No package with SBOM found",
			query:   "test uri 1",
			wantErr: true,
		},
	}
	ctx := s.Ctx
	for _, tt := range tests {
		s.Run(tt.name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}

			_, err = b.IngestPackages(ctx, tt.InPkg)
			if err != nil {
				t.Fatalf("did not get expected ingest error, %v", err)
			}
			if err != nil {
				return
			}

			for _, isDependency := range tt.InIsDependency {
				_, err := b.IngestDependency(ctx, isDependency.P1, isDependency.P2, isDependency.MF, isDependency.ID)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			for _, hasMetadata := range tt.InHasMetadata {
				_, err := b.IngestHasMetadata(ctx, hasMetadata.Sub, hasMetadata.PMT, hasMetadata.HM)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			for _, hasSBOM := range tt.InHasSBOM {
				_, err := b.IngestHasSbom(ctx, hasSBOM.Sub, hasSBOM.HS)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			_, err = b.IngestVulnerabilities(ctx, tt.InVulnerability)
			if err != nil {
				t.Fatalf("did not get expected ingest error, %v", err)
			}
			if err != nil {
				return
			}

			for _, vexStatement := range tt.InCertifyVexStatement {
				_, err := b.IngestVEXStatement(ctx, vexStatement.Sub, vexStatement.Vuln, vexStatement.In)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			for _, vuln := range tt.InCertifyVuln {
				_, err := b.IngestCertifyVuln(ctx, *vuln.Pkg, *vuln.Vuln, *vuln.CertifyVuln)
				if err != nil {
					t.Fatalf("did not get expected ingest error, %v", err)
				}
				if err != nil {
					return
				}
			}

			got, err := b.FindVulnerabilitySbomURI(ctx, tt.query, ptrfrom.Int(0), ptrfrom.Int(10))
			if (err != nil) != tt.wantErr {
				t.Errorf("FindTopLevelPackagesRelatedToVulnerability error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
