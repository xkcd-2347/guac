package inmem

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/backends"
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

func Test_demoClient_FindTopLevelPackagesRelatedToVulnerability(t *testing.T) {
	ctx := context.Background()
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
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := backends.Get("inmem", nil, nil)
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

func Test_demoClient_FindVulnerability(t *testing.T) {
	ctx := context.Background()
	type IsDependency struct {
		P1 model.PkgInputSpec
		P2 model.PkgInputSpec
		MF model.MatchFlags
		ID model.IsDependencyInputSpec
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
		InVulnerability       []*model.VulnerabilityInputSpec
		InCertifyVexStatement []CertifyVEXStatement
		InCertifyVuln         []CertifyVuln
		query                 string
		want                  []model.CertifyVulnOrCertifyVEXStatement
		wantErr               bool
	}{
		{
			name:  "Happy Path VEX",
			InPkg: []*model.PkgInputSpec{p1, p2, p6},
			// p1 is a dependency ONLY of p2
			InIsDependency: []IsDependency{
				{
					P1: *p2,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
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
			query: helpers.PkgToPurl(p2.Type, "", p2.Name, *p2.Version, "", []string{}),
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
			name:  "Happy Path VEX Finds nothing",
			InPkg: []*model.PkgInputSpec{p1, p2, p6},
			// p1 is a dependency ONLY of p2
			InIsDependency: []IsDependency{
				{
					P1: *p1,
					P2: *p2,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
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
			query:   helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
			want:    []model.CertifyVulnOrCertifyVEXStatement{},
			wantErr: false,
		},
		{
			name:  "Happy Path Vuln",
			InPkg: []*model.PkgInputSpec{p1, p2, p6},
			// p1 is a dependency ONLY of p2
			InIsDependency: []IsDependency{
				{
					P1: *p2,
					P2: *p1,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
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
			query: helpers.PkgToPurl(p2.Type, "", p2.Name, *p2.Version, "", []string{}),
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
			name:  "Happy Path Vuln Finds nothing",
			InPkg: []*model.PkgInputSpec{p1, p2, p6},
			// p1 is a dependency ONLY of p2
			InIsDependency: []IsDependency{
				{
					P1: *p1,
					P2: *p2,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
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
			query:   helpers.PkgToPurl(p6.Type, "", p6.Name, *p6.Version, "", []string{}),
			want:    []model.CertifyVulnOrCertifyVEXStatement{},
			wantErr: false,
		}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := backends.Get("inmem", nil, nil)
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

			//for _, hasSBOM := range tt.InHasSBOM {
			//	_, err := b.IngestHasSbom(ctx, hasSBOM.Sub, hasSBOM.HS)
			//	if err != nil {
			//		t.Fatalf("did not get expected ingest error, %v", err)
			//	}
			//	if err != nil {
			//		return
			//	}
			//}

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
				t.Errorf("FindVulnerability error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_demoClient_FindVulnerabilityCPE(t *testing.T) {
	ctx := context.Background()
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
		InVulnerability       []*model.VulnerabilityInputSpec
		InCertifyVexStatement []CertifyVEXStatement
		InCertifyVuln         []CertifyVuln
		query                 string
		want                  []model.CertifyVulnOrCertifyVEXStatement
		wantErr               bool
	}{
		{
			name:  "Happy Path VEX",
			InPkg: []*model.PkgInputSpec{p1, p2, p6},
			// p1 is a dependency ONLY of p2
			InIsDependency: []IsDependency{
				{
					P1: *p2,
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
						Package: p2,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "cpe",
						Value: "cpe:2.3:a:log4j-core:log4j_core:2.8.1:*:*:*:*:*:*:*",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "cpe",
						Value: "cpe:2.3:a:grep:grep:3.6-1:*:*:*:*:*:*:*",
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
			query: "cpe:2.3:a:log4j-core:log4j_core:2.8.1:*:*:*:*:*:*:*",
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
			name:  "Happy Path VEX Finds nothing",
			InPkg: []*model.PkgInputSpec{p1, p2, p6},
			// p1 is a dependency ONLY of p2
			InIsDependency: []IsDependency{
				{
					P1: *p1,
					P2: *p2,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			InHasMetadata: []HasMetadata{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p2,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "cpe",
						Value: "cpe:2.3:a:log4j-core:log4j_core:2.8.1:*:*:*:*:*:*:*",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "cpe",
						Value: "cpe:2.3:a:grep:grep:3.6-1:*:*:*:*:*:*:*",
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
			query:   "cpe:2.3:a:grep:grep:3.6-1:*:*:*:*:*:*:*",
			want:    []model.CertifyVulnOrCertifyVEXStatement{},
			wantErr: false,
		},
		{
			name:  "Happy Path Vuln",
			InPkg: []*model.PkgInputSpec{p1, p2, p6},
			// p1 is a dependency ONLY of p2
			InIsDependency: []IsDependency{
				{
					P1: *p2,
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
						Package: p2,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "cpe",
						Value: "cpe:2.3:a:log4j-core:log4j_core:2.8.1:*:*:*:*:*:*:*",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "cpe",
						Value: "cpe:2.3:a:grep:grep:3.6-1:*:*:*:*:*:*:*",
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
			query: "cpe:2.3:a:log4j-core:log4j_core:2.8.1:*:*:*:*:*:*:*",
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
			name:  "Happy Path Vuln Finds nothing",
			InPkg: []*model.PkgInputSpec{p1, p2, p6},
			// p1 is a dependency ONLY of p2
			InIsDependency: []IsDependency{
				{
					P1: *p1,
					P2: *p2,
					MF: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					ID: model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			InHasMetadata: []HasMetadata{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p2,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "cpe",
						Value: "cpe:2.3:a:log4j-core:log4j_core:2.8.1:*:*:*:*:*:*:*",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p6,
					},
					PMT: &model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HM: model.HasMetadataInputSpec{
						Key:   "cpe",
						Value: "cpe:2.3:a:grep:grep:3.6-1:*:*:*:*:*:*:*",
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
			query:   "cpe:2.3:a:grep:grep:3.6-1:*:*:*:*:*:*:*",
			want:    []model.CertifyVulnOrCertifyVEXStatement{},
			wantErr: false,
		}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := backends.Get("inmem", nil, nil)
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
				t.Errorf("FindVulnerability error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
