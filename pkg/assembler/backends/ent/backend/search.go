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

package backend

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvuln"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hasmetadata"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilitytype"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"
)

// FindSoftware takes in a searchText string and looks for software
// that may be relevant for the input text. This can be seen as fuzzy search
// function for Packages, Sources and Artifacts. findSoftware returns a list
// of Packages, Sources and Artifacts that it determines to be relevant to
// the input searchText.

// Due to the nature of full text search being implemented differently on
// different db platforms, the behavior of findSoftware is not guaranteed
// to be the same. In addition, their statistical nature may result in
// results being different per call and not reproducible.

// All that is asked in the implementation of this API is that it follows
// the spirit of helping to retrieve the right nodes with best effort.

// Warning: This is an EXPERIMENTAL feature. This is subject to change.
// Warning: This is an OPTIONAL feature. Backends are not required to
// implement this API.
func (b *EntBackend) FindSoftware(ctx context.Context, searchText string) ([]model.PackageSourceOrArtifact, error) {
	// Arbitrarily only search if the search text is longer than 2 characters
	// Search Artifacts
	results := make([]model.PackageSourceOrArtifact, 0)
	if len(searchText) <= 2 {
		return results, nil
	}

	// Search by Package Name
	packages, err := b.client.PackageVersion.Query().Where(
		packageversion.HasNameWith(
			packagename.NameContainsFold(searchText),
		),
	).WithName(func(q *ent.PackageNameQuery) {
		q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
			q.WithPackage()
		})
	}).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	results = append(results, collect(packages, func(v *ent.PackageVersion) model.PackageSourceOrArtifact {
		return toModelPackage(backReferencePackageVersion(v))
	})...)

	// Search Sources
	sources, err := b.client.SourceName.Query().Where(
		sourcename.Or(
			sourcename.NameContainsFold(searchText),
			sourcename.HasNamespaceWith(
				sourcenamespace.NamespaceContainsFold(searchText),
			),
		),
	).WithNamespace(func(q *ent.SourceNamespaceQuery) {
		q.WithSourceType()
	}).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}
	results = append(results, collect(sources, func(v *ent.SourceName) model.PackageSourceOrArtifact {
		return toModelSource(backReferenceSourceName(v))
	})...)

	artifacts, err := b.client.Artifact.Query().Where(
		artifact.DigestContains(searchText),
	).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	results = append(results, collect(artifacts, func(v *ent.Artifact) model.PackageSourceOrArtifact {
		return toModelArtifact(v)
	})...)

	return results, nil
}

func (b *EntBackend) FindTopLevelPackagesRelatedToVulnerability(ctx context.Context, vulnerabilityID string) ([][]model.Node, error) {
	// TODO use directly the query because the EntBackend.HasSBOM is limited to MaxPageSize
	hasSBOMs, err := b.HasSBOM(ctx, &model.HasSBOMSpec{})
	if err != nil {
		return nil, gqlerror.Errorf("FindTopLevelPackagesRelatedToVulnerability failed with err: %v", err)
	}

	result := [][]model.Node{}
	productIDsCheckedVulnerable := make(map[string]bool, len(hasSBOMs))
	for _, hasSBOM := range hasSBOMs {
		switch v := hasSBOM.Subject.(type) {
		case *model.Artifact:
			productIDsCheckedVulnerable[v.ID] = false
		case *model.Package:
			productIDsCheckedVulnerable[v.Namespaces[0].Names[0].Versions[0].ID] = false
		}
	}

	if len(productIDsCheckedVulnerable) != 0 {
		vexStatements, err := b.client.CertifyVex.Query().
			Where(
				certifyvex.HasVulnerabilityWith(vulnerabilityid.VulnerabilityIDEqualFold(vulnerabilityID)),
				certifyvex.StatusNEQ(model.VexStatusNotAffected.String()),
				certifyvex.PackageIDNotNil(),
			).
			WithVulnerability(func(q *ent.VulnerabilityIDQuery) {
				q.WithType()
			}).
			WithPackage(func(q *ent.PackageVersionQuery) {
				q.WithName(func(q *ent.PackageNameQuery) {
					q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
						q.WithPackage()
					})
				})
			}).
			All(ctx)
		if err != nil {
			return nil, gqlerror.Errorf("FindTopLevelPackagesRelatedToVulnerability failed with err: %v", err)
		}
		packagesAlreadyInvestigated := make([]int, 0)
		for _, vexStatement := range vexStatements {
			paths, err := b.bfsFromVulnerablePackage(ctx, *vexStatement.PackageID, &productIDsCheckedVulnerable)
			if err != nil {
				return nil, err
			}
			if len(paths) > 0 {
				for i := range paths {
					paths[i] = append([]model.Node{toModelCertifyVEXStatement(vexStatement)}, paths[i]...)
				}
				result = append(result, paths...)
				packagesAlreadyInvestigated = append(packagesAlreadyInvestigated, *vexStatement.PackageID)
			}
		}
		// if no VEX Statements have been found or no path from any VEX statement to product has been found
		// then let's check also for CertifyVuln
		if len(vexStatements) == 0 || slices.Contains(maps.Values(productIDsCheckedVulnerable), false) {
			vulnStatements, err := b.CertifyVuln(ctx, &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: &vulnerabilityID,
				},
			})
			if err != nil {
				return nil, gqlerror.Errorf("FindTopLevelPackagesRelatedToVulnerability failed with err: %v", err)
			}
			for _, vuln := range vulnStatements {
				pkg, err := strconv.Atoi(vuln.Package.Namespaces[0].Names[0].Versions[0].ID)
				if err != nil {
					return nil, err
				}
				if !slices.Contains(packagesAlreadyInvestigated, pkg) {
					products, err := b.bfsFromVulnerablePackage(ctx, pkg, &productIDsCheckedVulnerable)
					if err != nil {
						return nil, err
					}
					for i := range products {
						products[i] = append([]model.Node{vuln}, products[i]...)
					}
					result = append(result, products...)
				}
			}
		}
	}
	return result, nil
}

// FindVulnerability returns all vulnerabilities related to a package
func (b *EntBackend) FindVulnerability(ctx context.Context, purl string, offset *int, limit *int) ([]model.CertifyVulnOrCertifyVEXStatement, error) {

	pkgInput, err := helpers.PurlToPkg(purl)
	if err != nil {
		return nil, gqlerror.Errorf("failed to parse PURL: %v", err)
	}

	pkgQualifierFilter := []*model.PackageQualifierSpec{}
	for _, qualifier := range pkgInput.Qualifiers {
		pkgQualifierFilter = append(pkgQualifierFilter, &model.PackageQualifierSpec{
			Key:   qualifier.Key,
			Value: &qualifier.Value,
		})
	}

	pkgFilter := &model.PkgSpec{
		Type:       &pkgInput.Type,
		Namespace:  pkgInput.Namespace,
		Name:       &pkgInput.Name,
		Version:    pkgInput.Version,
		Subpath:    pkgInput.Subpath,
		Qualifiers: pkgQualifierFilter,
	}

	vulnerabilities, err := b.findVulnerabilities(ctx, pkgFilter, purl, offset, limit)
	if err != nil {
		return nil, err
	}
	return *vulnerabilities, err
}

// FindVulnerabilityCPE returns all vulnerabilities related to the package identified by the CPE
func (b *EntBackend) FindVulnerabilityCPE(ctx context.Context, cpe string) ([]model.CertifyVulnOrCertifyVEXStatement, error) {

	packagesFound := map[string]*model.Package{}
	metadatas, err := b.HasMetadata(ctx, &model.HasMetadataSpec{Key: ptrfrom.String("cpe"), Value: &cpe})
	if err != nil {
		return nil, gqlerror.Errorf("error querying for HasMetadata: %v", err)
	}
	// if multiple times the same key-value metadata has been attached to the same package,
	// it means the referenced package is just only the same one.
	for i := range metadatas {
		pkg, ok := metadatas[i].Subject.(*model.Package)
		if ok {
			id := pkg.Namespaces[0].Names[0].Versions[0].ID
			if _, found := packagesFound[id]; !found {
				packagesFound[id] = pkg
			}
		}
	}
	if len(maps.Values(packagesFound)) != 1 {
		return nil, gqlerror.Errorf("failed to locate a single package based on the provided CPE %v", cpe)
	}

	pkg := maps.Values(packagesFound)[0]
	pkgFilter, purl, gqlError := b.getPkgSpecAndPurl(ctx, pkg)
	if gqlError != nil {
		return nil, gqlError
	}
	vulnerabilities, err := b.findVulnerabilities(ctx, pkgFilter, *purl, nil, nil)
	if err != nil {
		return nil, err
	}
	return *vulnerabilities, nil
}

// FindVulnerabilitySbomURI returns all vulnerabilities related to the package identified by the SBOM ID
func (b *EntBackend) FindVulnerabilitySbomURI(ctx context.Context, sbomURI string, offset *int, limit *int) ([]model.CertifyVulnOrCertifyVEXStatement, error) {

	packagesFound := map[string]*model.Package{}
	hasSboms, err := b.HasSBOM(ctx, &model.HasSBOMSpec{URI: ptrfrom.String(sbomURI)})
	if err != nil {
		return nil, gqlerror.Errorf("error querying for HasMetadata: %v", err)
	}
	// if multiple times the same key-value metadata has been attached to the same package,
	// it means the referenced package is just only the same one.
	for i := range hasSboms {
		pkg, ok := hasSboms[i].Subject.(*model.Package)
		if ok {
			id := pkg.Namespaces[0].Names[0].Versions[0].ID
			if _, found := packagesFound[id]; !found {
				packagesFound[id] = pkg
			}
		}
	}
	if len(maps.Values(packagesFound)) != 1 {
		return nil, gqlerror.Errorf("failed to locate a single package based on the provided SBOM URI %v", sbomURI)
	}

	pkg := maps.Values(packagesFound)[0]

	pkgFilter, purl, gqlError := b.getPkgSpecAndPurl(ctx, pkg)
	if gqlError != nil {
		return nil, gqlError
	}
	vulnerabilities, err := b.findVulnerabilities(ctx, pkgFilter, *purl, offset, limit)
	if err != nil {
		return nil, err
	}
	return *vulnerabilities, nil
}

func (b *EntBackend) getPkgSpecAndPurl(ctx context.Context, pkg *model.Package) (*model.PkgSpec, *string, *gqlerror.Error) {
	pkgFilter := &model.PkgSpec{
		ID: &pkg.Namespaces[0].Names[0].Versions[0].ID,
	}
	pkgID, err := strconv.Atoi(*pkgFilter.ID)
	if err != nil {
		return nil, nil, gqlerror.Errorf("error converting pkg.ID: %v", pkg.ID)
	}
	purlMetadata, err := b.client.HasMetadata.Query().Select(hasmetadata.FieldValue).
		Where(
			hasmetadata.PackageVersionID(pkgID),
			hasmetadata.KeyEQ("topLevelPackage"),
		).
		Only(ctx)
	if err != nil {
		return nil, nil, gqlerror.Errorf("error querying for HasMetadata: %v", err)
	}
	return pkgFilter, &purlMetadata.Value, nil
}

func (b *EntBackend) findVulnerabilities(ctx context.Context, pkgFilter *model.PkgSpec, purl string, offset *int, limit *int) (*[]model.CertifyVulnOrCertifyVEXStatement, error) {
	// check the provided input
	_, err := b.client.PackageVersion.Query().
		Where(packageVersionQuery(pkgFilter)).
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("error querying for package: %v", err)
	}
	vulnerabilities := make(chan model.CertifyVulnOrCertifyVEXStatement)
	eg, ctx := errgroup.WithContext(ctx)
	concurrentlyRead(eg, func() error {
		query := b.client.CertifyVex.Query().
			Where(
				certifyvex.StatusNEQ(model.VexStatusNotAffected.String()),
				certifyvex.HasPackageWith(
					packageversion.HasHasMetadataWith(
						hasmetadata.KeyEQ("topLevelPackage"),
						hasmetadata.ValueEQ(purl),
						hasmetadata.PackageVersionIDNotNil(),
						hasmetadata.PackageNameIDIsNil(),
						hasmetadata.SourceIDIsNil(),
						hasmetadata.ArtifactIDIsNil()),
				),
				certifyvex.HasVulnerabilityWith(
					vulnerabilityid.HasTypeWith(
						vulnerabilitytype.TypeNEQ(NoVuln),
					),
				),
			).
			WithVulnerability(func(q *ent.VulnerabilityIDQuery) {
				q.WithType()
			}).
			WithPackage(withPackageVersionTree()).
			Order(ent.Desc(vulnerabilityid.FieldID))

		if offset != nil {
			query.Offset(*offset)
		}

		if limit != nil {
			query.Limit(*limit)
		}

		certifyVexes, err := query.All(ctx)
		if err != nil {
			return err
		}
		for i := range certifyVexes {
			index := i
			vulnerabilities <- toModelCertifyVEXStatement(certifyVexes[index])
		}
		return nil
	})
	concurrentlyRead(eg, func() error {
		query := b.client.CertifyVuln.Query().
			Where(
				certifyvuln.HasPackageWith(
					packageversion.HasHasMetadataWith(
						hasmetadata.KeyEQ("topLevelPackage"),
						hasmetadata.ValueEQ(purl),
						hasmetadata.PackageVersionIDNotNil(),
						hasmetadata.PackageNameIDIsNil(),
						hasmetadata.SourceIDIsNil(),
						hasmetadata.ArtifactIDIsNil()),
				),
				certifyvuln.HasVulnerabilityWith(
					vulnerabilityid.HasTypeWith(
						vulnerabilitytype.TypeNEQ(NoVuln),
					),
				),
			).
			WithVulnerability(func(q *ent.VulnerabilityIDQuery) {
				q.WithType()
			}).
			WithPackage(withPackageVersionTree()).
			Order(ent.Desc(vulnerabilityid.FieldID))

		if offset != nil {
			query.Offset(*offset)
		}

		if limit != nil {
			query.Limit(*limit)
		}

		certifyVulns, err := query.All(ctx)
		if err != nil {
			return err
		}
		for i := range certifyVulns {
			index := i
			vulnerabilities <- toModelCertifyVulnerability(certifyVulns[index])
		}
		return nil
	})
	go func() {
		if err := eg.Wait(); err != nil {
			fmt.Printf("WARN: error in a concurrentlyRead :: %s", err)
		}
		close(vulnerabilities)
	}()
	var result []model.CertifyVulnOrCertifyVEXStatement
	for vulnerability := range vulnerabilities {
		result = append(result, vulnerability)
	}
	return &result, nil
}
