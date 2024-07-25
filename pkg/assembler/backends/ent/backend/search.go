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

	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvuln"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"golang.org/x/exp/maps"
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
	).WithName(func(q *ent.PackageNameQuery) {}).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed package version query with err: %w", err)
	}

	results = append(results, collect(packages, func(v *ent.PackageVersion) model.PackageSourceOrArtifact {
		return toModelPackage(backReferencePackageVersion(v))
	})...)

	// Search Sources
	sources, err := b.client.SourceName.Query().Where(
		sourcename.Or(
			sourcename.NameContainsFold(searchText),
			sourcename.NamespaceContainsFold(searchText),
		),
	).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed source name query with err: %w", err)
	}
	results = append(results, collect(sources, func(v *ent.SourceName) model.PackageSourceOrArtifact {
		return toModelSource(v)
	})...)

	artifacts, err := b.client.Artifact.Query().Where(
		artifact.DigestContains(searchText),
	).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed artifact query with err: %w", err)
	}

	results = append(results, collect(artifacts, func(v *ent.Artifact) model.PackageSourceOrArtifact {
		return toModelArtifact(v)
	})...)

	return results, nil
}

func (b *EntBackend) FindSoftwareList(ctx context.Context, searchText string, after *string, first *int) (*model.FindSoftwareConnection, error) {
	return nil, fmt.Errorf("not implemented: FindSoftwareList")
}

// FindVulnerability returns all vulnerabilities related to a package
func (b *EntBackend) FindVulnerability(ctx context.Context, purl string, offset *int, limit *int) ([]model.CertifyVulnOrCertifyVEXStatement, error) {
	pkgFilter, err := PurlToPkgSpec(purl)
	if err != nil {
		return nil, gqlerror.Errorf("failed to parse PURL: %v", err)
	}
	vulnerabilities, err := b.findVulnerabilities(ctx,
		&model.HasSBOMSpec{
			Subject: &model.PackageOrArtifactSpec{
				Package: pkgFilter,
			},
		},
		offset,
		limit)
	if err != nil {
		return nil, err
	}
	return *vulnerabilities, nil
}

func PurlToPkgSpec(purl string) (*model.PkgSpec, error) {
	pkgInput, err := helpers.PurlToPkg(purl)
	if err != nil {
		return nil, err
	}

	pkgQualifierFilter := []*model.PackageQualifierSpec{}
	for _, qualifier := range pkgInput.Qualifiers {
		pkgQualifierFilter = append(pkgQualifierFilter, &model.PackageQualifierSpec{
			Key:   qualifier.Key,
			Value: ptrfrom.String(qualifier.Value),
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
	return pkgFilter, nil
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
	var qualifiers []string
	for _, qualifier := range pkg.Namespaces[0].Names[0].Versions[0].Qualifiers {
		qualifiers = append(qualifiers, qualifier.Key, qualifier.Value)
	}
	purl := helpers.PkgToPurl(pkg.Type, pkg.Namespaces[0].Namespace, pkg.Namespaces[0].Names[0].Name, pkg.Namespaces[0].Names[0].Versions[0].Version, pkg.Namespaces[0].Names[0].Versions[0].Subpath, qualifiers)
	return b.FindVulnerability(ctx, purl, nil, nil)
}

// FindVulnerabilitySbomURI returns all vulnerabilities related to the package identified by the SBOM ID
func (b *EntBackend) FindVulnerabilitySbomURI(ctx context.Context, sbomURI string, offset *int, limit *int) ([]model.CertifyVulnOrCertifyVEXStatement, error) {
	vulnerabilities, err := b.findVulnerabilities(ctx, &model.HasSBOMSpec{URI: ptrfrom.String(sbomURI)}, offset, limit)
	if err != nil {
		return nil, err
	}
	return *vulnerabilities, nil
}

func (b *EntBackend) findVulnerabilities(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec, offset *int, limit *int) (*[]model.CertifyVulnOrCertifyVEXStatement, error) {
	// check the SBOM URI provided identifies just one SBOM
	sbom, err := b.client.BillOfMaterials.Query().
		Where(hasSBOMQuery(*hasSBOMSpec)).
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("failed to locate a single SBOM based on the provided SBOM URI %+v due to : %v", hasSBOMSpec, err)
	}
	sbomURI := sbom.URI
	// collect the SBOM's dependencies UUIDs
	dependencies, err := b.client.BillOfMaterials.QueryIncludedDependencies(sbom).All(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("error querying for IncludedDependencies with SBOM URI %v due to : %v", sbomURI, err)
	}
	var dependenciesPackagesUUIDs uuid.UUIDs
	for _, dependency := range dependencies {
		dependenciesPackagesUUIDs = append(dependenciesPackagesUUIDs, dependency.DependentPackageVersionID)
	}

	// retrieve CertifyVex
	certifyVexQuery := b.client.CertifyVex.Query().
		Where(
			certifyvex.StatusNEQ(model.VexStatusNotAffected.String()),
			certifyvex.PackageIDIn(dependenciesPackagesUUIDs...),
		).
		WithVulnerability().
		WithPackage(withPackageVersionTree()).
		Order(ent.Desc(vulnerabilityid.FieldID))

	if offset != nil {
		certifyVexQuery.Offset(*offset)
	}

	if limit != nil {
		certifyVexQuery.Limit(*limit)
	}

	certifyVexes, err := certifyVexQuery.All(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("error querying for CertifyVex with SBOM URI %v due to : %v", sbomURI, err)
	}

	var result []model.CertifyVulnOrCertifyVEXStatement
	for _, certifyVex := range certifyVexes {
		result = append(result, toModelCertifyVEXStatement(certifyVex))
	}

	// retrieve CertifyVuln
	certifyVulnQuery := b.client.CertifyVuln.Query().
		Where(
			certifyvuln.PackageIDIn(dependenciesPackagesUUIDs...),
		).
		WithVulnerability().
		WithPackage(withPackageVersionTree()).
		Order(ent.Desc(vulnerabilityid.FieldID))

	if offset != nil {
		certifyVulnQuery.Offset(*offset)
	}

	if limit != nil {
		certifyVulnQuery.Limit(*limit)
	}

	certifyVulns, err := certifyVulnQuery.All(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("error querying for CertifyVuln with SBOM URI %v due to : %v", sbomURI, err)
	}
	for _, certifyVuln := range certifyVulns {
		result = append(result, toModelCertifyVulnerability(certifyVuln))
	}

	return &result, nil
}
