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
	"sort"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvuln"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
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

func (b *EntBackend) FindTopLevelPackagesRelatedToVulnerability(ctx context.Context, vulnerabilityID string) ([][]model.Node, error) {
	// retrieve (if any) the vulnerability by vulnerabilityID with its CertifyVEX and CertifyVuln related entities
	vulnerability, err := b.client.VulnerabilityID.Query().
		Where(
			vulnerabilityid.VulnerabilityIDEqualFold(vulnerabilityID),
			vulnerabilityid.Or(
				vulnerabilityid.HasVexWith(
					certifyvex.StatusNEQ(model.VexStatusNotAffected.String()),
					certifyvex.PackageIDNotNil(),
					certifyvex.HasPackageWith(
						packageversion.HasIncludedInSboms(),
					),
				),
				vulnerabilityid.HasCertifyVuln(),
			),
		).
		WithVex(func(q *ent.CertifyVexQuery) {
			q.Where(
				certifyvex.HasVulnerabilityWith(
					vulnerabilityid.TypeNEQ(NoVuln)),
				certifyvex.StatusNEQ(model.VexStatusNotAffected.String()),
				certifyvex.PackageIDNotNil(),
				certifyvex.HasPackageWith(
					packageversion.HasIncludedInSboms(),
				),
			).
				WithPackage(func(q *ent.PackageVersionQuery) {
					q.WithName()
				})
		}).
		WithCertifyVuln(func(q *ent.CertifyVulnQuery) {
			q.Where(
				certifyvuln.HasVulnerabilityWith(
					vulnerabilityid.TypeNEQ(NoVuln)),
				certifyvuln.HasPackageWith(
					packageversion.HasIncludedInSboms(),
				),
			).
				WithPackage(func(q *ent.PackageVersionQuery) {
					q.WithName()
				})
		}).
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("error querying for SBOMs related to %v due to : %v", vulnerabilityID, err)
	}
	// build the output result backward compatible with the previous version
	var result [][]model.Node
	// Vex has priority over Vuln just for consistency with previous implementation, but it could be changed
	if len(vulnerability.Edges.Vex) > 0 {
		for _, vex := range vulnerability.Edges.Vex {
			dependencyPathFromVulnerablePkgToProduct, err := b.recursivelyFindPathFromPackageToProduct(ctx, vex.PackageID)
			if err != nil {
				return nil, gqlerror.Errorf("error searching for paths from vulnerable package to SBOMs related to %v due to : %v", vulnerabilityID, err)
			}
			// inject the vulnerability in order for the toModelCertifyVEXStatement method to work
			vex.Edges.Vulnerability = vulnerability
			result = append(result, getResponse(*toModelCertifyVEXStatement(vex), dependencyPathFromVulnerablePkgToProduct)...)
		}
	} else {
		for _, vuln := range vulnerability.Edges.CertifyVuln {
			dependencyPathFromVulnerablePkgToProduct, err := b.recursivelyFindPathFromPackageToProduct(ctx, &vuln.PackageID)
			if err != nil {
				return nil, gqlerror.Errorf("error searching for paths from vulnerable package to SBOMs related to %v due to : %v", vulnerabilityID, err)
			}
			// inject the vulnerability in order for the toModelCertifyVEXStatement method to work
			vuln.Edges.Vulnerability = vulnerability
			result = append(result, getResponse(*toModelCertifyVulnerability(vuln), dependencyPathFromVulnerablePkgToProduct)...)
		}
	}
	return result, nil
}

func (b *EntBackend) recursivelyFindPathFromPackageToProduct(ctx context.Context, vulnerablePackage *uuid.UUID) ([][]*ent.Dependency, error) {
	// SQL WITH RECURSIVE statement for traversing the dependencies table from the vulnerable package to the products it belongs to
	dependenciesFromVulnerablePackageToProduct, err := b.client.Dependency.Query().
		Where(func(s *sql.Selector) {
			t1, t2 := sql.Table(dependency.Table), sql.Table(dependency.Table)
			with := sql.WithRecursive("package")
			with.As(
				// The initial `SELECT` statement executed once at the start,
				// and produces the initial row or rows for the recursion.
				sql.Select(t1.Columns(dependency.Columns...)...).
					From(t1).
					Where(
						sql.EQ(t1.C(dependency.FieldDependentPackageVersionID), vulnerablePackage),
					).
					// Merge the `SELECT` statement above with the following:
					UnionAll(
						// A `SELECT` statement that produces additional rows and recurses by referring
						// to the CTE name (e.g. "package"), and ends when there are no more new rows.
						sql.Select(t2.Columns(dependency.Columns...)...).
							From(t2).
							Join(with).
							On(t2.C(dependency.FieldDependentPackageVersionID), with.C(dependency.FieldPackageID)),
					),
			)
			// Join the root `SELECT` query with the CTE result (`WITH` clause).
			s.Prefix(with).Join(with).
				On(s.C(dependency.FieldID), with.C(dependency.FieldID))
		}).
		Select(dependency.Columns...).
		WithDependentPackageVersion(func(q *ent.PackageVersionQuery) {
			q.WithName()
		}).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName()
		}).
		All(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("error querying for SBOMs related to package %v due to : %v", vulnerablePackage.String(), err)
	}
	// create a map to quickly pick a dependency by dependant package ID
	pkgWithDependantPkgs := make(map[uuid.UUID][]*ent.Dependency)
	for _, dep := range dependenciesFromVulnerablePackageToProduct {
		pkgWithDependantPkgs[dep.DependentPackageVersionID] = append(pkgWithDependantPkgs[dep.DependentPackageVersionID], dep)
	}
	// in this call allowIndirect is true because, if available, an indirect (i.e. transitive) dependency from
	// the found vulnerable package and the products it belongs to is something expected to be retrieved
	dependencyPaths := buildDependencyPath(pkgWithDependantPkgs, vulnerablePackage, true)
	// sort them in ascending paths length to ensure the first is (one of) the shortest path
	sort.Slice(dependencyPaths, func(i, j int) bool {
		return len(dependencyPaths[i]) < len(dependencyPaths[j])
	})
	// the vulnerable package could belong to multiple products so the approach is to go through the sorted dependencyPaths
	// and leveraging a map to store the shortest path for each product found (product is always the package referenced
	// in the last element of a path)
	var result = make(map[uuid.UUID][]*ent.Dependency)
	for _, path := range dependencyPaths {
		productID := path[len(path)-1].PackageID
		// if nothing has been added for the current productID, then it means we can add it because it's the shortest path
		// (based on the fact that dependencyPaths has been previously sorted by paths' length)
		if _, found := result[productID]; !found {
			result[productID] = path
		}
	}
	// we return all the shortest paths from the vulnerable package to all the products it belongs to
	return maps.Values(result), nil
}

func buildDependencyPath(resultSet map[uuid.UUID][]*ent.Dependency, current *uuid.UUID, allowIndirect bool) [][]*ent.Dependency {
	var result [][]*ent.Dependency
	// keep track of the dependencies already evaluated to avoid having duplicated paths
	// it happens when the SQL recursive query finds multiple paths through the same package, i.e.
	// pkg A -> pkg B -> pkg C -> product
	// pkg A -> pkg B -> pkg D -> pkg C -> product
	// in this situation, the dependency "pkg C -> product" appears twice in the DB result set,
	// but it must be evaluated only once
	var analyzedDependencies = make(map[uuid.UUID]struct{})
	for _, dependant := range resultSet[*current] {
		if _, ok := analyzedDependencies[dependant.ID]; !ok {
			analyzedDependencies[dependant.ID] = struct{}{}
			if allowIndirect || dependant.DependencyType != dependency.DependencyTypeINDIRECT {
				// now allowIndirect is false because in an inner recursive step we're not interested in getting
				// transitive (i.e. INDIRECT) dependencies but just the direct one to properly create the full path
				// from the vulnerable package to each product it belongs to
				dependencyPath := buildDependencyPath(resultSet, &dependant.PackageID, false)
				// no further dependencies found, i.e. a product has been found, so it's the base case for the recursion
				if len(dependencyPath) == 0 {
					result = append(result, []*ent.Dependency{dependant})
				} else {
					for _, deeperPath := range dependencyPath {
						result = append(result, append([]*ent.Dependency{dependant}, deeperPath...))
					}
				}
			}
		}
	}
	return result
}

func getResponse(certifyVexOrVuln model.Node, dependencyPaths [][]*ent.Dependency) [][]model.Node {
	var result [][]model.Node
	// each array of dependencies connects a vulnerable package with a product (i.e. package with an SBOM) the package belongs to
	// so looping through the dependencies will ensure all the products are listed in the response
	for _, dependencyPath := range dependencyPaths {
		for _, dep := range dependencyPath {
			var response []model.Node
			// the 1st expected element of each inner array is a CertifyVEXStatement or a CertifyVuln re to the vulnerabilityID
			response = append(response, certifyVexOrVuln)
			// inject the PackageVersion in order for the toModelPackage method to work
			dep.Edges.DependentPackageVersion.Edges.Name.Edges.Versions = []*ent.PackageVersion{dep.Edges.DependentPackageVersion}
			// the 2nd expected element of each inner array is the vulnerable Package
			response = append(response, toModelPackage(dep.Edges.DependentPackageVersion.Edges.Name))
			// the 3rd expected element of each inner array is the IsDependency between the vulnerable package and its SBOM
			response = append(response, toModelIsDependencyWithBackrefs(dep))
			// inject the PackageVersion in order for the toModelPackage method to work
			dep.Edges.Package.Edges.Name.Edges.Versions = []*ent.PackageVersion{dep.Edges.Package}
			// the 4th expected element of each inner array is the SBOM Package
			response = append(response, toModelPackage(dep.Edges.Package.Edges.Name))
			result = append(result, response)
		}
	}
	return result
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

func (b *EntBackend) FindDependentProduct(ctx context.Context, purl string, offset *int, limit *int) ([]*model.HasSbom, error) {
	pkgFilter, err := PurlToPkgSpec(purl)
	if err != nil {
		return nil, gqlerror.Errorf("failed to parse PURL: %v", err)
	}
	sbomQuery := b.client.BillOfMaterials.Query().
		Where(
			hasSBOMQuery(*&model.HasSBOMSpec{
				IncludedDependencies: []*model.IsDependencySpec{
					{
						DependencyPackage: pkgFilter,
					},
				},
			}),
		).
		WithPackage(withPackageVersionTree()).
		Order(billofmaterials.ByID(), ent.Desc())
	if offset != nil {
		sbomQuery.Offset(*offset)
	}
	if limit != nil {
		sbomQuery.Limit(*limit)
	}
	sboms, err := sbomQuery.All(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("error querying for products dependant on purl %v due to : %v", purl, err)
	}
	return collect(sboms, toModelHasSBOM), nil
}
