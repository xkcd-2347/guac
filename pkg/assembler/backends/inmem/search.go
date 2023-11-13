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

package inmem

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"golang.org/x/exp/maps"
)

var edgesAllowed = []model.Edge{
	model.EdgeIsDependencyPackage,
	model.EdgePackageIsDependency,
}

var edgesAllowedFindVulnerability = []model.Edge{
	model.EdgeArtifactCertifyVexStatement,
	model.EdgeCertifyVexStatementVulnerability,
	model.EdgeCertifyVexStatementPackage,
	model.EdgeCertifyVexStatementArtifact,
	model.EdgeCertifyVulnPackage,
	model.EdgeIsDependencyPackage,
	model.EdgePackageCertifyVexStatement,
	model.EdgePackageIsDependency,
	model.EdgeVulnerabilityCertifyVexStatement,
	model.EdgeVulnerabilityCertifyVuln,
}

func (c *demoClient) FindSoftware(ctx context.Context, searchText string) ([]model.PackageSourceOrArtifact, error) {
	return []model.PackageSourceOrArtifact{}, fmt.Errorf("not implemented: FindSoftware")
}

func (c *demoClient) FindTopLevelPackagesRelatedToVulnerability(ctx context.Context, vulnerabilityID string) ([][]model.Node, error) {
	hasSBOMs, err := c.HasSBOM(ctx, &model.HasSBOMSpec{})
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
		vexStatements, err := c.CertifyVEXStatement(ctx, &model.CertifyVEXStatementSpec{
			Vulnerability: &model.VulnerabilitySpec{
				VulnerabilityID: &vulnerabilityID,
			},
		})
		if err != nil {
			return nil, gqlerror.Errorf("FindTopLevelPackagesRelatedToVulnerability failed with err: %v", err)
		}
		for _, vexStatement := range vexStatements {
			subject := vexStatement.Subject
			var pkgVulnerable *model.Package
			switch v := subject.(type) {
			case *model.Package:
				pkgVulnerable = v
			case *model.Artifact:
				continue
			}
			products, err := c.findRelatedProducts(ctx, pkgVulnerable, vexStatement, productIDsCheckedVulnerable)
			if err != nil {
				return nil, err
			}
			result = append(result, products...)
		}
		// if no VEX Statements have been found or no path from any VEX statement to product has been found
		// then let's check also for CertifyVuln
		if len(vexStatements) == 0 || slices.Contains(maps.Values(productIDsCheckedVulnerable), false) {
			vulnStatements, err := c.CertifyVuln(ctx, &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: &vulnerabilityID,
				},
			})
			if err != nil {
				return nil, gqlerror.Errorf("FindTopLevelPackagesRelatedToVulnerability failed with err: %v", err)
			}
			for _, vuln := range vulnStatements {
				products, err := c.findRelatedProducts(ctx, vuln.Package, vuln, productIDsCheckedVulnerable)
				if err != nil {
					return nil, err
				}
				result = append(result, products...)
			}
		}

	}
	return result, nil
}

func (c *demoClient) findRelatedProducts(ctx context.Context, pkgVulnerable *model.Package, vuln model.Node, productIDsCheckedVulnerable map[string]bool) ([][]model.Node, error) {
	result := [][]model.Node{}
	// if the package affected from the vulnerability is a product ID
	// then we found a path from vulnerability to the package representing the product
	if alreadyFoundVulnerable, ok := productIDsCheckedVulnerable[pkgVulnerable.Namespaces[0].Names[0].Versions[0].ID]; ok && !alreadyFoundVulnerable {
		result = append(result, []model.Node{vuln, pkgVulnerable})
		productIDsCheckedVulnerable[pkgVulnerable.Namespaces[0].Names[0].Versions[0].ID] = true
	} else {
		for idProduct, checkedVulnerable := range productIDsCheckedVulnerable {
			if !checkedVulnerable {
				path, err := c.PathThroughIsDependency(ctx, pkgVulnerable.Namespaces[0].Names[0].Versions[0].ID, idProduct, 10, edgesAllowed)
				if err == nil {
					path = append([]model.Node{vuln}, path...)
					result = append(result, path)
					productIDsCheckedVulnerable[idProduct] = true
				}
			}
		}

	}
	return result, nil
}

// FindVulnerability returns all vulnerabilities related to a package
func (c *demoClient) FindVulnerability(ctx context.Context, purl string, offset *int, limit *int) ([]model.CertifyVulnOrCertifyVEXStatement, error) {

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
	vulnerabilities, err := c.findVulnerabilities(ctx, pkgFilter)
	if err != nil {
		return nil, err
	}
	return *vulnerabilities, err
}

// FindVulnerabilityCPE returns all vulnerabilities related to the package identified by the CPE
func (c *demoClient) FindVulnerabilityCPE(ctx context.Context, cpe string) ([]model.CertifyVulnOrCertifyVEXStatement, error) {

	metadatas, err := c.HasMetadata(ctx, &model.HasMetadataSpec{Key: ptrfrom.String("cpe"), Value: &cpe})
	packagesFound := map[string]*model.Package{}
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
		return nil, gqlerror.Errorf("failed to locate a single package based on the provided CPE")
	}

	pkg := maps.Values(packagesFound)[0]
	pkgQualifierFilter := []*model.PackageQualifierSpec{}
	for _, qualifier := range pkg.Namespaces[0].Names[0].Versions[0].Qualifiers {
		pkgQualifierFilter = append(pkgQualifierFilter, &model.PackageQualifierSpec{
			Key:   qualifier.Key,
			Value: &qualifier.Value,
		})
	}
	pkgFilter := &model.PkgSpec{
		Type:       &pkg.Type,
		Namespace:  &pkg.Namespaces[0].Namespace,
		Name:       &pkg.Namespaces[0].Names[0].Name,
		Version:    &pkg.Namespaces[0].Names[0].Versions[0].Version,
		Subpath:    &pkg.Namespaces[0].Names[0].Versions[0].Subpath,
		Qualifiers: pkgQualifierFilter,
	}
	vulnerabilities, err := c.findVulnerabilities(ctx, pkgFilter)
	if err != nil {
		return nil, err
	}
	return *vulnerabilities, nil
}

func (c *demoClient) findVulnerabilities(ctx context.Context, pkgFilter *model.PkgSpec) (*[]model.CertifyVulnOrCertifyVEXStatement, error) {

	pkgResponse, err := c.Packages(ctx, pkgFilter)
	if err != nil {
		return nil, gqlerror.Errorf("error querying for package: %v", err)
	}
	if len(pkgResponse) != 1 {
		return nil, gqlerror.Errorf("failed to locate package based on purl")
	}

	idProduct := pkgResponse[0].Namespaces[0].Names[0].Versions[0].ID
	product, err := strconv.ParseUint(idProduct, 10, 32)
	if err != nil {
		return nil, err
	}
	return c.bfsFromProduct(uint32(product))
}
