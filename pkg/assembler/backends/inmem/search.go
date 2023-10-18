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

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/misc/depversion"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"golang.org/x/exp/maps"
)

var edgesAllowed = []model.Edge{
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
	if len(hasSBOMs) == 0 {
		return nil, gqlerror.Errorf("FindTopLevelPackagesRelatedToVulnerability failed with err: Found no package with an SBOM")
	}

	var result [][]model.Node
	for _, hasSBOM := range hasSBOMs {
		var idProduct *string
		switch v := hasSBOM.Subject.(type) {
		case *model.Artifact:
			idProduct = &v.ID
		case *model.Package:
			idProduct = &v.Namespaces[0].Names[0].Versions[0].ID
		default:
			idProduct = nil
		}
		if idProduct != nil {
			vexStatements, err := c.CertifyVEXStatement(ctx, &model.CertifyVEXStatementSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: &vulnerabilityID,
				},
			})
			if err != nil {
				return nil, gqlerror.Errorf("FindTopLevelPackagesRelatedToVulnerability failed with err: %v", err)
			}
			found := false
			for _, vexStatement := range vexStatements {
				path, err := c.Path(ctx, vexStatement.ID, *idProduct, 10, edgesAllowed)
				if err == nil {
					result = append(result, path)
					found = true
				}
			}
			// if no VEX Statements have been found or no path from any VEX statement to product has been found
			// then let's check also for CertifyVuln
			if len(vexStatements) == 0 || !found {
				vulnStatements, err := c.CertifyVuln(ctx, &model.CertifyVulnSpec{
					Vulnerability: &model.VulnerabilitySpec{
						VulnerabilityID: &vulnerabilityID,
					},
				})
				if err != nil {
					return nil, gqlerror.Errorf("FindTopLevelPackagesRelatedToVulnerability failed with err: %v", err)
				}
				for _, vuln := range vulnStatements {
					path, err := c.Path(ctx, vuln.ID, *idProduct, 10, edgesAllowed)
					if err == nil {
						result = append(result, path)
						found = true
					}
				}
			}
		}
	}
	return result, nil
}

// FindVulnerability is based upon the "guacone query vuln" CLI command (i.e. [github.com/guacsec/guac/cmd/guacone/cmd/vulnerability.go])
func (c *demoClient) FindVulnerability(ctx context.Context, purl string) ([]model.CertifyVulnOrCertifyVEXStatement, error) {

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
	pkgResponse, err := c.Packages(ctx, pkgFilter)
	if err != nil {
		return nil, gqlerror.Errorf("error querying for package: %v", err)
	}
	if len(pkgResponse) != 1 {
		return nil, gqlerror.Errorf("failed to locate package based on purl")
	}

	vulnerabilities := []model.CertifyVulnOrCertifyVEXStatement{}

	if pkgResponse[0].Type != helpers.PurlTypeGuac {
		vulnPath, err := c.queryVulnsViaPackageNeighbors(ctx, pkgResponse[0].Namespaces[0].Names[0].Versions[0].ID, []model.Edge{model.EdgePackageCertifyVuln, model.EdgePackageCertifyVexStatement})
		if err != nil {
			return nil, gqlerror.Errorf("error querying neighbor: %v", err)
		}
		vulnerabilities = append(vulnerabilities, vulnPath...)
	}
	depVulnPath, err := c.searchDependencyPackages(ctx, pkgResponse[0].Namespaces[0].Names[0].Versions[0].ID, 10)
	if err != nil {
		return nil, gqlerror.Errorf("error searching dependency packages match: %v", err)
	}
	vulnerabilities = append(vulnerabilities, depVulnPath...)

	//vexStatements, err := c.CertifyVEXStatement(ctx, &model.CertifyVEXStatementSpec{})
	//if err != nil {
	//	return nil, gqlerror.Errorf("FindVulnerability failed with err: %v", err)
	//}
	//idProduct := pkgResponse[0].Namespaces[0].Names[0].Versions[0].ID
	//for _, vexStatement := range vexStatements {
	//	path, err := c.Path(ctx, vexStatement.ID, idProduct, 10, edgesAllowed)
	//	if err == nil {
	//		vulnerabilities = append(vulnerabilities, path[0].(*model.CertifyVEXStatement))
	//	}
	//}
	//vulnStatements, err := c.CertifyVuln(ctx, &model.CertifyVulnSpec{})
	//if err != nil {
	//	return nil, gqlerror.Errorf("FindVulnerability failed with err: %v", err)
	//}
	//for _, vuln := range vulnStatements {
	//	path, err := c.Path(ctx, vuln.ID, idProduct, 10, edgesAllowed)
	//	if err == nil {
	//		certifyVuln := path[0].(*model.CertifyVuln)
	//		if certifyVuln.Vulnerability.Type != noVulnType {
	//			vulnerabilities = append(vulnerabilities, certifyVuln)
	//		}
	//	}
	//}

	return vulnerabilities, nil
}

func (c *demoClient) queryVulnsViaPackageNeighbors(ctx context.Context, pkgVersionID string, edgeTypes []model.Edge) ([]model.CertifyVulnOrCertifyVEXStatement, error) {
	pkgVersionNeighborResponse, err := c.Neighbors(ctx, pkgVersionID, edgeTypes)
	if err != nil {
		return nil, fmt.Errorf("error querying neighbor for vulnerability: %w", err)
	}
	var vulnerabilities []model.CertifyVulnOrCertifyVEXStatement
	for _, neighbor := range pkgVersionNeighborResponse {
		if certifyVuln, ok := neighbor.(*model.CertifyVuln); ok {
			if certifyVuln.Vulnerability.Type != noVulnType {
				vulnerabilities = append(vulnerabilities, certifyVuln)
			}
		}
		if certifyVex, ok := neighbor.(*model.CertifyVEXStatement); ok {
			vulnerabilities = append(vulnerabilities, certifyVex)
		}
	}
	return vulnerabilities, nil
}

func (c *demoClient) searchDependencyPackages(ctx context.Context, topPkgID string, maxLength int) ([]model.CertifyVulnOrCertifyVEXStatement, error) {
	//var vulnerabilities []model.CertifyVulnOrCertifyVEXStatement
	vulnerabilities := map[string]model.CertifyVulnOrCertifyVEXStatement{}
	queue := make([]string, 0) // the queue of nodes in bfs
	type dfsNode struct {
		expanded bool // true once all node neighbors are added to queue
		parent   string
		depth    int
	}
	nodeMap := map[string]dfsNode{}

	nodeMap[topPkgID] = dfsNode{}
	queue = append(queue, topPkgID)

	for len(queue) > 0 {
		now := queue[0]
		queue = queue[1:]
		nowNode := nodeMap[now]

		if maxLength != 0 && nowNode.depth >= maxLength {
			break
		}

		isDependencyNeighborResponses, err := c.Neighbors(ctx, now, []model.Edge{model.EdgePackageIsDependency})
		if err != nil {
			return nil, fmt.Errorf("failed getting package neighbors:%w", err)
		}
		for _, neighbor := range isDependencyNeighborResponses {
			if isDependency, ok := neighbor.(*model.IsDependency); ok {
				if isDependency.DependencyPackage.Type == helpers.PurlTypeGuac {
					continue
				}

				depPkgFilter := &model.PkgSpec{
					Type:      &isDependency.DependencyPackage.Type,
					Namespace: &isDependency.DependencyPackage.Namespaces[0].Namespace,
					Name:      &isDependency.DependencyPackage.Namespaces[0].Names[0].Name,
				}

				depPkgResponse, err := c.Packages(ctx, depPkgFilter)
				if err != nil {
					return nil, fmt.Errorf("error querying for dependent package: %w", err)
				}

				depPkgVersionsMap := map[string]string{}
				depPkgVersions := []string{}
				for _, depPkgVersion := range depPkgResponse[0].Namespaces[0].Names[0].Versions {
					depPkgVersions = append(depPkgVersions, depPkgVersion.Version)
					depPkgVersionsMap[depPkgVersion.Version] = depPkgVersion.ID
				}

				matchingDepPkgVersions, err := depversion.WhichVersionMatches(depPkgVersions, isDependency.VersionRange)
				if err != nil {
					// TODO(jeffmendoza): depversion is not handling all/new possible
					// version ranges from deps.dev. Continue here to report possible
					// vulns even if some paths cannot be followed.
					matchingDepPkgVersions = nil
				}

				for matchingDepPkgVersion := range matchingDepPkgVersions {
					matchingDepPkgVersionID := depPkgVersionsMap[matchingDepPkgVersion]
					vulns, err := c.queryVulnsViaPackageNeighbors(ctx, matchingDepPkgVersionID, []model.Edge{model.EdgePackageCertifyVuln, model.EdgePackageCertifyVexStatement})
					if err != nil {
						return nil, fmt.Errorf("error querying neighbor: %w", err)
					}
					//vulnerabilities = append(vulnerabilities, vulns...)
					for _, vuln := range vulns {
						if certifyVuln, ok := vuln.(*model.CertifyVuln); ok {
							if certifyVuln.Vulnerability.Type != noVulnType {
								vulnerabilities[certifyVuln.ID] = certifyVuln
							}
						} else if certifyVex, ok := vuln.(*model.CertifyVEXStatement); ok {
							vulnerabilities[certifyVex.ID] = certifyVex
						}
					}

					dfsN, seen := nodeMap[matchingDepPkgVersionID]
					if !seen {
						dfsN = dfsNode{
							parent: now,
							depth:  nowNode.depth + 1,
						}
						nodeMap[matchingDepPkgVersionID] = dfsN
					}
					if !dfsN.expanded {
						queue = append(queue, matchingDepPkgVersionID)
					}
				}
			}
		}

		nowNode.expanded = true
		nodeMap[now] = nowNode
	}

	//return vulnerabilities, nil
	return maps.Values(vulnerabilities), nil
}
