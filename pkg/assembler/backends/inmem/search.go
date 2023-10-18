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
	"github.com/vektah/gqlparser/v2/gqlerror"
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

	result := [][]model.Node{}
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
