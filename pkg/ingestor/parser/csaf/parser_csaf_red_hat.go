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

package csaf

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
	"golang.org/x/exp/maps"
)

type csafParserRedHat struct {
	csafParser
}

func NewCsafRedHatParser() common.DocumentParser {
	return &csafParserRedHat{
		csafParser{
			identifierStrings: &common.IdentifierStrings{},
		},
	}
}

// findPkgSpec finds the package specification for the product with the
// given ID in the CSAF document. It returns a pointer to the package
// specification if found, otherwise an error.
func (c *csafParserRedHat) findPkgSpec(ctx context.Context, product_id string) (*generated.PkgInputSpec, error) {
	logger := logging.FromContext(ctx)
	pref, relToProdRef := findProductsRef(ctx, c.csaf.ProductTree, product_id)
	if pref == nil {
		return nil, fmt.Errorf("unable to locate product reference for id %s", product_id)
	}

	purl := findPurl(ctx, c.csaf.ProductTree, *pref)
	if purl == nil {
		return nil, fmt.Errorf("unable to locate product url for reference %s", *pref)
	} else if *purl == "" {
		// if no purl is available in the product reference entry, then let's try to search for it into guac
		httpClient := http.Client{}
		endpoint, ok := ctx.Value(common.KeyGraphqlEndpoint).(string)
		if !ok {
			return nil, fmt.Errorf("unable to locate product url for reference %s due to missing graphqlEndpoint value", *pref)
		}
		gqlclient := graphql.NewClient(endpoint, &httpClient)
		// get all packages with metadata with key == "cpe"
		filterHasMetadata := &generated.HasMetadataSpec{
			Key: ptrfrom.String("cpe"),
		}
		cpe := findCPE(ctx, c.csaf.ProductTree, *relToProdRef)
		pkgsWithMetadata, err := generated.HasMetadata(ctx, gqlclient, *filterHasMetadata)
		if err != nil {
			return nil, err
		}
		purlsMap := make(map[string]struct{})
		for _, pkgWithMetadata := range pkgsWithMetadata.HasMetadata {
			// check the ones whose value starts with the CPE found in the VEX
			if strings.HasPrefix(pkgWithMetadata.Value, *cpe) {
				depPkg := &generated.PkgSpec{Name: pref}
				filterIsDependency := &generated.IsDependencySpec{
					DependencyPackage: depPkg,
				}
				switch subject := pkgWithMetadata.Subject.(type) {
				case *generated.AllHasMetadataSubjectPackage:
					filterIsDependency.Package = &generated.PkgSpec{
						Type:      &subject.Type,
						Namespace: &subject.Namespaces[0].Namespace,
						Name:      &subject.Namespaces[0].Names[0].Name,
						Version:   &subject.Namespaces[0].Names[0].Versions[0].Version,
					}
					isDependency, err := generated.IsDependency(ctx, gqlclient, *filterIsDependency)
					if err != nil {
						return nil, err
					}
					for _, isDep := range isDependency.IsDependency {
						toPkg, err := helpers.PurlToPkg(helpers.AllPkgTreeToPurl(isDep.DependencyPackage.AllPkgTree, true))
						if err != nil {
							logger.Warnf("Failed to handle the IsDependency response %+v\n", isDep)
						} else {
							purlsMap[helpers.PkgInputSpecToPurl(toPkg)] = struct{}{}
						}
					}
				case *generated.AllHasMetadataSubjectSource:
					continue
				case *generated.AllHasMetadataSubjectArtifact:
					continue
				}
			}
		}
		purls := maps.Keys(purlsMap)
		sort.Strings(purls)
		if len(purls) > 0 {
			if len(purls) > 1 {
				logger.Warnf("More than one dependency package with name '%v' has been found for CPE %+v\n%v\n", *pref, *cpe, purls)
			}
			purl = &purls[0]
			logger.Infof("[csaf] product_id '%v' mapped to guac package %v", product_id, *purl)
		}
	}

	return helpers.PurlToPkg(*purl)
}

// GetPredicates generates the VEX and CertifyVuln predicates for the CSAF document.
//
// It returns a pointer to an assembler.IngestPredicates struct containing the
// generated VEX and CertifyVuln predicates.
func (c *csafParserRedHat) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	rv := &assembler.IngestPredicates{}
	var vis []assembler.VexIngest
	var cvs []assembler.CertifyVulnIngest

	for _, v := range c.csaf.Vulnerabilities {
		vuln, err := helpers.CreateVulnInput(v.CVE)
		if err != nil {
			return nil
		}

		statuses := []string{"fixed", "known_not_affected", "known_affected", "first_affected", "first_fixed", "last_affected", "recommended", "under_investigation"}
		for _, status := range statuses {
			products := v.ProductStatus[status]
			for _, product := range products {
				vi := generateVexIngest(ctx, &c.csafParser, c, vuln, &v, status, product)
				if vi == nil {
					continue
				}

				if status == "known_affected" || status == "under_investigation" {
					vulnData := generated.ScanMetadataInput{
						TimeScanned: c.csaf.Document.Tracking.CurrentReleaseDate,
					}
					cv := assembler.CertifyVulnIngest{
						Pkg:           vi.Pkg,
						Vulnerability: vuln,
						VulnData:      &vulnData,
					}
					cvs = append(cvs, cv)
				} else if status == "known_not_affected" || status == "fixed" {
					vulnData := generated.ScanMetadataInput{
						TimeScanned: c.csaf.Document.Tracking.CurrentReleaseDate,
					}
					noVuln := generated.VulnerabilityInputSpec{
						Type: "NoVuln",
					}
					cv := assembler.CertifyVulnIngest{
						Pkg:           vi.Pkg,
						Vulnerability: &noVuln,
						VulnData:      &vulnData,
					}
					cvs = append(cvs, cv)
				}
				vis = append(vis, *vi)
			}
		}
	}
	rv.Vex = vis
	rv.CertifyVuln = cvs
	return rv
}
