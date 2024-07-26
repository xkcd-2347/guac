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
	"sort"
	"strings"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	assembler_helpers "github.com/guacsec/guac/pkg/assembler/clients/helpers"
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
		endpoint, ok := ctx.Value(common.KeyGraphqlEndpoint).(string)
		if !ok {
			return nil, fmt.Errorf("unable to locate product url for reference %s due to missing graphqlEndpoint value", *pref)
		}
		gqlclient, err := assembler_helpers.GetGqlClient(endpoint)
		if err != nil {
			return nil, err
		}
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
		var packageName, packageNamespace *string
		packageInfo := strings.Split(*pref, "/")
		if len(packageInfo) == 2 {
			// pref "io.quarkus/quarkus-spring-security"
			packageNamespace = &packageInfo[0]
			packageName = &packageInfo[1]
		} else if len(packageInfo) == 1 {
			// pref "vim"
			packageName = &packageInfo[0]
		} else {
			return nil, fmt.Errorf("unable to derive a valid package reference from %v", pref)
		}
		for _, pkgWithMetadata := range pkgsWithMetadata.HasMetadata {
			// check the ones whose value starts with the CPE found in the VEX
			if strings.HasPrefix(pkgWithMetadata.Value, *cpe) {
				switch productPkg := pkgWithMetadata.Subject.(type) {
				case *generated.AllHasMetadataSubjectPackage:
					toPkg, err := helpers.PurlToPkgFilter(helpers.AllPkgTreeToPurl(&productPkg.AllPkgTree))
					if err != nil {
						logger.Warnf("Failed to handle the HasMetadata response %+v\n", productPkg)
						continue
					}
					filterProductDependencies := &generated.HasSBOMSpec{
						IncludedDependencies: []generated.IsDependencySpec{
							{
								Package: &toPkg,
								DependencyPackage: &generated.PkgSpec{
									Namespace: packageNamespace,
									Name:      packageName,
								},
							},
						},
					}
					includedDependenciesHasSBOMResponse, err := generated.HasSBOMs(ctx, gqlclient, *filterProductDependencies)
					if err != nil {
						return nil, err
					}
					for _, hasSBOM := range includedDependenciesHasSBOMResponse.HasSBOM {
						for _, includedDependency := range hasSBOM.IncludedDependencies {
							if strings.EqualFold(includedDependency.DependencyPackage.Namespaces[0].Names[0].Name, *packageName) {
								vulnerablePkgInputSpec, err := helpers.PurlToPkg(helpers.AllPkgTreeToPurl(&includedDependency.DependencyPackage.AllPkgTree))
								if err != nil {
									logger.Warnf("Failed to handle the IsDependency response %+v\n", includedDependency)
								} else {
									purlsMap[helpers.PkgInputSpecToPurl(vulnerablePkgInputSpec)] = struct{}{}
								}
							}
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
	logger := logging.FromContext(ctx)
	rv := &assembler.IngestPredicates{}
	var vis = make(map[string]assembler.VexIngest)

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
				var purl = helpers.PkgInputSpecToPurl(vi.Pkg)
				if _, ok := vis[purl]; ok {
					logger.Debugf("Duplicate ingest entry %v\n", vis)
				} else {
					vis[purl] = *vi
				}
			}
		}
	}
	rv.Vex = maps.Values(vis)
	return rv
}
