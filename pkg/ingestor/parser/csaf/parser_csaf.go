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
	"strconv"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	guaccasf "github.com/guacsec/guac/pkg/handler/processor/csaf"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"

	"github.com/openvex/go-vex/pkg/csaf"
)

var (
	justificationsMap = map[string]generated.VexJustification{
		"component_not_present":                             generated.VexJustificationComponentNotPresent,
		"vulnerable_code_not_present":                       generated.VexJustificationVulnerableCodeNotPresent,
		"vulnerable_code_not_in_execute_path":               generated.VexJustificationVulnerableCodeNotInExecutePath,
		"vulnerable_code_cannot_be_controlled_by_adversary": generated.VexJustificationVulnerableCodeCannotBeControlledByAdversary,
		"inline_mitigations_already_exist":                  generated.VexJustificationInlineMitigationsAlreadyExist,
	}

	vexStatusMap = map[string]generated.VexStatus{
		"known_not_affected":  generated.VexStatusNotAffected,
		"known_affected":      generated.VexStatusAffected,
		"fixed":               generated.VexStatusFixed,
		"first_fixed":         generated.VexStatusFixed,
		"under_investigation": generated.VexStatusUnderInvestigation,
		"first_affected":      generated.VexStatusAffected,
		"last_affected":       generated.VexStatusAffected,
		"recommended":         generated.VexStatusAffected,
	}
)

type findPkgSpec interface {
	findPkgSpec(ctx context.Context, product_id string) (*generated.PkgInputSpec, error)
}

type csafParser struct {
	doc               *processor.Document
	identifierStrings *common.IdentifierStrings

	csaf *csaf.CSAF
}

type visitedProductRef struct {
	productName string
	productID   string
	name        string
	category    string
}

func NewCsafParser() common.DocumentParser {
	return &csafParser{
		identifierStrings: &common.IdentifierStrings{},
	}
}

// Parse breaks out the document into the graph components
func (c *csafParser) Parse(ctx context.Context, doc *processor.Document) error {
	c.doc = doc
	var decoded csaf.CSAF
	err := guaccasf.UnmarshallFixingDates(doc.Blob, &decoded)
	c.csaf = &decoded
	if err != nil {
		return fmt.Errorf("failed to parse CSAF: %w", err)
	}

	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (c *csafParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (c *csafParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return c.identifierStrings, nil
}

// findPurl searches the given CSAF product tree recursively to find the
// purl for the specified product reference.
//
// It recursively calls itself on each child branch of the tree in a
// depth first search manner if the nodes name isn't equal to product_ref.
func findPurl(ctx context.Context, tree csaf.ProductBranch, product_ref string) *string {
	return findIdentificationHelperSearch(ctx, "purl", tree, product_ref, make(map[string]bool))
}

// findCPE searches the given CSAF product tree recursively to find the
// cpe for the specified product reference.
//
// It recursively calls itself on each child branch of the tree in a
// depth first search manner if the nodes name isn't equal to product_ref.
func findCPE(ctx context.Context, tree csaf.ProductBranch, product_ref string) *string {
	return findIdentificationHelperSearch(ctx, "cpe", tree, product_ref, make(map[string]bool))
}

func findIdentificationHelperSearch(ctx context.Context, identificationHelperKey string, tree csaf.ProductBranch, product_ref string, visited map[string]bool) *string {
	if tree.Name == product_ref || tree.Product.ID == product_ref {
		purl := tree.Product.IdentificationHelper[identificationHelperKey]
		return &purl
	}

	for i, b := range tree.Branches {
		key := fmt.Sprintf("%v-%v-%v", tree.Name, strconv.Itoa(i), b.Name)
		if visited[key] {
			continue
		}
		visited[key] = true
		purl := findIdentificationHelperSearch(ctx, identificationHelperKey, b, product_ref, visited)
		if purl != nil {
			return purl
		}
	}

	return nil
}

// findProductsRef searches for a product_reference and relates_to_product_reference strings pair
// for the given product ID by recursively traversing the CSAF product tree.
//
// findProductRefAndRelatesToProductRefSearch was seperated from findProductsRef so that the code can use
// a visited map and avoid infinite recursion.
//
// It returns a pointer to the product reference string if found,
// otherwise nil.
func findProductsRef(ctx context.Context, tree csaf.ProductBranch, product_id string) (*string, *string) {
	return findProductRefAndRelatesToProductRefSearch(ctx, tree, product_id, make(map[visitedProductRef]bool))
}

// findProductRefAndRelatesToProductRefSearch recursively searches the product tree for a product
// reference matching the given product ID. It does this with a visited map to
// avoid infinite recursion.
//
// It returns a pointer to the product reference string if found,
// otherwise nil.
func findProductRefAndRelatesToProductRefSearch(ctx context.Context, tree csaf.ProductBranch, product_id string, visited map[visitedProductRef]bool) (*string, *string) {
	if visited[visitedProductRef{tree.Product.Name, tree.Product.ID, tree.Name, tree.Category}] {
		return nil, nil
	}
	visited[visitedProductRef{tree.Product.Name, tree.Product.ID, tree.Name, tree.Category}] = true

	for _, r := range tree.Relationships {
		if r.FullProductName.ID == product_id {
			return &r.ProductRef, &r.RelatesToProductRef
		}
	}

	for _, b := range tree.Branches {
		prodRef, relToProdRef := findProductRefAndRelatesToProductRefSearch(ctx, b, product_id, visited)
		if prodRef != nil {
			return prodRef, relToProdRef
		}
	}
	return nil, nil
}

// findActionStatement searches the given Vulnerability tree to find the action statement
// for the product with the given product_id. If a matching product is found, it returns
// a pointer to the Details string for the Remediation.
// If no matching product is found, it returns nil.
func findActionStatement(tree *csaf.Vulnerability, product_id string) *string {
	for _, r := range tree.Remediations {
		for _, p := range r.ProductIDs {
			if p == product_id {
				return &r.Details
			}
		}
	}
	return nil
}

// findImpactStatement searches the given Vulnerability tree to find the impact statement
// for the product with the given product_id. If a matching product is found, it returns
// a pointer to the Details string for the Threat.
// If no matching product is found, it returns nil.
func findImpactStatement(tree *csaf.Vulnerability, product_id string) *string {
	for _, t := range tree.Threats {
		if t.Category == "impact" {
			for _, p := range t.ProductIDs {
				if p == product_id {
					return &t.Details
				}
			}
		}
	}
	return nil
}

// findPkgSpec finds the package specification for the product with the
// given ID in the CSAF document. It returns a pointer to the package
// specification if found, otherwise an error.
func (c *csafParser) findPkgSpec(ctx context.Context, product_id string) (*generated.PkgInputSpec, error) {
	pref, _ := findProductsRef(ctx, c.csaf.ProductTree, product_id)
	if pref == nil {
		return nil, fmt.Errorf("unable to locate product reference for id %s", product_id)
	}

	purl := findPurl(ctx, c.csaf.ProductTree, *pref)
	if purl == nil {
		return nil, fmt.Errorf("unable to locate product url for reference %s", *pref)
	}

	return helpers.PurlToPkg(*purl)
}

// generateVexIngest generates a VEX ingest object from a CSAF vulnerability and other input data.
//
// The function maps CSAF data into a VEX ingest object for adding to the vulnerability graph.
// It then tries to find the package for the product ID to add to ingest.
// If it can't be found, it then returns nil, otherwise it returns a pointer to the VEX ingest object.
func generateVexIngest(ctx context.Context, c *csafParser, parser findPkgSpec, vulnInput *generated.VulnerabilityInputSpec, csafVuln *csaf.Vulnerability, status string, product_id string) *assembler.VexIngest {
	logger := logging.FromContext(ctx)
	vi := &assembler.VexIngest{}

	vd := generated.VexStatementInputSpec{}
	vd.KnownSince = c.csaf.Document.Tracking.CurrentReleaseDate
	vd.Origin = c.csaf.Document.Tracking.ID
	vd.VexJustification = generated.VexJustificationNotProvided

	if vexStatus, ok := vexStatusMap[status]; ok {
		vd.Status = vexStatus
	}

	var statement *string
	if vd.Status == generated.VexStatusNotAffected {
		statement = findImpactStatement(csafVuln, product_id)
	} else {
		statement = findActionStatement(csafVuln, product_id)
	}

	if statement != nil {
		vd.Statement = *statement
	}

	for _, flag := range csafVuln.Flags {
		found := false
		for _, pid := range flag.ProductIDs {
			if pid == product_id {
				found = true
			}
		}
		if found {
			if just, ok := justificationsMap[flag.Label]; ok {
				vd.VexJustification = just
			}
		}
	}

	vi.VexData = &vd
	vi.Vulnerability = vulnInput
	c.identifierStrings.PurlStrings = append(c.identifierStrings.PurlStrings, product_id)

	pkg, err := parser.findPkgSpec(ctx, product_id)
	if err != nil {
		logger.Warnf("[csaf] unable to locate package for not-affected product %s: %v", product_id, err)
		return nil
	}
	vi.Pkg = pkg

	return vi
}

// GetPredicates generates the VEX and CertifyVuln predicates for the CSAF document.
//
// It returns a pointer to an assembler.IngestPredicates struct containing the
// generated VEX and CertifyVuln predicates.
func (c *csafParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	rv := &assembler.IngestPredicates{}
	var vis []assembler.VexIngest

	for _, v := range c.csaf.Vulnerabilities {
		vuln, err := helpers.CreateVulnInput(v.CVE)
		if err != nil {
			return nil
		}

		statuses := []string{"fixed", "known_not_affected", "known_affected", "first_affected", "first_fixed", "last_affected", "recommended", "under_investigation"}
		for _, status := range statuses {
			products := v.ProductStatus[status]
			for _, product := range products {
				vi := generateVexIngest(ctx, c, c, vuln, &v, status, product)
				if vi == nil {
					continue
				}
				vis = append(vis, *vi)
			}
		}
	}
	rv.Vex = vis
	return rv
}
