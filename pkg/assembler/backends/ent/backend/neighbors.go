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
	"log"
	"strconv"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagetype"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcetype"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) Neighbors(ctx context.Context, node string, usingOnly []model.Edge) ([]model.Node, error) {
	return nil, nil
}

func (b *EntBackend) Node(ctx context.Context, node string) (model.Node, error) {
	id, err := strconv.Atoi(node)
	if err != nil {
		return nil, err
	}

	record, err := b.client.Noder(ctx, id)
	if err != nil {
		return nil, err
	}

	switch v := record.(type) {
	case *ent.Artifact:
		return toModelArtifact(v), nil
	case *ent.PackageVersion:
		pv, err := b.client.PackageVersion.Query().
			Where(packageversion.ID(v.ID)).
			WithName(func(q *ent.PackageNameQuery) {
				q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
					q.WithPackage()
				})
			}).
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelPackage(backReferencePackageVersion(pv)), nil
	case *ent.PackageName:
		pn, err := b.client.PackageName.Query().
			Where(packagename.ID(v.ID)).
			WithNamespace(func(q *ent.PackageNamespaceQuery) {
				q.WithPackage()
			}).
			WithVersions().
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelPackage(backReferencePackageName(pn)), nil
	case *ent.PackageNamespace:
		pns, err := b.client.PackageNamespace.Query().
			Where(packagenamespace.ID(v.ID)).
			WithPackage().
			WithNames(func(q *ent.PackageNameQuery) {
				q.WithVersions()
			}).
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelPackage(backReferencePackageNamespace(pns)), nil
	case *ent.PackageType:
		pt, err := b.client.PackageType.Query().
			Where(packagetype.ID(v.ID)).
			WithNamespaces().
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelPackage(pt), nil
	case *ent.SourceType:
		s, err := b.client.SourceType.Query().
			Where(sourcetype.ID(v.ID)).
			WithNamespaces().
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelSource(s), nil
	case *ent.Builder:
		return toModelBuilder(v), nil
	case *ent.VulnerabilityType:
		return toModelVulnerability(v), nil
	case *ent.Dependency:
		isDep, err := b.client.Dependency.Query().
			Where(dependency.ID(v.ID)).
			WithPackage(withPackageVersionTree()).
			WithDependentPackageName(withPackageNameTree()).
			WithDependentPackageVersion(withPackageVersionTree()).
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelIsDependencyWithBackrefs(isDep), nil
	default:
		log.Printf("Unknown node type: %T", v)
	}

	return nil, nil
}

func (b *EntBackend) Nodes(ctx context.Context, nodes []string) ([]model.Node, error) {
	rv := make([]model.Node, 0, len(nodes))
	for _, id := range nodes {
		n, err := b.Node(ctx, id)
		if err != nil {
			return nil, err
		}
		rv = append(rv, n)
	}
	return rv, nil
}

func (b *EntBackend) bfsFromVulnerablePackage(ctx context.Context, pkg int) ([][]model.Node, error) {
	queue := make([]int, 0) // the queue of nodes in bfs
	type dfsNode struct {
		expanded bool // true once all node neighbors are added to queue
		parent   int
	}
	nodeMap := map[int]dfsNode{}

	nodeMap[pkg] = dfsNode{}
	queue = append(queue, pkg)

	var now int
	var productsFound []int
	for len(queue) > 0 {
		now = queue[0]
		queue = queue[1:]
		nowNode := nodeMap[now]

		isDependencies, err := b.client.Dependency.Query().
			Select(dependency.FieldID, dependency.FieldPackageID).
			Where(dependency.DependentPackageVersionID(now)).
			All(ctx)
		if err != nil {
			return nil, gqlerror.Errorf("bfsThroughIsDependency ::  %s", err)
		}
		foundDependentPkg := false
		for _, isDependency := range isDependencies {
			foundDependentPkg = true
			next := isDependency.PackageID
			dfsN, seen := nodeMap[next]
			if !seen {
				dfsNIsDependency := dfsNode{
					parent: now,
				}
				nodeMap[isDependency.ID] = dfsNIsDependency
				dfsN = dfsNode{
					parent: isDependency.ID,
				}
				nodeMap[next] = dfsN
			}
			if !dfsN.expanded {
				queue = append(queue, next)
			}
		}
		// if none of the dependencies found has 'depPkg' as dependency package,
		// then it means 'depPkg' is a top level package (i.e. "product")
		// to be 100% the 'HasSBOM' check should/could be added
		if !foundDependentPkg {
			productsFound = append(productsFound, now)
		}

		nowNode.expanded = true
		nodeMap[now] = nowNode
	}

	result := [][]model.Node{}
	for i := range productsFound {
		reversedPath := []int{}
		step := productsFound[i]
		for step != pkg {
			reversedPath = append(reversedPath, step)
			step = nodeMap[step].parent
		}
		reversedPath = append(reversedPath, step)

		// reverse path
		path := make([]int, len(reversedPath))
		for i, x := range reversedPath {
			path[len(reversedPath)-i-1] = x
		}

		nodes, err := b.buildModelNodes(ctx, path)
		if err != nil {
			return nil, err
		}
		result = append(result, nodes)
	}
	return result, nil
}

func (b *EntBackend) buildModelNodes(ctx context.Context, nodeIDs []int) ([]model.Node, error) {
	out := make([]model.Node, len(nodeIDs))

	for i, nodeID := range nodeIDs {
		var err error
		out[i], err = b.Node(ctx, strconv.Itoa(nodeID))
		if err != nil {
			return nil, gqlerror.Errorf("Internal data error: got invalid node id %d :: %s", nodeID, err)
		}
	}

	return out, nil
}
