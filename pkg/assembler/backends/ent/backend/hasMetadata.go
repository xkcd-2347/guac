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
	stdsql "database/sql"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hasmetadata"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"golang.org/x/sync/errgroup"
)

func (b *EntBackend) HasMetadata(ctx context.Context, filter *model.HasMetadataSpec) ([]*model.HasMetadata, error) {
	records, err := b.client.HasMetadata.Query().
		Where(hasMetadataPredicate(filter, nil)).
		Limit(MaxPageSize).
		WithSource(withSourceNameTreeQuery()).
		WithArtifact().
		WithPackageVersion(withPackageVersionTree()).
		WithAllVersions(withPackageNameTree()).
		All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve HasMetadata :: %s", err)
	}

	return collect(records, toModelHasMetadata), nil
}

func (b *EntBackend) IngestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec) (*model.HasMetadata, error) {
	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		return upsertHasMetadata(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, hasMetadata)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to execute IngestHasMetadata :: %s", err)
	}

	return &model.HasMetadata{ID: nodeID(*recordID)}, nil
}

func (b *EntBackend) IngestBulkHasMetadata(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, hasMetadataList []*model.HasMetadataInputSpec) ([]string, error) {
	var results = make([]string, len(hasMetadataList))
	eg, ctx := errgroup.WithContext(ctx)
	for i := range hasMetadataList {
		index := i
		hmSpec := *hasMetadataList[i]
		var subject model.PackageSourceOrArtifactInput
		if len(subjects.Packages) > 0 {
			subject = model.PackageSourceOrArtifactInput{Package: subjects.Packages[i]}
		} else if len(subjects.Artifacts) > 0 {
			subject = model.PackageSourceOrArtifactInput{Artifact: subjects.Artifacts[i]}
		} else {
			subject = model.PackageSourceOrArtifactInput{Source: subjects.Sources[i]}
		}
		concurrently(eg, func() error {
			hm, err := b.IngestHasMetadata(ctx, subject, pkgMatchType, hmSpec)
			if err == nil {
				results[index] = hm.ID
				return err
			} else {
				return gqlerror.Errorf("IngestBulkHasMetadata failed with element #%v %+v with err: %v", index, *subject.Package, err)
			}
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}

func hasMetadataPredicate(filter *model.HasMetadataSpec, pkgMatchType *model.MatchFlags) predicate.HasMetadata {
	predicates := []predicate.HasMetadata{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Since, hasmetadata.TimestampGTE),
		optionalPredicate(filter.Key, hasmetadata.KeyEQ),
		optionalPredicate(filter.Value, hasmetadata.ValueEQ),
		optionalPredicate(filter.Justification, hasmetadata.JustificationEQ),
		optionalPredicate(filter.Origin, hasmetadata.OriginEQ),
		optionalPredicate(filter.Collector, hasmetadata.CollectorEQ),
	}

	if filter.Subject != nil {
		switch {
		case filter.Subject.Artifact != nil:
			if filter.Subject.Artifact.ID != nil {
				predicates = append(predicates,
					sql.FieldEQ(hasmetadata.FieldArtifactID, filter.Subject.Artifact.ID),
				)
			} else {
				predicates = append(predicates,
					hasmetadata.HasArtifactWith(artifactQueryPredicates(filter.Subject.Artifact)),
				)
			}
			predicates = append(predicates,
				hasmetadata.SourceIDIsNil(),
				hasmetadata.PackageNameIDIsNil(),
				hasmetadata.PackageVersionIDIsNil(),
			)
		case filter.Subject.Package != nil:
			if filter.Subject.Package.ID != nil {
				if (pkgMatchType != nil && pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion) ||
					filter.Subject.Package.Version != nil {
					predicates = append(predicates,
						sql.FieldEQ(hasmetadata.FieldPackageVersionID, filter.Subject.Package.ID),
						hasmetadata.PackageNameIDIsNil(),
					)
				} else {
					predicates = append(predicates,
						hasmetadata.PackageVersionIDIsNil(),
						sql.FieldEQ(hasmetadata.FieldPackageNameID, filter.Subject.Package.ID),
					)
				}
			} else {
				predicates = append(predicates, hasmetadata.Or(
					hasmetadata.HasAllVersionsWith(packageNameQuery(pkgNameQueryFromPkgSpec(filter.Subject.Package))),
					hasmetadata.HasPackageVersionWith(packageVersionQuery(filter.Subject.Package)),
				))
			}
			predicates = append(predicates,
				hasmetadata.SourceIDIsNil(),
				hasmetadata.ArtifactIDIsNil(),
			)
		case filter.Subject.Source != nil:
			if filter.Subject.Source.ID != nil {
				predicates = append(predicates,
					sql.FieldEQ(hasmetadata.FieldSourceID, filter.Subject.Source.ID),
				)
			} else {
				predicates = append(predicates,
					hasmetadata.HasSourceWith(sourceQuery(filter.Subject.Source)),
				)
			}
			predicates = append(predicates,
				hasmetadata.PackageNameIDIsNil(),
				hasmetadata.PackageVersionIDIsNil(),
				hasmetadata.ArtifactIDIsNil(),
			)
		}
	}
	return hasmetadata.And(predicates...)
}

func upsertHasMetadata(ctx context.Context, client *ent.Tx, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.HasMetadataInputSpec) (*int, error) {
	insert := client.HasMetadata.Create().
		SetKey(spec.Key).
		SetValue(spec.Value).
		SetTimestamp(spec.Timestamp.UTC()).
		SetJustification(spec.Justification).
		SetOrigin(spec.Origin).
		SetCollector(spec.Collector)

	conflictColumns := []string{
		hasmetadata.FieldKey,
		hasmetadata.FieldValue,
		hasmetadata.FieldJustification,
		hasmetadata.FieldOrigin,
		hasmetadata.FieldCollector,
	}
	var conflictWhere *sql.Predicate

	var subjectSpec *model.PackageSourceOrArtifactSpec
	switch {
	case subject.Artifact != nil:
		art, err := client.Artifact.Query().Where(artifactQueryInputPredicates(*subject.Artifact)).OnlyID(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve subject artifact :: %s", err)
		}
		insert.SetArtifactID(art)
		conflictColumns = append(conflictColumns, hasmetadata.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(hasmetadata.FieldArtifactID),
			sql.IsNull(hasmetadata.FieldPackageNameID),
			sql.IsNull(hasmetadata.FieldPackageVersionID),
			sql.IsNull(hasmetadata.FieldSourceID),
		)
		subjectSpec = &model.PackageSourceOrArtifactSpec{
			Artifact: &model.ArtifactSpec{ID: ptrfrom.String(nodeID(art))},
		}

	case subject.Package != nil:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			pv, err := getPkgVersionID(ctx, client.Client(), *subject.Package)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve subject package version :: %s", err)
			}
			insert.SetPackageVersionID(pv)
			conflictColumns = append(conflictColumns, hasmetadata.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(hasmetadata.FieldArtifactID),
				sql.NotNull(hasmetadata.FieldPackageVersionID),
				sql.IsNull(hasmetadata.FieldPackageNameID),
				sql.IsNull(hasmetadata.FieldSourceID),
			)
			subjectSpec = &model.PackageSourceOrArtifactSpec{
				Package: &model.PkgSpec{ID: ptrfrom.String(nodeID(pv))},
			}
		} else {
			pn, err := getPkgNameID(ctx, client.Client(), *subject.Package)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve subject package name :: %s", err)
			}
			insert.SetAllVersionsID(pn)
			conflictColumns = append(conflictColumns, hasmetadata.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(hasmetadata.FieldArtifactID),
				sql.IsNull(hasmetadata.FieldPackageVersionID),
				sql.NotNull(hasmetadata.FieldPackageNameID),
				sql.IsNull(hasmetadata.FieldSourceID),
			)
			//subject.Package.Version = nil
			subjectSpec = &model.PackageSourceOrArtifactSpec{
				Package: &model.PkgSpec{ID: ptrfrom.String(nodeID(pn))},
			}
		}

	case subject.Source != nil:
		srcID, err := getSourceNameID(ctx, client.Client(), *subject.Source)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve subject source :: %s", err)
		}
		insert.SetSourceID(srcID)
		conflictColumns = append(conflictColumns, hasmetadata.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(hasmetadata.FieldArtifactID),
			sql.IsNull(hasmetadata.FieldPackageVersionID),
			sql.IsNull(hasmetadata.FieldPackageNameID),
			sql.NotNull(hasmetadata.FieldSourceID),
		)
		subjectSpec = &model.PackageSourceOrArtifactSpec{
			Source: &model.SourceSpec{ID: ptrfrom.String(nodeID(srcID))},
		}
	}

	id, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert HasMetadata node")
		}
		id, err = client.HasMetadata.Query().
			Where(hasMetadataInputPredicate(subjectSpec, pkgMatchType, spec)).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get HasMetadata")
		}
	}

	return &id, nil
}

func toModelHasMetadata(v *ent.HasMetadata) *model.HasMetadata {
	var sub model.PackageSourceOrArtifact

	switch {
	case v.Edges.Source != nil:
		sub = toModelSource(backReferenceSourceName(v.Edges.Source))
	case v.Edges.PackageVersion != nil:
		sub = toModelPackage(backReferencePackageVersion(v.Edges.PackageVersion))
	case v.Edges.AllVersions != nil:
		pkg := toModelPackage(backReferencePackageName(v.Edges.AllVersions))
		// in this case, the expected response is package name with an empty package version array
		pkg.Namespaces[0].Names[0].Versions = []*model.PackageVersion{}
		sub = pkg
	case v.Edges.Artifact != nil:
		sub = toModelArtifact(v.Edges.Artifact)
	}

	return &model.HasMetadata{
		ID:            nodeID(v.ID),
		Subject:       sub,
		Key:           v.Key,
		Value:         v.Value,
		Timestamp:     v.Timestamp,
		Justification: v.Justification,
		Origin:        v.Origin,
		Collector:     v.Collector,
	}
}

func hasMetadataInputPredicate(subjectSpec *model.PackageSourceOrArtifactSpec, pkgMatchType *model.MatchFlags, filter model.HasMetadataInputSpec) predicate.HasMetadata {
	return hasMetadataPredicate(&model.HasMetadataSpec{
		Subject:       subjectSpec,
		Key:           &filter.Key,
		Value:         &filter.Value,
		Justification: &filter.Justification,
		Origin:        &filter.Origin,
		Collector:     &filter.Collector,
	},
		pkgMatchType)
}
