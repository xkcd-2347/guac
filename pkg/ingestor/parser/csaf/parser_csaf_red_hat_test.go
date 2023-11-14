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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_csafRedHatParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name           string
		doc            *processor.Document
		wantPredicates *assembler.IngestPredicates
		wantErr        bool
	}{{
		name: "valid big CSAF document",
		doc: &processor.Document{
			Blob:   testdata.CsafExampleRedHat,
			Format: processor.FormatJSON,
			Type:   processor.DocumentCsaf,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantPredicates: &assembler.IngestPredicates{
			Vex: testdata.CsafVexIngest,
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewCsafRedHatParser()
			err := s.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("csafParse.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			preds := s.GetPredicates(ctx)
			if d := cmp.Diff(tt.wantPredicates, preds, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
				t.Errorf("csaf.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}

func Test_csafRedHatParser_GetIdentifiers(t *testing.T) {
	type fields struct {
		doc               *processor.Document
		identifierStrings *common.IdentifierStrings
	}
	test := struct {
		name    string
		fields  fields
		ctx     context.Context
		want    *common.IdentifierStrings
		wantErr bool
	}{
		name: "default test",
		fields: fields{
			doc: &processor.Document{
				Blob:   testdata.CsafExampleRedHat,
				Format: processor.FormatJSON,
				Type:   processor.DocumentCsaf,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			identifierStrings: &common.IdentifierStrings{},
		},
		ctx: context.Background(),
		want: &common.IdentifierStrings{
			PurlStrings: []string{
				"BaseOS-8.6.0.Z.EUS:openssl-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-1:1.1.1k-8.el8_6.src",
				"BaseOS-8.6.0.Z.EUS:openssl-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-debuginfo-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-debuginfo-1:1.1.1k-8.el8_6.i686",
				"BaseOS-8.6.0.Z.EUS:openssl-debuginfo-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-debuginfo-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-debuginfo-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-debugsource-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-debugsource-1:1.1.1k-8.el8_6.i686",
				"BaseOS-8.6.0.Z.EUS:openssl-debugsource-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-debugsource-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-debugsource-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-devel-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-devel-1:1.1.1k-8.el8_6.i686",
				"BaseOS-8.6.0.Z.EUS:openssl-devel-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-devel-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-devel-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-1:1.1.1k-8.el8_6.i686",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-debuginfo-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-debuginfo-1:1.1.1k-8.el8_6.i686",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-debuginfo-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-debuginfo-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-debuginfo-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-perl-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-perl-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-perl-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-perl-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-1:1.1.1k-7.el8_6.x86_64",
			},
		},
	}

	c := NewCsafRedHatParser()

	err := c.Parse(test.ctx, test.fields.doc)
	if err != nil {
		t.Errorf("Parse() error = %v", err)
		return
	}

	_ = c.GetPredicates(test.ctx)

	got, err := c.GetIdentifiers(test.ctx)
	if (err != nil) != test.wantErr {
		t.Errorf("GetIdentifiers() error = %v, wantErr %v", err, test.wantErr)
		return
	}
	if d := cmp.Diff(test.want, got, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
		t.Errorf("csaf.GetPredicate mismatch values (+got, -expected): %s", d)
	}
}
