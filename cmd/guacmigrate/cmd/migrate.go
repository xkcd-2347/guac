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

//go:build !(386 || arm || mips)

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/backend"
	entbackend "github.com/guacsec/guac/pkg/assembler/backends/ent/backend"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
)

const (
	ent = "ent"
)

type optsFunc func() backends.BackendArgs

var getOpts map[string]optsFunc

func init() {
	if getOpts == nil {
		getOpts = make(map[string]optsFunc)
	}
}

func runMigrate(cmd *cobra.Command) {
	ctx := logging.WithLogger(context.Background())

	opts := entbackend.BackendOptions{
		DriverName:  flags.dbDriver,
		Address:     flags.dbAddress,
		Debug:       flags.dbDebug,
		AutoMigrate: true,
	}

	_, err := backend.SetupBackend(ctx, &opts)

	if err != nil {
		fmt.Printf("failed to setup backend, %v\n", err)
		os.Exit(1)
	}
}
