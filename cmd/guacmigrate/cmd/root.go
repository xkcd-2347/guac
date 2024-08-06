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
	"fmt"
	"os"
	"strings"

	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var flags = struct {
	backend string

	// Needed only if using ent backend
	dbAddress string
	dbDriver  string
	dbDebug   bool
	dbMigrate bool
}{}

var rootCmd = &cobra.Command{
	Use:     "guacmigrate",
	Short:   "GUAC migrate command",
	Version: version.Version,
	Run: func(cmd *cobra.Command, args []string) {
		flags.dbAddress = viper.GetString("db-address")
		flags.dbDriver = viper.GetString("db-driver")
		flags.dbDebug = viper.GetBool("db-debug")

		runMigrate(cmd)
	},
}

func init() {
	cobra.OnInitialize(cli.InitConfig)

	set, err := cli.BuildFlags([]string{
		"db-address", "db-driver", "db-debug",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	rootCmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(rootCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	viper.SetEnvPrefix("GUAC")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
