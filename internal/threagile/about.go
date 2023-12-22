/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package threagile

import (
	"github.com/spf13/cobra"

	"github.com/threagile/threagile/pkg/docs"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Get version information",
	Long:  "\n" + docs.Logo + "\n\n" + docs.VersionText,
}
