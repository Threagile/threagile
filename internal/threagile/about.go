/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package threagile

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/threagile/threagile/pkg/docs"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Get version information",
	Long:  "\n" + docs.Logo + "\n\n" + docs.VersionText,
}

var print3rdPartyCmd = &cobra.Command{
	Use:   "print-3rd-party-licenses",
	Short: "Print 3rd-party license information",
	Long:  "\n" + docs.Logo + "\n\n" + docs.VersionText + "\n\n" + docs.ThirdPartyLicenses,
}

var printLicenseCmd = &cobra.Command{
	Use:   "print-license",
	Short: "Print license information",
	RunE: func(cmd *cobra.Command, args []string) error {
		appDir, err := cmd.Flags().GetString(appDirFlagName)
		if err != nil {
			cmd.Printf("Unable to read app-dir flag: %v", err)
			return err
		}
		cmd.Println(docs.Logo + "\n\n" + docs.VersionText)
		if appDir != filepath.Clean(appDir) {
			// TODO: do we need this check here?
			cmd.Printf("weird app folder %v", appDir)
			return errors.New("weird app folder")
		}
		content, err := os.ReadFile(filepath.Join(appDir, "LICENSE.txt"))
		if err != nil {
			cmd.Printf("Unable to read license file: %v", err)
			return err
		}
		cmd.Print(string(content))
		cmd.Println()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(print3rdPartyCmd)
	rootCmd.AddCommand(printLicenseCmd)
}
