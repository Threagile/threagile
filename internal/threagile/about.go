/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"errors"
	"fmt"
	"github.com/threagile/threagile/pkg/common"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/threagile/threagile/pkg/docs"
)

func (what *Threagile) initAbout() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.PrintVersionCommand,
		Short: "Get version information",
		Long:  "\n" + docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp),
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.Print3rdPartyCommand,
		Short: "Print 3rd-party license information",
		Long:  "\n" + docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp) + "\n\n" + docs.ThirdPartyLicenses,
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.PrintLicenseCommand,
		Short: "Print license information",
		RunE: func(cmd *cobra.Command, args []string) error {
			appDir, err := cmd.Flags().GetString(appDirFlagName)
			if err != nil {
				cmd.Printf("Unable to read app-dir flag: %v", err)
				return err
			}
			cmd.Println(docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp))
			if appDir != filepath.Clean(appDir) {
				// TODO: do we need this check here?
				cmd.Printf("weird app folder %v", appDir)
				return errors.New("weird app folder")
			}
			content, err := os.ReadFile(filepath.Clean(filepath.Join(appDir, "LICENSE.txt")))
			if err != nil {
				cmd.Printf("Unable to read license file: %v", err)
				return err
			}
			cmd.Print(string(content))
			cmd.Println()
			return nil
		},
	})

	return what
}
