/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/examples"
)

func (what *Threagile) initCreate() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.CreateExampleModelCommand,
		Short: "Create example threagile model",
		Long:  "\n" + docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp) + "\n\njust create an example model named threagile-example-model.yaml in the output directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			appDir, err := cmd.Flags().GetString(appDirFlagName)
			if err != nil {
				cmd.Printf("Unable to read app-dir flag: %v", err)
				return err
			}
			outDir, err := cmd.Flags().GetString(outputFlagName)
			if err != nil {
				cmd.Printf("Unable to read output flag: %v", err)
				return err
			}

			err = examples.CreateExampleModelFile(appDir, outDir)
			if err != nil {
				cmd.Printf("Unable to copy example model: %v", err)
				return err
			}

			cmd.Println(docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp))
			cmd.Println("An example model was created named threagile-example-model.yaml in the output directory.")
			cmd.Println()
			cmd.Println(docs.Examples)
			cmd.Println()
			return nil
		},
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.CreateStubModelCommand,
		Short: "Create stub threagile model",
		Long:  "\n" + docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp) + "\n\njust create a minimal stub model named threagile-stub-model.yaml in the output directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			appDir, err := cmd.Flags().GetString(appDirFlagName)
			if err != nil {
				cmd.Printf("Unable to read app-dir flag: %v", err)
				return err
			}
			outDir, err := cmd.Flags().GetString(outputFlagName)
			if err != nil {
				cmd.Printf("Unable to read output flag: %v", err)
				return err
			}

			err = examples.CreateStubModelFile(appDir, outDir)
			if err != nil {
				cmd.Printf("Unable to copy stub model: %v", err)
				return err
			}

			cmd.Println(docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp))
			cmd.Println("A minimal stub model was created named threagile-stub-model.yaml in the output directory.")
			cmd.Println()
			cmd.Println(docs.Examples)
			cmd.Println()
			return nil
		},
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.CreateEditingSupportCommand,
		Short: "Create editing support",
		Long:  "\n" + docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp) + "\n\njust create some editing support stuff in the output directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			appDir, err := cmd.Flags().GetString(appDirFlagName)
			if err != nil {
				cmd.Printf("Unable to read app-dir flag: %v", err)
				return err
			}
			outDir, err := cmd.Flags().GetString(outputFlagName)
			if err != nil {
				cmd.Printf("Unable to read output flag: %v", err)
				return err
			}

			err = examples.CreateEditingSupportFiles(appDir, outDir)
			if err != nil {
				cmd.Printf("Unable to copy editing support files: %v", err)
				return err
			}

			cmd.Println(docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp))
			cmd.Println("The following files were created in the output directory:")
			cmd.Println(" - schema.json")
			cmd.Println(" - live-templates.txt")
			cmd.Println()
			cmd.Println("For a perfect editing experience within your IDE of choice you can easily get " +
				"model syntax validation and autocompletion (very handy for enum values) as well as live templates: " +
				"Just import the schema.json into your IDE and assign it as \"schema\" to each Threagile YAML file. " +
				"Also try to import individual parts from the live-templates.txt file into your IDE as live editing templates.")
			cmd.Println()
			return nil
		},
	})

	return what
}
