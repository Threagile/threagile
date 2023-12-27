/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package common

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

type ProgressReporter interface {
	Println(a ...any) (n int, err error)
	Fatalf(format string, v ...any)
}

type SilentProgressReporter struct{}

func (SilentProgressReporter) Println(a ...any) (n int, err error) {
	return 0, nil
}

func (SilentProgressReporter) Fatalf(format string, v ...any) {
}

type CommandLineProgressReporter struct{}

func (CommandLineProgressReporter) Println(a ...any) (n int, err error) {
	return fmt.Println(a...)
}
func (CommandLineProgressReporter) Fatalf(format string, v ...any) {
	log.Fatalf(format, v...)
}

func GetProgressReporter(cobraCmd *cobra.Command) ProgressReporter {
	if cobraCmd == nil {
		return CommandLineProgressReporter{}
	}
	if cobraCmd.Flags().Lookup("verbose") != nil && cobraCmd.Flags().Lookup("verbose").Changed {
		return SilentProgressReporter{}
	}
	return CommandLineProgressReporter{}
}
