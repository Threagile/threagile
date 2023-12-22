/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"fmt"
	"log"
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
