/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package common

import (
	"fmt"
	"log"
)

type DefaultProgressReporter struct {
	Verbose       bool
	SuppressError bool
}

func (r DefaultProgressReporter) Info(a ...any) {
	if r.Verbose {
		fmt.Println(a...)
	}
}

func (DefaultProgressReporter) Warn(a ...any) {
	fmt.Println(a...)
}

func (r DefaultProgressReporter) Error(v ...any) {
	if r.SuppressError {
		r.Warn(v...)
		return
	}
	log.Fatal(v...)
}

func (r DefaultProgressReporter) Infof(format string, a ...any) {
	if r.Verbose {
		fmt.Printf(format, a...)
		fmt.Println()
	}
}

func (DefaultProgressReporter) Warnf(format string, a ...any) {
	fmt.Print("WARNING: ")
	fmt.Printf(format, a...)
	fmt.Println()
}

func (r DefaultProgressReporter) Errorf(format string, v ...any) {
	if r.SuppressError {
		r.Warnf(format, v...)
		return
	}
	log.Fatalf(format, v...)
}
