package main

import (
	threagile "github.com/threagile/threagile/internal/threagile"
)

const (
	buildTimestamp = ""
)

func main() {
	new(threagile.Threagile).Init().Execute()
}
