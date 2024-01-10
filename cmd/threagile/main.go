package main

import (
	"github.com/threagile/threagile/internal/threagile"
)

const (
	buildTimestamp = ""
)

func main() {
	new(threagile.Threagile).Init(buildTimestamp).Execute()
}
