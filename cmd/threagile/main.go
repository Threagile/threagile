package main

import (
	"github.com/threagile/threagile/internal/threagile"
)

var (
	buildTimestamp = ""
)

func main() {
	new(threagile.Threagile).Init(buildTimestamp).Execute()
}
