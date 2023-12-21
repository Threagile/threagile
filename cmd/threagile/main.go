package main

import "github.com/threagile/threagile/internal/threagile"

func main() {
	context := new(threagile.Context).Defaults()
	context.ParseCommandlineArgs()
	if context.ServerPort > 0 {
		context.StartServer()
	} else {
		context.DoIt()
	}
}
