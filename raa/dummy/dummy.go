package main

import (
	"fmt"
	"github.com/threagile/threagile/model"
	"math/rand"
)

// JUST A DUMMY TO HAVE AN ALTERNATIVE PLUGIN TO USE/TEST

// used from plugin caller:
func CalculateRAA() string {
	for techAssetID, techAsset := range model.ParsedModelRoot.TechnicalAssets {
		techAsset.RAA = float64(rand.Intn(100))
		fmt.Println("Using dummy RAA random calculation (just to test the usage of other shared object files as plugins)")
		model.ParsedModelRoot.TechnicalAssets[techAssetID] = techAsset
	}
	// return intro text (for reporting etc., can be short summary-like)
	return "Just some dummy algorithm implementation for demo purposes of pluggability..."
}
