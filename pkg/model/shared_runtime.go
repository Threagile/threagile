/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package model

import (
	"sort"

	"github.com/threagile/threagile/pkg/security/types"
)

type SharedRuntime struct {
	Id, Title, Description string
	Tags                   []string
	TechnicalAssetsRunning []string
}

func (what SharedRuntime) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

func (what SharedRuntime) IsTaggedWithBaseTag(baseTag string) bool {
	return IsTaggedWithBaseTag(what.Tags, baseTag)
}

func (what SharedRuntime) HighestConfidentiality(model *ParsedModel) types.Confidentiality {
	highest := types.Public
	for _, id := range what.TechnicalAssetsRunning {
		techAsset := model.TechnicalAssets[id]
		if techAsset.HighestConfidentiality(model) > highest {
			highest = techAsset.HighestConfidentiality(model)
		}
	}
	return highest
}

func (what SharedRuntime) HighestIntegrity(model *ParsedModel) types.Criticality {
	highest := types.Archive
	for _, id := range what.TechnicalAssetsRunning {
		techAsset := model.TechnicalAssets[id]
		if techAsset.HighestIntegrity(model) > highest {
			highest = techAsset.HighestIntegrity(model)
		}
	}
	return highest
}

func (what SharedRuntime) HighestAvailability(model *ParsedModel) types.Criticality {
	highest := types.Archive
	for _, id := range what.TechnicalAssetsRunning {
		techAsset := model.TechnicalAssets[id]
		if techAsset.HighestAvailability(model) > highest {
			highest = techAsset.HighestAvailability(model)
		}
	}
	return highest
}

func (what SharedRuntime) TechnicalAssetWithHighestRAA(model *ParsedModel) TechnicalAsset {
	result := model.TechnicalAssets[what.TechnicalAssetsRunning[0]]
	for _, asset := range what.TechnicalAssetsRunning {
		candidate := model.TechnicalAssets[asset]
		if candidate.RAA > result.RAA {
			result = candidate
		}
	}
	return result
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

func SortedKeysOfSharedRuntime(model *ParsedModel) []string {
	keys := make([]string, 0)
	for k := range model.SharedRuntimes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

type BySharedRuntimeTitleSort []SharedRuntime

func (what BySharedRuntimeTitleSort) Len() int      { return len(what) }
func (what BySharedRuntimeTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what BySharedRuntimeTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}
