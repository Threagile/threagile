/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"sort"
)

type SharedRuntime struct {
	Id                     string   `json:"id,omitempty"`
	Title                  string   `json:"title,omitempty"`
	Description            string   `json:"description,omitempty"`
	Tags                   []string `json:"tags,omitempty"`
	TechnicalAssetsRunning []string `json:"technical_assets_running,omitempty"`
}

func (what SharedRuntime) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

func (what SharedRuntime) IsTaggedWithBaseTag(baseTag string) bool {
	return IsTaggedWithBaseTag(what.Tags, baseTag)
}

func (what SharedRuntime) HighestConfidentiality(model *ParsedModel) Confidentiality {
	highest := Public
	for _, id := range what.TechnicalAssetsRunning {
		techAsset := model.TechnicalAssets[id]
		if techAsset.HighestConfidentiality(model) > highest {
			highest = techAsset.HighestConfidentiality(model)
		}
	}
	return highest
}

func (what SharedRuntime) HighestIntegrity(model *ParsedModel) Criticality {
	highest := Archive
	for _, id := range what.TechnicalAssetsRunning {
		techAsset := model.TechnicalAssets[id]
		if techAsset.HighestIntegrity(model) > highest {
			highest = techAsset.HighestIntegrity(model)
		}
	}
	return highest
}

func (what SharedRuntime) HighestAvailability(model *ParsedModel) Criticality {
	highest := Archive
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
