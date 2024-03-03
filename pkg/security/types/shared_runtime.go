/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"sort"
)

type SharedRuntime struct {
	Id                     string   `json:"id,omitempty" yaml:"id,omitempty"`
	Title                  string   `json:"title,omitempty" yaml:"title,omitempty"`
	Description            string   `json:"description,omitempty" yaml:"description,omitempty"`
	Tags                   []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	TechnicalAssetsRunning []string `json:"technical_assets_running,omitempty" yaml:"technical_assets_running,omitempty"`
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
		if techAsset.HighestProcessedConfidentiality(model) > highest {
			highest = techAsset.HighestProcessedConfidentiality(model)
		}
	}
	return highest
}

func (what SharedRuntime) HighestIntegrity(model *ParsedModel) Criticality {
	highest := Archive
	for _, id := range what.TechnicalAssetsRunning {
		techAsset := model.TechnicalAssets[id]
		if techAsset.HighestProcessedIntegrity(model) > highest {
			highest = techAsset.HighestProcessedIntegrity(model)
		}
	}
	return highest
}

func (what SharedRuntime) HighestAvailability(model *ParsedModel) Criticality {
	highest := Archive
	for _, id := range what.TechnicalAssetsRunning {
		techAsset := model.TechnicalAssets[id]
		if techAsset.HighestProcessedAvailability(model) > highest {
			highest = techAsset.HighestProcessedAvailability(model)
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
