/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"sort"
)

type TrustBoundary struct {
	Id                    string            `json:"id,omitempty" yaml:"id,omitempty"`
	Title                 string            `json:"title,omitempty" yaml:"title,omitempty"`
	Description           string            `json:"description,omitempty" yaml:"description,omitempty"`
	Type                  TrustBoundaryType `json:"type,omitempty" yaml:"type,omitempty"`
	Tags                  []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	TechnicalAssetsInside []string          `json:"technical_assets_inside,omitempty" yaml:"technical_assets_inside,omitempty"`
	TrustBoundariesNested []string          `json:"trust_boundaries_nested,omitempty" yaml:"trust_boundaries_nested,omitempty"`
}

func (what TrustBoundary) RecursivelyAllTechnicalAssetIDsInside(model *Model) []string {
	result := make([]string, 0)
	what.addAssetIDsRecursively(model, &result)
	return result
}

func (what TrustBoundary) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

func (what TrustBoundary) ParentTrustBoundaryID(model *Model) string {
	var result string
	for _, candidate := range model.TrustBoundaries {
		if contains(candidate.TrustBoundariesNested, what.Id) {
			result = candidate.Id
			return result
		}
	}
	return result
}

func (what TrustBoundary) HighestConfidentiality(model *Model) Confidentiality {
	highest := Public
	for _, id := range what.RecursivelyAllTechnicalAssetIDsInside(model) {
		techAsset := model.TechnicalAssets[id]
		if techAsset.HighestProcessedConfidentiality(model) > highest {
			highest = techAsset.HighestProcessedConfidentiality(model)
		}
	}
	return highest
}

func (what TrustBoundary) HighestIntegrity(model *Model) Criticality {
	highest := Archive
	for _, id := range what.RecursivelyAllTechnicalAssetIDsInside(model) {
		techAsset := model.TechnicalAssets[id]
		if techAsset.HighestProcessedIntegrity(model) > highest {
			highest = techAsset.HighestProcessedIntegrity(model)
		}
	}
	return highest
}

func (what TrustBoundary) HighestAvailability(model *Model) Criticality {
	highest := Archive
	for _, id := range what.RecursivelyAllTechnicalAssetIDsInside(model) {
		techAsset := model.TechnicalAssets[id]
		if techAsset.HighestProcessedAvailability(model) > highest {
			highest = techAsset.HighestProcessedAvailability(model)
		}
	}
	return highest
}

func (what TrustBoundary) AllParentTrustBoundaryIDs(model *Model) []string {
	result := make([]string, 0)
	what.addTrustBoundaryIDsRecursively(model, &result)
	return result
}

func (what TrustBoundary) addAssetIDsRecursively(model *Model, result *[]string) {
	*result = append(*result, what.TechnicalAssetsInside...)
	for _, nestedBoundaryID := range what.TrustBoundariesNested {
		model.TrustBoundaries[nestedBoundaryID].addAssetIDsRecursively(model, result)
	}
}

func (what TrustBoundary) addTrustBoundaryIDsRecursively(model *Model, result *[]string) {
	*result = append(*result, what.Id)
	parentID := what.ParentTrustBoundaryID(model)
	if len(parentID) > 0 {
		model.TrustBoundaries[parentID].addTrustBoundaryIDsRecursively(model, result)
	}
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

func SortedKeysOfTrustBoundaries(model *Model) []string {
	keys := make([]string, 0)
	for k := range model.TrustBoundaries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

type ByTrustBoundaryTitleSort []*TrustBoundary

func (what ByTrustBoundaryTitleSort) Len() int      { return len(what) }
func (what ByTrustBoundaryTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTrustBoundaryTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}
