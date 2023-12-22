/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package model

import (
	"sort"
	"time"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/types"
)

type ParsedModel struct {
	Author                                        input.Author
	Title                                         string
	Date                                          time.Time
	ManagementSummaryComment                      string
	BusinessOverview                              input.Overview
	TechnicalOverview                             input.Overview
	BusinessCriticality                           types.Criticality
	SecurityRequirements                          map[string]string
	Questions                                     map[string]string
	AbuseCases                                    map[string]string
	TagsAvailable                                 []string
	DataAssets                                    map[string]DataAsset
	TechnicalAssets                               map[string]TechnicalAsset
	TrustBoundaries                               map[string]TrustBoundary
	SharedRuntimes                                map[string]SharedRuntime
	IndividualRiskCategories                      map[string]RiskCategory
	RiskTracking                                  map[string]RiskTracking
	CommunicationLinks                            map[string]CommunicationLink
	AllSupportedTags                              map[string]bool
	DiagramTweakNodesep, DiagramTweakRanksep      int
	DiagramTweakEdgeLayout                        string
	DiagramTweakSuppressEdgeLabels                bool
	DiagramTweakLayoutLeftToRight                 bool
	DiagramTweakInvisibleConnectionsBetweenAssets []string
	DiagramTweakSameRankAssets                    []string

	// TODO: those are generated based on items above and needs to be private
	IncomingTechnicalCommunicationLinksMappedByTargetId   map[string][]CommunicationLink
	DirectContainingTrustBoundaryMappedByTechnicalAssetId map[string]TrustBoundary
	GeneratedRisksByCategory                              map[RiskCategory][]Risk
	GeneratedRisksBySyntheticId                           map[string]Risk
}

func CalculateSeverity(likelihood types.RiskExploitationLikelihood, impact types.RiskExploitationImpact) types.RiskSeverity {
	result := likelihood.Weight() * impact.Weight()
	if result <= 1 {
		return types.LowSeverity
	}
	if result <= 3 {
		return types.MediumSeverity
	}
	if result <= 8 {
		return types.ElevatedSeverity
	}
	if result <= 12 {
		return types.HighSeverity
	}
	return types.CriticalSeverity
}

func (model *ParsedModel) InScopeTechnicalAssets() []TechnicalAsset {
	result := make([]TechnicalAsset, 0)
	for _, asset := range model.TechnicalAssets {
		if !asset.OutOfScope {
			result = append(result, asset)
		}
	}
	return result
}

func (what *ParsedModel) SortedTechnicalAssetIDs() []string {
	res := make([]string, 0)
	for id := range what.TechnicalAssets {
		res = append(res, id)
	}
	sort.Strings(res)
	return res
}

func (what *ParsedModel) TagsActuallyUsed() []string {
	result := make([]string, 0)
	for _, tag := range what.TagsAvailable {
		if len(what.TechnicalAssetsTaggedWithAny(tag)) > 0 ||
			len(what.CommunicationLinksTaggedWithAny(tag)) > 0 ||
			len(what.DataAssetsTaggedWithAny(tag)) > 0 ||
			len(what.TrustBoundariesTaggedWithAny(tag)) > 0 ||
			len(what.SharedRuntimesTaggedWithAny(tag)) > 0 {
			result = append(result, tag)
		}
	}
	return result
}

func (what *ParsedModel) TechnicalAssetsTaggedWithAny(tags ...string) []TechnicalAsset {
	result := make([]TechnicalAsset, 0)
	for _, candidate := range what.TechnicalAssets {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func (what *ParsedModel) CommunicationLinksTaggedWithAny(tags ...string) []CommunicationLink {
	result := make([]CommunicationLink, 0)
	for _, asset := range what.TechnicalAssets {
		for _, candidate := range asset.CommunicationLinks {
			if candidate.IsTaggedWithAny(tags...) {
				result = append(result, candidate)
			}
		}
	}
	return result
}

func (what *ParsedModel) DataAssetsTaggedWithAny(tags ...string) []DataAsset {
	result := make([]DataAsset, 0)
	for _, candidate := range what.DataAssets {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func (what *ParsedModel) TrustBoundariesTaggedWithAny(tags ...string) []TrustBoundary {
	result := make([]TrustBoundary, 0)
	for _, candidate := range what.TrustBoundaries {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func (what *ParsedModel) SharedRuntimesTaggedWithAny(tags ...string) []SharedRuntime {
	result := make([]SharedRuntime, 0)
	for _, candidate := range what.SharedRuntimes {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func (what *ParsedModel) OutOfScopeTechnicalAssets() []TechnicalAsset {
	assets := make([]TechnicalAsset, 0)
	for _, asset := range what.TechnicalAssets {
		if asset.OutOfScope {
			assets = append(assets, asset)
		}
	}
	sort.Sort(ByTechnicalAssetTitleSort(assets))
	return assets
}
