/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"sort"
)

type DataAsset struct {
	Id                     string          `yaml:"id" json:"id"`                   // TODO: tag here still required?
	Title                  string          `yaml:"title" json:"title"`             // TODO: tag here still required?
	Description            string          `yaml:"description" json:"description"` // TODO: tag here still required?
	Usage                  Usage           `yaml:"usage" json:"usage"`
	Tags                   []string        `yaml:"tags" json:"tags"`
	Origin                 string          `yaml:"origin" json:"origin"`
	Owner                  string          `yaml:"owner" json:"owner"`
	Quantity               Quantity        `yaml:"quantity" json:"quantity"`
	Confidentiality        Confidentiality `yaml:"confidentiality" json:"confidentiality"`
	Integrity              Criticality     `yaml:"integrity" json:"integrity"`
	Availability           Criticality     `yaml:"availability" json:"availability"`
	JustificationCiaRating string          `yaml:"justification_cia_rating" json:"justification_cia_rating"`
}

func (what DataAsset) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

func (what DataAsset) IsTaggedWithBaseTag(baseTag string) bool {
	return IsTaggedWithBaseTag(what.Tags, baseTag)
}

/*
func (what DataAsset) IsAtRisk() bool {
	for _, techAsset := range what.ProcessedByTechnicalAssetsSorted() {
		if len(ReduceToOnlyStillAtRisk(techAsset.GeneratedRisks())) > 0 {
			return true
		}
	}
	for _, techAsset := range what.StoredByTechnicalAssetsSorted() {
		if len(ReduceToOnlyStillAtRisk(techAsset.GeneratedRisks())) > 0 {
			return true
		}
	}
	return false
}
*/

/*
func (what DataAsset) IdentifiedRiskSeverityStillAtRisk() RiskSeverity {
	highestRiskSeverity := Low
	for _, techAsset := range what.ProcessedByTechnicalAssetsSorted() {
		candidateSeverity := HighestSeverityStillAtRisk(ReduceToOnlyStillAtRisk(techAsset.GeneratedRisks()))
		if candidateSeverity > highestRiskSeverity {
			highestRiskSeverity = candidateSeverity
		}
	}
	for _, techAsset := range what.StoredByTechnicalAssetsSorted() {
		candidateSeverity := HighestSeverityStillAtRisk(ReduceToOnlyStillAtRisk(techAsset.GeneratedRisks()))
		if candidateSeverity > highestRiskSeverity {
			highestRiskSeverity = candidateSeverity
		}
	}
	return highestRiskSeverity
}
*/

func (what DataAsset) IdentifiedRisksByResponsibleTechnicalAssetId(model *ParsedModel) map[string][]Risk {
	uniqueTechAssetIDsResponsibleForThisDataAsset := make(map[string]interface{})
	for _, techAsset := range what.ProcessedByTechnicalAssetsSorted(model) {
		if len(techAsset.GeneratedRisks(model)) > 0 {
			uniqueTechAssetIDsResponsibleForThisDataAsset[techAsset.Id] = true
		}
	}
	for _, techAsset := range what.StoredByTechnicalAssetsSorted(model) {
		if len(techAsset.GeneratedRisks(model)) > 0 {
			uniqueTechAssetIDsResponsibleForThisDataAsset[techAsset.Id] = true
		}
	}

	result := make(map[string][]Risk)
	for techAssetId := range uniqueTechAssetIDsResponsibleForThisDataAsset {
		result[techAssetId] = append(result[techAssetId], model.TechnicalAssets[techAssetId].GeneratedRisks(model)...)
	}
	return result
}

func (what DataAsset) IsDataBreachPotentialStillAtRisk(parsedModel *ParsedModel) bool {
	for _, risk := range FilteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				return true
			}
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsStored, what.Id) {
				return true
			}
		}
	}
	return false
}

func (what DataAsset) IdentifiedDataBreachProbability(parsedModel *ParsedModel) DataBreachProbability {
	highestProbability := Improbable
	for _, risk := range AllRisks(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsStored, what.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
		}
	}
	return highestProbability
}

func (what DataAsset) IdentifiedDataBreachProbabilityStillAtRisk(parsedModel *ParsedModel) DataBreachProbability {
	highestProbability := Improbable
	for _, risk := range FilteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsStored, what.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
		}
	}
	return highestProbability
}

func (what DataAsset) IdentifiedDataBreachProbabilityRisksStillAtRisk(parsedModel *ParsedModel) []Risk {
	result := make([]Risk, 0)
	for _, risk := range FilteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				result = append(result, risk)
				break
			}
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsStored, what.Id) {
				result = append(result, risk)
				break
			}
		}
	}
	return result
}

func (what DataAsset) IdentifiedDataBreachProbabilityRisks(parsedModel *ParsedModel) []Risk {
	result := make([]Risk, 0)
	for _, risk := range AllRisks(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				result = append(result, risk)
				break
			}
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsStored, what.Id) {
				result = append(result, risk)
				break
			}
		}
	}
	return result
}

func (what DataAsset) ProcessedByTechnicalAssetsSorted(parsedModel *ParsedModel) []TechnicalAsset {
	result := make([]TechnicalAsset, 0)
	for _, technicalAsset := range parsedModel.TechnicalAssets {
		for _, candidateID := range technicalAsset.DataAssetsProcessed {
			if candidateID == what.Id {
				result = append(result, technicalAsset)
			}
		}
	}
	sort.Sort(ByTechnicalAssetTitleSort(result))
	return result
}

func (what DataAsset) StoredByTechnicalAssetsSorted(parsedModel *ParsedModel) []TechnicalAsset {
	result := make([]TechnicalAsset, 0)
	for _, technicalAsset := range parsedModel.TechnicalAssets {
		for _, candidateID := range technicalAsset.DataAssetsStored {
			if candidateID == what.Id {
				result = append(result, technicalAsset)
			}
		}
	}
	sort.Sort(ByTechnicalAssetTitleSort(result))
	return result
}

func (what DataAsset) SentViaCommLinksSorted(parsedModel *ParsedModel) []CommunicationLink {
	result := make([]CommunicationLink, 0)
	for _, technicalAsset := range parsedModel.TechnicalAssets {
		for _, commLink := range technicalAsset.CommunicationLinks {
			for _, candidateID := range commLink.DataAssetsSent {
				if candidateID == what.Id {
					result = append(result, commLink)
				}
			}
		}
	}
	sort.Sort(ByTechnicalCommunicationLinkTitleSort(result))
	return result
}

func (what DataAsset) ReceivedViaCommLinksSorted(parsedModel *ParsedModel) []CommunicationLink {
	result := make([]CommunicationLink, 0)
	for _, technicalAsset := range parsedModel.TechnicalAssets {
		for _, commLink := range technicalAsset.CommunicationLinks {
			for _, candidateID := range commLink.DataAssetsReceived {
				if candidateID == what.Id {
					result = append(result, commLink)
				}
			}
		}
	}
	sort.Sort(ByTechnicalCommunicationLinkTitleSort(result))
	return result
}

func SortByDataAssetDataBreachProbabilityAndTitle(parsedModel *ParsedModel, assets []DataAsset) {
	sort.Slice(assets, func(i, j int) bool {
		highestDataBreachProbabilityLeft := assets[i].IdentifiedDataBreachProbability(parsedModel)
		highestDataBreachProbabilityRight := assets[j].IdentifiedDataBreachProbability(parsedModel)
		if highestDataBreachProbabilityLeft == highestDataBreachProbabilityRight {
			return assets[i].Title < assets[j].Title
		}
		return highestDataBreachProbabilityLeft > highestDataBreachProbabilityRight
	})
}

func SortByDataAssetDataBreachProbabilityAndTitleStillAtRisk(parsedModel *ParsedModel, assets []DataAsset) {
	sort.Slice(assets, func(i, j int) bool {
		risksLeft := assets[i].IdentifiedDataBreachProbabilityRisksStillAtRisk(parsedModel)
		risksRight := assets[j].IdentifiedDataBreachProbabilityRisksStillAtRisk(parsedModel)
		highestDataBreachProbabilityLeft := assets[i].IdentifiedDataBreachProbabilityStillAtRisk(parsedModel)
		highestDataBreachProbabilityRight := assets[j].IdentifiedDataBreachProbabilityStillAtRisk(parsedModel)
		if highestDataBreachProbabilityLeft == highestDataBreachProbabilityRight {
			if len(risksLeft) == 0 && len(risksRight) > 0 {
				return false
			}
			if len(risksLeft) > 0 && len(risksRight) == 0 {
				return true
			}
			return assets[i].Title < assets[j].Title
		}
		return highestDataBreachProbabilityLeft > highestDataBreachProbabilityRight
	})
}

type ByDataAssetTitleSort []DataAsset

func (what ByDataAssetTitleSort) Len() int      { return len(what) }
func (what ByDataAssetTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByDataAssetTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}
