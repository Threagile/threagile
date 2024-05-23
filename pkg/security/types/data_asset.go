/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"sort"
)

type DataAsset struct {
	Id                     string          `yaml:"id,omitempty" json:"id,omitempty"`                   // TODO: tag here still required?
	Title                  string          `yaml:"title,omitempty" json:"title,omitempty"`             // TODO: tag here still required?
	Description            string          `yaml:"description,omitempty" json:"description,omitempty"` // TODO: tag here still required?
	Usage                  Usage           `yaml:"usage,omitempty" json:"usage,omitempty"`
	Tags                   []string        `yaml:"tags,omitempty" json:"tags,omitempty"`
	Origin                 string          `yaml:"origin,omitempty" json:"origin,omitempty"`
	Owner                  string          `yaml:"owner,omitempty" json:"owner,omitempty"`
	Quantity               Quantity        `yaml:"quantity,omitempty" json:"quantity,omitempty"`
	Confidentiality        Confidentiality `yaml:"confidentiality,omitempty" json:"confidentiality,omitempty"`
	Integrity              Criticality     `yaml:"integrity,omitempty" json:"integrity,omitempty"`
	Availability           Criticality     `yaml:"availability,omitempty" json:"availability,omitempty"`
	JustificationCiaRating string          `yaml:"justification_cia_rating,omitempty" json:"justification_cia_rating,omitempty"`
}

func (what DataAsset) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

func (what DataAsset) IsTaggedWithBaseTag(baseTag string) bool {
	return IsTaggedWithBaseTag(what.Tags, baseTag)
}

func (what DataAsset) IdentifiedRisksByResponsibleTechnicalAssetId(model *Model) map[string][]*Risk {
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

	result := make(map[string][]*Risk)
	for techAssetId := range uniqueTechAssetIDsResponsibleForThisDataAsset {
		result[techAssetId] = append(result[techAssetId], model.TechnicalAssets[techAssetId].GeneratedRisks(model)...)
	}
	return result
}

func (what DataAsset) IsDataBreachPotentialStillAtRisk(parsedModel *Model) bool {
	for _, risk := range FilteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				return true
			}
		}
	}
	return false
}

func (what DataAsset) IdentifiedDataBreachProbability(parsedModel *Model) DataBreachProbability {
	highestProbability := Improbable
	for _, risk := range AllRisks(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
		}
	}
	return highestProbability
}

func (what DataAsset) IdentifiedDataBreachProbabilityStillAtRisk(parsedModel *Model) DataBreachProbability {
	highestProbability := Improbable
	for _, risk := range FilteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
		}
	}
	return highestProbability
}

func (what DataAsset) IdentifiedDataBreachProbabilityRisksStillAtRisk(parsedModel *Model) []*Risk {
	result := make([]*Risk, 0)
	for _, risk := range FilteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				result = append(result, risk)
				break
			}
		}
	}
	return result
}

func (what DataAsset) IdentifiedDataBreachProbabilityRisks(parsedModel *Model) []*Risk {
	result := make([]*Risk, 0)
	for _, risk := range AllRisks(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
				result = append(result, risk)
				break
			}
		}
	}
	return result
}

func (what DataAsset) ProcessedByTechnicalAssetsSorted(parsedModel *Model) []*TechnicalAsset {
	result := make([]*TechnicalAsset, 0)
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

func (what DataAsset) StoredByTechnicalAssetsSorted(parsedModel *Model) []*TechnicalAsset {
	result := make([]*TechnicalAsset, 0)
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

func (what DataAsset) SentViaCommLinksSorted(parsedModel *Model) []*CommunicationLink {
	result := make([]*CommunicationLink, 0)
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

func (what DataAsset) ReceivedViaCommLinksSorted(parsedModel *Model) []*CommunicationLink {
	result := make([]*CommunicationLink, 0)
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

func SortByDataAssetDataBreachProbabilityAndTitle(parsedModel *Model, assets []*DataAsset) {
	sort.Slice(assets, func(i, j int) bool {
		highestDataBreachProbabilityLeft := assets[i].IdentifiedDataBreachProbability(parsedModel)
		highestDataBreachProbabilityRight := assets[j].IdentifiedDataBreachProbability(parsedModel)
		if highestDataBreachProbabilityLeft == highestDataBreachProbabilityRight {
			return assets[i].Title < assets[j].Title
		}
		return highestDataBreachProbabilityLeft > highestDataBreachProbabilityRight
	})
}

func SortByDataAssetDataBreachProbabilityAndTitleStillAtRisk(parsedModel *Model, assets []*DataAsset) {
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

type ByDataAssetTitleSort []*DataAsset

func (what ByDataAssetTitleSort) Len() int      { return len(what) }
func (what ByDataAssetTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByDataAssetTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}
