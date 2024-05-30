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

type ByDataAssetTitleSort []*DataAsset

func (what ByDataAssetTitleSort) Len() int      { return len(what) }
func (what ByDataAssetTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByDataAssetTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}
