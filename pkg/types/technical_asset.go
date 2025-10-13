/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"sort"
)

type TechnicalAsset struct {
	Id                      string                `json:"id,omitempty" yaml:"id,omitempty"`
	Title                   string                `json:"title,omitempty" yaml:"title,omitempty"`
	Description             string                `json:"description,omitempty" yaml:"description,omitempty"`
	Usage                   Usage                 `json:"usage,omitempty" yaml:"usage,omitempty"`
	Type                    TechnicalAssetType    `json:"type,omitempty" yaml:"type,omitempty"`
	Size                    TechnicalAssetSize    `json:"size,omitempty" yaml:"size,omitempty"`
	Technologies            TechnologyList        `json:"technologies,omitempty" yaml:"technologies,omitempty"`
	Machine                 TechnicalAssetMachine `json:"machine,omitempty" yaml:"machine,omitempty"`
	Internet                bool                  `json:"internet,omitempty" yaml:"internet,omitempty"`
	MultiTenant             bool                  `json:"multi_tenant,omitempty" yaml:"multi_tenant,omitempty"`
	Redundant               bool                  `json:"redundant,omitempty" yaml:"redundant,omitempty"`
	CustomDevelopedParts    bool                  `json:"custom_developed_parts,omitempty" yaml:"custom_developed_parts,omitempty"`
	OutOfScope              bool                  `json:"out_of_scope,omitempty" yaml:"out_of_scope,omitempty"`
	UsedAsClientByHuman     bool                  `json:"used_as_client_by_human,omitempty" yaml:"used_as_client_by_human,omitempty"`
	Encryption              EncryptionStyle       `json:"encryption,omitempty" yaml:"encryption,omitempty"`
	JustificationOutOfScope string                `json:"justification_out_of_scope,omitempty" yaml:"justification_out_of_scope,omitempty"`
	Owner                   string                `json:"owner,omitempty" yaml:"owner,omitempty"`
	Confidentiality         Confidentiality       `json:"confidentiality,omitempty" yaml:"confidentiality,omitempty"`
	Integrity               Criticality           `json:"integrity,omitempty" yaml:"integrity,omitempty"`
	Availability            Criticality           `json:"availability,omitempty" yaml:"availability,omitempty"`
	JustificationCiaRating  string                `json:"justification_cia_rating,omitempty" yaml:"justification_cia_rating,omitempty"`
	Tags                    []string              `json:"tags,omitempty" yaml:"tags,omitempty"`
	DataAssetsProcessed     []string              `json:"data_assets_processed,omitempty" yaml:"data_assets_processed,omitempty"`
	DataAssetsStored        []string              `json:"data_assets_stored,omitempty" yaml:"data_assets_stored,omitempty"`
	DataFormatsAccepted     []DataFormat          `json:"data_formats_accepted,omitempty" yaml:"data_formats_accepted,omitempty"`
	CommunicationLinks      []*CommunicationLink  `json:"communication_links,omitempty" yaml:"communication_links,omitempty"`
	DiagramTweakOrder       int                   `json:"diagram_tweak_order,omitempty" yaml:"diagram_tweak_order,omitempty"`
	RAA                     float64               `json:"raa,omitempty" yaml:"raa,omitempty"` // will be set by separate calculation step
}

func (what TechnicalAsset) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

func (what TechnicalAsset) HighestSensitivityScore() float64 {
	return what.Confidentiality.AttackerAttractivenessForAsset() +
		what.Integrity.AttackerAttractivenessForAsset() +
		what.Availability.AttackerAttractivenessForAsset()
}

func (what TechnicalAsset) DataFormatsAcceptedSorted() []DataFormat {
	result := make([]DataFormat, 0)
	result = append(result, what.DataFormatsAccepted...)
	sort.Sort(ByDataFormatAcceptedSort(result))
	return result
}

func (what TechnicalAsset) CommunicationLinksSorted() []*CommunicationLink {
	result := make([]*CommunicationLink, 0)
	result = append(result, what.CommunicationLinks...)
	sort.Sort(ByTechnicalCommunicationLinkTitleSort(result))
	return result
}

type ByTechnicalAssetRAAAndTitleSort []*TechnicalAsset

func (what ByTechnicalAssetRAAAndTitleSort) Len() int      { return len(what) }
func (what ByTechnicalAssetRAAAndTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalAssetRAAAndTitleSort) Less(i, j int) bool {
	raaLeft := what[i].RAA
	raaRight := what[j].RAA
	if raaLeft == raaRight {
		return what[i].Title < what[j].Title
	}
	return raaLeft > raaRight
}

type ByTechnicalAssetTitleSort []*TechnicalAsset

func (what ByTechnicalAssetTitleSort) Len() int      { return len(what) }
func (what ByTechnicalAssetTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalAssetTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

type ByOrderAndIdSort []*TechnicalAsset

func (what ByOrderAndIdSort) Len() int      { return len(what) }
func (what ByOrderAndIdSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByOrderAndIdSort) Less(i, j int) bool {
	if what[i].DiagramTweakOrder == what[j].DiagramTweakOrder {
		return what[i].Id > what[j].Id
	}
	return what[i].DiagramTweakOrder < what[j].DiagramTweakOrder
}

/*
// Loops over all data assets (stored and processed by this technical asset) and determines for each
// data asset, how many percentage of the data risk is reduced when this technical asset has all risks mitigated.
// Example: This means if the data asset is loosing a risk and thus getting from red to amber it counts as 1.
// Other example: When only one out of four lines (see data risk mapping) leading to red tech assets are removed by
// the mitigations, then this counts as 0.25. The overall sum is returned.
func (what TechnicalAsset) QuickWins() float64 {
	result := 0.0
	uniqueDataAssetsStoredAndProcessed := make(map[string]interface{})
	for _, dataAssetId := range what.DataAssetsStored {
		uniqueDataAssetsStoredAndProcessed[dataAssetId] = true
	}
	for _, dataAssetId := range what.DataAssetsProcessed {
		uniqueDataAssetsStoredAndProcessed[dataAssetId] = true
	}
	highestSeverity := HighestSeverityStillAtRisk(what.GeneratedRisks())
	for dataAssetId, _ := range uniqueDataAssetsStoredAndProcessed {
		dataAsset := ParsedModelRoot.DataAssets[dataAssetId]
		if dataAsset.IdentifiedRiskSeverityStillAtRisk() <= highestSeverity {
			howManySameLevelCausingUsagesOfThisData := 0.0
			for techAssetId, risks := range dataAsset.IdentifiedRisksByResponsibleTechnicalAssetId() {
				if !ParsedModelRoot.TechnicalAssets[techAssetId].OutOfScope {
					for _, risk := range risks {
						if len(risk.MostRelevantTechnicalAssetId) > 0 { // T O D O caching of generated risks inside the method?
							if HighestSeverityStillAtRisk(ParsedModelRoot.TechnicalAssets[risk.MostRelevantTechnicalAssetId].GeneratedRisks()) == highestSeverity {
								howManySameLevelCausingUsagesOfThisData++
								break
							}
						}
					}
				}
			}
			if howManySameLevelCausingUsagesOfThisData > 0 {
				result += 1.0 / howManySameLevelCausingUsagesOfThisData
			}
		}
	}
	return result
}
*/

/*
type ByTechnicalAssetQuickWinsAndTitleSort []TechnicalAsset

func (what ByTechnicalAssetQuickWinsAndTitleSort) Len() int      { return len(what) }
func (what ByTechnicalAssetQuickWinsAndTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }

	func (what ByTechnicalAssetQuickWinsAndTitleSort) Less(i, j int) bool {
		qwLeft := what[i].QuickWins()
		qwRight := what[j].QuickWins()
		if qwLeft == qwRight {
			return what[i].Title < what[j].Title
		}
		return qwLeft > qwRight
	}
*/
func (what TechnicalAsset) IsPersistentStorageIDS() bool {
	var flag = false
	if what.Type == Datastore {
		return true
	}
	_, isPersistentStgTech := persistStgTech[what.Technologies.String()]
	if isPersistentStgTech {
		return true
	}

	for _, tag := range what.Tags {
		_, isOrgPersistStgTags := orgPersistStgTags[tag]
		if isOrgPersistStgTags {
			return true
		}
	}
	return flag
}
