/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"sort"

	"github.com/threagile/threagile/pkg/colors"
)

type TechnicalAsset struct {
	Id                      string                   `json:"id,omitempty"`
	Title                   string                   `json:"title,omitempty"`
	Description             string                   `json:"description,omitempty"`
	Usage                   Usage                    `json:"usage,omitempty"`
	Type                    TechnicalAssetType       `json:"type,omitempty"`
	Size                    TechnicalAssetSize       `json:"size,omitempty"`
	Technology              TechnicalAssetTechnology `json:"technology,omitempty"`
	Machine                 TechnicalAssetMachine    `json:"machine,omitempty"`
	Internet                bool                     `json:"internet,omitempty"`
	MultiTenant             bool                     `json:"multi_tenant,omitempty"`
	Redundant               bool                     `json:"redundant,omitempty"`
	CustomDevelopedParts    bool                     `json:"custom_developed_parts,omitempty"`
	OutOfScope              bool                     `json:"out_of_scope,omitempty"`
	UsedAsClientByHuman     bool                     `json:"used_as_client_by_human,omitempty"`
	Encryption              EncryptionStyle          `json:"encryption,omitempty"`
	JustificationOutOfScope string                   `json:"justification_out_of_scope,omitempty"`
	Owner                   string                   `json:"owner,omitempty"`
	Confidentiality         Confidentiality          `json:"confidentiality,omitempty"`
	Integrity               Criticality              `json:"integrity,omitempty"`
	Availability            Criticality              `json:"availability,omitempty"`
	JustificationCiaRating  string                   `json:"justification_cia_rating,omitempty"`
	Tags                    []string                 `json:"tags,omitempty"`
	DataAssetsProcessed     []string                 `json:"data_assets_processed,omitempty"`
	DataAssetsStored        []string                 `json:"data_assets_stored,omitempty"`
	DataFormatsAccepted     []DataFormat             `json:"data_formats_accepted,omitempty"`
	CommunicationLinks      []CommunicationLink      `json:"communication_links,omitempty"`
	DiagramTweakOrder       int                      `json:"diagram_tweak_order,omitempty"`
	// will be set by separate calculation step:
	RAA float64 `json:"raa,omitempty"`
}

func (what TechnicalAsset) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

func (what TechnicalAsset) IsTaggedWithBaseTag(baseTag string) bool {
	return IsTaggedWithBaseTag(what.Tags, baseTag)
}

// first use the tag(s) of the asset itself, then their trust boundaries (recursively up) and then their shared runtime

func (what TechnicalAsset) IsTaggedWithAnyTraversingUp(model *ParsedModel, tags ...string) bool {
	if containsCaseInsensitiveAny(what.Tags, tags...) {
		return true
	}
	tbID := what.GetTrustBoundaryId(model)
	if len(tbID) > 0 {
		if model.TrustBoundaries[tbID].IsTaggedWithAnyTraversingUp(model, tags...) {
			return true
		}
	}
	for _, sr := range model.SharedRuntimes {
		if contains(sr.TechnicalAssetsRunning, what.Id) && sr.IsTaggedWithAny(tags...) {
			return true
		}
	}
	return false
}

func (what TechnicalAsset) IsSameTrustBoundary(parsedModel *ParsedModel, otherAssetId string) bool {
	trustBoundaryOfMyAsset := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.Id]
	trustBoundaryOfOtherAsset := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
}

func (what TechnicalAsset) IsSameExecutionEnvironment(parsedModel *ParsedModel, otherAssetId string) bool {
	trustBoundaryOfMyAsset := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.Id]
	trustBoundaryOfOtherAsset := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	if trustBoundaryOfMyAsset.Type == ExecutionEnvironment && trustBoundaryOfOtherAsset.Type == ExecutionEnvironment {
		return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
	}
	return false
}

func (what TechnicalAsset) IsSameTrustBoundaryNetworkOnly(parsedModel *ParsedModel, otherAssetId string) bool {
	trustBoundaryOfMyAsset := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[what.Id]
	if !trustBoundaryOfMyAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfMyAsset = parsedModel.TrustBoundaries[trustBoundaryOfMyAsset.ParentTrustBoundaryID(parsedModel)]
	}
	trustBoundaryOfOtherAsset := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	if !trustBoundaryOfOtherAsset.Type.IsNetworkBoundary() { // find and use the parent boundary then
		trustBoundaryOfOtherAsset = parsedModel.TrustBoundaries[trustBoundaryOfOtherAsset.ParentTrustBoundaryID(parsedModel)]
	}
	return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
}

func (what TechnicalAsset) HighestSensitivityScore() float64 {
	return what.Confidentiality.AttackerAttractivenessForAsset() +
		what.Integrity.AttackerAttractivenessForAsset() +
		what.Availability.AttackerAttractivenessForAsset()
}

func (what TechnicalAsset) HighestConfidentiality(parsedModel *ParsedModel) Confidentiality {
	highest := what.Confidentiality
	for _, dataId := range what.DataAssetsProcessed {
		dataAsset := parsedModel.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	for _, dataId := range what.DataAssetsStored {
		dataAsset := parsedModel.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	return highest
}

func (what TechnicalAsset) DataAssetsProcessedSorted(parsedModel *ParsedModel) []DataAsset {
	result := make([]DataAsset, 0)
	for _, assetID := range what.DataAssetsProcessed {
		result = append(result, parsedModel.DataAssets[assetID])
	}
	sort.Sort(ByDataAssetTitleSort(result))
	return result
}

func (what TechnicalAsset) DataAssetsStoredSorted(parsedModel *ParsedModel) []DataAsset {
	result := make([]DataAsset, 0)
	for _, assetID := range what.DataAssetsStored {
		result = append(result, parsedModel.DataAssets[assetID])
	}
	sort.Sort(ByDataAssetTitleSort(result))
	return result
}

func (what TechnicalAsset) DataFormatsAcceptedSorted() []DataFormat {
	result := make([]DataFormat, 0)
	for _, format := range what.DataFormatsAccepted {
		result = append(result, format)
	}
	sort.Sort(ByDataFormatAcceptedSort(result))
	return result
}

func (what TechnicalAsset) CommunicationLinksSorted() []CommunicationLink {
	result := make([]CommunicationLink, 0)
	for _, format := range what.CommunicationLinks {
		result = append(result, format)
	}
	sort.Sort(ByTechnicalCommunicationLinkTitleSort(result))
	return result
}

func (what TechnicalAsset) HighestIntegrity(model *ParsedModel) Criticality {
	highest := what.Integrity
	for _, dataId := range what.DataAssetsProcessed {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	for _, dataId := range what.DataAssetsStored {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	return highest
}

func (what TechnicalAsset) HighestAvailability(model *ParsedModel) Criticality {
	highest := what.Availability
	for _, dataId := range what.DataAssetsProcessed {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	for _, dataId := range what.DataAssetsStored {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	return highest
}

func (what TechnicalAsset) HasDirectConnection(parsedModel *ParsedModel, otherAssetId string) bool {
	for _, dataFlow := range parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[what.Id] {
		if dataFlow.SourceId == otherAssetId {
			return true
		}
	}
	// check both directions, hence two times, just reversed
	for _, dataFlow := range parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[otherAssetId] {
		if dataFlow.SourceId == what.Id {
			return true
		}
	}
	return false
}

func (what TechnicalAsset) GeneratedRisks(parsedModel *ParsedModel) []Risk {
	resultingRisks := make([]Risk, 0)
	if len(SortedRiskCategories(parsedModel)) == 0 {
		fmt.Println("Uh, strange, no risks generated (yet?) and asking for them by tech asset...")
	}
	for _, category := range SortedRiskCategories(parsedModel) {
		risks := SortedRisksOfCategory(parsedModel, category)
		for _, risk := range risks {
			if risk.MostRelevantTechnicalAssetId == what.Id {
				resultingRisks = append(resultingRisks, risk)
			}
		}
	}
	SortByRiskSeverity(resultingRisks, parsedModel)
	return resultingRisks
}

/*
func (what TechnicalAsset) HighestRiskSeverity() RiskSeverity {
	highest := Low
	for _, risk := range what.GeneratedRisks() {
		if risk.Severity > highest {
			highest = risk.Severity
		}
	}
	return highest
}
*/

func (what TechnicalAsset) IsZero() bool {
	return len(what.Id) == 0
}

func (what TechnicalAsset) ProcessesOrStoresDataAsset(dataAssetId string) bool {
	if contains(what.DataAssetsProcessed, dataAssetId) {
		return true
	}
	if contains(what.DataAssetsStored, dataAssetId) {
		return true
	}
	return false
}

// red when >= confidential data stored in unencrypted technical asset

func (what TechnicalAsset) DetermineLabelColor(model *ParsedModel) string {
	// TODO: Just move into main.go and let the generated risk determine the color, don't duplicate the logic here
	// Check for red
	if what.Integrity == MissionCritical {
		return colors.Red
	}
	for _, storedDataAsset := range what.DataAssetsStored {
		if model.DataAssets[storedDataAsset].Integrity == MissionCritical {
			return colors.Red
		}
	}
	for _, processedDataAsset := range what.DataAssetsProcessed {
		if model.DataAssets[processedDataAsset].Integrity == MissionCritical {
			return colors.Red
		}
	}
	// Check for amber
	if what.Integrity == Critical {
		return colors.Amber
	}
	for _, storedDataAsset := range what.DataAssetsStored {
		if model.DataAssets[storedDataAsset].Integrity == Critical {
			return colors.Amber
		}
	}
	for _, processedDataAsset := range what.DataAssetsProcessed {
		if model.DataAssets[processedDataAsset].Integrity == Critical {
			return colors.Amber
		}
	}
	return colors.Black
	/*
		if what.Encrypted {
			return colors.Black
		} else {
			if what.Confidentiality == StrictlyConfidential {
				return colors.Red
			}
			for _, storedDataAsset := range what.DataAssetsStored {
				if ParsedModelRoot.DataAssets[storedDataAsset].Confidentiality == StrictlyConfidential {
					return colors.Red
				}
			}
			if what.Confidentiality == Confidential {
				return colors.Amber
			}
			for _, storedDataAsset := range what.DataAssetsStored {
				if ParsedModelRoot.DataAssets[storedDataAsset].Confidentiality == Confidential {
					return colors.Amber
				}
			}
			return colors.Black
		}
	*/
}

// red when mission-critical integrity, but still unauthenticated (non-readonly) channels access it
// amber when critical integrity, but still unauthenticated (non-readonly) channels access it
// pink when model forgery attempt (i.e. nothing being processed or stored)

func (what TechnicalAsset) DetermineShapeBorderColor(parsedModel *ParsedModel) string {
	// TODO: Just move into main.go and let the generated risk determine the color, don't duplicate the logic here
	// Check for red
	if what.Confidentiality == StrictlyConfidential {
		return colors.Red
	}
	for _, storedDataAsset := range what.DataAssetsStored {
		if parsedModel.DataAssets[storedDataAsset].Confidentiality == StrictlyConfidential {
			return colors.Red
		}
	}
	for _, processedDataAsset := range what.DataAssetsProcessed {
		if parsedModel.DataAssets[processedDataAsset].Confidentiality == StrictlyConfidential {
			return colors.Red
		}
	}
	// Check for amber
	if what.Confidentiality == Confidential {
		return colors.Amber
	}
	for _, storedDataAsset := range what.DataAssetsStored {
		if parsedModel.DataAssets[storedDataAsset].Confidentiality == Confidential {
			return colors.Amber
		}
	}
	for _, processedDataAsset := range what.DataAssetsProcessed {
		if parsedModel.DataAssets[processedDataAsset].Confidentiality == Confidential {
			return colors.Amber
		}
	}
	return colors.Black
	/*
		if what.Integrity == MissionCritical {
			for _, dataFlow := range IncomingTechnicalCommunicationLinksMappedByTargetId[what.Id] {
				if !dataFlow.Readonly && dataFlow.Authentication == NoneAuthentication {
					return colors.Red
				}
			}
		}

		if what.Integrity == Critical {
			for _, dataFlow := range IncomingTechnicalCommunicationLinksMappedByTargetId[what.Id] {
				if !dataFlow.Readonly && dataFlow.Authentication == NoneAuthentication {
					return colors.Amber
				}
			}
		}

		if len(what.DataAssetsProcessed) == 0 && len(what.DataAssetsStored) == 0 {
			return colors.Pink // pink, because it's strange when too many technical assets process no data... some are ok, but many in a diagram is a sign of model forgery...
		}

		return colors.Black
	*/
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

// dotted when model forgery attempt (i.e. nothing being processed or stored)

func (what TechnicalAsset) DetermineShapeBorderLineStyle() string {
	if len(what.DataAssetsProcessed) == 0 && len(what.DataAssetsStored) == 0 || what.OutOfScope {
		return "dotted" // dotted, because it's strange when too many technical communication links transfer no data... some ok, but many in a diagram ist a sign of model forgery...
	}
	return "solid"
}

// 3 when redundant

func (what TechnicalAsset) DetermineShapePeripheries() int {
	if what.Redundant {
		return 2
	}
	return 1
}

func (what TechnicalAsset) DetermineShapeStyle() string {
	return "filled"
}

func (what TechnicalAsset) GetTrustBoundaryId(model *ParsedModel) string {
	for _, trustBoundary := range model.TrustBoundaries {
		for _, techAssetInside := range trustBoundary.TechnicalAssetsInside {
			if techAssetInside == what.Id {
				return trustBoundary.Id
			}
		}
	}
	return ""
}

func (what TechnicalAsset) DetermineShapeFillColor(parsedModel *ParsedModel) string {
	fillColor := colors.VeryLightGray
	if len(what.DataAssetsProcessed) == 0 && len(what.DataAssetsStored) == 0 ||
		what.Technology == UnknownTechnology {
		fillColor = colors.LightPink // lightPink, because it's strange when too many technical assets process no data... some ok, but many in a diagram ist a sign of model forgery...
	} else if len(what.CommunicationLinks) == 0 && len(parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[what.Id]) == 0 {
		fillColor = colors.LightPink
	} else if what.Internet {
		fillColor = colors.ExtremeLightBlue
	} else if what.OutOfScope {
		fillColor = colors.OutOfScopeFancy
	} else if what.CustomDevelopedParts {
		fillColor = colors.CustomDevelopedParts
	}
	switch what.Machine {
	case Physical:
		fillColor = colors.DarkenHexColor(fillColor)
	case Container:
		fillColor = colors.BrightenHexColor(fillColor)
	case Serverless:
		fillColor = colors.BrightenHexColor(colors.BrightenHexColor(fillColor))
	case Virtual:
	}
	return fillColor
}

func SortByTechnicalAssetRiskSeverityAndTitleStillAtRisk(assets []TechnicalAsset, parsedModel *ParsedModel) {
	sort.Slice(assets, func(i, j int) bool {
		risksLeft := ReduceToOnlyStillAtRisk(parsedModel, assets[i].GeneratedRisks(parsedModel))
		risksRight := ReduceToOnlyStillAtRisk(parsedModel, assets[j].GeneratedRisks(parsedModel))
		highestSeverityLeft := HighestSeverityStillAtRisk(parsedModel, risksLeft)
		highestSeverityRight := HighestSeverityStillAtRisk(parsedModel, risksRight)
		var result bool
		if highestSeverityLeft == highestSeverityRight {
			if len(risksLeft) == 0 && len(risksRight) > 0 {
				return false
			} else if len(risksLeft) > 0 && len(risksRight) == 0 {
				return true
			} else {
				result = assets[i].Title < assets[j].Title
			}
		} else {
			result = highestSeverityLeft > highestSeverityRight
		}
		if assets[i].OutOfScope && assets[j].OutOfScope {
			result = assets[i].Title < assets[j].Title
		} else if assets[i].OutOfScope {
			result = false
		} else if assets[j].OutOfScope {
			result = true
		}
		return result
	})
}

func (what TechnicalAsset) DetermineShapeBorderPenWidth(parsedModel *ParsedModel) string {
	if what.DetermineShapeBorderColor(parsedModel) == colors.Pink {
		return fmt.Sprintf("%f", 3.5)
	}
	if what.DetermineShapeBorderColor(parsedModel) != colors.Black {
		return fmt.Sprintf("%f", 3.0)
	}
	return fmt.Sprintf("%f", 2.0)
}

type ByTechnicalAssetRAAAndTitleSort []TechnicalAsset

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

type ByTechnicalAssetTitleSort []TechnicalAsset

func (what ByTechnicalAssetTitleSort) Len() int      { return len(what) }
func (what ByTechnicalAssetTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalAssetTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

type ByOrderAndIdSort []TechnicalAsset

func (what ByOrderAndIdSort) Len() int      { return len(what) }
func (what ByOrderAndIdSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByOrderAndIdSort) Less(i, j int) bool {
	if what[i].DiagramTweakOrder == what[j].DiagramTweakOrder {
		return what[i].Id > what[j].Id
	}
	return what[i].DiagramTweakOrder < what[j].DiagramTweakOrder
}
