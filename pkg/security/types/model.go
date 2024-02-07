/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/input"
)

// TODO: move model out of types package and
// rename parsedModel to model or something like this to emphasize that it's just a model
// maybe
type ParsedModel struct {
	ThreagileVersion                              string                       `yaml:"threagile_version,omitempty" json:"threagile_version,omitempty"`
	Includes                                      []string                     `yaml:"includes,omitempty" json:"includes,omitempty"`
	Title                                         string                       `json:"title,omitempty" yaml:"title,omitempty"`
	Author                                        input.Author                 `json:"author,omitempty" yaml:"author,omitempty"`
	Contributors                                  []input.Author               `yaml:"contributors,omitempty" json:"contributors,omitempty"`
	Date                                          Date                         `json:"date,omitempty" yaml:"date,omitempty"`
	AppDescription                                input.Overview               `yaml:"application_description,omitempty" json:"application_description,omitempty"`
	BusinessOverview                              input.Overview               `json:"business_overview,omitempty" yaml:"business_overview,omitempty"`
	TechnicalOverview                             input.Overview               `json:"technical_overview,omitempty" yaml:"technical_overview,omitempty"`
	BusinessCriticality                           Criticality                  `json:"business_criticality,omitempty" yaml:"business_criticality,omitempty"`
	ManagementSummaryComment                      string                       `json:"management_summary_comment,omitempty" yaml:"management_summary_comment,omitempty"`
	SecurityRequirements                          map[string]string            `json:"security_requirements,omitempty" yaml:"security_requirements,omitempty"`
	Questions                                     map[string]string            `json:"questions,omitempty" yaml:"questions,omitempty"`
	AbuseCases                                    map[string]string            `json:"abuse_cases,omitempty" yaml:"abuse_cases,omitempty"`
	TagsAvailable                                 []string                     `json:"tags_available,omitempty" yaml:"tags_available,omitempty"`
	DataAssets                                    map[string]DataAsset         `json:"data_assets,omitempty" yaml:"data_assets,omitempty"`
	TechnicalAssets                               map[string]TechnicalAsset    `json:"technical_assets,omitempty" yaml:"technical_assets,omitempty"`
	TrustBoundaries                               map[string]TrustBoundary     `json:"trust_boundaries,omitempty" yaml:"trust_boundaries,omitempty"`
	SharedRuntimes                                map[string]SharedRuntime     `json:"shared_runtimes,omitempty" yaml:"shared_runtimes,omitempty"`
	IndividualRiskCategories                      map[string]RiskCategory      `json:"individual_risk_categories,omitempty" yaml:"individual_risk_categories,omitempty"`
	BuiltInRiskCategories                         map[string]RiskCategory      `json:"built_in_risk_categories,omitempty" yaml:"built_in_risk_categories,omitempty"`
	RiskTracking                                  map[string]RiskTracking      `json:"risk_tracking,omitempty" yaml:"risk_tracking,omitempty"`
	CommunicationLinks                            map[string]CommunicationLink `json:"communication_links,omitempty" yaml:"communication_links,omitempty"`
	AllSupportedTags                              map[string]bool              `json:"all_supported_tags,omitempty" yaml:"all_supported_tags,omitempty"`
	DiagramTweakNodesep                           int                          `json:"diagram_tweak_nodesep,omitempty" yaml:"diagram_tweak_nodesep,omitempty"`
	DiagramTweakRanksep                           int                          `json:"diagram_tweak_ranksep,omitempty" yaml:"diagram_tweak_ranksep,omitempty"`
	DiagramTweakEdgeLayout                        string                       `json:"diagram_tweak_edge_layout,omitempty" yaml:"diagram_tweak_edge_layout,omitempty"`
	DiagramTweakSuppressEdgeLabels                bool                         `json:"diagram_tweak_suppress_edge_labels,omitempty" yaml:"diagram_tweak_suppress_edge_labels,omitempty"`
	DiagramTweakLayoutLeftToRight                 bool                         `json:"diagram_tweak_layout_left_to_right,omitempty" yaml:"diagram_tweak_layout_left_to_right,omitempty"`
	DiagramTweakInvisibleConnectionsBetweenAssets []string                     `json:"diagram_tweak_invisible_connections_between_assets,omitempty" yaml:"diagram_tweak_invisible_connections_between_assets,omitempty"`
	DiagramTweakSameRankAssets                    []string                     `json:"diagram_tweak_same_rank_assets,omitempty" yaml:"diagram_tweak_same_rank_assets,omitempty"`

	// TODO: those are generated based on items above and needs to be private
	IncomingTechnicalCommunicationLinksMappedByTargetId   map[string][]CommunicationLink `json:"incoming_technical_communication_links_mapped_by_target_id,omitempty" yaml:"incoming_technical_communication_links_mapped_by_target_id,omitempty"`
	DirectContainingTrustBoundaryMappedByTechnicalAssetId map[string]TrustBoundary       `json:"direct_containing_trust_boundary_mapped_by_technical_asset_id,omitempty" yaml:"direct_containing_trust_boundary_mapped_by_technical_asset_id,omitempty"`
	GeneratedRisksByCategory                              map[string][]Risk              `json:"generated_risks_by_category,omitempty" yaml:"generated_risks_by_category,omitempty"`
	GeneratedRisksBySyntheticId                           map[string]Risk                `json:"generated_risks_by_synthetic_id,omitempty" yaml:"generated_risks_by_synthetic_id,omitempty"`
}

func (parsedModel *ParsedModel) AddToListOfSupportedTags(tags []string) {
	for _, tag := range tags {
		parsedModel.AllSupportedTags[tag] = true
	}
}

func (parsedModel *ParsedModel) GetDeferredRiskTrackingDueToWildcardMatching() map[string]RiskTracking {
	deferredRiskTrackingDueToWildcardMatching := make(map[string]RiskTracking)
	for syntheticRiskId, riskTracking := range parsedModel.RiskTracking {
		if strings.Contains(syntheticRiskId, "*") { // contains a wildcard char
			deferredRiskTrackingDueToWildcardMatching[syntheticRiskId] = riskTracking
		}
	}

	return deferredRiskTrackingDueToWildcardMatching
}

func (parsedModel *ParsedModel) HasNotYetAnyDirectNonWildcardRiskTracking(syntheticRiskId string) bool {
	if _, ok := parsedModel.RiskTracking[syntheticRiskId]; ok {
		return false
	}
	return true
}

func (parsedModel *ParsedModel) CheckTags(tags []string, where string) ([]string, error) {
	var tagsUsed = make([]string, 0)
	if tags != nil {
		tagsUsed = make([]string, len(tags))
		for i, parsedEntry := range tags {
			referencedTag := fmt.Sprintf("%v", parsedEntry)
			err := parsedModel.CheckTagExists(referencedTag, where)
			if err != nil {
				return nil, err
			}
			tagsUsed[i] = referencedTag
		}
	}
	return tagsUsed, nil
}

func (parsedModel *ParsedModel) ApplyWildcardRiskTrackingEvaluation(ignoreOrphanedRiskTracking bool, progressReporter ProgressReporter) error {
	progressReporter.Info("Executing risk tracking evaluation")
	for syntheticRiskIdPattern, riskTracking := range parsedModel.GetDeferredRiskTrackingDueToWildcardMatching() {
		progressReporter.Infof("Applying wildcard risk tracking for risk id: %v", syntheticRiskIdPattern)

		foundSome := false
		var matchingRiskIdExpression = regexp.MustCompile(strings.ReplaceAll(regexp.QuoteMeta(syntheticRiskIdPattern), `\*`, `[^@]+`))
		for syntheticRiskId := range parsedModel.GeneratedRisksBySyntheticId {
			if matchingRiskIdExpression.Match([]byte(syntheticRiskId)) && parsedModel.HasNotYetAnyDirectNonWildcardRiskTracking(syntheticRiskId) {
				foundSome = true
				parsedModel.RiskTracking[syntheticRiskId] = RiskTracking{
					SyntheticRiskId: strings.TrimSpace(syntheticRiskId),
					Justification:   riskTracking.Justification,
					CheckedBy:       riskTracking.CheckedBy,
					Ticket:          riskTracking.Ticket,
					Status:          riskTracking.Status,
					Date:            riskTracking.Date,
				}
			}
		}

		if !foundSome {
			if ignoreOrphanedRiskTracking {
				progressReporter.Warnf("Wildcard risk tracking does not match any risk id: %v", syntheticRiskIdPattern)
			} else {
				return fmt.Errorf("wildcard risk tracking does not match any risk id: %v", syntheticRiskIdPattern)
			}
		}
	}
	return nil
}

func (parsedModel *ParsedModel) CheckRiskTracking(ignoreOrphanedRiskTracking bool, progressReporter ProgressReporter) error {
	progressReporter.Info("Checking risk tracking")
	for _, tracking := range parsedModel.RiskTracking {
		if _, ok := parsedModel.GeneratedRisksBySyntheticId[tracking.SyntheticRiskId]; !ok {
			if ignoreOrphanedRiskTracking {
				progressReporter.Infof("Risk tracking references unknown risk (risk id not found): %v", tracking.SyntheticRiskId)
			} else {
				return fmt.Errorf("Risk tracking references unknown risk (risk id not found) - you might want to use the option -ignore-orphaned-risk-tracking: %v"+
					"\n\nNOTE: For risk tracking each risk-id needs to be defined (the string with the @ sign in it). "+
					"These unique risk IDs are visible in the PDF report (the small grey string under each risk), "+
					"the Excel (column \"ID\"), as well as the JSON responses. Some risk IDs have only one @ sign in them, "+
					"while others multiple. The idea is to allow for unique but still speaking IDs. Therefore each risk instance "+
					"creates its individual ID by taking all affected elements causing the risk to be within an @-delimited part. "+
					"Using wildcards (the * sign) for parts delimited by @ signs allows to handle groups of certain risks at once. "+
					"Best is to lookup the IDs to use in the created Excel file. Alternatively a model macro \"seed-risk-tracking\" "+
					"is available that helps in initially seeding the risk tracking part here based on already identified and not yet handled risks.",
					tracking.SyntheticRiskId)
			}
		}
	}

	// save also the risk-category-id and risk-status directly in the risk for better JSON marshalling
	for category := range parsedModel.GeneratedRisksByCategory {
		for i := range parsedModel.GeneratedRisksByCategory[category] {
			//			context.parsedModel.GeneratedRisksByCategory[category][i].CategoryId = category
			parsedModel.GeneratedRisksByCategory[category][i].RiskStatus = parsedModel.GeneratedRisksByCategory[category][i].GetRiskTrackingStatusDefaultingUnchecked(parsedModel)
		}
	}
	return nil
}

func (parsedModel *ParsedModel) CheckTagExists(referencedTag, where string) error {
	if !slices.Contains(parsedModel.TagsAvailable, referencedTag) {
		return fmt.Errorf("missing referenced tag in overall tag list at %v: %v", where, referencedTag)
	}
	return nil
}

func (parsedModel *ParsedModel) CheckDataAssetTargetExists(referencedAsset, where string) error {
	if _, ok := parsedModel.DataAssets[referencedAsset]; !ok {
		return fmt.Errorf("missing referenced data asset target at %v: %v", where, referencedAsset)
	}
	return nil
}

func (parsedModel *ParsedModel) CheckTrustBoundaryExists(referencedId, where string) error {
	if _, ok := parsedModel.TrustBoundaries[referencedId]; !ok {
		return fmt.Errorf("missing referenced trust boundary at %v: %v", where, referencedId)
	}
	return nil
}

func (parsedModel *ParsedModel) CheckSharedRuntimeExists(referencedId, where string) error {
	if _, ok := parsedModel.SharedRuntimes[referencedId]; !ok {
		return fmt.Errorf("missing referenced shared runtime at %v: %v", where, referencedId)
	}
	return nil
}

func (parsedModel *ParsedModel) CheckCommunicationLinkExists(referencedId, where string) error {
	if _, ok := parsedModel.CommunicationLinks[referencedId]; !ok {
		return fmt.Errorf("missing referenced communication link at %v: %v", where, referencedId)
	}
	return nil
}

func (parsedModel *ParsedModel) CheckTechnicalAssetExists(referencedAsset, where string, onlyForTweak bool) error {
	if _, ok := parsedModel.TechnicalAssets[referencedAsset]; !ok {
		suffix := ""
		if onlyForTweak {
			suffix = " (only referenced in diagram tweak)"
		}
		return fmt.Errorf("missing referenced technical asset target%v at %v: %v", suffix, where, referencedAsset)
	}
	return nil
}

func (parsedModel *ParsedModel) CheckNestedTrustBoundariesExisting() error {
	for _, trustBoundary := range parsedModel.TrustBoundaries {
		for _, nestedId := range trustBoundary.TrustBoundariesNested {
			if _, ok := parsedModel.TrustBoundaries[nestedId]; !ok {
				return fmt.Errorf("missing referenced nested trust boundary: %v", nestedId)
			}
		}
	}
	return nil
}

func CalculateSeverity(likelihood RiskExploitationLikelihood, impact RiskExploitationImpact) RiskSeverity {
	result := likelihood.Weight() * impact.Weight()
	if result <= 1 {
		return LowSeverity
	}
	if result <= 3 {
		return MediumSeverity
	}
	if result <= 8 {
		return ElevatedSeverity
	}
	if result <= 12 {
		return HighSeverity
	}
	return CriticalSeverity
}

func (parsedModel *ParsedModel) InScopeTechnicalAssets() []TechnicalAsset {
	result := make([]TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		if !asset.OutOfScope {
			result = append(result, asset)
		}
	}
	return result
}

func (parsedModel *ParsedModel) SortedTechnicalAssetIDs() []string {
	res := make([]string, 0)
	for id := range parsedModel.TechnicalAssets {
		res = append(res, id)
	}
	sort.Strings(res)
	return res
}

func (parsedModel *ParsedModel) TagsActuallyUsed() []string {
	result := make([]string, 0)
	for _, tag := range parsedModel.TagsAvailable {
		if len(parsedModel.TechnicalAssetsTaggedWithAny(tag)) > 0 ||
			len(parsedModel.CommunicationLinksTaggedWithAny(tag)) > 0 ||
			len(parsedModel.DataAssetsTaggedWithAny(tag)) > 0 ||
			len(parsedModel.TrustBoundariesTaggedWithAny(tag)) > 0 ||
			len(parsedModel.SharedRuntimesTaggedWithAny(tag)) > 0 {
			result = append(result, tag)
		}
	}
	return result
}

func (parsedModel *ParsedModel) TechnicalAssetsTaggedWithAny(tags ...string) []TechnicalAsset {
	result := make([]TechnicalAsset, 0)
	for _, candidate := range parsedModel.TechnicalAssets {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func (parsedModel *ParsedModel) CommunicationLinksTaggedWithAny(tags ...string) []CommunicationLink {
	result := make([]CommunicationLink, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		for _, candidate := range asset.CommunicationLinks {
			if candidate.IsTaggedWithAny(tags...) {
				result = append(result, candidate)
			}
		}
	}
	return result
}

func (parsedModel *ParsedModel) DataAssetsTaggedWithAny(tags ...string) []DataAsset {
	result := make([]DataAsset, 0)
	for _, candidate := range parsedModel.DataAssets {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func (parsedModel *ParsedModel) TrustBoundariesTaggedWithAny(tags ...string) []TrustBoundary {
	result := make([]TrustBoundary, 0)
	for _, candidate := range parsedModel.TrustBoundaries {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func (parsedModel *ParsedModel) SharedRuntimesTaggedWithAny(tags ...string) []SharedRuntime {
	result := make([]SharedRuntime, 0)
	for _, candidate := range parsedModel.SharedRuntimes {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func (parsedModel *ParsedModel) OutOfScopeTechnicalAssets() []TechnicalAsset {
	assets := make([]TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		if asset.OutOfScope {
			assets = append(assets, asset)
		}
	}
	sort.Sort(ByTechnicalAssetTitleSort(assets))
	return assets
}

func (parsedModel *ParsedModel) RisksOfOnlySTRIDEInformationDisclosure(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, categoryRisks := range risksByCategory {
		for _, risk := range categoryRisks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.STRIDE == InformationDisclosure {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func (parsedModel *ParsedModel) RisksOfOnlySTRIDEDenialOfService(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, categoryRisks := range risksByCategory {
		for _, risk := range categoryRisks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.STRIDE == DenialOfService {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func (parsedModel *ParsedModel) RisksOfOnlySTRIDEElevationOfPrivilege(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, categoryRisks := range risksByCategory {
		for _, risk := range categoryRisks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.STRIDE == ElevationOfPrivilege {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func (parsedModel *ParsedModel) RisksOfOnlyBusinessSide(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, categoryRisks := range risksByCategory {
		for _, risk := range categoryRisks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.Function == BusinessSide {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func (parsedModel *ParsedModel) RisksOfOnlyArchitecture(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, categoryRisks := range risksByCategory {
		for _, risk := range categoryRisks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.Function == Architecture {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func (parsedModel *ParsedModel) RisksOfOnlyDevelopment(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, categoryRisks := range risksByCategory {
		for _, risk := range categoryRisks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.Function == Development {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func (parsedModel *ParsedModel) RisksOfOnlyOperation(risksByCategory map[string][]Risk) map[string][]Risk {
	result := make(map[string][]Risk)
	for categoryId, categoryRisks := range risksByCategory {
		for _, risk := range categoryRisks {
			category := GetRiskCategory(parsedModel, categoryId)
			if category.Function == Operations {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}
