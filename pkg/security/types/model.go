/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/threagile/threagile/pkg/input"
)

type ParsedModel struct {
	Author                                        input.Author                 `json:"author" yaml:"author"`
	Title                                         string                       `json:"title,omitempty" yaml:"title"`
	Date                                          time.Time                    `json:"date" yaml:"date"`
	ManagementSummaryComment                      string                       `json:"management_summary_comment,omitempty" yaml:"management_summary_comment"`
	BusinessOverview                              input.Overview               `json:"business_overview" yaml:"business_overview"`
	TechnicalOverview                             input.Overview               `json:"technical_overview" yaml:"technical_overview"`
	BusinessCriticality                           Criticality                  `json:"business_criticality,omitempty" yaml:"business_criticality"`
	SecurityRequirements                          map[string]string            `json:"security_requirements,omitempty" yaml:"security_requirements"`
	Questions                                     map[string]string            `json:"questions,omitempty" yaml:"questions"`
	AbuseCases                                    map[string]string            `json:"abuse_cases,omitempty" yaml:"abuse_cases"`
	TagsAvailable                                 []string                     `json:"tags_available,omitempty" yaml:"tags_available"`
	DataAssets                                    map[string]DataAsset         `json:"data_assets,omitempty" yaml:"data_assets"`
	TechnicalAssets                               map[string]TechnicalAsset    `json:"technical_assets,omitempty" yaml:"technical_assets"`
	TrustBoundaries                               map[string]TrustBoundary     `json:"trust_boundaries,omitempty" yaml:"trust_boundaries"`
	SharedRuntimes                                map[string]SharedRuntime     `json:"shared_runtimes,omitempty" yaml:"shared_runtimes"`
	IndividualRiskCategories                      map[string]RiskCategory      `json:"individual_risk_categories,omitempty" yaml:"individual_risk_categories"`
	BuiltInRiskCategories                         map[string]RiskCategory      `json:"built_in_risk_categories,omitempty" yaml:"built_in_risk_categories"`
	RiskTracking                                  map[string]RiskTracking      `json:"risk_tracking,omitempty" yaml:"risk_tracking"`
	CommunicationLinks                            map[string]CommunicationLink `json:"communication_links,omitempty" yaml:"communication_links"`
	AllSupportedTags                              map[string]bool              `json:"all_supported_tags,omitempty" yaml:"all_supported_tags"`
	DiagramTweakNodesep                           int                          `json:"diagram_tweak_nodesep,omitempty" yaml:"diagram_tweak_nodesep"`
	DiagramTweakRanksep                           int                          `json:"diagram_tweak_ranksep,omitempty" yaml:"diagram_tweak_ranksep"`
	DiagramTweakEdgeLayout                        string                       `json:"diagram_tweak_edge_layout,omitempty" yaml:"diagram_tweak_edge_layout"`
	DiagramTweakSuppressEdgeLabels                bool                         `json:"diagram_tweak_suppress_edge_labels,omitempty" yaml:"diagram_tweak_suppress_edge_labels"`
	DiagramTweakLayoutLeftToRight                 bool                         `json:"diagram_tweak_layout_left_to_right,omitempty" yaml:"diagram_tweak_layout_left_to_right"`
	DiagramTweakInvisibleConnectionsBetweenAssets []string                     `json:"diagram_tweak_invisible_connections_between_assets,omitempty" yaml:"diagram_tweak_invisible_connections_between_assets"`
	DiagramTweakSameRankAssets                    []string                     `json:"diagram_tweak_same_rank_assets,omitempty" yaml:"diagram_tweak_same_rank_assets"`

	// TODO: those are generated based on items above and needs to be private
	IncomingTechnicalCommunicationLinksMappedByTargetId   map[string][]CommunicationLink `json:"incoming_technical_communication_links_mapped_by_target_id,omitempty" yaml:"incoming_technical_communication_links_mapped_by_target_id"`
	DirectContainingTrustBoundaryMappedByTechnicalAssetId map[string]TrustBoundary       `json:"direct_containing_trust_boundary_mapped_by_technical_asset_id,omitempty" yaml:"direct_containing_trust_boundary_mapped_by_technical_asset_id"`
	GeneratedRisksByCategory                              map[string][]Risk              `json:"generated_risks_by_category,omitempty" yaml:"generated_risks_by_category"`
	GeneratedRisksBySyntheticId                           map[string]Risk                `json:"generated_risks_by_synthetic_id,omitempty" yaml:"generated_risks_by_synthetic_id"`
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

func (parsedModel *ParsedModel) CheckTagExists(referencedTag, where string) error {
	if !contains(parsedModel.TagsAvailable, referencedTag) {
		return errors.New("missing referenced tag in overall tag list at " + where + ": " + referencedTag)
	}
	return nil
}

func (parsedModel *ParsedModel) CheckDataAssetTargetExists(referencedAsset, where string) error {
	if _, ok := parsedModel.DataAssets[referencedAsset]; !ok {
		return errors.New("missing referenced data asset target at " + where + ": " + referencedAsset)
	}
	return nil
}

func (parsedModel *ParsedModel) CheckTrustBoundaryExists(referencedId, where string) error {
	if _, ok := parsedModel.TrustBoundaries[referencedId]; !ok {
		return errors.New("missing referenced trust boundary at " + where + ": " + referencedId)
	}
	return nil
}

func (parsedModel *ParsedModel) CheckSharedRuntimeExists(referencedId, where string) error {
	if _, ok := parsedModel.SharedRuntimes[referencedId]; !ok {
		return errors.New("missing referenced shared runtime at " + where + ": " + referencedId)
	}
	return nil
}

func (parsedModel *ParsedModel) CheckCommunicationLinkExists(referencedId, where string) error {
	if _, ok := parsedModel.CommunicationLinks[referencedId]; !ok {
		return errors.New("missing referenced communication link at " + where + ": " + referencedId)
	}
	return nil
}

func (parsedModel *ParsedModel) CheckTechnicalAssetExists(referencedAsset, where string, onlyForTweak bool) error {
	if _, ok := parsedModel.TechnicalAssets[referencedAsset]; !ok {
		suffix := ""
		if onlyForTweak {
			suffix = " (only referenced in diagram tweak)"
		}
		return errors.New("missing referenced technical asset target" + suffix + " at " + where + ": " + referencedAsset)
	}
	return nil
}

func (parsedModel *ParsedModel) CheckNestedTrustBoundariesExisting() error {
	for _, trustBoundary := range parsedModel.TrustBoundaries {
		for _, nestedId := range trustBoundary.TrustBoundariesNested {
			if _, ok := parsedModel.TrustBoundaries[nestedId]; !ok {
				return errors.New("missing referenced nested trust boundary: " + nestedId)
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
