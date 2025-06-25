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
)

// TODO: move model out of types package and
// rename model to model or something like this to emphasize that it's just a model
// maybe

type Model struct {
	ThreagileVersion                              string                        `yaml:"threagile_version,omitempty" json:"threagile_version,omitempty"`
	Includes                                      []string                      `yaml:"includes,omitempty" json:"includes,omitempty"`
	Title                                         string                        `json:"title,omitempty" yaml:"title,omitempty"`
	Author                                        *Author                       `json:"author,omitempty" yaml:"author,omitempty"`
	Contributors                                  []*Author                     `yaml:"contributors,omitempty" json:"contributors,omitempty"`
	Date                                          Date                          `json:"date,omitempty" yaml:"date,omitempty"`
	AppDescription                                *Overview                     `yaml:"application_description,omitempty" json:"application_description,omitempty"`
	BusinessOverview                              *Overview                     `json:"business_overview,omitempty" yaml:"business_overview,omitempty"`
	TechnicalOverview                             *Overview                     `json:"technical_overview,omitempty" yaml:"technical_overview,omitempty"`
	BusinessCriticality                           Criticality                   `json:"business_criticality,omitempty" yaml:"business_criticality,omitempty"`
	ManagementSummaryComment                      string                        `json:"management_summary_comment,omitempty" yaml:"management_summary_comment,omitempty"`
	SecurityRequirements                          map[string]string             `json:"security_requirements,omitempty" yaml:"security_requirements,omitempty"`
	Questions                                     map[string]string             `json:"questions,omitempty" yaml:"questions,omitempty"`
	AbuseCases                                    map[string]string             `json:"abuse_cases,omitempty" yaml:"abuse_cases,omitempty"`
	TagsAvailable                                 []string                      `json:"tags_available,omitempty" yaml:"tags_available,omitempty"`
	DataAssets                                    map[string]*DataAsset         `json:"data_assets,omitempty" yaml:"data_assets,omitempty"`
	TechnicalAssets                               map[string]*TechnicalAsset    `json:"technical_assets,omitempty" yaml:"technical_assets,omitempty"`
	TrustBoundaries                               map[string]*TrustBoundary     `json:"trust_boundaries,omitempty" yaml:"trust_boundaries,omitempty"`
	SharedRuntimes                                map[string]*SharedRuntime     `json:"shared_runtimes,omitempty" yaml:"shared_runtimes,omitempty"`
	CustomRiskCategories                          RiskCategories                `json:"custom_risk_categories,omitempty" yaml:"custom_risk_categories,omitempty"`
	BuiltInRiskCategories                         RiskCategories                `json:"built_in_risk_categories,omitempty" yaml:"built_in_risk_categories,omitempty"`
	RiskTracking                                  map[string]*RiskTracking      `json:"risk_tracking,omitempty" yaml:"risk_tracking,omitempty"`
	CommunicationLinks                            map[string]*CommunicationLink `json:"communication_links,omitempty" yaml:"communication_links,omitempty"`
	AllSupportedTags                              map[string]bool               `json:"all_supported_tags,omitempty" yaml:"all_supported_tags,omitempty"`
	DiagramTweakNodesep                           int                           `json:"diagram_tweak_nodesep,omitempty" yaml:"diagram_tweak_nodesep,omitempty"`
	DiagramTweakRanksep                           int                           `json:"diagram_tweak_ranksep,omitempty" yaml:"diagram_tweak_ranksep,omitempty"`
	DiagramTweakEdgeLayout                        string                        `json:"diagram_tweak_edge_layout,omitempty" yaml:"diagram_tweak_edge_layout,omitempty"`
	DiagramTweakSuppressEdgeLabels                bool                          `json:"diagram_tweak_suppress_edge_labels,omitempty" yaml:"diagram_tweak_suppress_edge_labels,omitempty"`
	DiagramTweakLayoutLeftToRight                 bool                          `json:"diagram_tweak_layout_left_to_right,omitempty" yaml:"diagram_tweak_layout_left_to_right,omitempty"`
	DiagramTweakInvisibleConnectionsBetweenAssets []string                      `json:"diagram_tweak_invisible_connections_between_assets,omitempty" yaml:"diagram_tweak_invisible_connections_between_assets,omitempty"`
	DiagramTweakSameRankAssets                    []string                      `json:"diagram_tweak_same_rank_assets,omitempty" yaml:"diagram_tweak_same_rank_assets,omitempty"`
	DeletePostFunctionalNeed                      bool                          `json:"delete_post_functional_need,omitempty" yaml:"delete_post_functional_need,omitempty"`
	Deidentified                                  bool                          `json:"deidentified,omitempty" yaml:"deidentified,omitempty"`
	PublicDisclosureSigned                        bool                          `json:"public_disclosure_signed,omitempty" yaml:"public_disclosure_signed,omitempty"`
	HasDataLifeCycleMgmt                          bool                          `json:"hasdatalifecyclemgmt,omitempty" yaml:"hasdatalifecyclemgmt,omitempty"`
	PIUserAccessMechanism                         bool                          `json:"piuseraccessmechanism,omitempty" yaml:"piuseraccessmechanism,omitempty"`

	// TODO: those are generated based on items above and needs to be private
	IncomingTechnicalCommunicationLinksMappedByTargetId   map[string][]*CommunicationLink `json:"incoming_technical_communication_links_mapped_by_target_id,omitempty" yaml:"incoming_technical_communication_links_mapped_by_target_id,omitempty"`
	DirectContainingTrustBoundaryMappedByTechnicalAssetId map[string]*TrustBoundary       `json:"direct_containing_trust_boundary_mapped_by_technical_asset_id,omitempty" yaml:"direct_containing_trust_boundary_mapped_by_technical_asset_id,omitempty"`
	GeneratedRisksByCategory                              map[string][]*Risk              `json:"generated_risks_by_category,omitempty" yaml:"generated_risks_by_category,omitempty"`
	GeneratedRisksBySyntheticId                           map[string]*Risk                `json:"generated_risks_by_synthetic_id,omitempty" yaml:"generated_risks_by_synthetic_id,omitempty"`
}

type ProgressReporter interface {
	Info(a ...any)
	Warn(a ...any)
	Error(a ...any)
	Infof(format string, a ...any)
	Warnf(format string, a ...any)
	Errorf(format string, a ...any)
}

func (model *Model) AddToListOfSupportedTags(tags []string) {
	for _, tag := range tags {
		model.AllSupportedTags[tag] = true
	}
}

func (model *Model) GetDeferredRiskTrackingDueToWildcardMatching() map[string]*RiskTracking {
	deferredRiskTrackingDueToWildcardMatching := make(map[string]*RiskTracking)
	for syntheticRiskId, riskTracking := range model.RiskTracking {
		if strings.Contains(syntheticRiskId, "*") { // contains a wildcard char
			deferredRiskTrackingDueToWildcardMatching[syntheticRiskId] = riskTracking
		}
	}

	return deferredRiskTrackingDueToWildcardMatching
}

func (model *Model) HasNotYetAnyDirectNonWildcardRiskTracking(syntheticRiskId string) bool {
	if _, ok := model.RiskTracking[syntheticRiskId]; ok {
		return false
	}
	return true
}

func (model *Model) CheckTags(tags []string, where string) ([]string, error) {
	var tagsUsed = make([]string, 0)
	if tags != nil {
		tagsUsed = make([]string, len(tags))
		for i, parsedEntry := range tags {
			referencedTag := fmt.Sprintf("%v", parsedEntry)
			err := model.CheckTagExists(referencedTag, where)
			if err != nil {
				return nil, err
			}
			tagsUsed[i] = referencedTag
		}
	}
	return tagsUsed, nil
}

func (model *Model) ApplyWildcardRiskTrackingEvaluation(ignoreOrphanedRiskTracking bool, progressReporter ProgressReporter) error {
	progressReporter.Info("Executing risk tracking evaluation")
	for syntheticRiskIdPattern, riskTracking := range model.GetDeferredRiskTrackingDueToWildcardMatching() {
		progressReporter.Infof("Applying wildcard risk tracking for risk id: %v", syntheticRiskIdPattern)

		foundSome := false
		var matchingRiskIdExpression = regexp.MustCompile(strings.ReplaceAll(regexp.QuoteMeta(syntheticRiskIdPattern), `\*`, `[^@]+`))
		for syntheticRiskId := range model.GeneratedRisksBySyntheticId {
			if matchingRiskIdExpression.Match([]byte(syntheticRiskId)) && model.HasNotYetAnyDirectNonWildcardRiskTracking(syntheticRiskId) {
				foundSome = true
				model.RiskTracking[syntheticRiskId] = &RiskTracking{
					SyntheticRiskId: strings.TrimSpace(syntheticRiskId),
					Justification:   riskTracking.Justification,
					CheckedBy:       riskTracking.CheckedBy,
					Ticket:          riskTracking.Ticket,
					Status:          riskTracking.Status,
					Date:            riskTracking.Date,
				}

				progressReporter.Infof("  => %v", syntheticRiskId)
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

func (model *Model) CheckRiskTracking(ignoreOrphanedRiskTracking bool, progressReporter ProgressReporter) error {
	progressReporter.Info("Checking risk tracking")
	for _, tracking := range model.RiskTracking {
		foundSome := false
		var matchingRiskIdExpression = regexp.MustCompile(strings.ReplaceAll(regexp.QuoteMeta(tracking.SyntheticRiskId), `\*`, `[^@]+`))
		for syntheticRiskId := range model.GeneratedRisksBySyntheticId {
			if matchingRiskIdExpression.Match([]byte(syntheticRiskId)) {
				foundSome = true
			}
		}

		if !foundSome {
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
					"is available that helps in initially seeding the risk tracking part here based on already identified and not yet handled risks",
					tracking.SyntheticRiskId)
			}
		}
	}

	return nil
}

func (model *Model) CheckTagExists(referencedTag, where string) error {
	if !slices.Contains(model.TagsAvailable, referencedTag) {
		return fmt.Errorf("missing referenced tag in overall tag list at %v: %v", where, referencedTag)
	}
	return nil
}

func (model *Model) CheckDataAssetTargetExists(referencedAsset, where string) error {
	if _, ok := model.DataAssets[referencedAsset]; !ok {
		return fmt.Errorf("missing referenced data asset target at %v: %v", where, referencedAsset)
	}
	return nil
}

func (model *Model) CheckTrustBoundaryExists(referencedId, where string) error {
	if _, ok := model.TrustBoundaries[referencedId]; !ok {
		return fmt.Errorf("missing referenced trust boundary at %v: %v", where, referencedId)
	}
	return nil
}

func (model *Model) CheckSharedRuntimeExists(referencedId, where string) error {
	if _, ok := model.SharedRuntimes[referencedId]; !ok {
		return fmt.Errorf("missing referenced shared runtime at %v: %v", where, referencedId)
	}
	return nil
}

func (model *Model) CheckCommunicationLinkExists(referencedId, where string) error {
	if _, ok := model.CommunicationLinks[referencedId]; !ok {
		return fmt.Errorf("missing referenced communication link at %v: %v", where, referencedId)
	}
	return nil
}

func (model *Model) CheckTechnicalAssetExists(referencedAsset, where string, onlyForTweak bool) error {
	if _, ok := model.TechnicalAssets[referencedAsset]; !ok {
		suffix := ""
		if onlyForTweak {
			suffix = " (only referenced in diagram tweak)"
		}
		return fmt.Errorf("missing referenced technical asset target%v at %v: %v", suffix, where, referencedAsset)
	}
	return nil
}

func (model *Model) CheckNestedTrustBoundariesExisting() error {
	for _, trustBoundary := range model.TrustBoundaries {
		for _, nestedId := range trustBoundary.TrustBoundariesNested {
			if _, ok := model.TrustBoundaries[nestedId]; !ok {
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

func (model *Model) InScopeTechnicalAssets() []*TechnicalAsset {
	result := make([]*TechnicalAsset, 0)
	for _, asset := range model.TechnicalAssets {
		if !asset.OutOfScope {
			result = append(result, asset)
		}
	}
	return result
}

func (model *Model) SortedTechnicalAssetIDs() []string {
	res := make([]string, 0)
	for id := range model.TechnicalAssets {
		res = append(res, id)
	}
	sort.Strings(res)
	return res
}

func (model *Model) TagsActuallyUsed() []string {
	result := make([]string, 0)
	for _, tag := range model.TagsAvailable {
		if len(model.TechnicalAssetsTaggedWithAny(tag)) > 0 ||
			len(model.CommunicationLinksTaggedWithAny(tag)) > 0 ||
			len(model.DataAssetsTaggedWithAny(tag)) > 0 ||
			len(model.TrustBoundariesTaggedWithAny(tag)) > 0 ||
			len(model.SharedRuntimesTaggedWithAny(tag)) > 0 {
			result = append(result, tag)
		}
	}
	return result
}

func (model *Model) TechnicalAssetsTaggedWithAny(tags ...string) []*TechnicalAsset {
	result := make([]*TechnicalAsset, 0)
	for _, candidate := range model.TechnicalAssets {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func (model *Model) CommunicationLinksTaggedWithAny(tags ...string) []*CommunicationLink {
	result := make([]*CommunicationLink, 0)
	for _, asset := range model.TechnicalAssets {
		for _, candidate := range asset.CommunicationLinks {
			if candidate.IsTaggedWithAny(tags...) {
				result = append(result, candidate)
			}
		}
	}
	return result
}

func (model *Model) DataAssetsTaggedWithAny(tags ...string) []*DataAsset {
	result := make([]*DataAsset, 0)
	for _, candidate := range model.DataAssets {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func (model *Model) TrustBoundariesTaggedWithAny(tags ...string) []*TrustBoundary {
	result := make([]*TrustBoundary, 0)
	for _, candidate := range model.TrustBoundaries {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func (model *Model) SharedRuntimesTaggedWithAny(tags ...string) []*SharedRuntime {
	result := make([]*SharedRuntime, 0)
	for _, candidate := range model.SharedRuntimes {
		if candidate.IsTaggedWithAny(tags...) {
			result = append(result, candidate)
		}
	}
	return result
}

func (model *Model) OutOfScopeTechnicalAssets() []*TechnicalAsset {
	assets := make([]*TechnicalAsset, 0)
	for _, asset := range model.TechnicalAssets {
		if asset.OutOfScope {
			assets = append(assets, asset)
		}
	}
	sort.Sort(ByTechnicalAssetTitleSort(assets))
	return assets
}

func (model *Model) FindSharedRuntimeHighestConfidentiality(sharedRuntime *SharedRuntime) Confidentiality {
	highest := Public
	for _, id := range sharedRuntime.TechnicalAssetsRunning {
		techAsset := model.TechnicalAssets[id]
		if model.HighestProcessedConfidentiality(techAsset) > highest {
			highest = model.HighestProcessedConfidentiality(techAsset)
		}
	}
	return highest
}

func (model *Model) FindSharedRuntimeHighestIntegrity(sharedRuntime *SharedRuntime) Criticality {
	highest := Archive
	for _, id := range sharedRuntime.TechnicalAssetsRunning {
		techAssetIntegrity := model.HighestProcessedIntegrity(model.TechnicalAssets[id])
		if techAssetIntegrity > highest {
			highest = techAssetIntegrity
		}
	}
	return highest
}

func (model *Model) FindSharedRuntimeHighestAvailability(sharedRuntime *SharedRuntime) Criticality {
	highest := Archive
	for _, id := range sharedRuntime.TechnicalAssetsRunning {
		techAssetAvailability := model.HighestProcessedAvailability(model.TechnicalAssets[id])
		if techAssetAvailability > highest {
			highest = techAssetAvailability
		}
	}
	return highest
}

func (model *Model) FindTrustBoundaryHighestConfidentiality(tb *TrustBoundary) Confidentiality {
	highest := Public
	for _, id := range model.RecursivelyAllTechnicalAssetIDsInside(tb) {
		techAsset := model.TechnicalAssets[id]
		if model.HighestProcessedConfidentiality(techAsset) > highest {
			highest = model.HighestProcessedConfidentiality(techAsset)
		}
	}
	return highest
}

func (model *Model) FindTrustBoundaryHighestIntegrity(tb *TrustBoundary) Criticality {
	highest := Archive
	for _, id := range model.RecursivelyAllTechnicalAssetIDsInside(tb) {
		techAssetIntegrity := model.HighestProcessedIntegrity(model.TechnicalAssets[id])
		if techAssetIntegrity > highest {
			highest = techAssetIntegrity
		}
	}
	return highest
}

func (model *Model) FindTrustBoundaryHighestAvailability(tb *TrustBoundary) Criticality {
	highest := Archive
	for _, id := range model.RecursivelyAllTechnicalAssetIDsInside(tb) {
		techAssetAvailability := model.HighestProcessedAvailability(model.TechnicalAssets[id])
		if techAssetAvailability > highest {
			highest = techAssetAvailability
		}
	}
	return highest
}

func (model *Model) RecursivelyAllTechnicalAssetIDsInside(tb *TrustBoundary) []string {
	result := make([]string, 0)
	model.addAssetIDsRecursively(tb, &result)
	return result
}

func (model *Model) addAssetIDsRecursively(tb *TrustBoundary, result *[]string) {
	*result = append(*result, tb.TechnicalAssetsInside...)
	for _, nestedBoundaryID := range tb.TrustBoundariesNested {
		model.addAssetIDsRecursively(model.TrustBoundaries[nestedBoundaryID], result)
	}
}

func (model *Model) AllParentTrustBoundaryIDs(what *TrustBoundary) []string {
	result := make([]string, 0)
	model.addTrustBoundaryIDsRecursively(what, &result)
	return result
}

func (model *Model) addTrustBoundaryIDsRecursively(what *TrustBoundary, result *[]string) {
	*result = append(*result, what.Id)
	parent := model.FindParentTrustBoundary(what)
	if parent != nil {
		model.addTrustBoundaryIDsRecursively(parent, result)
	}
}

func (model *Model) FindParentTrustBoundary(tb *TrustBoundary) *TrustBoundary {
	if tb == nil {
		return nil
	}
	for _, candidate := range model.TrustBoundaries {
		if contains(candidate.TrustBoundariesNested, tb.Id) {
			return candidate
		}
	}
	return nil
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:

func (model *Model) SortedRiskCategories() []*RiskCategory {
	categoryMap := make(map[string]*RiskCategory)
	for categoryId := range model.GeneratedRisksByCategory {
		category := model.GetRiskCategory(categoryId)
		if category != nil {
			categoryMap[categoryId] = category
		}
	}

	categories := make([]*RiskCategory, 0)
	for categoryId := range categoryMap {
		categories = append(categories, categoryMap[categoryId])
	}

	model.SortByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk(categories)
	return categories
}

func (model *Model) SortedRisksOfCategory(category *RiskCategory) []*Risk {
	risks := model.GeneratedRisksByCategoryWithCurrentStatus()[category.ID]
	SortByRiskSeverity(risks)
	return risks
}

func (model *Model) SortByRiskCategoryHighestContainingRiskSeveritySortStillAtRisk(riskCategories []*RiskCategory) {
	sort.Slice(riskCategories, func(i, j int) bool {
		risksLeft := ReduceToOnlyStillAtRisk(model.GeneratedRisksByCategory[riskCategories[i].ID])
		risksRight := ReduceToOnlyStillAtRisk(model.GeneratedRisksByCategory[riskCategories[j].ID])
		highestLeft := HighestSeverityStillAtRisk(risksLeft)
		highestRight := HighestSeverityStillAtRisk(risksRight)
		if highestLeft == highestRight {
			if len(risksLeft) == 0 && len(risksRight) > 0 {
				return false
			}
			if len(risksLeft) > 0 && len(risksRight) == 0 {
				return true
			}
			return riskCategories[i].Title < riskCategories[j].Title
		}
		return highestLeft > highestRight
	})
}

func (model *Model) GetRiskCategory(categoryID string) *RiskCategory {
	if len(model.CustomRiskCategories) > 0 {
		for _, custom := range model.CustomRiskCategories {
			if strings.EqualFold(custom.ID, categoryID) {
				return custom
			}
		}
	}

	if len(model.BuiltInRiskCategories) > 0 {
		for _, builtIn := range model.BuiltInRiskCategories {
			if strings.EqualFold(builtIn.ID, categoryID) {
				return builtIn
			}
		}
	}

	return nil
}

func (model *Model) AllRisks() []*Risk {
	result := make([]*Risk, 0)
	for _, risks := range model.GeneratedRisksByCategory {
		result = append(result, risks...)
	}
	return result
}

func (model *Model) IdentifiedDataBreachProbability(what *DataAsset) DataBreachProbability {
	highestProbability := Improbable
	for _, risk := range model.AllRisks() {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			ta := model.TechnicalAssets[techAsset]
			if ta != nil && what != nil && (len(ta.DataAssetsProcessed) > 0) {
				if contains(model.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
					if risk.DataBreachProbability > highestProbability {
						highestProbability = risk.DataBreachProbability
						break
					}
				}
			}
		}
	}
	return highestProbability
}

func (model *Model) IdentifiedDataBreachProbabilityRisks(what *DataAsset) []*Risk {
	result := make([]*Risk, 0)
	for _, risk := range model.AllRisks() {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			ta := model.TechnicalAssets[techAsset]
			if ta != nil && what != nil && (len(ta.DataAssetsProcessed) > 0) {
				if contains(model.TechnicalAssets[techAsset].DataAssetsProcessed, what.Id) {
					result = append(result, risk)
					break
				}
			}
		}
	}
	return result
}

func (model *Model) ProcessedByTechnicalAssetsSorted(what *DataAsset) []*TechnicalAsset {
	result := make([]*TechnicalAsset, 0)
	for _, technicalAsset := range model.TechnicalAssets {
		for _, candidateID := range technicalAsset.DataAssetsProcessed {
			if candidateID == what.Id {
				result = append(result, technicalAsset)
			}
		}
	}
	sort.Sort(ByTechnicalAssetTitleSort(result))
	return result
}

func (model *Model) StoredByTechnicalAssetsSorted(what *DataAsset) []*TechnicalAsset {
	result := make([]*TechnicalAsset, 0)
	for _, technicalAsset := range model.TechnicalAssets {
		for _, candidateID := range technicalAsset.DataAssetsStored {
			if candidateID == what.Id {
				result = append(result, technicalAsset)
			}
		}
	}
	sort.Sort(ByTechnicalAssetTitleSort(result))
	return result
}

func (model *Model) SentViaCommLinksSorted(what *DataAsset) []*CommunicationLink {
	result := make([]*CommunicationLink, 0)
	for _, technicalAsset := range model.TechnicalAssets {
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

func (model *Model) ReceivedViaCommLinksSorted(what *DataAsset) []*CommunicationLink {
	result := make([]*CommunicationLink, 0)
	for _, technicalAsset := range model.TechnicalAssets {
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

func (model *Model) HighestCommunicationLinkConfidentiality(what *CommunicationLink) Confidentiality {
	highest := Public
	for _, dataId := range what.DataAssetsSent {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	for _, dataId := range what.DataAssetsReceived {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	return highest
}

func (model *Model) HighestCommunicationLinkIntegrity(what *CommunicationLink) Criticality {
	highest := Archive
	for _, dataId := range what.DataAssetsSent {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	for _, dataId := range what.DataAssetsReceived {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	return highest
}

func (model *Model) HighestCommunicationLinkAvailability(what *CommunicationLink) Criticality {
	highest := Archive
	for _, dataId := range what.DataAssetsSent {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	for _, dataId := range what.DataAssetsReceived {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	return highest
}

func (model *Model) DataAssetsSentSorted(what *CommunicationLink) []*DataAsset {
	result := make([]*DataAsset, 0)
	for _, assetID := range what.DataAssetsSent {
		result = append(result, model.DataAssets[assetID])
	}
	sort.Sort(byDataAssetTitleSort(result))
	return result
}

func (model *Model) DataAssetsReceivedSorted(what *CommunicationLink) []*DataAsset {
	result := make([]*DataAsset, 0)
	for _, assetID := range what.DataAssetsReceived {
		result = append(result, model.DataAssets[assetID])
	}
	sort.Sort(byDataAssetTitleSort(result))
	return result
}

func (model *Model) GetTechnicalAssetTrustBoundaryId(ta *TechnicalAsset) string {
	for _, trustBoundary := range model.TrustBoundaries {
		for _, techAssetInside := range trustBoundary.TechnicalAssetsInside {
			if techAssetInside == ta.Id {
				return trustBoundary.Id
			}
		}
	}
	return ""
}

func (model *Model) HighestTechnicalAssetConfidentiality(what *TechnicalAsset) Confidentiality {
	highest := what.Confidentiality
	highestProcessed := model.HighestProcessedConfidentiality(what)
	if highest < highestProcessed {
		highest = highestProcessed
	}

	highestStored := model.HighestStoredConfidentiality(what)
	if highest < highestStored {
		highest = highestStored
	}

	return highest
}

func (model *Model) HighestProcessedConfidentiality(what *TechnicalAsset) Confidentiality {
	highest := what.Confidentiality
	for _, dataId := range what.DataAssetsProcessed {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	return highest
}

func (model *Model) HighestStoredConfidentiality(what *TechnicalAsset) Confidentiality {
	highest := what.Confidentiality
	for _, dataId := range what.DataAssetsStored {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Confidentiality > highest {
			highest = dataAsset.Confidentiality
		}
	}
	return highest
}

func (model *Model) DataAssetsProcessedSorted(what *TechnicalAsset) []*DataAsset {
	result := make([]*DataAsset, 0)
	for _, assetID := range what.DataAssetsProcessed {
		result = append(result, model.DataAssets[assetID])
	}
	sort.Sort(ByDataAssetTitleSort(result))
	return result
}

func (model *Model) DataAssetsStoredSorted(what *TechnicalAsset) []*DataAsset {
	result := make([]*DataAsset, 0)
	for _, assetID := range what.DataAssetsStored {
		result = append(result, model.DataAssets[assetID])
	}
	sort.Sort(ByDataAssetTitleSort(result))
	return result
}

func (model *Model) HighestIntegrity(what *TechnicalAsset) Criticality {
	highest := what.Integrity
	highestProcessed := model.HighestProcessedIntegrity(what)
	if highest < highestProcessed {
		highest = highestProcessed
	}

	highestStored := model.HighestStoredIntegrity(what)
	if highest < highestStored {
		highest = highestStored
	}

	return highest
}

func (model *Model) HighestProcessedIntegrity(what *TechnicalAsset) Criticality {
	highest := what.Integrity
	for _, dataId := range what.DataAssetsProcessed {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	return highest
}

func (model *Model) HighestStoredIntegrity(what *TechnicalAsset) Criticality {
	highest := what.Integrity
	for _, dataId := range what.DataAssetsStored {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Integrity > highest {
			highest = dataAsset.Integrity
		}
	}
	return highest
}

func (model *Model) HighestAvailability(what *TechnicalAsset) Criticality {
	highest := what.Availability
	highestProcessed := model.HighestProcessedAvailability(what)
	if highest < highestProcessed {
		highest = highestProcessed
	}

	highestStored := model.HighestStoredAvailability(what)
	if highest < highestStored {
		highest = highestStored
	}

	return highest
}

func (model *Model) HighestProcessedAvailability(what *TechnicalAsset) Criticality {
	highest := what.Availability
	for _, dataId := range what.DataAssetsProcessed {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	return highest
}

func (model *Model) HighestStoredAvailability(what *TechnicalAsset) Criticality {
	highest := what.Availability
	for _, dataId := range what.DataAssetsStored {
		dataAsset := model.DataAssets[dataId]
		if dataAsset.Availability > highest {
			highest = dataAsset.Availability
		}
	}
	return highest
}

func (model *Model) HasDirectConnection(what *TechnicalAsset, otherAssetId string) bool {
	for _, dataFlow := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[what.Id] {
		if dataFlow.SourceId == otherAssetId {
			return true
		}
	}
	// check both directions, hence two times, just reversed
	for _, dataFlow := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[otherAssetId] {
		if dataFlow.SourceId == what.Id {
			return true
		}
	}
	return false
}

func (model *Model) GeneratedRisks(what *TechnicalAsset) []*Risk {
	resultingRisks := make([]*Risk, 0)
	if len(model.SortedRiskCategories()) == 0 {
		fmt.Println("Uh, strange, no risks generated (yet?) and asking for them by tech asset...")
	}
	for _, category := range model.SortedRiskCategories() {
		risks := model.SortedRisksOfCategory(category)
		for _, risk := range risks {
			if risk.MostRelevantTechnicalAssetId == what.Id {
				resultingRisks = append(resultingRisks, risk)
			}
		}
	}
	SortByRiskSeverity(resultingRisks)
	return resultingRisks
}

func (model *Model) GetRiskTracking(what *Risk) *RiskTracking { // TODO: Unify function naming regarding Get etc.
	if riskTracking, ok := model.RiskTracking[what.SyntheticId]; ok {
		return riskTracking
	}
	return nil
}

func (model *Model) GetRiskTrackingWithDefault(what *Risk) RiskTracking { // TODO: Unify function naming regarding Get etc.
	if riskTracking, ok := model.RiskTracking[what.SyntheticId]; ok {
		return *riskTracking
	}
	return RiskTracking{}
}

func (model *Model) IsRiskTracked(what *Risk) bool {
	if _, ok := model.RiskTracking[what.SyntheticId]; ok {
		return true
	}
	return false
}

func (model *Model) GeneratedRisksByCategoryWithCurrentStatus() map[string][]*Risk {
	generatedRisksByCategoryWithCurrentStatus := model.GeneratedRisksByCategory
	for catId, risks := range generatedRisksByCategoryWithCurrentStatus {
		for idx, risk := range risks {
			riskTracked, ok := model.RiskTracking[risk.SyntheticId]
			if ok {
				generatedRisksByCategoryWithCurrentStatus[catId][idx].RiskStatus = riskTracked.Status
			}
		}
	}
	return generatedRisksByCategoryWithCurrentStatus
}

func (model *Model) GetMapOfDASentByTechnicalAsset() map[string]map[string]bool {
	daSent := make(map[string]map[string]bool)
	for _, ta := range model.TechnicalAssets {
		daSent[ta.Id] = make(map[string]bool)
	}

	for _, ta := range model.TechnicalAssets {
		for _, c := range ta.CommunicationLinks {
			daSent[c.SourceId] = addDAToMap(daSent[c.SourceId], c.DataAssetsSent)
			daSent[c.TargetId] = addDAToMap(daSent[c.TargetId], c.DataAssetsReceived)
		}
	}
	return daSent
}

func (model *Model) GetPI(setDA []string) []string {
	listDIs := []string{}
	for _, daID := range setDA {
		daObj := model.DataAssets[daID]
		if daObj.PINameType.IsPI() {
			listDIs = append(listDIs, daObj.Id)
		}
	}
	return listDIs
}

/*
Return a global map of data assets received by each technical asset. Technical asset ID is the key.
The value is a map of data asset IDs received by the technical asset.
*/
func (model *Model) GetDARecvd() map[string]map[string]bool {
	daRecvd := make(map[string]map[string]bool)
	for _, ta := range model.TechnicalAssets {
		daRecvd[ta.Id] = make(map[string]bool)
	}

	for _, ta := range model.TechnicalAssets {
		for _, c := range ta.CommunicationLinks {
			daRecvd[c.TargetId] = addDAToMap(daRecvd[c.TargetId], c.DataAssetsSent)
			daRecvd[c.SourceId] = addDAToMap(daRecvd[c.SourceId], c.DataAssetsReceived)
		}
	}
	return daRecvd
}

func (what *Model) IsSameTrustBoundary(taID string, otherAssetId string) bool {
	trustBoundaryOfMyAsset := what.DirectContainingTrustBoundaryMappedByTechnicalAssetId[taID]
	trustBoundaryOfOtherAsset := what.DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	if trustBoundaryOfMyAsset == nil || trustBoundaryOfOtherAsset == nil {
		return false
	}
	return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
}
