/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package input

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/mpvl/unique"

	"gopkg.in/yaml.v3"
)

// === Model Type Stuff ======================================

type Model struct { // TODO: Eventually remove this and directly use ParsedModelRoot? But then the error messages for model errors are not quite as good anymore...
	ThreagileVersion                              string                            `yaml:"threagile_version,omitempty" json:"threagile_version,omitempty"`
	Includes                                      []string                          `yaml:"includes,omitempty" json:"includes,omitempty"`
	Title                                         string                            `yaml:"title,omitempty" json:"title,omitempty"`
	Author                                        Author                            `yaml:"author,omitempty" json:"author,omitempty"`
	Contributors                                  []Author                          `yaml:"contributors,omitempty" json:"contributors,omitempty"`
	Date                                          string                            `yaml:"date,omitempty" json:"date,omitempty"`
	AppDescription                                Overview                          `yaml:"application_description,omitempty" json:"application_description,omitempty"`
	BusinessOverview                              Overview                          `yaml:"business_overview,omitempty" json:"business_overview,omitempty"`
	TechnicalOverview                             Overview                          `yaml:"technical_overview,omitempty" json:"technical_overview,omitempty"`
	BusinessCriticality                           string                            `yaml:"business_criticality,omitempty" json:"business_criticality,omitempty"`
	ManagementSummaryComment                      string                            `yaml:"management_summary_comment,omitempty" json:"management_summary_comment,omitempty"`
	SecurityRequirements                          map[string]string                 `yaml:"security_requirements,omitempty" json:"security_requirements,omitempty"`
	Questions                                     map[string]string                 `yaml:"questions,omitempty" json:"questions,omitempty"`
	AbuseCases                                    map[string]string                 `yaml:"abuse_cases,omitempty" json:"abuse_cases,omitempty"`
	TagsAvailable                                 []string                          `yaml:"tags_available,omitempty" json:"tags_available,omitempty"`
	DataAssets                                    map[string]DataAsset              `yaml:"data_assets,omitempty" json:"data_assets,omitempty"`
	TechnicalAssets                               map[string]TechnicalAsset         `yaml:"technical_assets,omitempty" json:"technical_assets,omitempty"`
	TrustBoundaries                               map[string]TrustBoundary          `yaml:"trust_boundaries,omitempty" json:"trust_boundaries,omitempty"`
	SharedRuntimes                                map[string]SharedRuntime          `yaml:"shared_runtimes,omitempty" json:"shared_runtimes,omitempty"`
	IndividualRiskCategories                      map[string]IndividualRiskCategory `yaml:"individual_risk_categories,omitempty" json:"individual_risk_categories,omitempty"`
	RiskTracking                                  map[string]RiskTracking           `yaml:"risk_tracking,omitempty" json:"risk_tracking,omitempty"`
	DiagramTweakNodesep                           int                               `yaml:"diagram_tweak_nodesep,omitempty" json:"diagram_tweak_nodesep,omitempty"`
	DiagramTweakRanksep                           int                               `yaml:"diagram_tweak_ranksep,omitempty" json:"diagram_tweak_ranksep,omitempty"`
	DiagramTweakEdgeLayout                        string                            `yaml:"diagram_tweak_edge_layout,omitempty" json:"diagram_tweak_edge_layout,omitempty"`
	DiagramTweakSuppressEdgeLabels                bool                              `yaml:"diagram_tweak_suppress_edge_labels,omitempty" json:"diagram_tweak_suppress_edge_labels,omitempty"`
	DiagramTweakLayoutLeftToRight                 bool                              `yaml:"diagram_tweak_layout_left_to_right,omitempty" json:"diagram_tweak_layout_left_to_right,omitempty"`
	DiagramTweakInvisibleConnectionsBetweenAssets []string                          `yaml:"diagram_tweak_invisible_connections_between_assets,omitempty" json:"diagram_tweak_invisible_connections_between_assets,omitempty"`
	DiagramTweakSameRankAssets                    []string                          `yaml:"diagram_tweak_same_rank_assets,omitempty" json:"diagram_tweak_same_rank_assets,omitempty"`
}

func (model *Model) Defaults() *Model {
	*model = Model{
		Questions:                make(map[string]string),
		AbuseCases:               make(map[string]string),
		SecurityRequirements:     make(map[string]string),
		DataAssets:               make(map[string]DataAsset),
		TechnicalAssets:          make(map[string]TechnicalAsset),
		TrustBoundaries:          make(map[string]TrustBoundary),
		SharedRuntimes:           make(map[string]SharedRuntime),
		IndividualRiskCategories: make(map[string]IndividualRiskCategory),
		RiskTracking:             make(map[string]RiskTracking),
	}

	return model
}

func (model *Model) Load(inputFilename string) error {
	modelYaml, readError := os.ReadFile(filepath.Clean(inputFilename))
	if readError != nil {
		log.Fatal("Unable to read model file: ", readError)
	}

	unmarshalError := yaml.Unmarshal(modelYaml, &model)
	if unmarshalError != nil {
		log.Fatal("Unable to parse model yaml: ", unmarshalError)
	}

	for _, includeFile := range model.Includes {
		mergeError := model.Merge(filepath.Dir(inputFilename), includeFile)
		if mergeError != nil {
			log.Fatalf("Unable to merge model include %q: %v", includeFile, mergeError)
		}
	}

	return nil
}

func (model *Model) Merge(dir string, includeFilename string) error {
	modelYaml, readError := os.ReadFile(filepath.Clean(filepath.Join(dir, includeFilename)))
	if readError != nil {
		return fmt.Errorf("unable to read model file: %v", readError)
	}

	var fileStructure map[string]any
	unmarshalStructureError := yaml.Unmarshal(modelYaml, &fileStructure)
	if unmarshalStructureError != nil {
		return fmt.Errorf("unable to parse model structure: %v", unmarshalStructureError)
	}

	var includedModel Model
	unmarshalError := yaml.Unmarshal(modelYaml, &includedModel)
	if unmarshalError != nil {
		return fmt.Errorf("unable to parse model yaml: %v", unmarshalError)
	}

	var mergeError error
	for item := range fileStructure {
		switch strings.ToLower(item) {
		case strings.ToLower("includes"):
			for _, includeFile := range includedModel.Includes {
				mergeError = model.Merge(filepath.Join(dir, filepath.Dir(includeFilename)), includeFile)
				if mergeError != nil {
					return fmt.Errorf("failed to merge model include %q: %v", includeFile, mergeError)
				}
			}

		case strings.ToLower("threagile_version"):
			model.ThreagileVersion, mergeError = new(Strings).MergeSingleton(model.ThreagileVersion, includedModel.ThreagileVersion)
			if mergeError != nil {
				return fmt.Errorf("failed to merge threagile version: %v", mergeError)
			}

		case strings.ToLower("title"):
			model.Title, mergeError = new(Strings).MergeSingleton(model.Title, includedModel.Title)
			if mergeError != nil {
				return fmt.Errorf("failed to merge title: %v", mergeError)
			}

		case strings.ToLower("author"):
			mergeError = model.Author.Merge(includedModel.Author)
			if mergeError != nil {
				return fmt.Errorf("failed to merge author: %v", mergeError)
			}

		case strings.ToLower("contributors"):
			model.Contributors, mergeError = new(Author).MergeList(append(model.Contributors, includedModel.Author))
			if mergeError != nil {
				return fmt.Errorf("failed to merge contributors: %v", mergeError)
			}

		case strings.ToLower("date"):
			model.Date, mergeError = new(Strings).MergeSingleton(model.Date, includedModel.Date)
			if mergeError != nil {
				return fmt.Errorf("failed to merge date: %v", mergeError)
			}

		case strings.ToLower("application_description"):
			mergeError = model.AppDescription.Merge(includedModel.AppDescription)
			if mergeError != nil {
				return fmt.Errorf("failed to merge application description: %v", mergeError)
			}

		case strings.ToLower("business_overview"):
			mergeError = model.BusinessOverview.Merge(includedModel.BusinessOverview)
			if mergeError != nil {
				return fmt.Errorf("failed to merge business overview: %v", mergeError)
			}

		case strings.ToLower("technical_overview"):
			mergeError = model.TechnicalOverview.Merge(includedModel.TechnicalOverview)
			if mergeError != nil {
				return fmt.Errorf("failed to merge technical overview: %v", mergeError)
			}

		case strings.ToLower("business_criticality"):
			model.BusinessCriticality, mergeError = new(Strings).MergeSingleton(model.BusinessCriticality, includedModel.BusinessCriticality)
			if mergeError != nil {
				return fmt.Errorf("failed to merge business criticality: %v", mergeError)
			}

		case strings.ToLower("management_summary_comment"):
			model.ManagementSummaryComment = new(Strings).MergeMultiline(model.ManagementSummaryComment, includedModel.ManagementSummaryComment)

		case strings.ToLower("security_requirements"):
			model.SecurityRequirements, mergeError = new(Strings).MergeMap(model.SecurityRequirements, includedModel.SecurityRequirements)
			if mergeError != nil {
				return fmt.Errorf("failed to merge security requirements: %v", mergeError)
			}

		case strings.ToLower("questions"):
			model.Questions, mergeError = new(Strings).MergeMap(model.Questions, includedModel.Questions)
			if mergeError != nil {
				return fmt.Errorf("failed to merge questions: %v", mergeError)
			}

		case strings.ToLower("abuse_cases"):
			model.AbuseCases, mergeError = new(Strings).MergeMap(model.AbuseCases, includedModel.AbuseCases)
			if mergeError != nil {
				return fmt.Errorf("failed to merge abuse cases: %v", mergeError)
			}

		case strings.ToLower("tags_available"):
			model.TagsAvailable = new(Strings).MergeUniqueSlice(model.TagsAvailable, includedModel.TagsAvailable)

		case strings.ToLower("data_assets"):
			model.DataAssets, mergeError = new(DataAsset).MergeMap(model.DataAssets, includedModel.DataAssets)
			if mergeError != nil {
				return fmt.Errorf("failed to merge data assets: %v", mergeError)
			}

		case strings.ToLower("technical_assets"):
			model.TechnicalAssets, mergeError = new(TechnicalAsset).MergeMap(model.TechnicalAssets, includedModel.TechnicalAssets)
			if mergeError != nil {
				return fmt.Errorf("failed to merge technical assets: %v", mergeError)
			}

		case strings.ToLower("trust_boundaries"):
			model.TrustBoundaries, mergeError = new(TrustBoundary).MergeMap(model.TrustBoundaries, includedModel.TrustBoundaries)
			if mergeError != nil {
				return fmt.Errorf("failed to merge trust boundaries: %v", mergeError)
			}

		case strings.ToLower("shared_runtimes"):
			model.SharedRuntimes, mergeError = new(SharedRuntime).MergeMap(model.SharedRuntimes, includedModel.SharedRuntimes)
			if mergeError != nil {
				return fmt.Errorf("failed to merge shared runtimes: %v", mergeError)
			}

		case strings.ToLower("individual_risk_categories"):
			model.IndividualRiskCategories, mergeError = new(IndividualRiskCategory).MergeMap(model.IndividualRiskCategories, includedModel.IndividualRiskCategories)
			if mergeError != nil {
				return fmt.Errorf("failed to merge risk categories: %v", mergeError)
			}

		case strings.ToLower("risk_tracking"):
			model.RiskTracking, mergeError = new(RiskTracking).MergeMap(model.RiskTracking, includedModel.RiskTracking)
			if mergeError != nil {
				return fmt.Errorf("failed to merge risk tracking: %v", mergeError)
			}

		case "diagram_tweak_nodesep":
			model.DiagramTweakNodesep = includedModel.DiagramTweakNodesep

		case "diagram_tweak_ranksep":
			model.DiagramTweakRanksep = includedModel.DiagramTweakRanksep

		case "diagram_tweak_edge_layout":
			model.DiagramTweakEdgeLayout = includedModel.DiagramTweakEdgeLayout

		case "diagram_tweak_suppress_edge_labels":
			model.DiagramTweakSuppressEdgeLabels = includedModel.DiagramTweakSuppressEdgeLabels

		case "diagram_tweak_layout_left_to_right":
			model.DiagramTweakLayoutLeftToRight = includedModel.DiagramTweakLayoutLeftToRight

		case "diagram_tweak_invisible_connections_between_assets":
			model.DiagramTweakInvisibleConnectionsBetweenAssets = append(model.DiagramTweakInvisibleConnectionsBetweenAssets, includedModel.DiagramTweakInvisibleConnectionsBetweenAssets...)
			sort.Strings(model.DiagramTweakInvisibleConnectionsBetweenAssets)
			unique.Strings(&model.DiagramTweakInvisibleConnectionsBetweenAssets)

		case "diagram_tweak_same_rank_assets":
			model.DiagramTweakSameRankAssets = append(model.DiagramTweakSameRankAssets, includedModel.DiagramTweakSameRankAssets...)
			sort.Strings(model.DiagramTweakSameRankAssets)
			unique.Strings(&model.DiagramTweakSameRankAssets)
		}
	}

	return nil
}

func (model *Model) AddTagToModelInput(tag string, dryRun bool, changes *[]string) {
	tag = NormalizeTag(tag)

	if !slices.Contains(model.TagsAvailable, tag) {
		*changes = append(*changes, "adding tag: "+tag)
		if !dryRun {
			model.TagsAvailable = append(model.TagsAvailable, tag)
		}
	}
}

func NormalizeTag(tag string) string {
	return strings.TrimSpace(strings.ToLower(tag))
}
