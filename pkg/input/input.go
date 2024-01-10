/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package input

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// === Model Type Stuff ======================================

type Author struct {
	Name     string `yaml:"name,omitempty" json:"name,omitempty"`
	Contact  string `yaml:"contact,omitempty" json:"contact,omitempty"`
	Homepage string `yaml:"homepage,omitempty" json:"homepage,omitempty"`
}

type Overview struct {
	Description string              `yaml:"description,omitempty" json:"description,omitempty"`
	Images      []map[string]string `yaml:"images,omitempty" json:"images,omitempty"` // yes, array of map here, as array keeps the order of the image keys
}

type DataAsset struct {
	ID                     string   `yaml:"id,omitempty" json:"id,omitempty"`
	Description            string   `yaml:"description,omitempty" json:"description,omitempty"`
	Usage                  string   `yaml:"usage,omitempty" json:"usage,omitempty"`
	Tags                   []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Origin                 string   `yaml:"origin,omitempty" json:"origin,omitempty"`
	Owner                  string   `yaml:"owner,omitempty" json:"owner,omitempty"`
	Quantity               string   `yaml:"quantity,omitempty" json:"quantity,omitempty"`
	Confidentiality        string   `yaml:"confidentiality,omitempty" json:"confidentiality,omitempty"`
	Integrity              string   `yaml:"integrity,omitempty" json:"integrity,omitempty"`
	Availability           string   `yaml:"availability,omitempty" json:"availability,omitempty"`
	JustificationCiaRating string   `yaml:"justification_cia_rating,omitempty" json:"justification_cia_rating,omitempty"`
}

type TechnicalAsset struct {
	ID                      string                       `yaml:"id,omitempty" json:"id,omitempty"`
	Description             string                       `yaml:"description,omitempty" json:"description,omitempty"`
	Type                    string                       `yaml:"type,omitempty" json:"type,omitempty"`
	Usage                   string                       `yaml:"usage,omitempty" json:"usage,omitempty"`
	UsedAsClientByHuman     bool                         `yaml:"used_as_client_by_human,omitempty" json:"used_as_client_by_human,omitempty"`
	OutOfScope              bool                         `yaml:"out_of_scope,omitempty" json:"out_of_scope,omitempty"`
	JustificationOutOfScope string                       `yaml:"justification_out_of_scope,omitempty" json:"justification_out_of_scope,omitempty"`
	Size                    string                       `yaml:"size,omitempty" json:"size,omitempty"`
	Technology              string                       `yaml:"technology,omitempty" json:"technology,omitempty"`
	Tags                    []string                     `yaml:"tags,omitempty" json:"tags,omitempty"`
	Internet                bool                         `yaml:"internet,omitempty" json:"internet,omitempty"`
	Machine                 string                       `yaml:"machine,omitempty" json:"machine,omitempty"`
	Encryption              string                       `yaml:"encryption,omitempty" json:"encryption,omitempty"`
	Owner                   string                       `yaml:"owner,omitempty" json:"owner,omitempty"`
	Confidentiality         string                       `yaml:"confidentiality,omitempty" json:"confidentiality,omitempty"`
	Integrity               string                       `yaml:"integrity,omitempty" json:"integrity,omitempty"`
	Availability            string                       `yaml:"availability,omitempty" json:"availability,omitempty"`
	JustificationCiaRating  string                       `yaml:"justification_cia_rating,omitempty" json:"justification_cia_rating,omitempty"`
	MultiTenant             bool                         `yaml:"multi_tenant,omitempty" json:"multi_tenant,omitempty"`
	Redundant               bool                         `yaml:"redundant,omitempty" json:"redundant,omitempty"`
	CustomDevelopedParts    bool                         `yaml:"custom_developed_parts,omitempty" json:"custom_developed_parts,omitempty"`
	DataAssetsProcessed     []string                     `yaml:"data_assets_processed,omitempty" json:"data_assets_processed,omitempty"`
	DataAssetsStored        []string                     `yaml:"data_assets_stored,omitempty" json:"data_assets_stored,omitempty"`
	DataFormatsAccepted     []string                     `yaml:"data_formats_accepted,omitempty" json:"data_formats_accepted,omitempty"`
	DiagramTweakOrder       int                          `yaml:"diagram_tweak_order,omitempty" json:"diagram_tweak_order,omitempty"`
	CommunicationLinks      map[string]CommunicationLink `yaml:"communication_links,omitempty" json:"communication_links,omitempty"`
}

type CommunicationLink struct {
	Target                 string   `yaml:"target,omitempty" json:"target,omitempty"`
	Description            string   `yaml:"description,omitempty" json:"description,omitempty"`
	Protocol               string   `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	Authentication         string   `yaml:"authentication,omitempty" json:"authentication,omitempty"`
	Authorization          string   `yaml:"authorization,omitempty" json:"authorization,omitempty"`
	Tags                   []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	VPN                    bool     `yaml:"vpn,omitempty" json:"vpn,omitempty"`
	IpFiltered             bool     `yaml:"ip_filtered,omitempty" json:"ip_filtered,omitempty"`
	Readonly               bool     `yaml:"readonly,omitempty" json:"readonly,omitempty"`
	Usage                  string   `yaml:"usage,omitempty" json:"usage,omitempty"`
	DataAssetsSent         []string `yaml:"data_assets_sent,omitempty" json:"data_assets_sent,omitempty"`
	DataAssetsReceived     []string `yaml:"data_assets_received,omitempty" json:"data_assets_received,omitempty"`
	DiagramTweakWeight     int      `yaml:"diagram_tweak_weight,omitempty" json:"diagram_tweak_weight,omitempty"`
	DiagramTweakConstraint bool     `yaml:"diagram_tweak_constraint,omitempty" json:"diagram_tweak_constraint,omitempty"`
}

type SharedRuntime struct {
	ID                     string   `yaml:"id,omitempty" json:"id,omitempty"`
	Description            string   `yaml:"description,omitempty" json:"description,omitempty"`
	Tags                   []string `yaml:"tags,omitempty" json:"tag,omitemptys"`
	TechnicalAssetsRunning []string `yaml:"technical_assets_running,omitempty" json:"technical_assets_running,omitempty"`
}

type TrustBoundary struct {
	ID                    string   `yaml:"id,omitempty" json:"id,omitempty"`
	Description           string   `yaml:"description,omitempty" json:"description,omitempty"`
	Type                  string   `yaml:"type,omitempty" json:"type,omitempty"`
	Tags                  []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	TechnicalAssetsInside []string `yaml:"technical_assets_inside,omitempty" json:"technical_assets_inside,omitempty"`
	TrustBoundariesNested []string `yaml:"trust_boundaries_nested,omitempty" json:"trust_boundaries_nested,omitempty"`
}

type IndividualRiskCategory struct {
	ID                         string                    `yaml:"id,omitempty" json:"id,omitempty"`
	Description                string                    `yaml:"description,omitempty" json:"description,omitempty"`
	Impact                     string                    `yaml:"impact,omitempty" json:"impact,omitempty"`
	ASVS                       string                    `yaml:"asvs,omitempty" json:"asvs,omitempty"`
	CheatSheet                 string                    `yaml:"cheat_sheet,omitempty" json:"cheat_sheet,omitempty"`
	Action                     string                    `yaml:"action,omitempty" json:"action,omitempty"`
	Mitigation                 string                    `yaml:"mitigation,omitempty" json:"mitigation,omitempty"`
	Check                      string                    `yaml:"check,omitempty" json:"check,omitempty"`
	Function                   string                    `yaml:"function,omitempty" json:"function,omitempty"`
	STRIDE                     string                    `yaml:"stride,omitempty" json:"stride,omitempty"`
	DetectionLogic             string                    `yaml:"detection_logic,omitempty" json:"detection_logic,omitempty"`
	RiskAssessment             string                    `yaml:"risk_assessment,omitempty" json:"risk_assessment,omitempty"`
	FalsePositives             string                    `yaml:"false_positives,omitempty" json:"false_positives,omitempty"`
	ModelFailurePossibleReason bool                      `yaml:"model_failure_possible_reason,omitempty" json:"model_failure_possible_reason,omitempty"`
	CWE                        int                       `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	RisksIdentified            map[string]RiskIdentified `yaml:"risks_identified,omitempty" json:"risks_identified,omitempty"`
}

type RiskIdentified struct {
	Severity                      string   `yaml:"severity,omitempty" json:"severity,omitempty"`
	ExploitationLikelihood        string   `yaml:"exploitation_likelihood,omitempty" json:"exploitation_likelihood,omitempty"`
	ExploitationImpact            string   `yaml:"exploitation_impact,omitempty" json:"exploitation_impact,omitempty"`
	DataBreachProbability         string   `yaml:"data_breach_probability,omitempty" json:"data_breach_probability,omitempty"`
	DataBreachTechnicalAssets     []string `yaml:"data_breach_technical_assets,omitempty" json:"data_breach_technical_assets,omitempty"`
	MostRelevantDataAsset         string   `yaml:"most_relevant_data_asset,omitempty" json:"most_relevant_data_asset,omitempty"`
	MostRelevantTechnicalAsset    string   `yaml:"most_relevant_technical_asset,omitempty" json:"most_relevant_technical_asset,omitempty"`
	MostRelevantCommunicationLink string   `yaml:"most_relevant_communication_link,omitempty" json:"most_relevant_communication_link,omitempty"`
	MostRelevantTrustBoundary     string   `yaml:"most_relevant_trust_boundary,omitempty" json:"most_relevant_trust_boundary,omitempty"`
	MostRelevantSharedRuntime     string   `yaml:"most_relevant_shared_runtime,omitempty" json:"most_relevant_shared_runtime,omitempty"`
}

type RiskTracking struct {
	Status        string `yaml:"status,omitempty" json:"status,omitempty"`
	Justification string `yaml:"justification,omitempty" json:"justification,omitempty"`
	Ticket        string `yaml:"ticket,omitempty" json:"ticket,omitempty"`
	Date          string `yaml:"date,omitempty" json:"date,omitempty"`
	CheckedBy     string `yaml:"checked_by,omitempty" json:"checked_by,omitempty"`
}

type Model struct { // TODO: Eventually remove this and directly use ParsedModelRoot? But then the error messages for model errors are not quite as good anymore...
	Includes                                      []string                          `yaml:"includes,omitempty" json:"includes,omitempty"`
	ThreagileVersion                              string                            `yaml:"threagile_version,omitempty" json:"threagile_version,omitempty"`
	Title                                         string                            `yaml:"title,omitempty" json:"title,omitempty"`
	Author                                        Author                            `yaml:"author,omitempty" json:"author,omitempty"`
	Contributors                                  []Author                          `yaml:"contributors,omitempty" json:"contributors,omitempty"`
	Date                                          string                            `yaml:"date,omitempty" json:"date,omitempty"`
	AppDescription                                Overview                          `yaml:"application_description,omitempty" json:"application_description,omitempty"`
	BusinessOverview                              Overview                          `yaml:"business_overview,omitempty" json:"business_overview,omitempty"`
	TechnicalOverview                             Overview                          `yaml:"technical_overview,omitempty" json:"technical_overview,omitempty"`
	BusinessCriticality                           string                            `yaml:"business_criticality,omitempty" json:"business_criticality,omitempty"`
	ManagementSummaryComment                      string                            `yaml:"management_summary_comment,omitempty" json:"management_summary_comment,omitempty"`
	Questions                                     map[string]string                 `yaml:"questions,omitempty" json:"questions,omitempty"`
	AbuseCases                                    map[string]string                 `yaml:"abuse_cases,omitempty" json:"abuse_cases,omitempty"`
	SecurityRequirements                          map[string]string                 `yaml:"security_requirements,omitempty" json:"security_requirements,omitempty"`
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
	modelYaml, readError := os.ReadFile(inputFilename)
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

type UniqueStringSlice []string

func (slice UniqueStringSlice) Merge(otherSlice []string) []string {
	valueMap := make(map[string]bool)
	for _, value := range slice {
		valueMap[value] = true
	}

	for _, value := range otherSlice {
		valueMap[value] = true
	}

	valueSlice := make(UniqueStringSlice, 0)
	for key := range valueMap {
		valueSlice = append(valueSlice, key)
	}

	return valueSlice
}

func (model *Model) Merge(dir string, includeFilename string) error {
	modelYaml, readError := os.ReadFile(filepath.Join(dir, includeFilename))
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

	for item := range fileStructure {
		switch strings.ToLower(item) {
		case strings.ToLower("includes"):
			for _, includeFile := range includedModel.Includes {
				mergeError := model.Merge(filepath.Join(dir, filepath.Dir(includeFilename)), includeFile)
				if mergeError != nil {
					return fmt.Errorf("unable to merge model include %q: %v", includeFile, mergeError)
				}
			}
			break

		case strings.ToLower("threagile_version"):
			model.ThreagileVersion = includedModel.ThreagileVersion
			break

		case strings.ToLower("title"):
			model.Title = includedModel.Title
			break

		case strings.ToLower("author"):
			model.Author = includedModel.Author
			break

		case strings.ToLower("date"):
			model.Date = includedModel.Date
			break

		case strings.ToLower("business_overview"):
			model.BusinessOverview = includedModel.BusinessOverview
			break

		case strings.ToLower("technical_overview"):
			model.TechnicalOverview = includedModel.TechnicalOverview
			break

		case strings.ToLower("business_criticality"):
			model.BusinessCriticality = includedModel.BusinessCriticality
			break

		case strings.ToLower("management_summary_comment"):
			model.ManagementSummaryComment = includedModel.ManagementSummaryComment
			break

		case strings.ToLower("questions"):
			for mapKey, mapValue := range includedModel.Questions {
				model.Questions[mapKey] = mapValue
			}
			break

		case strings.ToLower("abuse_cases"):
			for mapKey, mapValue := range includedModel.AbuseCases {
				model.AbuseCases[mapKey] = mapValue
			}
			break

		case strings.ToLower("security_requirements"):
			for mapKey, mapValue := range includedModel.SecurityRequirements {
				model.SecurityRequirements[mapKey] = mapValue
			}
			break

		case strings.ToLower("tags_available"):
			model.TagsAvailable = UniqueStringSlice(model.TagsAvailable).Merge(includedModel.TagsAvailable)
			break

		case strings.ToLower("data_assets"):
			for mapKey, mapValue := range includedModel.DataAssets {
				model.DataAssets[mapKey] = mapValue
			}
			break

		case strings.ToLower("technical_assets"):
			for mapKey, mapValue := range includedModel.TechnicalAssets {
				model.TechnicalAssets[mapKey] = mapValue
			}
			break

		case strings.ToLower("trust_boundaries"):
			for mapKey, mapValue := range includedModel.TrustBoundaries {
				model.TrustBoundaries[mapKey] = mapValue
			}
			break

		case strings.ToLower("shared_runtimes"):
			for mapKey, mapValue := range includedModel.SharedRuntimes {
				model.SharedRuntimes[mapKey] = mapValue
			}
			break

		case strings.ToLower("individual_risk_categories"):
			for mapKey, mapValue := range includedModel.IndividualRiskCategories {
				model.IndividualRiskCategories[mapKey] = mapValue
			}
			break

		case strings.ToLower("risk_tracking"):
			for mapKey, mapValue := range includedModel.RiskTracking {
				model.RiskTracking[mapKey] = mapValue
			}
			break

		case "diagram_tweak_nodesep":
			model.DiagramTweakNodesep = includedModel.DiagramTweakNodesep
			break

		case "diagram_tweak_ranksep":
			model.DiagramTweakRanksep = includedModel.DiagramTweakRanksep
			break

		case "diagram_tweak_edge_layout":
			model.DiagramTweakEdgeLayout = includedModel.DiagramTweakEdgeLayout
			break

		case "diagram_tweak_suppress_edge_labels":
			model.DiagramTweakSuppressEdgeLabels = includedModel.DiagramTweakSuppressEdgeLabels
			break

		case "diagram_tweak_layout_left_to_right":
			model.DiagramTweakLayoutLeftToRight = includedModel.DiagramTweakLayoutLeftToRight
			break

		case "diagram_tweak_invisible_connections_between_assets":
			model.DiagramTweakInvisibleConnectionsBetweenAssets = append(model.DiagramTweakInvisibleConnectionsBetweenAssets, includedModel.DiagramTweakInvisibleConnectionsBetweenAssets...)
			break

		case "diagram_tweak_same_rank_assets":
			model.DiagramTweakSameRankAssets = append(model.DiagramTweakSameRankAssets, includedModel.DiagramTweakSameRankAssets...)
		}
	}

	return nil
}

func AddTagToModelInput(modelInput *Model, tag string, dryRun bool, changes *[]string) {
	tag = NormalizeTag(tag)
	if !contains(modelInput.TagsAvailable, tag) {
		*changes = append(*changes, "adding tag: "+tag)
		if !dryRun {
			modelInput.TagsAvailable = append(modelInput.TagsAvailable, tag)
		}
	}
}

func NormalizeTag(tag string) string {
	return strings.TrimSpace(strings.ToLower(tag))
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}
