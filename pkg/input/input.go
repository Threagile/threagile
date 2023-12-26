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
	Name     string `yaml:"name" json:"name"`
	Homepage string `yaml:"homepage" json:"homepage"`
}

type Overview struct {
	Description string              `yaml:"description" json:"description"`
	Images      []map[string]string `yaml:"images" json:"images"` // yes, array of map here, as array keeps the order of the image keys
}

type InputDataAsset struct {
	ID                     string   `yaml:"id" json:"id"`
	Description            string   `yaml:"description" json:"description"`
	Usage                  string   `yaml:"usage" json:"usage"`
	Tags                   []string `yaml:"tags" json:"tags"`
	Origin                 string   `yaml:"origin" json:"origin"`
	Owner                  string   `yaml:"owner" json:"owner"`
	Quantity               string   `yaml:"quantity" json:"quantity"`
	Confidentiality        string   `yaml:"confidentiality" json:"confidentiality"`
	Integrity              string   `yaml:"integrity" json:"integrity"`
	Availability           string   `yaml:"availability" json:"availability"`
	JustificationCiaRating string   `yaml:"justification_cia_rating" json:"justification_cia_rating"`
}

type InputTechnicalAsset struct {
	ID                      string                            `yaml:"id" json:"id"`
	Description             string                            `yaml:"description" json:"description"`
	Type                    string                            `yaml:"type" json:"type"`
	Usage                   string                            `yaml:"usage" json:"usage"`
	UsedAsClientByHuman     bool                              `yaml:"used_as_client_by_human" json:"used_as_client_by_human"`
	OutOfScope              bool                              `yaml:"out_of_scope" json:"out_of_scope"`
	JustificationOutOfScope string                            `yaml:"justification_out_of_scope" json:"justification_out_of_scope"`
	Size                    string                            `yaml:"size" json:"size"`
	Technology              string                            `yaml:"technology" json:"technology"`
	Tags                    []string                          `yaml:"tags" json:"tags"`
	Internet                bool                              `yaml:"internet" json:"internet"`
	Machine                 string                            `yaml:"machine" json:"machine"`
	Encryption              string                            `yaml:"encryption" json:"encryption"`
	Owner                   string                            `yaml:"owner" json:"owner"`
	Confidentiality         string                            `yaml:"confidentiality" json:"confidentiality"`
	Integrity               string                            `yaml:"integrity" json:"integrity"`
	Availability            string                            `yaml:"availability" json:"availability"`
	JustificationCiaRating  string                            `yaml:"justification_cia_rating" json:"justification_cia_rating"`
	MultiTenant             bool                              `yaml:"multi_tenant" json:"multi_tenant"`
	Redundant               bool                              `yaml:"redundant" json:"redundant"`
	CustomDevelopedParts    bool                              `yaml:"custom_developed_parts" json:"custom_developed_parts"`
	DataAssetsProcessed     []string                          `yaml:"data_assets_processed" json:"data_assets_processed"`
	DataAssetsStored        []string                          `yaml:"data_assets_stored" json:"data_assets_stored"`
	DataFormatsAccepted     []string                          `yaml:"data_formats_accepted" json:"data_formats_accepted"`
	DiagramTweakOrder       int                               `yaml:"diagram_tweak_order" json:"diagram_tweak_order"`
	CommunicationLinks      map[string]InputCommunicationLink `yaml:"communication_links" json:"communication_links"`
}

type InputCommunicationLink struct {
	Target                 string   `yaml:"target" json:"target"`
	Description            string   `yaml:"description" json:"description"`
	Protocol               string   `yaml:"protocol" json:"protocol"`
	Authentication         string   `yaml:"authentication" json:"authentication"`
	Authorization          string   `yaml:"authorization" json:"authorization"`
	Tags                   []string `yaml:"tags" json:"tags"`
	VPN                    bool     `yaml:"vpn" json:"vpn"`
	IpFiltered             bool     `yaml:"ip_filtered" json:"ip_filtered"`
	Readonly               bool     `yaml:"readonly" json:"readonly"`
	Usage                  string   `yaml:"usage" json:"usage"`
	DataAssetsSent         []string `yaml:"data_assets_sent" json:"data_assets_sent"`
	DataAssetsReceived     []string `yaml:"data_assets_received" json:"data_assets_received"`
	DiagramTweakWeight     int      `yaml:"diagram_tweak_weight" json:"diagram_tweak_weight"`
	DiagramTweakConstraint bool     `yaml:"diagram_tweak_constraint" json:"diagram_tweak_constraint"`
}

type InputSharedRuntime struct {
	ID                     string   `yaml:"id" json:"id"`
	Description            string   `yaml:"description" json:"description"`
	Tags                   []string `yaml:"tags" json:"tags"`
	TechnicalAssetsRunning []string `yaml:"technical_assets_running" json:"technical_assets_running"`
}

type InputTrustBoundary struct {
	ID                    string   `yaml:"id" json:"id"`
	Description           string   `yaml:"description" json:"description"`
	Type                  string   `yaml:"type" json:"type"`
	Tags                  []string `yaml:"tags" json:"tags"`
	TechnicalAssetsInside []string `yaml:"technical_assets_inside" json:"technical_assets_inside"`
	TrustBoundariesNested []string `yaml:"trust_boundaries_nested" json:"trust_boundaries_nested"`
}

type InputIndividualRiskCategory struct {
	ID                         string                         `yaml:"id" json:"id"`
	Description                string                         `yaml:"description" json:"description"`
	Impact                     string                         `yaml:"impact" json:"impact"`
	ASVS                       string                         `yaml:"asvs" json:"asvs"`
	CheatSheet                 string                         `yaml:"cheat_sheet" json:"cheat_sheet"`
	Action                     string                         `yaml:"action" json:"action"`
	Mitigation                 string                         `yaml:"mitigation" json:"mitigation"`
	Check                      string                         `yaml:"check" json:"check"`
	Function                   string                         `yaml:"function" json:"function"`
	STRIDE                     string                         `yaml:"stride" json:"stride"`
	DetectionLogic             string                         `yaml:"detection_logic" json:"detection_logic"`
	RiskAssessment             string                         `yaml:"risk_assessment" json:"risk_assessment"`
	FalsePositives             string                         `yaml:"false_positives" json:"false_positives"`
	ModelFailurePossibleReason bool                           `yaml:"model_failure_possible_reason" json:"model_failure_possible_reason"`
	CWE                        int                            `yaml:"cwe" json:"cwe"`
	RisksIdentified            map[string]InputRiskIdentified `yaml:"risks_identified" json:"risks_identified"`
}

type InputRiskIdentified struct {
	Severity                      string   `yaml:"severity" json:"severity"`
	ExploitationLikelihood        string   `yaml:"exploitation_likelihood" json:"exploitation_likelihood"`
	ExploitationImpact            string   `yaml:"exploitation_impact" json:"exploitation_impact"`
	DataBreachProbability         string   `yaml:"data_breach_probability" json:"data_breach_probability"`
	DataBreachTechnicalAssets     []string `yaml:"data_breach_technical_assets" json:"data_breach_technical_assets"`
	MostRelevantDataAsset         string   `yaml:"most_relevant_data_asset" json:"most_relevant_data_asset"`
	MostRelevantTechnicalAsset    string   `yaml:"most_relevant_technical_asset" json:"most_relevant_technical_asset"`
	MostRelevantCommunicationLink string   `yaml:"most_relevant_communication_link" json:"most_relevant_communication_link"`
	MostRelevantTrustBoundary     string   `yaml:"most_relevant_trust_boundary" json:"most_relevant_trust_boundary"`
	MostRelevantSharedRuntime     string   `yaml:"most_relevant_shared_runtime" json:"most_relevant_shared_runtime"`
}

type InputRiskTracking struct {
	Status        string `yaml:"status" json:"status"`
	Justification string `yaml:"justification" json:"justification"`
	Ticket        string `yaml:"ticket" json:"ticket"`
	Date          string `yaml:"date" json:"date"`
	CheckedBy     string `yaml:"checked_by" json:"checked_by"`
}

type ModelInput struct { // TODO: Eventually remove this and directly use ParsedModelRoot? But then the error messages for model errors are not quite as good anymore...
	Includes                                      []string                               `yaml:"includes,omitempty" json:"includes,omitempty"`
	ThreagileVersion                              string                                 `yaml:"threagile_version" json:"threagile_version"`
	Title                                         string                                 `yaml:"title" json:"title"`
	Author                                        Author                                 `yaml:"author" json:"author"`
	Date                                          string                                 `yaml:"date" json:"date"`
	BusinessOverview                              Overview                               `yaml:"business_overview" json:"business_overview"`
	TechnicalOverview                             Overview                               `yaml:"technical_overview" json:"technical_overview"`
	BusinessCriticality                           string                                 `yaml:"business_criticality" json:"business_criticality"`
	ManagementSummaryComment                      string                                 `yaml:"management_summary_comment" json:"management_summary_comment"`
	Questions                                     map[string]string                      `yaml:"questions" json:"questions"`
	AbuseCases                                    map[string]string                      `yaml:"abuse_cases" json:"abuse_cases"`
	SecurityRequirements                          map[string]string                      `yaml:"security_requirements" json:"security_requirements"`
	TagsAvailable                                 []string                               `yaml:"tags_available,omitempty" json:"tags_available,omitempty"`
	DataAssets                                    map[string]InputDataAsset              `yaml:"data_assets" json:"data_assets"`
	TechnicalAssets                               map[string]InputTechnicalAsset         `yaml:"technical_assets" json:"technical_assets"`
	TrustBoundaries                               map[string]InputTrustBoundary          `yaml:"trust_boundaries" json:"trust_boundaries"`
	SharedRuntimes                                map[string]InputSharedRuntime          `yaml:"shared_runtimes" json:"shared_runtimes"`
	IndividualRiskCategories                      map[string]InputIndividualRiskCategory `yaml:"individual_risk_categories" json:"individual_risk_categories"`
	RiskTracking                                  map[string]InputRiskTracking           `yaml:"risk_tracking" json:"risk_tracking"`
	DiagramTweakNodesep                           int                                    `yaml:"diagram_tweak_nodesep" json:"diagram_tweak_nodesep"`
	DiagramTweakRanksep                           int                                    `yaml:"diagram_tweak_ranksep" json:"diagram_tweak_ranksep"`
	DiagramTweakEdgeLayout                        string                                 `yaml:"diagram_tweak_edge_layout" json:"diagram_tweak_edge_layout"`
	DiagramTweakSuppressEdgeLabels                bool                                   `yaml:"diagram_tweak_suppress_edge_labels" json:"diagram_tweak_suppress_edge_labels"`
	DiagramTweakLayoutLeftToRight                 bool                                   `yaml:"diagram_tweak_layout_left_to_right" json:"diagram_tweak_layout_left_to_right"`
	DiagramTweakInvisibleConnectionsBetweenAssets []string                               `yaml:"diagram_tweak_invisible_connections_between_assets,omitempty" json:"diagram_tweak_invisible_connections_between_assets,omitempty"`
	DiagramTweakSameRankAssets                    []string                               `yaml:"diagram_tweak_same_rank_assets,omitempty" json:"diagram_tweak_same_rank_assets,omitempty"`
}

func (model *ModelInput) Defaults() *ModelInput {
	*model = ModelInput{
		Questions:                make(map[string]string),
		AbuseCases:               make(map[string]string),
		SecurityRequirements:     make(map[string]string),
		DataAssets:               make(map[string]InputDataAsset),
		TechnicalAssets:          make(map[string]InputTechnicalAsset),
		TrustBoundaries:          make(map[string]InputTrustBoundary),
		SharedRuntimes:           make(map[string]InputSharedRuntime),
		IndividualRiskCategories: make(map[string]InputIndividualRiskCategory),
		RiskTracking:             make(map[string]InputRiskTracking),
	}

	return model
}

func (model *ModelInput) Load(inputFilename string) error {
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

func (model *ModelInput) Merge(dir string, includeFilename string) error {
	modelYaml, readError := os.ReadFile(filepath.Join(dir, includeFilename))
	if readError != nil {
		return fmt.Errorf("unable to read model file: %v", readError)
	}

	var fileStructure map[string]any
	unmarshalStructureError := yaml.Unmarshal(modelYaml, &fileStructure)
	if unmarshalStructureError != nil {
		return fmt.Errorf("unable to parse model structure: %v", unmarshalStructureError)
	}

	var includedModel ModelInput
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

func AddTagToModelInput(modelInput *ModelInput, tag string, dryRun bool, changes *[]string) {
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
