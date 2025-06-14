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

	"github.com/goccy/go-yaml"
)

// === Model Type Stuff ======================================

type Model struct { // TODO: Eventually remove this and directly use ParsedModelRoot? But then the error messages for model errors are not quite as good anymore...
	ThreagileVersion                              string                       `yaml:"threagile_version,omitempty" json:"threagile_version,omitempty"`
	SourceFile                                    string                       `yaml:"source-file,omitempty" json:"source-file,omitempty"`
	References                                    []string                     `yaml:"references,omitempty" json:"references,omitempty"`
	Includes                                      []string                     `yaml:"includes,omitempty" json:"includes,omitempty"`
	Title                                         string                       `yaml:"title,omitempty" json:"title,omitempty"`
	Author                                        Author                       `yaml:"author,omitempty" json:"author,omitempty"`
	Contributors                                  []Author                     `yaml:"contributors,omitempty" json:"contributors,omitempty"`
	Date                                          string                       `yaml:"date,omitempty" json:"date,omitempty"`
	AppDescription                                Overview                     `yaml:"application_description,omitempty" json:"application_description,omitempty"`
	BusinessOverview                              Overview                     `yaml:"business_overview,omitempty" json:"business_overview,omitempty"`
	TechnicalOverview                             Overview                     `yaml:"technical_overview,omitempty" json:"technical_overview,omitempty"`
	BusinessCriticality                           string                       `yaml:"business_criticality,omitempty" json:"business_criticality,omitempty"`
	ManagementSummaryComment                      string                       `yaml:"management_summary_comment,omitempty" json:"management_summary_comment,omitempty"`
	SecurityRequirements                          map[string]string            `yaml:"security_requirements,omitempty" json:"security_requirements,omitempty"`
	Questions                                     map[string]string            `yaml:"questions,omitempty" json:"questions,omitempty"`
	AbuseCases                                    map[string]string            `yaml:"abuse_cases,omitempty" json:"abuse_cases,omitempty"`
	TagsAvailable                                 []string                     `yaml:"tags_available,omitempty" json:"tags_available,omitempty"`
	DataAssets                                    map[string]DataAsset         `yaml:"data_assets,omitempty" json:"data_assets,omitempty"`
	TechnicalAssets                               map[string]TechnicalAsset    `yaml:"technical_assets,omitempty" json:"technical_assets,omitempty"`
	TrustBoundaries                               map[string]TrustBoundary     `yaml:"trust_boundaries,omitempty" json:"trust_boundaries,omitempty"`
	SharedRuntimes                                map[string]SharedRuntime     `yaml:"shared_runtimes,omitempty" json:"shared_runtimes,omitempty"`
	CommunicationLinks                            map[string]CommunicationLink `yaml:"communication_links,omitempty" json:"communication_links,omitempty"`
	CustomRiskCategories                          RiskCategories               `yaml:"custom_risk_categories,omitempty" json:"custom_risk_categories,omitempty"`
	RiskTracking                                  map[string]RiskTracking      `yaml:"risk_tracking,omitempty" json:"risk_tracking,omitempty"`
	DiagramTweakNodesep                           int                          `yaml:"diagram_tweak_nodesep,omitempty" json:"diagram_tweak_nodesep,omitempty"`
	DiagramTweakRanksep                           int                          `yaml:"diagram_tweak_ranksep,omitempty" json:"diagram_tweak_ranksep,omitempty"`
	DiagramTweakEdgeLayout                        string                       `yaml:"diagram_tweak_edge_layout,omitempty" json:"diagram_tweak_edge_layout,omitempty"`
	DiagramTweakSuppressEdgeLabels                bool                         `yaml:"diagram_tweak_suppress_edge_labels,omitempty" json:"diagram_tweak_suppress_edge_labels,omitempty"`
	DiagramTweakLayoutLeftToRight                 bool                         `yaml:"diagram_tweak_layout_left_to_right,omitempty" json:"diagram_tweak_layout_left_to_right,omitempty"`
	DiagramTweakInvisibleConnectionsBetweenAssets []string                     `yaml:"diagram_tweak_invisible_connections_between_assets,omitempty" json:"diagram_tweak_invisible_connections_between_assets,omitempty"`
	DiagramTweakSameRankAssets                    []string                     `yaml:"diagram_tweak_same_rank_assets,omitempty" json:"diagram_tweak_same_rank_assets,omitempty"`
}

func (model *Model) Defaults() *Model {
	*model = Model{
		Questions:            make(map[string]string),
		AbuseCases:           make(map[string]string),
		SecurityRequirements: make(map[string]string),
		DataAssets:           make(map[string]DataAsset),
		TechnicalAssets:      make(map[string]TechnicalAsset),
		TrustBoundaries:      make(map[string]TrustBoundary),
		SharedRuntimes:       make(map[string]SharedRuntime),
		CommunicationLinks:   make(map[string]CommunicationLink),
		CustomRiskCategories: make(RiskCategories, 0),
		RiskTracking:         make(map[string]RiskTracking),
	}

	return model
}

func (model *Model) Load(config configReader, inputFilename string) error {
	model.UpdateSourceFile(filepath.Clean(inputFilename))

	modelYaml, readError := os.ReadFile(model.SourceFile)
	if readError != nil {
		log.Fatal("Unable to read model file: ", readError)
	}

	unmarshalError := yaml.UnmarshalWithOptions(modelYaml, model, yaml.AllowDuplicateMapKey(), yaml.ReferenceFiles(model.References...))
	if unmarshalError != nil {
		log.Fatal("Unable to parse model yaml: ", unmarshalError)
	}

	for n := range model.References {
		if !filepath.IsAbs(model.References[n]) {
			model.References[n] = filepath.Clean(filepath.Join(filepath.Dir(model.SourceFile), model.References[n]))
		}
	}

	for _, includeFile := range model.Includes {
		isFatal, mergeError := model.Merge(config, filepath.Dir(model.SourceFile), filepath.Clean(includeFile))
		if mergeError != nil {
			if !config.GetMergeModels() || isFatal {
				log.Fatalf("Unable to merge model include %q: %v", includeFile, mergeError)
			}

			config.GetProgressReporter().Infof("merged included model %v (%v -> %v)", includeFile, model.SourceFile, filepath.Clean(includeFile))
		}
	}

	model.Prune()
	model.AddLinks(config)

	return nil
}

func (model *Model) UpdateSourceFile(name string) {
	model.SourceFile = filepath.Clean(name)

	model.Author.SourceFile = model.SourceFile

	for id, item := range model.Contributors {
		item.SourceFile = model.SourceFile
		model.Contributors[id] = item
	}

	model.AppDescription.SourceFile = model.SourceFile
	model.BusinessOverview.SourceFile = model.SourceFile
	model.TechnicalOverview.SourceFile = model.SourceFile

	for id, item := range model.DataAssets {
		item.SourceFile = model.SourceFile
		model.DataAssets[id] = item
	}

	for id, item := range model.TechnicalAssets {
		item.SourceFile = model.SourceFile
		model.TechnicalAssets[id] = item
	}

	for id, item := range model.TrustBoundaries {
		item.SourceFile = model.SourceFile
		model.TrustBoundaries[id] = item
	}

	for id, item := range model.SharedRuntimes {
		item.SourceFile = model.SourceFile
		model.SharedRuntimes[id] = item
	}

	for id, item := range model.CommunicationLinks {
		item.SourceFile = model.SourceFile
		model.CommunicationLinks[id] = item
	}

	for id, item := range model.CustomRiskCategories {
		item.SourceFile = model.SourceFile
		model.CustomRiskCategories[id] = item
	}
}

func (model *Model) Prune() {
	for name := range (*model).DataAssets {
		if model.DataAssets[name].IsTemplate {
			delete(model.DataAssets, name)
		}
	}

	for name := range (*model).TechnicalAssets {
		if model.TechnicalAssets[name].IsTemplate {
			delete(model.TechnicalAssets, name)
		} else {
			asset := (*model).TechnicalAssets[name]
			asset.Prune()
			model.TechnicalAssets[name] = asset
		}
	}

	for name := range (*model).TrustBoundaries {
		if model.TrustBoundaries[name].IsTemplate {
			delete(model.TrustBoundaries, name)
		}
	}

	for name := range (*model).SharedRuntimes {
		if model.SharedRuntimes[name].IsTemplate {
			delete(model.SharedRuntimes, name)
		}
	}

	for index := range (*model).CustomRiskCategories {
		if model.CustomRiskCategories[index].IsTemplate {
			model.CustomRiskCategories = append(model.CustomRiskCategories[:index], model.CustomRiskCategories[index+1:]...)
		}
	}

	for name := range model.CommunicationLinks {
		if model.CommunicationLinks[name].IsTemplate {
			delete(model.CommunicationLinks, name)
		}
	}
}

func (model *Model) AddLinks(config configReader) {
	for newLinkName, newLink := range model.CommunicationLinks {
		found := false
		for assetName, asset := range model.TechnicalAssets {
			if strings.EqualFold(newLink.Source, asset.ID) {
				for linkName, link := range asset.CommunicationLinks {
					if strings.EqualFold(link.ID, newLink.ID) {
						config.GetProgressReporter().Warnf("communication link %q from %q redefined in %q", link.ID, link.SourceFile, asset.SourceFile)
					}

					if strings.EqualFold(linkName, newLinkName) {
						config.GetProgressReporter().Warnf("communication link %q from %q redefined in %q (duplicate name)", link.ID, link.SourceFile, asset.SourceFile)
					}
				}

				if asset.CommunicationLinks == nil {
					asset.CommunicationLinks = make(map[string]CommunicationLink)
				}

				found = true
				asset.CommunicationLinks[newLinkName] = model.CommunicationLinks[newLinkName]
				model.TechnicalAssets[assetName] = asset
			}
		}

		if !found {
			config.GetProgressReporter().Warnf("source asset %q for communication link %q not found", newLink.Source, newLink.ID)
		}
	}
}

func (model *Model) Merge(config configReader, dir string, includeFilename string) (bool, error) {
	modelYaml, readError := os.ReadFile(filepath.Clean(filepath.Join(dir, includeFilename)))
	if readError != nil {
		return true, fmt.Errorf("unable to read model file: %w", readError)
	}

	var fileStructure map[string]any
	unmarshalStructureError := yaml.UnmarshalWithOptions(modelYaml, &fileStructure, yaml.AllowDuplicateMapKey(), yaml.ReferenceFiles(model.References...))
	if unmarshalStructureError != nil {
		return true, fmt.Errorf("unable to parse model structure (%v): %w", filepath.Clean(filepath.Join(dir, includeFilename)), unmarshalStructureError)
	}

	var includedModel Model
	includedModel.UpdateSourceFile(includeFilename)
	includedModel.References = model.References

	for item := range fileStructure {
		switch strings.ToLower(item) {
		case strings.ToLower("references"):
			switch references := fileStructure[item].(type) {
			case []string:
				for _, ref := range references {
					if !filepath.IsAbs(ref) {
						ref = filepath.Clean(filepath.Join(filepath.Dir(model.SourceFile), ref))
					}

					includedModel.References = append(includedModel.References, ref)
				}

			case []any:
				for _, ref := range references {
					referenceString, ok := ref.(string)
					if ok {
						if !filepath.IsAbs(referenceString) {
							referenceString = filepath.Clean(filepath.Join(filepath.Dir(model.SourceFile), referenceString))
						}

						includedModel.References = append(includedModel.References, filepath.Clean(referenceString))
					}
				}
			}
		}
	}

	unmarshalError := yaml.UnmarshalWithOptions(modelYaml, &includedModel, yaml.AllowDuplicateMapKey(), yaml.ReferenceFiles(includedModel.References...))
	if unmarshalError != nil {
		return true, fmt.Errorf("unable to parse model yaml %v: %w", filepath.Clean(filepath.Join(dir, includeFilename)), unmarshalError)
	}

	var mergeError error
	var isFatal bool
	for item := range fileStructure {
		switch strings.ToLower(item) {
		case strings.ToLower("includes"):
			for _, includeFile := range includedModel.Includes {
				isFatal, mergeError = model.Merge(config, filepath.Join(dir, filepath.Dir(includeFilename)), includeFile)
				if mergeError != nil {
					if !config.GetMergeModels() || isFatal {
						return isFatal, fmt.Errorf("failed to merge model include %q (%v -> %v): %w", includeFile, includedModel.SourceFile, model.SourceFile, mergeError)
					}

					config.GetProgressReporter().Infof("merged model include %v (%v -> %v)", includeFile, includedModel.SourceFile, model.SourceFile)
				}
			}

		case strings.ToLower("threagile_version"):
			model.ThreagileVersion, isFatal, mergeError = new(Strings).MergeSingleton(config, model.ThreagileVersion, includedModel.ThreagileVersion)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge threagile version (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged threagile version (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("title"):
			model.Title, isFatal, mergeError = new(Strings).MergeSingleton(config, model.Title, includedModel.Title)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge title (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged title (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("author"):
			isFatal, mergeError = model.Author.Merge(config, includedModel.Author)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge author (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged author (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("contributors"):
			model.Contributors, isFatal, mergeError = new(Author).MergeList(config, append(model.Contributors, includedModel.Author))
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge contributors (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged contributors (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("date"):
			model.Date, isFatal, mergeError = new(Strings).MergeSingleton(config, model.Date, includedModel.Date)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge date (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged model date (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("application_description"):
			isFatal, mergeError = model.AppDescription.Merge(config, includedModel.AppDescription)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge application description (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged application description (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("business_overview"):
			isFatal, mergeError = model.BusinessOverview.Merge(config, includedModel.BusinessOverview)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge business overview (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged business overview (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("technical_overview"):
			isFatal, mergeError = model.TechnicalOverview.Merge(config, includedModel.TechnicalOverview)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge technical overview (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged technical overview (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("business_criticality"):
			model.BusinessCriticality, isFatal, mergeError = new(Strings).MergeSingleton(config, model.BusinessCriticality, includedModel.BusinessCriticality)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge business criticality (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged business criticality (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("management_summary_comment"):
			model.ManagementSummaryComment = new(Strings).MergeMultiline(config, model.ManagementSummaryComment, includedModel.ManagementSummaryComment)

		case strings.ToLower("security_requirements"):
			model.SecurityRequirements, isFatal, mergeError = new(Strings).MergeMap(config, model.SecurityRequirements, includedModel.SecurityRequirements)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge security requirements (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged security requirements (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("questions"):
			model.Questions, isFatal, mergeError = new(Strings).MergeMap(config, model.Questions, includedModel.Questions)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge questions (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged questions (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("abuse_cases"):
			model.AbuseCases, isFatal, mergeError = new(Strings).MergeMap(config, model.AbuseCases, includedModel.AbuseCases)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge abuse cases (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged abuse cases (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("tags_available"):
			model.TagsAvailable = new(Strings).MergeUniqueSlice(config, model.TagsAvailable, includedModel.TagsAvailable)

		case strings.ToLower("data_assets"):
			model.DataAssets, isFatal, mergeError = new(DataAsset).MergeMap(config, model.DataAssets, includedModel.DataAssets)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge data assets (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged data assets (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("technical_assets"):
			model.TechnicalAssets, isFatal, mergeError = new(TechnicalAsset).MergeMap(config, model.TechnicalAssets, includedModel.TechnicalAssets)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge technical assets (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged technical assets (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("trust_boundaries"):
			model.TrustBoundaries, isFatal, mergeError = new(TrustBoundary).MergeMap(config, model.TrustBoundaries, includedModel.TrustBoundaries)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge trust boundaries (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged trust boundaries (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("shared_runtimes"):
			model.SharedRuntimes, isFatal, mergeError = new(SharedRuntime).MergeMap(config, model.SharedRuntimes, includedModel.SharedRuntimes)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge shared runtimes (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged shared runtimes (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("communication_links"):
			model.CommunicationLinks, isFatal, mergeError = new(CommunicationLink).MergeMap(config, model.CommunicationLinks, includedModel.CommunicationLinks)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge communication links (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged communication links (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("custom_risk_categories"):
			isFatal, mergeError = model.CustomRiskCategories.Add(config, includedModel.CustomRiskCategories...)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge risk categories (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged custom risk categories (%v -> %v)", includedModel.SourceFile, model.SourceFile)
			}

		case strings.ToLower("risk_tracking"):
			model.RiskTracking, isFatal, mergeError = new(RiskTracking).MergeMap(config, model.RiskTracking, includedModel.RiskTracking)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return isFatal, fmt.Errorf("failed to merge risk tracking (%v -> %v): %w", includedModel.SourceFile, model.SourceFile, mergeError)
				}

				config.GetProgressReporter().Infof("merged risk tracking (%v -> %v)", includedModel.SourceFile, model.SourceFile)
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

	return false, nil
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
