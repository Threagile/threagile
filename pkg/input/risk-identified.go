package input

import (
	"errors"
	"fmt"
)

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

func (what *RiskIdentified) Merge(config configReader, other RiskIdentified) (bool, error) {
	var mergeErrors error
	var mergeError error
	var isFatal bool
	what.Severity, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Severity, other.Severity)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge severity: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge false severity: %w", mergeError), mergeErrors)
	}

	what.ExploitationLikelihood, isFatal, mergeError = new(Strings).MergeSingleton(config, what.ExploitationLikelihood, other.ExploitationLikelihood)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge exploitation likelihood: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge exploitation likelihood: %w", mergeError), mergeErrors)
	}

	what.ExploitationImpact, isFatal, mergeError = new(Strings).MergeSingleton(config, what.ExploitationImpact, other.ExploitationImpact)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge exploitation impact: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge exploitation impact: %w", mergeError), mergeErrors)
	}

	what.DataBreachProbability, isFatal, mergeError = new(Strings).MergeSingleton(config, what.DataBreachProbability, other.DataBreachProbability)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge date: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge date: %w", mergeError), mergeErrors)
	}

	what.DataBreachTechnicalAssets = new(Strings).MergeUniqueSlice(config, what.DataBreachTechnicalAssets, other.DataBreachTechnicalAssets)

	what.MostRelevantDataAsset, isFatal, mergeError = new(Strings).MergeSingleton(config, what.MostRelevantDataAsset, other.MostRelevantDataAsset)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge most relevant data asset: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge most relevant data asset: %w", mergeError), mergeErrors)
	}

	what.MostRelevantTechnicalAsset, isFatal, mergeError = new(Strings).MergeSingleton(config, what.MostRelevantTechnicalAsset, other.MostRelevantTechnicalAsset)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge most relevant technical asset: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge most relevant technical asset: %w", mergeError), mergeErrors)
	}

	what.MostRelevantCommunicationLink, isFatal, mergeError = new(Strings).MergeSingleton(config, what.MostRelevantCommunicationLink, other.MostRelevantCommunicationLink)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge most relevant communication link: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge most relevant communication link: %w", mergeError), mergeErrors)
	}

	what.MostRelevantTrustBoundary, isFatal, mergeError = new(Strings).MergeSingleton(config, what.MostRelevantTrustBoundary, other.MostRelevantTrustBoundary)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge most relevant trust boundary: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge most relevant trust boundary: %w", mergeError), mergeErrors)
	}

	what.MostRelevantSharedRuntime, isFatal, mergeError = new(Strings).MergeSingleton(config, what.MostRelevantSharedRuntime, other.MostRelevantSharedRuntime)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge most relevant shared runtime: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge most relevant shared runtime: %w", mergeError), mergeErrors)
	}

	return isFatal, mergeErrors
}

func (what *RiskIdentified) MergeMap(config configReader, first map[string]RiskIdentified, second map[string]RiskIdentified) (map[string]RiskIdentified, bool, error) {
	var mergeErrors error
	var mergeError error
	var isFatal bool
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			isFatal, mergeError = mapItem.Merge(config, mapValue)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return first, isFatal, fmt.Errorf("failed to merge risk %q: %w", mapKey, mergeError)
				}

				mergeErrors = errors.Join(fmt.Errorf("failed to merge risk %q: %w", mapKey, mergeError), mergeErrors)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, isFatal, mergeErrors
}
