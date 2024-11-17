package input

import "fmt"

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

func (what *RiskIdentified) Merge(other RiskIdentified) error {
	var mergeError error
	what.Severity, mergeError = new(Strings).MergeSingleton(what.Severity, other.Severity)
	if mergeError != nil {
		return fmt.Errorf("failed to merge severity: %w", mergeError)
	}

	what.ExploitationLikelihood, mergeError = new(Strings).MergeSingleton(what.ExploitationLikelihood, other.ExploitationLikelihood)
	if mergeError != nil {
		return fmt.Errorf("failed to merge exploitation_likelihood: %w", mergeError)
	}

	what.ExploitationImpact, mergeError = new(Strings).MergeSingleton(what.ExploitationImpact, other.ExploitationImpact)
	if mergeError != nil {
		return fmt.Errorf("failed to merge exploitation_impact: %w", mergeError)
	}

	what.DataBreachProbability, mergeError = new(Strings).MergeSingleton(what.DataBreachProbability, other.DataBreachProbability)
	if mergeError != nil {
		return fmt.Errorf("failed to merge date: %w", mergeError)
	}

	what.DataBreachTechnicalAssets = new(Strings).MergeUniqueSlice(what.DataBreachTechnicalAssets, other.DataBreachTechnicalAssets)

	what.MostRelevantDataAsset, mergeError = new(Strings).MergeSingleton(what.MostRelevantDataAsset, other.MostRelevantDataAsset)
	if mergeError != nil {
		return fmt.Errorf("failed to merge most_relevant_data_asset: %w", mergeError)
	}

	what.MostRelevantTechnicalAsset, mergeError = new(Strings).MergeSingleton(what.MostRelevantTechnicalAsset, other.MostRelevantTechnicalAsset)
	if mergeError != nil {
		return fmt.Errorf("failed to merge most_relevant_technical_asset: %w", mergeError)
	}

	what.MostRelevantCommunicationLink, mergeError = new(Strings).MergeSingleton(what.MostRelevantCommunicationLink, other.MostRelevantCommunicationLink)
	if mergeError != nil {
		return fmt.Errorf("failed to merge most_relevant_communication_link: %w", mergeError)
	}

	what.MostRelevantTrustBoundary, mergeError = new(Strings).MergeSingleton(what.MostRelevantTrustBoundary, other.MostRelevantTrustBoundary)
	if mergeError != nil {
		return fmt.Errorf("failed to merge most_relevant_trust_boundary: %w", mergeError)
	}

	what.MostRelevantSharedRuntime, mergeError = new(Strings).MergeSingleton(what.MostRelevantSharedRuntime, other.MostRelevantSharedRuntime)
	if mergeError != nil {
		return fmt.Errorf("failed to merge most_relevant_shared_runtime: %w", mergeError)
	}

	return nil
}

func (what *RiskIdentified) MergeMap(first map[string]RiskIdentified, second map[string]RiskIdentified) (map[string]RiskIdentified, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge risk %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
