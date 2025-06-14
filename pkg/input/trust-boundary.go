package input

import (
	"errors"
	"fmt"
)

type TrustBoundary struct {
	SourceFile            string   `yaml:"-" json:"-"`
	ID                    string   `yaml:"id,omitempty" json:"id,omitempty"`
	Description           string   `yaml:"description,omitempty" json:"description,omitempty"`
	Type                  string   `yaml:"type,omitempty" json:"type,omitempty"`
	Tags                  []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	TechnicalAssetsInside []string `yaml:"technical_assets_inside,omitempty" json:"technical_assets_inside,omitempty"`
	TrustBoundariesNested []string `yaml:"trust_boundaries_nested,omitempty" json:"trust_boundaries_nested,omitempty"`
	IsTemplate            bool     `yaml:"is_template,omitempty" json:"is_template,omitempty"`
}

func (what *TrustBoundary) Merge(config configReader, other TrustBoundary) (bool, error) {
	var mergeErrors error
	var mergeError error
	var isFatal bool
	what.ID, isFatal, mergeError = new(Strings).MergeSingleton(config, what.ID, other.ID)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge id: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge id: %w", mergeError), mergeErrors)
	}

	what.Description, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Description, other.Description)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge description: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge description: %w", mergeError), mergeErrors)
	}

	what.Type, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Type, other.Type)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge type: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge type: %w", mergeError), mergeErrors)
	}

	what.Tags = new(Strings).MergeUniqueSlice(config, what.Tags, other.Tags)

	what.TechnicalAssetsInside = new(Strings).MergeUniqueSlice(config, what.TechnicalAssetsInside, other.TechnicalAssetsInside)

	what.TrustBoundariesNested = new(Strings).MergeUniqueSlice(config, what.TrustBoundariesNested, other.TrustBoundariesNested)

	return isFatal, mergeErrors
}

func (what *TrustBoundary) MergeMap(config configReader, first map[string]TrustBoundary, second map[string]TrustBoundary) (map[string]TrustBoundary, bool, error) {
	var mergeErrors error
	var mergeError error
	var isFatal bool
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			config.GetProgressReporter().Warnf("trust boundary %q from %q redefined in %q", mapKey, mapValue.SourceFile, mapItem.SourceFile)

			isFatal, mergeError = mapItem.Merge(config, mapValue)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return first, isFatal, fmt.Errorf("failed to merge trust boundary %q: %w", mapKey, mergeError)
				}

				mergeErrors = errors.Join(fmt.Errorf("failed to merge trust boundary %q: %w", mapKey, mergeError), mergeErrors)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, isFatal, nil
}
