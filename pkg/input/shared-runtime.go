package input

import (
	"errors"
	"fmt"
)

type SharedRuntime struct {
	SourceFile             string   `yaml:"-" json:"-"`
	ID                     string   `yaml:"id,omitempty" json:"id,omitempty"`
	Description            string   `yaml:"description,omitempty" json:"description,omitempty"`
	Tags                   []string `yaml:"tags,omitempty" json:"tag,omitempty"`
	TechnicalAssetsRunning []string `yaml:"technical_assets_running,omitempty" json:"technical_assets_running,omitempty"`
	IsTemplate             bool     `yaml:"is_template,omitempty" json:"is_template,omitempty"`
}

func (what *SharedRuntime) Merge(config configReader, other SharedRuntime) (bool, error) {
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

	what.Tags = new(Strings).MergeUniqueSlice(config, what.Tags, other.Tags)

	what.TechnicalAssetsRunning = new(Strings).MergeUniqueSlice(config, what.TechnicalAssetsRunning, other.TechnicalAssetsRunning)

	return isFatal, mergeErrors
}

func (what *SharedRuntime) MergeMap(config configReader, first map[string]SharedRuntime, second map[string]SharedRuntime) (map[string]SharedRuntime, bool, error) {
	var mergeErrors error
	var mergeError error
	var isFatal bool
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			config.GetProgressReporter().Warnf("shared runtime %q from %q redefined in %q", mapKey, mapValue.SourceFile, mapItem.SourceFile)

			isFatal, mergeError = mapItem.Merge(config, mapValue)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return first, isFatal, fmt.Errorf("failed to merge shared runtime %q: %w", mapKey, mergeError)
				}

				mergeErrors = errors.Join(fmt.Errorf("failed to merge shared runtime %q: %w", mapKey, mergeError), mergeErrors)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, isFatal, mergeErrors
}
