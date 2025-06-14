package input

import (
	"errors"
	"fmt"
)

type DataAsset struct {
	SourceFile             string   `yaml:"-" json:"-"`
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
	IsTemplate             bool     `yaml:"is_template,omitempty" json:"is_template,omitempty"`
}

func (what *DataAsset) Merge(config configReader, other DataAsset) (bool, error) {
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

	what.Usage, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Usage, other.Usage)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge usage: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge usage: %w", mergeError), mergeErrors)
	}

	what.Tags = new(Strings).MergeUniqueSlice(config, what.Tags, other.Tags)

	what.Origin, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Origin, other.Origin)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge origin: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge origin: %w", mergeError), mergeErrors)
	}

	what.Owner, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Owner, other.Owner)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge owner: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge owner: %w", mergeError), mergeErrors)
	}

	what.Quantity, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Quantity, other.Quantity)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge quantity: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge quantity: %w", mergeError), mergeErrors)
	}

	what.Confidentiality, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Confidentiality, other.Confidentiality)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge confidentiality: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge confidentiality: %w", mergeError), mergeErrors)
	}

	what.Integrity, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Integrity, other.Integrity)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge integrity: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge integrity: %w", mergeError), mergeErrors)
	}

	what.Availability, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Availability, other.Availability)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge availability: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge availability: %w", mergeError), mergeErrors)
	}

	what.JustificationCiaRating = new(Strings).MergeMultiline(config, what.JustificationCiaRating, other.JustificationCiaRating)

	return isFatal, mergeErrors
}

func (what *DataAsset) MergeMap(config configReader, first map[string]DataAsset, second map[string]DataAsset) (map[string]DataAsset, bool, error) {
	var mergeErrors error
	var mergeError error
	var isFatal bool
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			config.GetProgressReporter().Warnf("data asset %q from %q redefined in %q", mapKey, mapValue.SourceFile, mapItem.SourceFile)

			isFatal, mergeError = mapItem.Merge(config, mapValue)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return first, isFatal, fmt.Errorf("failed to merge data asset %q: %w", mapKey, mergeError)
				}

				mergeErrors = errors.Join(fmt.Errorf("failed to merge data asset %q: %w", mapKey, mergeError), mergeErrors)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, isFatal, mergeErrors
}
