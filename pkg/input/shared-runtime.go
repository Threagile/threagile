package input

import "fmt"

type SharedRuntime struct {
	SourceFile             string   `yaml:"-" json:"-"`
	ID                     string   `yaml:"id,omitempty" json:"id,omitempty"`
	Description            string   `yaml:"description,omitempty" json:"description,omitempty"`
	Tags                   []string `yaml:"tags,omitempty" json:"tag,omitempty"`
	TechnicalAssetsRunning []string `yaml:"technical_assets_running,omitempty" json:"technical_assets_running,omitempty"`
	IsTemplate             bool     `yaml:"is_template,omitempty" json:"is_template,omitempty"`
}

func (what *SharedRuntime) Merge(other SharedRuntime) error {
	var mergeError error
	what.ID, mergeError = new(Strings).MergeSingleton(what.ID, other.ID)
	if mergeError != nil {
		return fmt.Errorf("failed to merge id: %w", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %w", mergeError)
	}

	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)

	what.TechnicalAssetsRunning = new(Strings).MergeUniqueSlice(what.TechnicalAssetsRunning, other.TechnicalAssetsRunning)

	return nil
}

func (what *SharedRuntime) MergeMap(config configReader, first map[string]SharedRuntime, second map[string]SharedRuntime) (map[string]SharedRuntime, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			config.GetProgressReporter().Warnf("shared runtime %q from %q redefined in %q", mapKey, mapValue.SourceFile, mapItem.SourceFile)

			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge shared runtime %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
