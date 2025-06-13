package input

import "fmt"

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

func (what *TrustBoundary) Merge(other TrustBoundary) error {
	var mergeError error
	what.ID, mergeError = new(Strings).MergeSingleton(what.ID, other.ID)
	if mergeError != nil {
		return fmt.Errorf("failed to merge id: %w", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %w", mergeError)
	}

	what.Type, mergeError = new(Strings).MergeSingleton(what.Type, other.Type)
	if mergeError != nil {
		return fmt.Errorf("failed to merge type: %w", mergeError)
	}

	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)

	what.TechnicalAssetsInside = new(Strings).MergeUniqueSlice(what.TechnicalAssetsInside, other.TechnicalAssetsInside)

	what.TrustBoundariesNested = new(Strings).MergeUniqueSlice(what.TrustBoundariesNested, other.TrustBoundariesNested)

	return nil
}

func (what *TrustBoundary) MergeMap(config configReader, first map[string]TrustBoundary, second map[string]TrustBoundary) (map[string]TrustBoundary, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			config.GetProgressReporter().Warnf("trust boundary %q from %q redefined in %q", mapKey, mapValue.SourceFile, mapItem.SourceFile)

			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge trust boundary %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
