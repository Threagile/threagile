package input

import "fmt"

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

func (what *DataAsset) Merge(other DataAsset) error {
	var mergeError error
	what.ID, mergeError = new(Strings).MergeSingleton(what.ID, other.ID)
	if mergeError != nil {
		return fmt.Errorf("failed to merge id: %v", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %v", mergeError)
	}

	what.Usage, mergeError = new(Strings).MergeSingleton(what.Usage, other.Usage)
	if mergeError != nil {
		return fmt.Errorf("failed to merge usage: %v", mergeError)
	}

	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)

	what.Origin, mergeError = new(Strings).MergeSingleton(what.Origin, other.Origin)
	if mergeError != nil {
		return fmt.Errorf("failed to merge origin: %v", mergeError)
	}

	what.Owner, mergeError = new(Strings).MergeSingleton(what.Owner, other.Owner)
	if mergeError != nil {
		return fmt.Errorf("failed to merge owner: %v", mergeError)
	}

	what.Quantity, mergeError = new(Strings).MergeSingleton(what.Quantity, other.Quantity)
	if mergeError != nil {
		return fmt.Errorf("failed to merge quantity: %v", mergeError)
	}

	what.Confidentiality, mergeError = new(Strings).MergeSingleton(what.Confidentiality, other.Confidentiality)
	if mergeError != nil {
		return fmt.Errorf("failed to merge confidentiality: %v", mergeError)
	}

	what.Integrity, mergeError = new(Strings).MergeSingleton(what.Integrity, other.Integrity)
	if mergeError != nil {
		return fmt.Errorf("failed to merge integrity: %v", mergeError)
	}

	what.Availability, mergeError = new(Strings).MergeSingleton(what.Availability, other.Availability)
	if mergeError != nil {
		return fmt.Errorf("failed to merge availability: %v", mergeError)
	}

	what.JustificationCiaRating = new(Strings).MergeMultiline(what.JustificationCiaRating, other.JustificationCiaRating)

	return nil
}

func (what *DataAsset) MergeMap(first map[string]DataAsset, second map[string]DataAsset) (map[string]DataAsset, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge data asset %q: %v", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
