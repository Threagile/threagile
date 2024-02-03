package input

import "fmt"

type RiskTracking struct {
	Status        string `yaml:"status,omitempty" json:"status,omitempty"`
	Justification string `yaml:"justification,omitempty" json:"justification,omitempty"`
	Ticket        string `yaml:"ticket,omitempty" json:"ticket,omitempty"`
	Date          string `yaml:"date,omitempty" json:"date,omitempty"`
	CheckedBy     string `yaml:"checked_by,omitempty" json:"checked_by,omitempty"`
}

func (what *RiskTracking) Merge(other RiskTracking) error {
	var mergeError error
	what.Status, mergeError = new(Strings).MergeSingleton(what.Status, other.Status)
	if mergeError != nil {
		return fmt.Errorf("failed to merge status: %v", mergeError)
	}

	what.Justification, mergeError = new(Strings).MergeSingleton(what.Justification, other.Justification)
	if mergeError != nil {
		return fmt.Errorf("failed to merge justification: %v", mergeError)
	}

	what.Ticket, mergeError = new(Strings).MergeSingleton(what.Ticket, other.Ticket)
	if mergeError != nil {
		return fmt.Errorf("failed to merge ticket: %v", mergeError)
	}

	what.Date, mergeError = new(Strings).MergeSingleton(what.Date, other.Date)
	if mergeError != nil {
		return fmt.Errorf("failed to merge date: %v", mergeError)
	}

	what.CheckedBy, mergeError = new(Strings).MergeSingleton(what.CheckedBy, other.CheckedBy)
	if mergeError != nil {
		return fmt.Errorf("failed to merge checked_by: %v", mergeError)
	}

	return nil
}

func (what *RiskTracking) MergeMap(first map[string]RiskTracking, second map[string]RiskTracking) (map[string]RiskTracking, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge risk tracking %q: %v", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
