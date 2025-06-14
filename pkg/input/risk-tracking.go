package input

import (
	"errors"
	"fmt"
)

type RiskTracking struct {
	Status        string `yaml:"status,omitempty" json:"status,omitempty"`
	Justification string `yaml:"justification,omitempty" json:"justification,omitempty"`
	Ticket        string `yaml:"ticket,omitempty" json:"ticket,omitempty"`
	Date          string `yaml:"date,omitempty" json:"date,omitempty"`
	CheckedBy     string `yaml:"checked_by,omitempty" json:"checked_by,omitempty"`
}

func (what *RiskTracking) Merge(config configReader, other RiskTracking) (bool, error) {
	var mergeErrors error
	var mergeError error
	var isFatal bool
	what.Status, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Status, other.Status)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge status: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge status: %w", mergeError), mergeErrors)
	}

	what.Justification, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Justification, other.Justification)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge justification: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge justification: %w", mergeError), mergeErrors)
	}

	what.Ticket, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Ticket, other.Ticket)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge ticket: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge ticket: %w", mergeError), mergeErrors)
	}

	what.Date, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Date, other.Date)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge date: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge date: %w", mergeError), mergeErrors)
	}

	what.CheckedBy, isFatal, mergeError = new(Strings).MergeSingleton(config, what.CheckedBy, other.CheckedBy)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge checked-by: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge checked-by: %w", mergeError), mergeErrors)
	}

	return isFatal, mergeErrors
}

func (what *RiskTracking) MergeMap(config configReader, first map[string]RiskTracking, second map[string]RiskTracking) (map[string]RiskTracking, bool, error) {
	var mergeErrors error
	var mergeError error
	var isFatal bool
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			isFatal, mergeError = mapItem.Merge(config, mapValue)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
				return first, isFatal, fmt.Errorf("failed to merge risk tracking %q: %w", mapKey, mergeError)
				}

				mergeErrors = errors.Join(fmt.Errorf("failed to merge risk tracking %q: %w", mapKey, mergeError), mergeErrors)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, isFatal, mergeErrors
}
