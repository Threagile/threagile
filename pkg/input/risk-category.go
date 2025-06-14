package input

import (
	"errors"
	"fmt"
	"strings"
)

type RiskCategory struct {
	ID                         string                    `yaml:"id,omitempty" json:"id,omitempty"`
	SourceFile                 string                    `yaml:"source-file,omitempty" json:"source-file,omitempty"`
	Title                      string                    `json:"title,omitempty" yaml:"title,omitempty"`
	Description                string                    `yaml:"description,omitempty" json:"description,omitempty"`
	Impact                     string                    `yaml:"impact,omitempty" json:"impact,omitempty"`
	ASVS                       string                    `yaml:"asvs,omitempty" json:"asvs,omitempty"`
	CheatSheet                 string                    `yaml:"cheat_sheet,omitempty" json:"cheat_sheet,omitempty"`
	Action                     string                    `yaml:"action,omitempty" json:"action,omitempty"`
	Mitigation                 string                    `yaml:"mitigation,omitempty" json:"mitigation,omitempty"`
	Check                      string                    `yaml:"check,omitempty" json:"check,omitempty"`
	Function                   string                    `yaml:"function,omitempty" json:"function,omitempty"`
	STRIDE                     string                    `yaml:"stride,omitempty" json:"stride,omitempty"`
	DetectionLogic             string                    `yaml:"detection_logic,omitempty" json:"detection_logic,omitempty"`
	RiskAssessment             string                    `yaml:"risk_assessment,omitempty" json:"risk_assessment,omitempty"`
	FalsePositives             string                    `yaml:"false_positives,omitempty" json:"false_positives,omitempty"`
	ModelFailurePossibleReason bool                      `yaml:"model_failure_possible_reason,omitempty" json:"model_failure_possible_reason,omitempty"`
	CWE                        int                       `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	RisksIdentified            map[string]RiskIdentified `yaml:"risks_identified,omitempty" json:"risks_identified,omitempty"`
	IsTemplate                 bool                      `yaml:"is_template,omitempty" json:"is_template,omitempty"`
}

type RiskCategories []*RiskCategory

func (what *RiskCategory) Merge(config configReader, other RiskCategory) (bool, error) {
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

	what.Impact, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Impact, other.Impact)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge impact: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge impact: %w", mergeError), mergeErrors)
	}

	what.ASVS, isFatal, mergeError = new(Strings).MergeSingleton(config, what.ASVS, other.ASVS)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge asvs: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge asvs: %w", mergeError), mergeErrors)
	}

	what.CheatSheet, isFatal, mergeError = new(Strings).MergeSingleton(config, what.CheatSheet, other.CheatSheet)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge cheat sheet: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge cheat sheet: %w", mergeError), mergeErrors)
	}

	what.Action, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Action, other.Action)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge action: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge action: %w", mergeError), mergeErrors)
	}

	what.Mitigation, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Mitigation, other.Mitigation)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge mitigation: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge mitigation: %w", mergeError), mergeErrors)
	}

	what.Check, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Check, other.Check)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge check: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge check: %w", mergeError), mergeErrors)
	}

	what.Function, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Function, other.Function)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge function: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge function: %w", mergeError), mergeErrors)
	}

	what.STRIDE, isFatal, mergeError = new(Strings).MergeSingleton(config, what.STRIDE, other.STRIDE)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge STRIDE: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge STRIDE: %w", mergeError), mergeErrors)
	}

	what.DetectionLogic, isFatal, mergeError = new(Strings).MergeSingleton(config, what.DetectionLogic, other.DetectionLogic)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge detection logic: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge detection logic: %w", mergeError), mergeErrors)
	}

	what.RiskAssessment, isFatal, mergeError = new(Strings).MergeSingleton(config, what.RiskAssessment, other.RiskAssessment)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge risk assessment: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge risk assessment: %w", mergeError), mergeErrors)
	}

	what.FalsePositives, isFatal, mergeError = new(Strings).MergeSingleton(config, what.FalsePositives, other.FalsePositives)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge false positives: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge false positives: %w", mergeError), mergeErrors)
	}

	if !what.ModelFailurePossibleReason {
		what.ModelFailurePossibleReason = other.ModelFailurePossibleReason
	}

	if what.CWE == 0 {
		what.CWE = other.CWE
	}

	what.RisksIdentified, isFatal, mergeError = new(RiskIdentified).MergeMap(config, what.RisksIdentified, other.RisksIdentified)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge identified risks: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge identified risks: %w", mergeError), mergeErrors)
	}

	return isFatal, mergeErrors
}

func (what *RiskCategories) Add(config configReader, items ...*RiskCategory) (bool, error) {
	var addErrors error
	for _, item := range items {
		for _, value := range *what {
			if strings.EqualFold(value.ID, item.ID) {
				if !config.GetMergeModels() {
					return false, fmt.Errorf("duplicate item %q in risk category list", value.ID)
				}

				addErrors = errors.Join(fmt.Errorf("duplicate item %q in risk category list", value.ID), addErrors)
			}
		}

		*what = append(*what, item)
	}

	return false, addErrors
}
