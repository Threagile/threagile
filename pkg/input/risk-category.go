package input

import (
	"fmt"
)

type IndividualRiskCategory struct {
	ID                         string                    `yaml:"id,omitempty" json:"id,omitempty"`
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
}

func (what *IndividualRiskCategory) Merge(other IndividualRiskCategory) error {
	var mergeError error
	what.ID, mergeError = new(Strings).MergeSingleton(what.ID, other.ID)
	if mergeError != nil {
		return fmt.Errorf("failed to merge id: %v", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %v", mergeError)
	}

	what.Impact, mergeError = new(Strings).MergeSingleton(what.Impact, other.Impact)
	if mergeError != nil {
		return fmt.Errorf("failed to merge impact: %v", mergeError)
	}

	what.ASVS, mergeError = new(Strings).MergeSingleton(what.ASVS, other.ASVS)
	if mergeError != nil {
		return fmt.Errorf("failed to merge asvs: %v", mergeError)
	}

	what.CheatSheet, mergeError = new(Strings).MergeSingleton(what.CheatSheet, other.CheatSheet)
	if mergeError != nil {
		return fmt.Errorf("failed to merge cheat_sheet: %v", mergeError)
	}

	what.Action, mergeError = new(Strings).MergeSingleton(what.Action, other.Action)
	if mergeError != nil {
		return fmt.Errorf("failed to merge action: %v", mergeError)
	}

	what.Mitigation, mergeError = new(Strings).MergeSingleton(what.Mitigation, other.Mitigation)
	if mergeError != nil {
		return fmt.Errorf("failed to merge mitigation: %v", mergeError)
	}

	what.Check, mergeError = new(Strings).MergeSingleton(what.Check, other.Check)
	if mergeError != nil {
		return fmt.Errorf("failed to merge check: %v", mergeError)
	}

	what.Function, mergeError = new(Strings).MergeSingleton(what.Function, other.Function)
	if mergeError != nil {
		return fmt.Errorf("failed to merge function: %v", mergeError)
	}

	what.STRIDE, mergeError = new(Strings).MergeSingleton(what.STRIDE, other.STRIDE)
	if mergeError != nil {
		return fmt.Errorf("failed to merge STRIDE: %v", mergeError)
	}

	what.DetectionLogic, mergeError = new(Strings).MergeSingleton(what.DetectionLogic, other.DetectionLogic)
	if mergeError != nil {
		return fmt.Errorf("failed to merge detection_logic: %v", mergeError)
	}

	what.RiskAssessment, mergeError = new(Strings).MergeSingleton(what.RiskAssessment, other.RiskAssessment)
	if mergeError != nil {
		return fmt.Errorf("failed to merge risk_assessment: %v", mergeError)
	}

	what.FalsePositives, mergeError = new(Strings).MergeSingleton(what.FalsePositives, other.FalsePositives)
	if mergeError != nil {
		return fmt.Errorf("failed to merge false_positives: %v", mergeError)
	}

	if !what.ModelFailurePossibleReason {
		what.ModelFailurePossibleReason = other.ModelFailurePossibleReason
	}

	if what.CWE == 0 {
		what.CWE = other.CWE
	}

	what.RisksIdentified, mergeError = new(RiskIdentified).MergeMap(what.RisksIdentified, other.RisksIdentified)
	if mergeError != nil {
		return fmt.Errorf("failed to merge identified risks: %v", mergeError)
	}

	return nil
}

func (what *IndividualRiskCategory) MergeMap(first map[string]IndividualRiskCategory, second map[string]IndividualRiskCategory) (map[string]IndividualRiskCategory, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge risk category %q: %v", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
