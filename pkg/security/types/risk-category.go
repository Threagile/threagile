package types

import "strings"

type RiskCategory struct {
	ID                         string       `json:"id,omitempty" yaml:"id,omitempty"`
	Title                      string       `json:"title,omitempty" yaml:"title,omitempty"`
	Description                string       `json:"description,omitempty" yaml:"description,omitempty"`
	Impact                     string       `json:"impact,omitempty" yaml:"impact,omitempty"`
	ASVS                       string       `json:"asvs,omitempty" yaml:"asvs,omitempty"`
	CheatSheet                 string       `json:"cheat_sheet,omitempty" yaml:"cheat_sheet,omitempty"`
	Action                     string       `json:"action,omitempty" yaml:"action,omitempty"`
	Mitigation                 string       `json:"mitigation,omitempty" yaml:"mitigation,omitempty"`
	Check                      string       `json:"check,omitempty" yaml:"check,omitempty"`
	Function                   RiskFunction `json:"function,omitempty" yaml:"function,omitempty"`
	STRIDE                     STRIDE       `json:"stride,omitempty" yaml:"stride,omitempty"`
	DetectionLogic             string       `json:"detection_logic,omitempty" yaml:"detection_logic,omitempty"`
	RiskAssessment             string       `json:"risk_assessment,omitempty" yaml:"risk_assessment,omitempty"`
	FalsePositives             string       `json:"false_positives,omitempty" yaml:"false_positives,omitempty"`
	ModelFailurePossibleReason bool         `json:"model_failure_possible_reason,omitempty" yaml:"model_failure_possible_reason,omitempty"`
	CWE                        int          `json:"cwe,omitempty" yaml:"cwe,omitempty"`
}

type RiskCategories []*RiskCategory

func (what *RiskCategories) Add(categories ...*RiskCategory) bool {
	for _, newCategory := range categories {
		for _, existingCategory := range *what {
			if strings.EqualFold(existingCategory.ID, newCategory.ID) {
				return false
			}
		}

		*what = append(*what, newCategory)
	}

	return true
}
