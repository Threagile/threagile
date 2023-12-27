package types

type RiskCategory struct {
	// TODO: refactor all "Id" here and elsewhere to "ID"
	Id                         string       `json:"id,omitempty"`
	Title                      string       `json:"title,omitempty"`
	Description                string       `json:"description,omitempty"`
	Impact                     string       `json:"impact,omitempty"`
	ASVS                       string       `json:"asvs,omitempty"`
	CheatSheet                 string       `json:"cheat_sheet,omitempty"`
	Action                     string       `json:"action,omitempty"`
	Mitigation                 string       `json:"mitigation,omitempty"`
	Check                      string       `json:"check,omitempty"`
	DetectionLogic             string       `json:"detection_logic,omitempty"`
	RiskAssessment             string       `json:"risk_assessment,omitempty"`
	FalsePositives             string       `json:"false_positives,omitempty"`
	Function                   RiskFunction `json:"function,omitempty"`
	STRIDE                     STRIDE       `json:"stride,omitempty"`
	ModelFailurePossibleReason bool         `json:"model_failure_possible_reason,omitempty"`
	CWE                        int          `json:"cwe,omitempty"`
}
