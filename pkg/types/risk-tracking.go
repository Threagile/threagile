package types

type RiskTracking struct {
	SyntheticRiskId string     `json:"synthetic_risk_id,omitempty" yaml:"synthetic_risk_id,omitempty"`
	Justification   string     `json:"justification,omitempty" yaml:"justification,omitempty"`
	Ticket          string     `json:"ticket,omitempty" yaml:"ticket,omitempty"`
	CheckedBy       string     `json:"checked_by,omitempty" yaml:"checked_by,omitempty"`
	Status          RiskStatus `json:"status,omitempty" yaml:"status,omitempty"`
	Date            Date       `json:"date,omitempty" yaml:"date,omitempty"`
}
