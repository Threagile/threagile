package types

import (
	"time"
)

type RiskTracking struct {
	SyntheticRiskId string     `json:"synthetic_risk_id,omitempty"`
	Justification   string     `json:"justification,omitempty"`
	Ticket          string     `json:"ticket,omitempty"`
	CheckedBy       string     `json:"checked_by,omitempty"`
	Status          RiskStatus `json:"status,omitempty"`
	Date            time.Time  `json:"date"`
}
