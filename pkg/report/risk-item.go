package report

import "github.com/threagile/threagile/pkg/security/types"

type RiskItem struct {
	Columns  []string
	Status   types.RiskStatus
	Severity types.RiskSeverity
}
