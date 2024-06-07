package report

import "github.com/threagile/threagile/pkg/types"

type RiskItem struct {
	Columns  []string
	Status   types.RiskStatus
	Severity types.RiskSeverity
}
