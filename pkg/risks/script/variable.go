package script

import (
	"github.com/threagile/threagile/pkg/risks/script/common"
)

type Variable struct {
	Name       string
	Expression common.Expression
}
