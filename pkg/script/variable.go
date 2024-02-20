package script

import (
	"github.com/threagile/threagile/pkg/script/common"
)

type Variable struct {
	Name       string
	Expression common.Expression
}
