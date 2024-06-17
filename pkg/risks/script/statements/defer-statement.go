package statements

import (
	"fmt"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

type DeferStatement struct {
	literal    string
	statements []common.Statement
}

func (what *DeferStatement) Parse(script any) (common.Statement, any, error) {
	what.literal = common.ToLiteral(script)

	switch castScript := script.(type) {
	case map[string]any:
		scriptMap := castScript
		if len(scriptMap) != 1 {
			return nil, script, fmt.Errorf("failed to parse defer-statement: statements must have single identifier")
		}

		for name, body := range scriptMap {
			return new(Statement).Parse(name, body)
		}

	case []any:
		for _, statement := range castScript {
			item, errorScript, itemError := what.Parse(statement)
			if itemError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse defer-statement: %w", itemError)
			}

			what.statements = append(what.statements, item)
		}

	default:
		return nil, script, fmt.Errorf("unexpected defer-statement format %T", script)
	}

	return what, nil, nil
}

func (what *DeferStatement) Run(scope *common.Scope) (string, error) {
	if scope.HasReturned {
		return "", nil
	}

	for _, statement := range what.statements {
		scope.Defer(statement)
	}

	return "", nil
}

func (what *DeferStatement) Literal() string {
	return what.literal
}
