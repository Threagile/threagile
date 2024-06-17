package statements

import (
	"fmt"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

type StatementList struct {
	literal    string
	statements []common.Statement
}

func (what *StatementList) Parse(script any) (common.Statement, any, error) {
	what.literal = common.ToLiteral(script)

	switch castScript := script.(type) {
	case map[string]any:
		scriptMap := castScript
		if len(scriptMap) != 1 {
			return nil, script, fmt.Errorf("failed to parse statement-list: statements must have single identifier")
		}

		for name, body := range scriptMap {
			return new(Statement).Parse(name, body)
		}

	case []any:
		for _, statement := range castScript {
			item, errorScript, itemError := what.Parse(statement)
			if itemError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse statement-list: %w", itemError)
			}

			what.statements = append(what.statements, item)
		}

		if len(what.statements) == 1 {
			statement := what.statements[0]
			what.statements = make([]common.Statement, 0)
			return statement, "", nil
		}

	default:
		return nil, script, fmt.Errorf("unexpected statement-list format %T", script)
	}

	return what, nil, nil
}

func (what *StatementList) Run(scope *common.Scope) (string, error) {
	if scope.HasReturned {
		return "", nil
	}

	for _, statement := range what.statements {
		if scope.HasReturned {
			return "", nil
		}

		errorLiteral, statementError := statement.Run(scope)
		if statementError != nil {
			return errorLiteral, statementError
		}
	}

	return "", nil
}

func (what *StatementList) Literal() string {
	return what.literal
}
