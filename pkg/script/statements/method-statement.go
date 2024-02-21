package statements

import (
	"fmt"
	"github.com/threagile/threagile/pkg/script/common"
)

type MethodStatement struct {
	literal    string
	parameters []string
	body       common.Statement
}

func (what *MethodStatement) Parse(script any) (common.Statement, any, error) {
	what.literal = common.ToLiteral(script)

	switch script.(type) {
	case map[string]any:
		for key, value := range script.(map[string]any) {
			switch key {
			case common.Parameter, common.Parameters:
				switch castValue := value.(type) {
				case []string:
					what.parameters = append(what.parameters, castValue...)

				case []any:
					for _, generic := range castValue {
						text, ok := generic.(string)
						if !ok {
							return nil, generic, fmt.Errorf("failed to parse %q of method-statement: expected string, got %T", key, generic)
						}

						what.parameters = append(what.parameters, text)
					}

				case string:
					what.parameters = append(what.parameters, castValue)

				case fmt.Stringer:
					what.parameters = append(what.parameters, castValue.String())

				default:
					return nil, value, fmt.Errorf("failed to parse %q of method-statement: unexpected parameter type %T", key, value)
				}

			case common.Do:
				item, errorScript, itemError := new(StatementList).Parse(value)
				if itemError != nil {
					return nil, errorScript, fmt.Errorf("failed to parse %q of method-statement: %v", key, itemError)
				}

				what.body = item

			default:
				return nil, script, fmt.Errorf("failed to parse method-statement: unexpected statement %q", key)
			}
		}

	default:
		return nil, script, fmt.Errorf("failed to parse method-statement: expected map[string]any, got %T", script)
	}

	return what, nil, nil
}

func (what *MethodStatement) Run(scope *common.Scope) (string, error) {
	if len(what.parameters) != len(scope.Args) {
		return what.Literal(), fmt.Errorf("failed to run method-statement: expected %d parameters, got %d", len(what.parameters), len(scope.Args))
	}

	for n, name := range what.parameters {
		scope.Set(name, scope.Args[n])
	}

	if what.body != nil {
		errorLiteral, runError := what.body.Run(scope)
		if runError != nil {
			return errorLiteral, fmt.Errorf("failed to run method: %v", runError)
		}
	}

	return "", nil
}

func (what *MethodStatement) Literal() string {
	return what.literal
}
