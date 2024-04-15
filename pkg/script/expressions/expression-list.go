package expressions

import (
	"fmt"
	"github.com/threagile/threagile/pkg/script/common"
)

type ExpressionList struct {
	literal     string
	expressions []common.Expression
}

func (what *ExpressionList) ParseExpression(script map[string]any) (common.Expression, any, error) {
	for key, value := range script {
		switch key {
		case common.All:
			return new(AllExpression).ParseBool(value)

		case common.Any:
			return new(AnyExpression).ParseBool(value)

		case common.And:
			return new(AndExpression).ParseBool(value)

		case common.Contains:
			return new(ContainsExpression).ParseBool(value)

		case common.Count:
			return new(CountExpression).ParseDecimal(value)

		case common.Equal:
			return new(EqualExpression).ParseBool(value)

		case common.EqualOrGreater:
			return new(EqualOrGreaterExpression).ParseBool(value)

		case common.EqualOrLess:
			return new(EqualOrLessExpression).ParseBool(value)

		case common.False:
			return new(FalseExpression).ParseBool(value)

		case common.Greater:
			return new(GreaterExpression).ParseBool(value)

		case common.Less:
			return new(LessExpression).ParseBool(value)

		case common.NotEqual:
			return new(NotEqualExpression).ParseBool(value)

		case common.Or:
			return new(OrExpression).ParseBool(value)

		case common.True:
			return new(TrueExpression).ParseBool(value)

		default:
			return nil, script, fmt.Errorf("failed to parse expression: unexpected keyword %q", key)
		}
	}

	return what, nil, nil
}

func (what *ExpressionList) ParseArray(script any) (common.ExpressionList, any, error) {
	what.literal = common.ToLiteral(script)

	switch castScript := script.(type) {
	case []any:
		for _, expression := range castScript {
			item, errorScript, itemError := what.ParseAny(expression)
			if itemError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse expression list: %v", itemError)
			}

			what.expressions = append(what.expressions, item)
		}

	default:
		return nil, script, fmt.Errorf("unexpected expression list format %T", script)
	}

	return what, nil, nil
}

func (what *ExpressionList) ParseAny(script any) (common.Expression, any, error) {
	what.literal = common.ToLiteral(script)

	switch castScript := script.(type) {
	case map[any]any:
		newMap := make(map[string]any)
		for key, value := range castScript {
			newMap[fmt.Sprintf("%v", key)] = value
		}

		return what.ParseExpression(newMap)

	case map[string]any:
		return what.ParseExpression(castScript)

	case []any:
		for _, expression := range castScript {
			item, errorScript, itemError := what.ParseAny(expression)
			if itemError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse expression list: %v", itemError)
			}

			what.expressions = append(what.expressions, item)
		}

		if len(what.expressions) == 1 {
			return what.expressions[0], nil, nil
		}

	default:
		return new(ValueExpression).ParseAny(script)
	}

	return what, nil, nil
}

func (what *ExpressionList) EvalAny(scope *common.Scope) (any, string, error) {
	if what.expressions == nil {
		return nil, "", nil
	}

	switch len(what.expressions) {
	case 0:
		return nil, "", nil

	case 1:
		return what.expressions[0].EvalAny(scope)

	default:
		var values common.ValueList
		for _, expression := range what.expressions {
			value, errorLiteral, statementError := expression.EvalAny(scope)
			if statementError != nil {
				return nil, errorLiteral, statementError
			}

			values = append(values, value)
		}

		return values, "", nil
	}
}

func (what *ExpressionList) Literal() string {
	return what.literal
}

func (what *ExpressionList) Expressions() []common.Expression {
	return what.expressions
}
