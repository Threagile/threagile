package expressions

import (
	"fmt"
	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/script/common"
	"regexp"
	"strconv"
	"strings"
)

type ValueExpression struct {
	literal string
	value   any
}

func (what *ValueExpression) ParseArray(script any) (common.ArrayExpression, any, error) {
	what.literal = common.ToLiteral(script)
	what.value = script

	return what, nil, nil
}

func (what *ValueExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)
	what.value = script

	return what, nil, nil
}

func (what *ValueExpression) ParseDecimal(script any) (common.DecimalExpression, any, error) {
	what.literal = common.ToLiteral(script)
	what.value = script

	return what, nil, nil
}

func (what *ValueExpression) ParseString(script any) (common.StringExpression, any, error) {
	what.literal = common.ToLiteral(script)
	what.value = script

	return what, nil, nil
}

func (what *ValueExpression) ParseValue(script any) (common.ValueExpression, any, error) {
	what.literal = common.ToLiteral(script)
	what.value = script

	return what, nil, nil
}

func (what *ValueExpression) ParseAny(script any) (common.Expression, any, error) {
	what.literal = common.ToLiteral(script)
	what.value = script

	return what, nil, nil
}

func (what *ValueExpression) EvalArray(scope *common.Scope) (*common.ArrayValue, string, error) {
	return what.evalArray(scope, common.SomeValue(what.value, common.NewHistory(what.literal)))
}

func (what *ValueExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	return what.evalBool(scope, common.SomeValue(what.value, common.NewHistory(what.literal)))
}

func (what *ValueExpression) EvalDecimal(scope *common.Scope) (*common.DecimalValue, string, error) {
	return what.evalDecimal(scope, common.SomeValue(what.value, common.NewHistory(what.literal)))
}

func (what *ValueExpression) EvalString(scope *common.Scope) (*common.StringValue, string, error) {
	return what.evalString(scope, common.SomeValue(what.value, common.NewHistory(what.literal)))
}

func (what *ValueExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.evalAny(scope, common.SomeValue(what.value, common.NewHistory(what.literal)))
}

func (what *ValueExpression) evalArray(scope *common.Scope, anyValue common.Value) (*common.ArrayValue, string, error) {
	switch castValue := anyValue.(type) {
	case *common.StringValue:
		value, errorLiteral, evalError := what.evalStringReference(scope, castValue)
		if evalError != nil {
			return common.EmptyArrayValue(), errorLiteral, evalError
		}

		arrayValue, arrayValueError := common.ToArrayValue(value)
		return arrayValue, what.Literal(), arrayValueError

	case *common.ArrayValue:
		array := make([]common.Value, 0)
		for _, item := range castValue.ArrayValue() {
			value, errorLiteral, evalError := what.evalAny(scope, item)
			if evalError != nil {
				return nil, errorLiteral, evalError
			}

			array = append(array, value)
		}

		return common.SomeArrayValue(array, common.NewHistory(what.literal)), "", nil

	case nil:
		return common.EmptyArrayValue(), "", nil

	default:
		return nil, what.Literal(), fmt.Errorf("failed to eval value-expression: value type %T is not an array", what.value)
	}
}

func (what *ValueExpression) evalBool(scope *common.Scope, anyValue common.Value) (*common.BoolValue, string, error) {
	switch castValue := anyValue.(type) {
	case *common.StringValue:
		return what.stringToBool(scope, castValue)

	case *common.BoolValue:
		return castValue, "", nil

	case nil:
		return common.SomeBoolValue(false, common.NewHistory(what.literal)), "", nil

	default:
		return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to eval value-expression: value type %T is not a bool", what.value)
	}
}

func (what *ValueExpression) evalDecimal(scope *common.Scope, anyValue common.Value) (*common.DecimalValue, string, error) {
	switch castValue := anyValue.(type) {
	case *common.StringValue:
		return what.stringToDecimal(scope, castValue)

	case *common.DecimalValue:
		return castValue, "", nil

	case nil:
		return common.SomeDecimalValue(decimal.Zero, common.NewHistory(what.literal)), "", nil

	default:
		return common.EmptyDecimalValue(), what.Literal(), fmt.Errorf("failed to eval value-expression: value type %T is not a decimal", what.value)
	}
}

func (what *ValueExpression) evalString(scope *common.Scope, anyValue common.Value) (*common.StringValue, string, error) {
	switch castValue := anyValue.(type) {
	case *common.StringValue:
		return what.stringToString(scope, castValue)

	case nil:
		return common.SomeStringValue("", common.NewHistory(what.literal)), "", nil

	default:
		return common.EmptyStringValue(), what.Literal(), fmt.Errorf("failed to eval value-expression: value type %T is not a string", what.value)
	}
}

func (what *ValueExpression) evalAny(scope *common.Scope, anyValue common.Value) (common.Value, string, error) {
	switch castValue := anyValue.(type) {
	case *common.StringValue:
		return what.evalStringReference(scope, castValue)

	case *common.BoolValue:
		return castValue, "", nil

	case *common.DecimalValue:
		return castValue, "", nil

	case *common.ArrayValue:
		return what.evalArray(scope, castValue)

	case nil:
		return common.SomeValue(nil, common.NewHistory(what.literal)), "", nil

	default:
		return nil, what.Literal(), fmt.Errorf("failed to eval value-expression: value type is %T", what.value)
	}
}

func (what *ValueExpression) stringToBool(scope *common.Scope, valueString *common.StringValue) (*common.BoolValue, string, error) {
	value, errorLiteral, evalError := what.evalStringReference(scope, valueString) // resolve references
	if evalError != nil {
		return common.EmptyBoolValue(), errorLiteral, evalError
	}

	switch castValue := value.Value().(type) {
	case string: // string literal
		if len(castValue) == 0 {
			return common.SomeBoolValue(false, value.History()), "", nil
		}

		boolValue, parseError := strconv.ParseBool(castValue)
		if parseError != nil {
			return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to parse value-expression: %w", parseError)
		}

		return common.SomeBoolValue(boolValue, value.History()), "", nil

	case fmt.Stringer: // string literal
		if len(castValue.String()) == 0 {
			return common.SomeBoolValue(false, value.History()), "", nil
		}

		boolValue, parseError := strconv.ParseBool(castValue.String())
		if parseError != nil {
			return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to parse value-expression: %w", parseError)
		}

		return common.SomeBoolValue(boolValue, value.History()), "", nil

	case bool: // bool value
		return common.SomeBoolValue(castValue, value.History()), "", nil

	case nil: // empty value
		return common.SomeBoolValue(false, value.History()), "", nil

	case common.Value:
		return what.evalBool(scope, castValue)

	default:
		return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("expected value-expression to eval to a bool instead of %T", value)
	}
}

func (what *ValueExpression) stringToDecimal(scope *common.Scope, valueString *common.StringValue) (*common.DecimalValue, string, error) {
	value, errorLiteral, evalError := what.evalStringReference(scope, valueString)
	if evalError != nil {
		return common.EmptyDecimalValue(), errorLiteral, evalError
	}

	switch castValue := value.Value().(type) {
	case decimal.Decimal:
		return common.SomeDecimalValue(castValue, value.History()), "", nil

	case string:
		decimalValue, parseError := decimal.NewFromString(castValue)
		if parseError != nil {
			return common.EmptyDecimalValue(), what.Literal(), fmt.Errorf("failed to parse value-expression: %w", parseError)
		}

		return common.SomeDecimalValue(decimalValue, value.History()), "", nil

	case fmt.Stringer:
		decimalValue, parseError := decimal.NewFromString(castValue.String())
		if parseError != nil {
			return common.EmptyDecimalValue(), what.Literal(), fmt.Errorf("failed to parse value-expression: %w", parseError)
		}

		return common.SomeDecimalValue(decimalValue, value.History()), "", nil

	case nil:
		return common.SomeDecimalValue(decimal.Zero, value.History()), "", nil

	default:
		return common.EmptyDecimalValue(), what.Literal(), fmt.Errorf("expected value-expression to eval to a decimal instead of %T", value)
	}
}

func (what *ValueExpression) stringToString(scope *common.Scope, valueString *common.StringValue) (*common.StringValue, string, error) {
	value, errorLiteral, evalError := what.evalStringReference(scope, valueString)
	if evalError != nil {
		return common.EmptyStringValue(), errorLiteral, evalError
	}

	switch castValue := value.Value().(type) {
	case string:
		return common.SomeStringValue(castValue, value.History()), "", nil

	case fmt.Stringer:
		return common.SomeStringValue(castValue.String(), value.History()), "", nil

	case *common.StringValue:
		return castValue, "", nil

	case nil:
		return common.EmptyStringValue(), "", nil

	default:
		return common.EmptyStringValue(), what.Literal(), fmt.Errorf("expected value-expression to eval to a string instead of %T", value)
	}
}

func (what *ValueExpression) evalStringReference(scope *common.Scope, ref *common.StringValue) (common.Value, string, error) {
	var history common.History
	varRe := `\{[^{}]+}`
	value := what.resolveStringValues(scope, varRe, ref)
	if value.StringValue() != ref.StringValue() {
		history = common.NewHistory(ref.StringValue()).From(ref.History())
	}

	if regexp.MustCompile(`^` + varRe + `$`).MatchString(value.StringValue()) {
		returnValue, _ := scope.Get(value.StringValue()[1 : len(value.StringValue())-1])
		return returnValue, "", nil
	}

	funcRe := `(\w+)\(([^()]+)\)`
	resolvedValue, errorLiteral, evalError := what.resolveMethodCalls(scope, funcRe, value)
	if evalError != nil {
		return common.EmptyStringValue(), errorLiteral, evalError
	}

	if regexp.MustCompile(`^` + funcRe + `$`).MatchString(resolvedValue.StringValue()) {
		genericValue, genericErrorLiteral, genericEvalError := what.resolveMethodCall(scope, funcRe, resolvedValue)
		return common.SomeValue(genericValue, history), genericErrorLiteral, genericEvalError
	}

	return common.SomeValue(resolvedValue, history), "", nil
}

func (what *ValueExpression) resolveStringValues(scope *common.Scope, reString string, value *common.StringValue) *common.StringValue {
	replacements := 0
	text := regexp.MustCompile(reString).ReplaceAllStringFunc(value.StringValue(), func(name string) string {
		cleanName := name[1 : len(name)-1]
		item, ok := scope.Get(strings.ToLower(cleanName))
		if !ok {
			return name
		}

		switch castItem := item.Value().(type) {
		case string:
			replacements++
			return castItem

		case fmt.Stringer:
			replacements++
			return castItem.String()

		case common.Value:
			stringValue := castItem.PlainValue()
			switch castStringValue := stringValue.(type) {
			case string:
				replacements++
				return castStringValue

			case fmt.Stringer:
				replacements++
				return castStringValue.String()

			default:
				return name
			}

		default:
			return name
		}
	})

	if replacements > 0 {
		return what.resolveStringValues(scope, reString, common.SomeStringValue(text, common.NewHistory(value.StringValue()).From(value.History())))
	}

	return common.SomeStringValue(text, common.NewHistory(value.StringValue()).From(value.History()))
}

func (what *ValueExpression) resolveMethodCalls(scope *common.Scope, reString string, value *common.StringValue) (*common.StringValue, string, error) {
	replacements := 0
	re := regexp.MustCompile(reString)
	text := re.ReplaceAllStringFunc(value.StringValue(), func(name string) string {
		returnValue, _, callError := what.resolveMethodCall(scope, reString, common.SomeStringValue(name, value.History()))
		if callError != nil {
			return name
		}

		if returnValue != nil {
			stringValue, valueError := common.ToString(returnValue)
			if valueError != nil {
				return name
			}

			replacements++
			return stringValue.StringValue()
		}

		return name
	})

	if replacements == 0 {
		return common.SomeStringValue(text, common.NewHistory(value.StringValue()).From(value.History())), "", nil
	}

	return what.resolveMethodCalls(scope, reString, common.SomeStringValue(text, common.NewHistory(value.StringValue()).From(value.History())))
}

func (what *ValueExpression) resolveMethodCall(scope *common.Scope, reString string, value *common.StringValue) (common.Value, string, error) {
	re := regexp.MustCompile(reString)

	match := re.FindStringSubmatch(value.StringValue())
	if len(match) != 3 {
		return common.NilValue(), what.Literal(), fmt.Errorf("method call match failed for %q", value)
	}

	name := strings.ToLower(match[1])
	args := make([]common.Value, 0)
	if len(strings.TrimSpace(match[2])) > 0 {
		// todo: better arg parsing for '{var1}, {var2}'
		for _, arg := range strings.Split(match[2], ",") {
			val, errorLiteral, evalError := what.evalStringReference(scope, common.SomeStringValue(strings.TrimSpace(arg), common.NewHistory(value.StringValue()).From(value.History())))
			if evalError != nil {
				return nil, errorLiteral, fmt.Errorf("failed to eval method parameter: %w", evalError)
			}

			args = append(args, val)
		}
	}

	method, ok := scope.Methods[name]
	if ok {
		newScope, cloneError := scope.Clone()
		if cloneError != nil {
			return common.NilValue(), what.Literal(), fmt.Errorf("failed to clone scope: %w", cloneError)
		}

		newScope.Args = args
		errorLiteral, runError := method.Run(newScope)
		if runError != nil {
			return common.NilValue(), errorLiteral, fmt.Errorf("failed to run method %q: %w", name, runError)
		}

		return newScope.GetReturnValue(), "", nil
	}

	if common.IsBuiltIn(name) {
		callValue, callError := common.CallBuiltIn(name, args...)
		if callError != nil {
			return common.NilValue(), what.Literal(), fmt.Errorf("failed to call %q: %w", name, callError)
		}

		return callValue, "", nil
	}

	return common.NilValue(), what.Literal(), fmt.Errorf("no method %q", match[1])
}

func (what *ValueExpression) Literal() string {
	return what.literal
}
