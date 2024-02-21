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

func (what *ValueExpression) EvalArray(scope *common.Scope) ([]any, string, error) {
	switch what.value.(type) {
	case string, fmt.Stringer:
		valueString := ""
		switch what.value.(type) {
		case string:
			valueString = what.value.(string)

		case fmt.Stringer:
			valueString = what.value.(fmt.Stringer).String()
		}

		value, errorLiteral, evalError := what.evalString(scope, valueString)
		if evalError != nil {
			return nil, errorLiteral, evalError
		}

		arrayValue, ok := value.([]any)
		if !ok {
			return nil, what.Literal(), fmt.Errorf("expected value-expression to eval to an array instead of %T", value)
		}

		return arrayValue, "", nil

	case []any:
		array := make([]any, 0)
		for _, item := range what.value.([]any) {
			value, errorLiteral, evalError := what.eval(scope, item)
			if evalError != nil {
				return nil, errorLiteral, evalError
			}

			array = append(array, value)
		}

		return array, "", nil

	case nil:
		return make([]any, 0), "", nil

	default:
		return nil, what.Literal(), fmt.Errorf("failed to eval value-expression: value type %T is not an array", what.value)
	}
}

func (what *ValueExpression) EvalBool(scope *common.Scope) (bool, string, error) {
	switch what.value.(type) {
	case string, fmt.Stringer:
		valueString := ""
		switch what.value.(type) {
		case string:
			valueString = what.value.(string)

		case fmt.Stringer:
			valueString = what.value.(fmt.Stringer).String()
		}

		value, errorLiteral, evalError := what.evalString(scope, valueString)
		if evalError != nil {
			return false, errorLiteral, evalError
		}

		switch castValue := value.(type) {
		case string, fmt.Stringer:
			stringValue := ""
			switch castStringValue := value.(type) {
			case string:
				stringValue = castStringValue

			case fmt.Stringer:
				stringValue = castStringValue.String()
			}

			if len(stringValue) == 0 {
				return false, "", nil
			}

			boolValue, parseError := strconv.ParseBool(stringValue)
			if parseError != nil {
				return false, what.Literal(), fmt.Errorf("failed to parse value-expression: %v", parseError)
			}

			return boolValue, "", nil

		case bool:
			return castValue, "", nil

		case nil:
			return false, "", nil

		default:
			return false, what.Literal(), fmt.Errorf("expected value-expression to eval to a bool instead of %T", value)
		}

	case bool:
		return what.value.(bool), "", nil

	case nil:
		return false, "", nil

	default:
		return false, what.Literal(), fmt.Errorf("failed to eval value-expression: value type %T is not a bool", what.value)
	}
}

func (what *ValueExpression) EvalDecimal(scope *common.Scope) (decimal.Decimal, string, error) {
	switch castOrigValue := what.value.(type) {
	case decimal.Decimal:
		return castOrigValue, "", nil

	case string, fmt.Stringer:
		valueString := ""
		switch castStringValue := what.value.(type) {
		case string:
			valueString = castStringValue

		case fmt.Stringer:
			valueString = castStringValue.String()
		}

		value, errorLiteral, evalError := what.evalString(scope, valueString)
		if evalError != nil {
			return decimal.NewFromInt(0), errorLiteral, evalError
		}

		switch castValue := value.(type) {
		case decimal.Decimal:
			return castValue, "", nil

		case string, fmt.Stringer:
			evalString := ""
			switch castStringValue := value.(type) {
			case string:
				evalString = castStringValue

			case fmt.Stringer:
				evalString = castStringValue.String()
			}

			decimalValue, parseError := decimal.NewFromString(evalString)
			if parseError != nil {
				return decimal.NewFromInt(0), what.Literal(), fmt.Errorf("failed to parse value-expression: %v", parseError)
			}

			return decimalValue, "", nil

		case nil:
			return decimal.NewFromInt(0), "", nil

		default:
			return decimal.NewFromInt(0), what.Literal(), fmt.Errorf("expected value-expression to eval to a decimal instead of %T", value)
		}

	case nil:
		return decimal.NewFromInt(0), "", nil

	default:
		return decimal.NewFromInt(0), what.Literal(), fmt.Errorf("failed to eval value-expression: value type %T is not a decimal", what.value)
	}
}

func (what *ValueExpression) EvalString(scope *common.Scope) (string, string, error) {
	switch what.value.(type) {
	case string, fmt.Stringer:
		valueString := ""
		switch what.value.(type) {
		case string:
			valueString = what.value.(string)

		case fmt.Stringer:
			valueString = what.value.(fmt.Stringer).String()

		case nil:
		}

		value, errorLiteral, evalError := what.evalString(scope, valueString)
		if evalError != nil {
			return "", errorLiteral, evalError
		}

		switch value.(type) {
		case string, fmt.Stringer:
			evalString := ""
			switch castStringValue := value.(type) {
			case string:
				evalString = castStringValue

			case fmt.Stringer:
				evalString = castStringValue.String()
			}

			return evalString, "", nil

		case nil:
			return "", "", nil

		default:
			return "", what.Literal(), fmt.Errorf("expected value-expression to eval to a string instead of %T", value)
		}

	default:
		return "", what.Literal(), fmt.Errorf("failed to eval value-expression: value type %T is not a string", what.value)
	}
}

func (what *ValueExpression) EvalAny(scope *common.Scope) (any, string, error) {
	switch what.value.(type) {
	case decimal.Decimal:
		return what.value.(decimal.Decimal), "", nil

	case string:
		return what.evalString(scope, what.value.(string))

	case fmt.Stringer:
		return what.evalString(scope, what.value.(fmt.Stringer).String())

	case bool:
		return what.value.(bool), "", nil

	case float64:
		return decimal.NewFromFloat(what.value.(float64)), "", nil

	case int64:
		return decimal.NewFromInt(what.value.(int64)), "", nil

	case []any:
		array := make([]any, 0)
		for _, item := range what.value.([]any) {
			value, errorLiteral, evalError := what.eval(scope, item)
			if evalError != nil {
				return nil, errorLiteral, evalError
			}

			array = append(array, value)
		}

		return array, "", nil

	case nil:
		return nil, "", nil

	default:
		return nil, what.Literal(), fmt.Errorf("failed to eval value-expression: value type is %T", what.value)
	}
}

func (what *ValueExpression) eval(scope *common.Scope, value any) (any, string, error) {
	switch castStringValue := value.(type) {
	case string:
		return what.evalString(scope, castStringValue)

	case fmt.Stringer:
		return what.evalString(scope, castStringValue.String())

	default:
		return value, "", nil
	}
}

func (what *ValueExpression) evalString(scope *common.Scope, value string) (any, string, error) {
	varRe := `\{[^{}]+}`
	value = what.resolveStringValues(scope, varRe, value)

	if regexp.MustCompile(`^` + varRe + `$`).MatchString(value) {
		returnValue, ok := scope.Get(value[1 : len(value)-1])
		if !ok {
			return "", "", nil
		}

		return returnValue, "", nil
	}

	funcRe := `(\w+)\(([^()]+)\)`
	resolvedValue, errorLiteral, evalError := what.resolveMethodCalls(scope, funcRe, value)
	if evalError != nil {
		return resolvedValue, errorLiteral, evalError
	}

	if regexp.MustCompile(`^` + funcRe + `$`).MatchString(resolvedValue) {
		return what.resolveMethodCall(scope, funcRe, resolvedValue)
	}

	return resolvedValue, "", nil
}

func (what *ValueExpression) resolveStringValues(scope *common.Scope, reString string, value string) string {
	replacements := 0
	text := regexp.MustCompile(reString).ReplaceAllStringFunc(value, func(name string) string {
		cleanName := name[1 : len(name)-1]
		item, ok := scope.Get(strings.ToLower(cleanName))
		if !ok {
			return name
		}

		switch castItem := item.(type) {
		case string:
			replacements++
			return castItem

		case fmt.Stringer:
			replacements++
			return castItem.String()

		default:
			return name
		}
	})

	if replacements > 0 {
		return what.resolveStringValues(scope, reString, text)
	}

	return text
}

func (what *ValueExpression) resolveMethodCalls(scope *common.Scope, reString string, value string) (string, string, error) {
	replacements := 0
	re := regexp.MustCompile(reString)
	text := re.ReplaceAllStringFunc(value, func(name string) string {
		returnValue, _, callError := what.resolveMethodCall(scope, reString, name)
		if callError != nil {
			return name
		}

		switch castReturnValue := returnValue.(type) {
		case string:
			replacements++
			return castReturnValue

		case fmt.Stringer:
			replacements++
			return castReturnValue.String()

		default:
			return name
		}
	})

	if replacements == 0 {
		return text, "", nil
	}

	return what.resolveMethodCalls(scope, reString, text)
}

func (what *ValueExpression) resolveMethodCall(scope *common.Scope, reString string, value string) (any, string, error) {
	re := regexp.MustCompile(reString)

	match := re.FindStringSubmatch(value)
	if len(match) != 3 {
		return value, what.Literal(), fmt.Errorf("method call match failed for %q", value)
	}

	name := strings.ToLower(match[1])
	args := make([]common.Value, 0)
	if len(strings.TrimSpace(match[2])) > 0 {
		// todo: better arg parsing for '{var1}, {var2}'
		for _, arg := range strings.Split(match[2], ",") {
			val, errorLiteral, evalError := what.evalString(scope, strings.TrimSpace(arg))
			if evalError != nil {
				return nil, errorLiteral, fmt.Errorf("failed to eval method parameter: %v", evalError)
			}

			args = append(args, val)
		}
	}

	method, ok := scope.Methods[name]
	if ok {
		newScope, cloneError := scope.Clone()
		if cloneError != nil {
			return value, what.Literal(), fmt.Errorf("failed to clone scope: %v", cloneError)
		}

		newScope.Args = args
		errorLiteral, runError := method.Run(newScope)
		if runError != nil {
			return value, errorLiteral, runError
		}

		return newScope.GetReturnValue(), "", nil
	}

	if common.IsBuiltIn(name) {
		callValue, callError := common.CallBuiltIn(name, args...)
		if callError != nil {
			return callValue, what.Literal(), fmt.Errorf("failed to call %q: %v", name, callError)
		}

		return callValue, "", nil
	}

	return value, what.Literal(), fmt.Errorf("no method %q", match[1])
}

func (what *ValueExpression) Literal() string {
	return what.literal
}
