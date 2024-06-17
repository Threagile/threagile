package statements

import (
	"fmt"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

type Statement struct {
}

func (what *Statement) Parse(name string, body any) (common.Statement, any, error) {
	switch name {
	case common.Assign:
		statement, errorScript, parseError := new(AssignStatement).Parse(body)
		if parseError != nil {
			return nil, errorScript, fmt.Errorf("failed to parse %q-statement: %w", name, parseError)
		}

		return statement, errorScript, parseError

	case common.Defer:
		statement, errorScript, parseError := new(DeferStatement).Parse(body)
		if parseError != nil {
			return nil, errorScript, fmt.Errorf("failed to parse %q-statement: %w", name, parseError)
		}

		return statement, errorScript, parseError

	case common.Explain:
		statement, errorScript, parseError := new(ExplainStatement).Parse(body)
		if parseError != nil {
			return nil, errorScript, fmt.Errorf("failed to parse %q-statement: %w", name, parseError)
		}

		return statement, errorScript, parseError

	case common.If:
		statement, errorScript, parseError := new(IfStatement).Parse(body)
		if parseError != nil {
			return nil, errorScript, fmt.Errorf("failed to parse %q-statement: %w", name, parseError)
		}

		return statement, errorScript, parseError

	case common.Loop:
		statement, errorScript, parseError := new(LoopStatement).Parse(body)
		if parseError != nil {
			return nil, errorScript, fmt.Errorf("failed to parse %q-statement: %w", name, parseError)
		}

		return statement, errorScript, parseError

	case common.Return:
		statement, errorScript, parseError := new(ReturnStatement).Parse(body)
		if parseError != nil {
			return nil, errorScript, fmt.Errorf("failed to parse %q-statement: %w", name, parseError)
		}

		return statement, errorScript, parseError

	default:
		return nil, body, fmt.Errorf("failed to parse statement: unexpected keyword %q", name)
	}
}
