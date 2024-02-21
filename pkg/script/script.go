package script

import (
	"fmt"
	"github.com/threagile/threagile/pkg/script/common"
	"github.com/threagile/threagile/pkg/script/expressions"
	"github.com/threagile/threagile/pkg/script/statements"
	"github.com/threagile/threagile/pkg/security/types"
	"gopkg.in/yaml.v3"
	"strings"
)

type Script struct {
	match common.Statement
	risk  map[string]any
	utils map[string]*statements.MethodStatement
}

func (what *Script) Parse(text []byte) error {
	items := make(map[string]any)
	parseError := yaml.Unmarshal(text, &items)
	if parseError != nil {
		return parseError
	}

	for key, value := range items {
		switch strings.ToLower(key) {
		case common.Risk:
			switch value.(type) {
			case map[string]any:
				what.risk = value.(map[string]any)

			default:
				return fmt.Errorf("failed to parse %q: unexpected script type %T\nscript:\n%v", key, value, what.AddLineNumbers(value))
			}

		case common.Match:
			item, errorScript, itemError := new(statements.MethodStatement).Parse(value)
			if itemError != nil {
				return fmt.Errorf("failed to parse %q: %v\nscript:\n%v", key, itemError, what.AddLineNumbers(errorScript))
			}

			what.match = item

		case common.Utils:
			item, errorScript, itemError := what.parseUtils(value)
			if itemError != nil {
				return fmt.Errorf("failed to parse %q: %v\nscript:\n%v", key, itemError, what.AddLineNumbers(errorScript))
			}

			what.utils = item
		}
	}

	return nil
}

func (what *Script) GenerateRisks(scope *common.Scope) (map[string]*types.Risk, string, error) {
	value, valueOk := what.getItem(scope.Model, "technical_assets")
	if !valueOk {
		return nil, "", fmt.Errorf("no technical assets in scope")
	}

	techAssets, techAssetsOk := value.(map[string]any)
	if !techAssetsOk {
		return nil, "", fmt.Errorf("unexpected format of technical assets %T", techAssets)
	}

	risks := make(map[string]*types.Risk)
	for _, techAsset := range techAssets {
		matchScope, matchCloneError := scope.Clone()
		if matchCloneError != nil {
			return nil, "", fmt.Errorf("failed to clone scope: %v", matchCloneError)
		}

		matchScope.Args = append(matchScope.Args, techAsset)
		isMatch, errorMatchLiteral, matchError := what.matchRisk(matchScope)
		if matchError != nil {
			return nil, errorMatchLiteral, matchError
		}

		if isMatch {
			fmt.Printf("risk: %v\n", what.getRiskID(matchScope, techAsset))

			riskScope, riskCloneError := scope.Clone()
			if riskCloneError != nil {
				return nil, "", fmt.Errorf("failed to clone scope: %v", riskCloneError)
			}

			riskScope.Args = append(riskScope.Args, techAsset)
			risk, errorRiskLiteral, riskError := what.generateRisk(riskScope)
			if riskError != nil {
				return nil, errorRiskLiteral, riskError
			}

			risks[risk.SyntheticId] = risk
		}
	}

	return risks, "", nil
}

func (what *Script) Utils() map[string]common.Statement {
	utils := make(map[string]common.Statement)
	for name, item := range what.utils {
		utils[name] = item
	}

	return utils
}

func (what *Script) AddLineNumbers(script any) string {
	text, isString := script.(string)
	if !isString {
		data, _ := yaml.Marshal(script)
		text = string(data)
	}

	lines := strings.Split(text, "\n")
	for n, line := range lines {
		lines[n] = fmt.Sprintf("%3d:\t%v", n+1, line)
	}

	return strings.Join(lines, "\n")
}

func (what *Script) IndentPrintf(level int, script any) string {
	text, isString := script.(string)
	if !isString {
		data, _ := yaml.Marshal(script)
		text = string(data)
	}

	lines := strings.Split(text, "\n")
	for n, line := range lines {
		lines[n] = strings.Repeat("    ", level) + line
	}

	return strings.Join(lines, "\n")
}

func (what *Script) IndentLine(level int, format string, params ...any) string {
	return strings.Repeat("    ", level) + fmt.Sprintf(format, params...)
}

func (what *Script) matchRisk(scope *common.Scope) (bool, string, error) {
	if what.match == nil {
		return false, "", nil
	}

	errorLiteral, runError := what.match.Run(scope)
	if runError != nil {
		return false, errorLiteral, runError
	}

	switch scope.GetReturnValue().(type) {
	case bool:
		return scope.GetReturnValue().(bool), "", nil
	}

	return false, "", nil
}

func (what *Script) getRiskID(scope *common.Scope, techAsset any) string {
	riskIdValue, riskIdValueOk := what.getItem(scope.Risk, "id")
	if !riskIdValueOk {
		return ""
	}

	riskId, riskIdOk := riskIdValue.(string)
	if !riskIdOk {
		return ""
	}

	assetIdValue, assetIdValueOk := what.getItem(techAsset, "id")
	if !assetIdValueOk {
		return ""
	}

	assetId, assetIdOk := assetIdValue.(string)
	if !assetIdOk {
		return ""
	}

	return fmt.Sprintf("%v@%v", riskId, assetId)
}

func (what *Script) generateRisk(scope *common.Scope) (*types.Risk, string, error) {
	if what.risk == nil {
		return nil, "", fmt.Errorf("no risk template")
	}

	parameter, ok := what.risk[common.Parameter]
	if ok {
		switch parameter.(type) {
		case string:
			if len(scope.Args) != 1 {
				return nil, common.ToLiteral(parameter), fmt.Errorf("expected single parameter, got %d", len(scope.Args))
			}

			if scope.Vars == nil {
				scope.Vars = make(map[string]common.Value)
			}

			scope.Vars[parameter.(string)] = scope.Args[0]

		default:
			return nil, common.ToLiteral(parameter), fmt.Errorf("unexpected parameter format %T", parameter)
		}
	}

	riskMap := make(map[string]any)
	for name, value := range what.risk {
		expression, errorParseLiteral, parseError := new(expressions.ValueExpression).ParseValue(value)
		if parseError != nil {
			return nil, common.ToLiteral(errorParseLiteral), fmt.Errorf("failed to parse field value: %v", parseError)
		}

		newValue, errorEvalLiteral, evalError := expression.EvalAny(scope)
		if parseError != nil {
			return nil, errorEvalLiteral, fmt.Errorf("failed to eval field value: %v", evalError)
		}

		riskMap[name] = newValue
	}

	riskData, marshalError := yaml.Marshal(&riskMap)
	if marshalError != nil {
		return nil, common.ToLiteral(riskMap), fmt.Errorf("failed to print risk: %v", marshalError)
	}

	var risk types.Risk
	unmarshalError := yaml.Unmarshal(riskData, &risk)
	if unmarshalError != nil {
		return nil, string(riskData), fmt.Errorf("failed to parse risk: %v", unmarshalError)
	}

	risk.CategoryId, _ = what.getItemString(scope.Risk, "id")
	risk.SyntheticId, _ = what.getItemString(riskMap, "id")

	if len(risk.SyntheticId) == 0 {
		risk.SyntheticId = risk.CategoryId + "@" + risk.MostRelevantDataAssetId
	}

	return &risk, "", nil
}

func (what *Script) getItemString(value any, path ...string) (string, bool) {
	item, itemOk := what.getItem(value, path...)
	if !itemOk {
		return "", false
	}

	itemString, itemStringOk := item.(string)
	if !itemStringOk {
		return "", false
	}

	return itemString, true
}

func (what *Script) getItem(value any, path ...string) (any, bool) {
	if len(path) == 0 {
		return nil, false
	}

	object, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}

	for name, item := range object {
		if strings.EqualFold(path[0], name) {
			if len(path[1:]) > 0 {
				return what.getItem(item)
			}

			return item, true
		}
	}

	return nil, false
}

func (what *Script) parseUtils(script any) (map[string]*statements.MethodStatement, any, error) {
	statementMap := make(map[string]*statements.MethodStatement)
	switch script.(type) {
	case map[string]any:
		for key, value := range script.(map[string]any) {
			methodStatement := new(statements.MethodStatement)
			_, errorScript, parseError := methodStatement.Parse(value)
			if parseError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse method %q: %v", key, parseError)
			}

			statementMap[key] = methodStatement
		}

	case []any:
		for n, value := range script.([]any) {
			newStatementMap, errorScript, parseError := what.parseUtils(value)
			if parseError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse method #%d: %v", n+1, parseError)
			}

			for name, method := range newStatementMap {
				_, ok := statementMap[name]
				if ok {
					return nil, errorScript, fmt.Errorf("method %q redefined", name)
				}

				statementMap[name] = method
			}
		}

	default:
		return nil, script, fmt.Errorf("unexpected utils format %T", script)
	}

	return statementMap, nil, nil
}
