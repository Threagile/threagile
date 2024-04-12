package script

import (
	"fmt"
	"github.com/threagile/threagile/pkg/input"
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

func (what *Script) NewScope(risk *types.RiskCategory) (*common.Scope, error) {
	methods := make(map[string]common.Statement)
	for name, method := range what.utils {
		methods[name] = method
	}

	scope := new(common.Scope)
	scopeError := scope.Init(risk, methods)
	if scopeError != nil {
		return scope, fmt.Errorf("error initializing scope: %v\n", scopeError)
	}

	return scope, nil
}

func (what *Script) ParseScriptsFromData(text []byte) (map[string]*Script, error) {
	items := make(map[string]any)
	parseError := yaml.Unmarshal(text, &items)
	if parseError != nil {
		return nil, parseError
	}

	return what.ParseScripts(items)
}

func (what *Script) ParseScripts(items map[string]any) (map[string]*Script, error) {
	for key, value := range items {
		switch strings.ToLower(key) {
		case "individual_risk_categories":
			riskScripts, ok := value.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("unexpected format %T in risk definition", value)
			}

			scripts := make(map[string]*Script)
			for scriptID, riskScript := range riskScripts {
				risk, ok := riskScript.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("unexpected format %T in risk definition for %q", riskScript, scriptID)
				}

				script, scriptError := new(Script).ParseScript(risk)
				if scriptError != nil {
					return nil, fmt.Errorf("failed to parse script of risk definition for %q: %v", scriptID, scriptError)
				}

				scripts[scriptID] = script
			}

			return scripts, nil

		default:
			return nil, fmt.Errorf("unexpected key %q in risk definition", key)
		}
	}

	return nil, fmt.Errorf("no scripts found")
}

func (what *Script) ParseCategoryFromData(text []byte) (*Script, error) {
	items := make(map[string]any)
	parseError := yaml.Unmarshal(text, &items)
	if parseError != nil {
		return nil, parseError
	}

	return what.ParseCategory(items)
}

func (what *Script) ParseCategory(script map[string]any) (*Script, error) {
	for key, value := range script {
		switch strings.ToLower(key) {
		case common.Script:
			switch castValue := value.(type) {
			case map[string]any:
				return what.ParseScript(castValue)

			default:
				return what, fmt.Errorf("failed to parse %q: unexpected script type %T\nscript:\n%v", key, value, new(input.Strings).AddLineNumbers(value))
			}
		}
	}

	return what, nil
}

func (what *Script) ParseScriptFromData(text []byte) (*Script, error) {
	items := make(map[string]any)
	parseError := yaml.Unmarshal(text, &items)
	if parseError != nil {
		return nil, parseError
	}

	return what.ParseScript(items)
}

func (what *Script) ParseScript(script map[string]any) (*Script, error) {
	for key, value := range script {
		switch strings.ToLower(key) {
		case common.Risk:
			switch castValue := value.(type) {
			case map[string]any:
				what.risk = castValue

			default:
				return what, fmt.Errorf("failed to parse %q: unexpected script type %T\nscript:\n%v", key, value, new(input.Strings).AddLineNumbers(value))
			}

		case common.Match:
			item, errorScript, itemError := new(statements.MethodStatement).Parse(value)
			if itemError != nil {
				return what, fmt.Errorf("failed to parse %q: %v\nscript:\n%v", key, itemError, new(input.Strings).AddLineNumbers(errorScript))
			}

			what.match = item

		case common.Utils:
			item, errorScript, itemError := what.parseUtils(value)
			if itemError != nil {
				return what, fmt.Errorf("failed to parse %q: %v\nscript:\n%v", key, itemError, new(input.Strings).AddLineNumbers(errorScript))
			}

			what.utils = item
		}
	}

	return what, nil
}

func (what *Script) GenerateRisks(scope *common.Scope) ([]*types.Risk, string, error) {
	value, valueOk := what.getItem(scope.Model, "technical_assets")
	if !valueOk {
		return nil, "", fmt.Errorf("no technical assets in scope")
	}

	techAssets, techAssetsOk := value.(map[string]any)
	if !techAssetsOk {
		return nil, "", fmt.Errorf("unexpected format of technical assets %T", techAssets)
	}

	risks := make([]*types.Risk, 0)
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
			riskScope, riskCloneError := scope.Clone()
			if riskCloneError != nil {
				return nil, "", fmt.Errorf("failed to clone scope: %v", riskCloneError)
			}

			riskScope.Args = append(riskScope.Args, techAsset)
			risk, errorRiskLiteral, riskError := what.generateRisk(riskScope)
			if riskError != nil {
				return nil, errorRiskLiteral, riskError
			}

			risks = append(risks, risk)
		}
	}

	return risks, "", nil
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

func (what *Script) generateRisk(scope *common.Scope) (*types.Risk, string, error) {
	if what.risk == nil {
		return nil, "", fmt.Errorf("no risk template")
	}

	parameter, ok := what.risk[common.Parameter]
	if ok {
		switch castParameter := parameter.(type) {
		case string:
			if len(scope.Args) != 1 {
				return nil, common.ToLiteral(parameter), fmt.Errorf("expected single parameter, got %d", len(scope.Args))
			}

			if scope.Vars == nil {
				scope.Vars = make(map[string]common.Value)
			}

			scope.Vars[castParameter] = scope.Args[0]

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
	switch castScript := script.(type) {
	case map[string]any:
		for key, value := range castScript {
			methodStatement := new(statements.MethodStatement)
			_, errorScript, parseError := methodStatement.Parse(value)
			if parseError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse method %q: %v", key, parseError)
			}

			statementMap[key] = methodStatement
		}

	case []any:
		for n, value := range castScript {
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
