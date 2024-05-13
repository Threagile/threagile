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
	id    map[string]any
	match common.Statement
	data  map[string]any
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
				return nil, fmt.Errorf("unexpected format %T in data definition", value)
			}

			scripts := make(map[string]*Script)
			for scriptID, riskScript := range riskScripts {
				risk, ok := riskScript.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("unexpected format %T in data definition for %q", riskScript, scriptID)
				}

				script, scriptError := new(Script).ParseScript(risk)
				if scriptError != nil {
					return nil, fmt.Errorf("failed to parse script of data definition for %q: %v", scriptID, scriptError)
				}

				scripts[scriptID] = script
			}

			return scripts, nil

		default:
			return nil, fmt.Errorf("unexpected key %q in data definition", key)
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
		case common.Risk:
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
		case common.ID:
			stringItem, ok := value.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("ID expression is not a script (map[string]any)")
			}

			what.id = stringItem

		case common.Data:
			switch castValue := value.(type) {
			case map[string]any:
				what.data = castValue

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

func (what *Script) GetTechnicalAssetsByRiskID(scope *common.Scope, riskID string) ([]any, error) {
	value, valueOk := what.getItem(scope.Model, "technical_assets")
	if !valueOk {
		return nil, fmt.Errorf("no technical assets in scope")
	}

	techAssets, techAssetsOk := value.(map[string]any)
	if !techAssetsOk {
		return nil, fmt.Errorf("unexpected format of technical assets %T", techAssets)
	}

	matchingTechAssets := make([]any, 0)
	for techAssetName, techAsset := range techAssets {
		_ = techAssetName

		isMatch, _, matchError := what.matchRisk(scope, techAsset)
		if matchError != nil {
			return nil, matchError
		}

		if !isMatch {
			continue
		}

		matchingTechAssets = append(matchingTechAssets, techAsset)
	}

	return matchingTechAssets, nil
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
	for techAssetName, techAsset := range techAssets {
		_ = techAssetName

		isMatch, errorMatchLiteral, matchError := what.matchRisk(scope, techAsset)
		if matchError != nil {
			return nil, errorMatchLiteral, matchError
		}

		if !isMatch {
			continue
		}

		risk, errorRiskLiteral, riskError := what.generateRisk(scope, techAsset)
		if riskError != nil {
			return nil, errorRiskLiteral, riskError
		}

		if risk == nil {
			continue
		}

		riskId, errorGetIDLiteral, errorId := what.getRiskID(scope, techAsset)
		if errorId != nil {
			return nil, errorGetIDLiteral, errorId
		}

		risk.SyntheticId = riskId
		if len(risk.SyntheticId) == 0 {
			risk.SyntheticId = risk.CategoryId + "@" + risk.MostRelevantDataAssetId
		}

		risks = append(risks, risk)
	}

	return risks, "", nil
}

func (what *Script) matchRisk(outerScope *common.Scope, techAsset any) (bool, string, error) {
	if what.match == nil {
		return false, "", nil
	}

	scope, cloneError := outerScope.Clone()
	if cloneError != nil {
		return false, "", fmt.Errorf("failed to clone scope: %v", cloneError)
	}

	scope.Args = append(scope.Args, techAsset)

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

func (what *Script) generateRisk(outerScope *common.Scope, techAsset any) (*types.Risk, string, error) {
	if what.data == nil {
		return nil, "", fmt.Errorf("no data template")
	}

	scope, cloneError := outerScope.Clone()
	if cloneError != nil {
		return nil, "", fmt.Errorf("failed to clone scope: %v", cloneError)
	}

	scope.Args = append(scope.Args, techAsset)

	parameter, ok := what.data[common.Parameter]
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
	for name, value := range what.data {
		expression, errorParseLiteral, parseError := new(expressions.ValueExpression).ParseValue(value)
		if parseError != nil {
			return nil, common.ToLiteral(errorParseLiteral), fmt.Errorf("failed to parse field value: %v", parseError)
		}

		newValue, errorEvalLiteral, evalError := expression.EvalAny(scope)
		if evalError != nil {
			return nil, errorEvalLiteral, fmt.Errorf("failed to eval field value: %v", evalError)
		}

		riskMap[name] = newValue
	}

	riskData, marshalError := yaml.Marshal(&riskMap)
	if marshalError != nil {
		return nil, common.ToLiteral(riskMap), fmt.Errorf("failed to print data: %v", marshalError)
	}

	var risk types.Risk
	unmarshalError := yaml.Unmarshal(riskData, &risk)
	if unmarshalError != nil {
		return nil, string(riskData), fmt.Errorf("failed to parse data: %v", unmarshalError)
	}

	risk.CategoryId, _ = what.getItemString(scope.Risk, "id")

	return &risk, "", nil
}

func (what *Script) getRiskID(outerScope *common.Scope, techAsset any) (string, string, error) {
	if len(what.id) == 0 {
		return "", "", fmt.Errorf("no ID expression")
	}

	scope, cloneError := outerScope.Clone()
	if cloneError != nil {
		return "", "", fmt.Errorf("failed to clone scope: %v", cloneError)
	}

	scope.Args = append(scope.Args, techAsset)

	parameter, parameterOk := what.id[common.Parameter]
	if parameterOk {
		switch castParameter := parameter.(type) {
		case string:
			if len(scope.Args) != 1 {
				return "", common.ToLiteral(parameter), fmt.Errorf("expected single parameter, got %d", len(scope.Args))
			}

			if scope.Vars == nil {
				scope.Vars = make(map[string]common.Value)
			}

			scope.Vars[castParameter] = scope.Args[0]

		default:
			return "", common.ToLiteral(parameter), fmt.Errorf("unexpected parameter format %T", parameter)
		}
	}

	id, idOk := what.id[common.ID]
	if idOk {
		expression, errorParseLiteral, parseError := new(expressions.ValueExpression).ParseValue(id)
		if parseError != nil {
			return "", common.ToLiteral(errorParseLiteral), fmt.Errorf("failed to parse ID expression: %v", parseError)
		}

		value, errorEvalLiteral, evalError := expression.EvalString(scope)
		if evalError != nil {
			return "", errorEvalLiteral, evalError
		}

		return value, "", nil
	}

	return "", "", nil
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
