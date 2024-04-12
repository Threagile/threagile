package script

import (
	"fmt"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/risks"
	"github.com/threagile/threagile/pkg/security/types"
	"gopkg.in/yaml.v3"
	"strings"
)

type RiskRule struct {
	risks.RiskRule
	category      types.RiskCategory
	supportedTags []string
	script        Script
}

func (what *RiskRule) Init() *RiskRule {
	return what
}

func (what *RiskRule) ParseFromData(text []byte) (*RiskRule, error) {
	items := make(map[string]any)
	parseError := yaml.Unmarshal(text, &items)
	if parseError != nil {
		return nil, parseError
	}

	return what.Parse(items)
}

func (what *RiskRule) Parse(items map[string]any) (*RiskRule, error) {
	// todo
	return nil, fmt.Errorf("not implemented")
}

func (what *RiskRule) Category() *types.RiskCategory {
	return &what.category
}

func (what *RiskRule) SupportedTags() []string {
	return what.supportedTags
}

func (what *RiskRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	newScope, scopeError := what.script.NewScope(&what.category)
	if scopeError != nil {
		return nil, scopeError
	}

	modelError := newScope.SetModel(parsedModel)
	if modelError != nil {
		return nil, modelError
	}

	newRisks, errorLiteral, riskError := what.script.GenerateRisks(newScope)
	if riskError != nil {
		msg := make([]string, 0)
		msg = append(msg, fmt.Sprintf("error generating risks: %v\n", riskError))

		if len(errorLiteral) > 0 {
			msg = append(msg, fmt.Sprintf("in:\n%v\n", new(input.Strings).IndentPrintf(1, errorLiteral)))
		}

		return nil, fmt.Errorf(strings.Join(msg, "\n"))
	}

	return newRisks, nil
}
