package script

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

type mockFormatter struct{}

func (m *mockFormatter) AddLineNumbers(script any) string {
	return fmt.Sprintf("%v", script)
}

func TestNewScript(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)
	assert.NotNil(t, s)
	assert.Same(t, f, s.formatter)
}

func TestParseScript_ValidSections(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	script := map[string]any{
		"id": map[string]any{
			"parameter": "tech_asset",
			"id":        "{tech_asset.id}",
		},
		"data": map[string]any{
			"parameter": "tech_asset",
			"title":     "some title",
		},
	}

	result, err := s.ParseScript(script)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.id)
	assert.NotNil(t, result.data)
}

func TestParseScript_WithMatch(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	script := map[string]any{
		"match": map[string]any{
			"parameter": "tech_asset",
			"do": []any{
				map[string]any{
					"return": true,
				},
			},
		},
	}

	result, err := s.ParseScript(script)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.match)
}

func TestParseScript_EmptyMap(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	result, err := s.ParseScript(map[string]any{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Nil(t, result.id)
	assert.Nil(t, result.match)
	assert.Nil(t, result.data)
	assert.Nil(t, result.utils)
}

func TestParseScript_WithUtils(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	script := map[string]any{
		"utils": map[string]any{
			"my_method": map[string]any{
				"parameter": "x",
				"do": []any{
					map[string]any{
						"return": true,
					},
				},
			},
		},
	}

	result, err := s.ParseScript(script)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.utils)
	assert.Contains(t, result.utils, "my_method")
}

func TestParseScript_InvalidIDFormat(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	script := map[string]any{
		"id": "not-a-map",
	}

	_, err := s.ParseScript(script)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ID expression is not a script")
}

func TestParseScript_InvalidDataFormat(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	script := map[string]any{
		"data": 42,
	}

	_, err := s.ParseScript(script)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected script type")
}

func TestParseScript_InvalidUtilsFormat(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	script := map[string]any{
		"utils": 42,
	}

	_, err := s.ParseScript(script)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected utils format")
}

func TestNewScope_CreatesScope(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	script := map[string]any{
		"utils": map[string]any{
			"my_util": map[string]any{
				"parameter": "x",
				"do": []any{
					map[string]any{
						"return": true,
					},
				},
			},
		},
	}

	parsed, err := s.ParseScript(script)
	assert.NoError(t, err)

	category := &types.RiskCategory{
		ID:    "test-cat",
		Title: "Test Category",
	}

	scope, scopeErr := parsed.NewScope(category)
	assert.NoError(t, scopeErr)
	assert.NotNil(t, scope)
	assert.NotNil(t, scope.Methods)
	assert.Contains(t, scope.Methods, "my_util")
	assert.Equal(t, category, scope.Category)
}

func TestNewScope_NilCategory(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	_, err := s.ParseScript(map[string]any{})
	assert.NoError(t, err)

	scope, scopeErr := s.NewScope(nil)
	assert.NoError(t, scopeErr)
	assert.NotNil(t, scope)
}

func TestNewScope_NoUtils(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	_, err := s.ParseScript(map[string]any{})
	assert.NoError(t, err)

	category := &types.RiskCategory{
		ID:    "test-cat",
		Title: "Test Category",
	}

	scope, scopeErr := s.NewScope(category)
	assert.NoError(t, scopeErr)
	assert.NotNil(t, scope)
	assert.NotNil(t, scope.Methods)
	assert.Empty(t, scope.Methods)
}

func TestGenerateRisks_NoTechnicalAssets(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	scriptMap := map[string]any{
		"match": map[string]any{
			"parameter": "tech_asset",
			"do": []any{
				map[string]any{
					"return": true,
				},
			},
		},
		"data": map[string]any{
			"parameter": "tech_asset",
			"title":     "Test risk",
		},
		"id": map[string]any{
			"parameter": "tech_asset",
			"id":        "test@{tech_asset.id}",
		},
	}

	parsed, err := s.ParseScript(scriptMap)
	assert.NoError(t, err)

	category := &types.RiskCategory{
		ID:    "test-rule",
		Title: "Test Rule",
	}

	scope, scopeErr := parsed.NewScope(category)
	assert.NoError(t, scopeErr)

	model := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{},
	}

	modelErr := scope.SetModel(model)
	assert.NoError(t, modelErr)

	_, _, riskErr := parsed.GenerateRisks(scope)
	assert.Error(t, riskErr)
	assert.Contains(t, riskErr.Error(), "no technical assets in scope")
}

func TestGenerateRisks_MatchingAsset(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	scriptMap := map[string]any{
		"match": map[string]any{
			"parameter": "tech_asset",
			"do": []any{
				map[string]any{
					"return": true,
				},
			},
		},
		"data": map[string]any{
			"parameter":                     "tech_asset",
			"title":                         "Test risk at {tech_asset.id}",
			"severity":                      "medium",
			"exploitation_likelihood":       "unlikely",
			"exploitation_impact":           "low",
			"most_relevant_technical_asset": "{tech_asset.id}",
		},
		"id": map[string]any{
			"parameter": "tech_asset",
			"id":        "test-rule@{tech_asset.id}",
		},
	}

	parsed, parseErr := s.ParseScript(scriptMap)
	assert.NoError(t, parseErr)

	category := &types.RiskCategory{
		ID:    "test-rule",
		Title: "Test Rule",
	}

	scope, scopeErr := parsed.NewScope(category)
	assert.NoError(t, scopeErr)

	model := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Test Asset",
			},
		},
	}

	modelErr := scope.SetModel(model)
	assert.NoError(t, modelErr)

	risks, errLiteral, riskErr := parsed.GenerateRisks(scope)
	assert.NoError(t, riskErr)
	assert.Empty(t, errLiteral)
	assert.Len(t, risks, 1)
	assert.Equal(t, "test-rule", risks[0].CategoryId)
	assert.Equal(t, "test-rule@ta1", risks[0].SyntheticId)
	assert.Equal(t, "ta1", risks[0].MostRelevantTechnicalAssetId)
}

func TestGenerateRisks_NoMatchReturnsEmpty(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	scriptMap := map[string]any{
		"match": map[string]any{
			"parameter": "tech_asset",
			"do": []any{
				map[string]any{
					"return": false,
				},
			},
		},
		"data": map[string]any{
			"parameter": "tech_asset",
			"title":     "Test risk",
		},
		"id": map[string]any{
			"parameter": "tech_asset",
			"id":        "test@{tech_asset.id}",
		},
	}

	parsed, parseErr := s.ParseScript(scriptMap)
	assert.NoError(t, parseErr)

	category := &types.RiskCategory{
		ID:    "test-rule",
		Title: "Test Rule",
	}

	scope, scopeErr := parsed.NewScope(category)
	assert.NoError(t, scopeErr)

	model := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:    "ta1",
				Title: "Test Asset",
			},
		},
	}

	modelErr := scope.SetModel(model)
	assert.NoError(t, modelErr)

	risks, errLiteral, riskErr := parsed.GenerateRisks(scope)
	assert.NoError(t, riskErr)
	assert.Empty(t, errLiteral)
	assert.Empty(t, risks)
}

func TestParseScriptFromData_ValidYAML(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	yamlData := []byte(`
id:
  parameter: tech_asset
  id: "test@{tech_asset.id}"
data:
  parameter: tech_asset
  title: "Test risk"
`)

	result, err := s.ParseScriptFromData(yamlData)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.id)
	assert.NotNil(t, result.data)
}

func TestParseScriptFromData_InvalidYAML(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	yamlData := []byte(`{invalid yaml: [`)

	_, err := s.ParseScriptFromData(yamlData)
	assert.Error(t, err)
}

func TestParseCategoryFromData(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	yamlData := []byte(`
risk:
  id:
    parameter: tech_asset
    id: "test@{tech_asset.id}"
  data:
    parameter: tech_asset
    title: "Test risk"
`)

	result, err := s.ParseCategoryFromData(yamlData)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.id)
	assert.NotNil(t, result.data)
}

func TestParseCategory_NoRiskSection(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	script := map[string]any{
		"something_else": "value",
	}

	result, err := s.ParseCategory(script)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Nil(t, result.id)
}

func TestParseCategory_InvalidRiskFormat(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	script := map[string]any{
		"risk": "not-a-map",
	}

	_, err := s.ParseCategory(script)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected script type")
}

func TestExplain_EmptyHistory(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	result := s.Explain(nil)
	assert.Empty(t, result)
}

func TestParseScripts_ValidFormat(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	items := map[string]any{
		"individual_risk_categories": map[string]any{
			"my-rule": map[string]any{
				"id": map[string]any{
					"parameter": "tech_asset",
					"id":        "test@{tech_asset.id}",
				},
			},
		},
	}

	scripts, err := s.ParseScripts(items)
	assert.NoError(t, err)
	assert.Len(t, scripts, 1)
	assert.Contains(t, scripts, "my-rule")
}

func TestParseScripts_UnexpectedKey(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	items := map[string]any{
		"unknown_key": map[string]any{},
	}

	_, err := s.ParseScripts(items)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected key")
}

func TestParseScripts_Empty(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	_, err := s.ParseScripts(map[string]any{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no scripts found")
}

func TestParseScripts_InvalidRiskCategoriesFormat(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	items := map[string]any{
		"individual_risk_categories": "not-a-map",
	}

	_, err := s.ParseScripts(items)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected format")
}

func TestParseScripts_InvalidRiskScriptFormat(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	items := map[string]any{
		"individual_risk_categories": map[string]any{
			"my-rule": "not-a-map",
		},
	}

	_, err := s.ParseScripts(items)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected format")
}

func TestGetItem_SingleLevel(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	data := map[string]any{
		"name": "hello",
	}

	result, ok := s.getItem(data, "name")
	assert.True(t, ok)
	assert.Equal(t, "hello", result)
}

func TestGetItem_NestedPath(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	data := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"level3": "deep-value",
			},
		},
	}

	result, ok := s.getItem(data, "level1", "level2", "level3")
	assert.True(t, ok)
	assert.Equal(t, "deep-value", result)
}

func TestGetItem_NestedPathMiddleLevel(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	data := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"value": "found",
			},
		},
	}

	result, ok := s.getItem(data, "level1", "level2")
	assert.True(t, ok)
	nested, isMap := result.(map[string]any)
	assert.True(t, isMap)
	assert.Equal(t, "found", nested["value"])
}

func TestGetItem_NotFound(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	data := map[string]any{
		"name": "hello",
	}

	_, ok := s.getItem(data, "missing")
	assert.False(t, ok)
}

func TestGetItem_NestedNotFound(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	data := map[string]any{
		"level1": map[string]any{
			"level2": "not-a-map",
		},
	}

	_, ok := s.getItem(data, "level1", "level2", "level3")
	assert.False(t, ok)
}

func TestGetItem_EmptyPath(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	_, ok := s.getItem(map[string]any{})
	assert.False(t, ok)
}

func TestGetItem_NonMapValue(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	_, ok := s.getItem("not-a-map", "key")
	assert.False(t, ok)
}

func TestGetItem_CaseInsensitive(t *testing.T) {
	f := &mockFormatter{}
	s := NewScript(f)

	data := map[string]any{
		"Name": "hello",
	}

	result, ok := s.getItem(data, "name")
	assert.True(t, ok)
	assert.Equal(t, "hello", result)
}
