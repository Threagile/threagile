package main

import (
	"encoding/json"
	"fmt"
	"github.com/akedrou/textdiff"
	"github.com/threagile/threagile/internal/threagile"
	"github.com/threagile/threagile/pkg/input"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestParseModelYaml(t *testing.T) {
	flatModelFile := filepath.Join("..", "..", "test", "all.yaml")
	flatModel := *new(input.Model).Defaults()
	flatLoadError := flatModel.Load(new(threagile.Config).Defaults(""), flatModelFile)
	if flatLoadError != nil {
		t.Errorf("unable to parse model yaml %q: %v", flatModelFile, flatLoadError)
		return
	}

	sort.Strings(flatModel.TagsAvailable)
	flatModel.TagsAvailable = []string{strings.Join(flatModel.TagsAvailable, ", ")}

	flatData, flatMarshalError := json.MarshalIndent(flatModel, "", "  ")
	if flatMarshalError != nil {
		t.Errorf("unable to print model yaml %q: %v", flatModelFile, flatMarshalError)
		return
	}

	splitModelFile := filepath.Join("..", "..", "test", "main.yaml")
	splitModel := *new(input.Model).Defaults()
	splitLoadError := splitModel.Load(new(threagile.Config).Defaults(""), splitModelFile)
	if splitLoadError != nil {
		t.Errorf("unable to parse model yaml %q: %v", splitModelFile, splitLoadError)
		return
	}

	sort.Strings(splitModel.TagsAvailable)
	splitModel.TagsAvailable = []string{strings.Join(splitModel.TagsAvailable, ", ")}

	splitModel.Includes = flatModel.Includes
	splitData, splitMarshalError := json.MarshalIndent(splitModel, "", "  ")
	if splitMarshalError != nil {
		t.Errorf("unable to print model yaml %q: %v", splitModelFile, splitMarshalError)
		return
	}

	if string(flatData) != strings.Replace(string(splitData), "../../test/main.yaml", "../../test/all.yaml", 1) {
		t.Errorf("parsing split model files is broken; diff: %v", textdiff.Unified(flatModelFile, splitModelFile, string(flatData), string(splitData)))
		return
	}
}

func TestParseModelJson(t *testing.T) {
	modelFile := filepath.Join("..", "..", "test", "all.yaml")
	model := *new(input.Model).Defaults()
	flatLoadError := model.Load(new(threagile.Config).Defaults(""), modelFile)
	if flatLoadError != nil {
		t.Errorf("unable to parse model yaml %q: %v", modelFile, flatLoadError)
		return
	}

	modelJson, marshalError := json.MarshalIndent(model, "", "  ")
	if marshalError != nil {
		t.Error("Unable to print model json: ", marshalError)
		return
	}

	var modelStruct input.Model
	unmarshalError := json.Unmarshal(modelJson, &modelStruct)
	if unmarshalError != nil {
		jsonFile := "test.json"
		_ = os.WriteFile(jsonFile, modelJson, 0644)
		fmt.Printf("Yaml file: %v\n", modelFile)
		fmt.Printf("Json file: %v\n", jsonFile)
		t.Error("Unable to parse model json: ", unmarshalError)
		return
	}
}
