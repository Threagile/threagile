package main

import (
	"encoding/json"
	"github.com/akedrou/textdiff"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/model"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestParseModelYaml(t *testing.T) {
	flatModelFile := filepath.Join("..", "..", "test", "all.yaml")
	flatModel := *new(input.ModelInput).Defaults()
	flatLoadError := flatModel.Load(flatModelFile)
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
	splitModel := *new(input.ModelInput).Defaults()
	splitLoadError := splitModel.Load(splitModelFile)
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

	if string(flatData) != string(splitData) {
		t.Errorf("parsing split model files is broken; diff: %v", textdiff.Unified(flatModelFile, splitModelFile, string(flatData), string(splitData)))
		return
	}
}

func TestParseModelJson(t *testing.T) {
	modelFile := filepath.Join("..", "..", "test", "all.json")
	modelJson, readError := os.ReadFile(modelFile)
	if readError != nil {
		t.Error("Unable to read model file: ", readError)
		return
	}

	var modelStruct model.ParsedModel
	unmarshalError := json.Unmarshal(modelJson, &modelStruct)
	if unmarshalError != nil {
		log.Fatal("Unable to parse model json: ", unmarshalError)
		return
	}

	_, marshalError := json.Marshal(&modelStruct)
	if marshalError != nil {
		log.Fatal("Unable to print model json: ", marshalError)
		return
	}
}
