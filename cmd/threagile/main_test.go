package main

import (
	"encoding/json"
	"github.com/akedrou/textdiff"
	"github.com/threagile/threagile/model"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestParseModel(t *testing.T) {
	flatModelFile := filepath.Join("..", "..", "test", "all.yaml")
	flatModel := *new(model.ModelInput).Defaults()
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
	splitModel := *new(model.ModelInput).Defaults()
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
