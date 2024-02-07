/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package macros

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/types"
	"gopkg.in/yaml.v3"
)

type Macros interface {
	GetMacroDetails() MacroDetails
	GetNextQuestion(model *types.ParsedModel) (nextQuestion MacroQuestion, err error)
	ApplyAnswer(questionID string, answer ...string) (message string, validResult bool, err error)
	GoBack() (message string, validResult bool, err error)
	GetFinalChangeImpact(modelInput *input.Model, model *types.ParsedModel) (changes []string, message string, validResult bool, err error)
	Execute(modelInput *input.Model, model *types.ParsedModel) (message string, validResult bool, err error)
}

func ListBuiltInMacros() []Macros {
	return []Macros{
		NewBuildPipeline(),
		NewAddVault(),
		NewPrettyPrint(),
		newRemoveUnusedTags(),
		NewSeedRiskTracking(),
		NewSeedTags(),
	}
}

func ListCustomMacros() []Macros {
	// TODO: implement
	return []Macros{}
}

func GetMacroByID(id string) (Macros, error) {
	builtinMacros := ListBuiltInMacros()
	customMacros := ListCustomMacros()
	allMacros := append(builtinMacros, customMacros...)
	for _, macro := range allMacros {
		if macro.GetMacroDetails().ID == id {
			return macro, nil
		}
	}
	return nil, fmt.Errorf("unknown macro id: %v", id)
}

func ExecuteModelMacro(modelInput *input.Model, inputFile string, parsedModel *types.ParsedModel, macroID string) error {
	macros, err := GetMacroByID(macroID)
	if err != nil {
		return err
	}

	macroDetails := macros.GetMacroDetails()

	fmt.Println("Executing model macro:", macroDetails.ID)
	fmt.Println()
	fmt.Println()
	printBorder(len(macroDetails.Title), true)
	fmt.Println(macroDetails.Title)
	printBorder(len(macroDetails.Title), true)
	if len(macroDetails.Description) > 0 {
		fmt.Println(macroDetails.Description)
	}
	fmt.Println()
	reader := bufio.NewReader(os.Stdin)
	for {
		nextQuestion, err := macros.GetNextQuestion(parsedModel)
		if err != nil {
			return err
		}
		if nextQuestion.NoMoreQuestions() {
			break
		}
		fmt.Println()
		printBorder(len(nextQuestion.Title), false)
		fmt.Println(nextQuestion.Title)
		printBorder(len(nextQuestion.Title), false)
		if len(nextQuestion.Description) > 0 {
			fmt.Println(nextQuestion.Description)
		}
		resultingMultiValueSelection := make([]string, 0)
		if nextQuestion.IsValueConstrained() {
			if nextQuestion.MultiSelect {
				selectedValues := make(map[string]bool)
				for {
					fmt.Println("Please select (multiple executions possible) from the following values (use number to select/deselect):")
					fmt.Println("    0:", "SELECTION PROCESS FINISHED: CONTINUE TO NEXT QUESTION")
					for i, val := range nextQuestion.PossibleAnswers {
						number := i + 1
						padding, selected := "", " "
						if number < 10 {
							padding = " "
						}
						if val, exists := selectedValues[val]; exists && val {
							selected = "*"
						}
						fmt.Println(" "+selected+" "+padding+strconv.Itoa(number)+":", val)
					}
					fmt.Println()
					fmt.Print("Enter number to select/deselect (or 0 when finished): ")
					answer, err := reader.ReadString('\n')
					// convert CRLF to LF
					answer = strings.TrimSpace(strings.Replace(answer, "\n", "", -1))
					if err != nil {
						return err
					}
					if val, err := strconv.Atoi(answer); err == nil { // flip selection
						if val == 0 {
							for key, selected := range selectedValues {
								if selected {
									resultingMultiValueSelection = append(resultingMultiValueSelection, key)
								}
							}
							break
						} else if val > 0 && val <= len(nextQuestion.PossibleAnswers) {
							selectedValues[nextQuestion.PossibleAnswers[val-1]] = !selectedValues[nextQuestion.PossibleAnswers[val-1]]
						}
					}
				}
			} else {
				fmt.Println("Please choose from the following values (enter value directly or use number):")
				for i, val := range nextQuestion.PossibleAnswers {
					number := i + 1
					padding := ""
					if number < 10 {
						padding = " "
					}
					fmt.Println("   "+padding+strconv.Itoa(number)+":", val)
				}
			}
		}
		message := ""
		validResult := true
		if !nextQuestion.IsValueConstrained() || !nextQuestion.MultiSelect {
			fmt.Println()
			fmt.Println("Enter your answer (use 'BACK' to go one step back or 'QUIT' to quit without executing the model macro)")
			fmt.Print("Answer")
			if len(nextQuestion.DefaultAnswer) > 0 {
				fmt.Print(" (default '" + nextQuestion.DefaultAnswer + "')")
			}
			fmt.Print(": ")
			answer, err := reader.ReadString('\n')
			// convert CRLF to LF
			answer = strings.TrimSpace(strings.Replace(answer, "\n", "", -1))
			if err != nil {
				return err
			}
			if len(answer) == 0 && len(nextQuestion.DefaultAnswer) > 0 { // accepting the default
				answer = nextQuestion.DefaultAnswer
			} else if nextQuestion.IsValueConstrained() { // convert number to value
				if val, err := strconv.Atoi(answer); err == nil {
					if val > 0 && val <= len(nextQuestion.PossibleAnswers) {
						answer = nextQuestion.PossibleAnswers[val-1]
					}
				}
			}
			if strings.ToLower(answer) == "quit" {
				fmt.Println("Quitting without executing the model macro")
				return nil
			} else if strings.ToLower(answer) == "back" {
				message, validResult, _ = macros.GoBack()
			} else if len(answer) > 0 { // individual answer
				if nextQuestion.IsValueConstrained() {
					if !nextQuestion.IsMatchingValueConstraint(answer) {
						fmt.Println()
						fmt.Println(">>> INVALID <<<")
						fmt.Println("Answer does not match any allowed value. Please try again:")
						continue
					}
				}
				message, validResult, _ = macros.ApplyAnswer(nextQuestion.ID, answer)
			}
		} else {
			message, validResult, _ = macros.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
		}
		if err != nil {
			return err
		}
		if !validResult {
			fmt.Println()
			fmt.Println(">>> INVALID <<<")
		}
		fmt.Println(message)
		fmt.Println()
	}
	for {
		fmt.Println()
		fmt.Println()
		fmt.Println("#################################################################")
		fmt.Println("Do you want to execute the model macro (updating the model file)?")
		fmt.Println("#################################################################")
		fmt.Println()
		fmt.Println("The following changes will be applied:")
		var changes []string
		message := ""

		changes, message, validResult, err := macros.GetFinalChangeImpact(modelInput, parsedModel)
		if err != nil {
			return err
		}
		for _, change := range changes {
			fmt.Println(" -", change)
		}
		if !validResult {
			fmt.Println()
			fmt.Println(">>> INVALID <<<")
		}
		fmt.Println()
		fmt.Println(message)
		fmt.Println()
		fmt.Print("Apply these changes to the model file?\nType Yes or No: ")
		answer, err := reader.ReadString('\n')
		// convert CRLF to LF
		answer = strings.TrimSpace(strings.Replace(answer, "\n", "", -1))
		if err != nil {
			return err
		}
		answer = strings.ToLower(answer)
		fmt.Println()
		if answer == "yes" || answer == "y" {
			message, validResult, err = macros.Execute(modelInput, parsedModel)
			if err != nil {
				return err
			}
			if !validResult {
				fmt.Println()
				fmt.Println(">>> INVALID <<<")
			}
			fmt.Println(message)
			fmt.Println()
			backupFilename := inputFile + ".backup"
			fmt.Println("Creating backup model file:", backupFilename) // TODO add random files in /dev/shm space?
			_, err = copyFile(inputFile, backupFilename)
			if err != nil {
				return err
			}
			fmt.Println("Updating model")
			yamlBytes, err := yaml.Marshal(modelInput)
			if err != nil {
				return err
			}
			/*
				yamlBytes = model.ReformatYAML(yamlBytes)
			*/
			fmt.Println("Writing model file:", inputFile)
			err = os.WriteFile(inputFile, yamlBytes, 0400)
			if err != nil {
				return err
			}
			fmt.Println("Model file successfully updated")
			return nil
		} else if answer == "no" || answer == "n" {
			fmt.Println("Quitting without executing the model macro")
			return nil
		}
	}
}

func printBorder(length int, bold bool) {
	char := "-"
	if bold {
		char = "="
	}
	for i := 1; i <= length; i++ {
		fmt.Print(char)
	}
	fmt.Println()
}

func copyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(filepath.Clean(src))
	if err != nil {
		return 0, err
	}
	defer func() { _ = source.Close() }()

	destination, err := os.Create(filepath.Clean(dst))
	if err != nil {
		return 0, err
	}
	defer func() { _ = destination.Close() }()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

type MacroDetails struct {
	ID, Title, Description string
}

type MacroQuestion struct {
	ID, Title, Description string
	PossibleAnswers        []string
	MultiSelect            bool
	DefaultAnswer          string
}

const NoMoreQuestionsID = ""

func NoMoreQuestions() MacroQuestion {
	return MacroQuestion{
		ID:              NoMoreQuestionsID,
		Title:           "",
		Description:     "",
		PossibleAnswers: nil,
		MultiSelect:     false,
		DefaultAnswer:   "",
	}
}

func (what MacroQuestion) NoMoreQuestions() bool {
	return what.ID == NoMoreQuestionsID
}

func (what MacroQuestion) IsValueConstrained() bool {
	return what.PossibleAnswers != nil && len(what.PossibleAnswers) > 0
}

func (what MacroQuestion) IsMatchingValueConstraint(answer string) bool {
	if what.IsValueConstrained() {
		for _, val := range what.PossibleAnswers {
			if strings.EqualFold(val, answer) {
				return true
			}
		}
		return false
	}
	return true
}
