package report

import (
	"fmt"
	"image"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/threagile/threagile/pkg/types"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type adocReport struct {
	targetDirectory string
	model           *types.Model
	mainFile        *os.File
	imagesDir       string

	riskRules types.RiskRules

	iconsType string
	tocDepth  int
}

func copyFile(source string, destination string) error {
	/* #nosec source is not tainted (see caller restricting it to files we created ourself or are legitimate to be copied) */
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	/* #nosec destination is not tainted (see caller restricting it to the desired report output folder) */
	dst, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer func() { _ = dst.Close() }()
	_, err = io.Copy(dst, src)
	if err != nil {
		return err
	}
	return nil
}

func fixBasicHtml(inputWithHtml string) string {
	result := strings.ReplaceAll(inputWithHtml, "<b>", "*")
	result = strings.ReplaceAll(result, "</b>", "*")

	result = strings.ReplaceAll(result, "<i>", "_")
	result = strings.ReplaceAll(result, "</i>", "_")

	result = strings.ReplaceAll(result, "<u>", "[.underline]#")
	result = strings.ReplaceAll(result, "</u>", "#")

	result = strings.ReplaceAll(result, "<br>", "\n")
	result = strings.ReplaceAll(result, "</br>", "\n")

	linkAndName := regexp.MustCompile(`<a href=\"(.*)\".*>(.*)</a>`)
	result = linkAndName.ReplaceAllString(result, "${1}[${2}]")
	return result
}

func NewAdocReport(targetDirectory string, riskRules types.RiskRules) adocReport {
	adoc := adocReport{
		targetDirectory: filepath.Join(targetDirectory, "adocReport"),
		iconsType:       "font",
		tocDepth:        2,
		imagesDir:       filepath.Join(targetDirectory, "adocReport", "images"),
		riskRules:       riskRules,
	}
	return adoc
}

func writeLine(file *os.File, line string) {
	_, err := file.WriteString(line + "\n")
	if err != nil {
		log.Fatal("Could not write »" + line + "« into: " + file.Name() + ": " + err.Error())
	}
}

func (adoc adocReport) writeDefaultTheme(logoImagePath string) error {
	err := os.MkdirAll(filepath.Join(adoc.targetDirectory, "theme"), 0750)
	if err != nil {
		return err
	}
	err = os.MkdirAll(adoc.imagesDir, 0750)
	if err != nil {
		return err
	}
	theme, err := os.Create(filepath.Join(adoc.targetDirectory, "theme", "pdf-theme.yml"))
	defer func() { _ = theme.Close() }()
	if err != nil {
		return err
	}
	adocLogoPath := ""
	if logoImagePath != "" {
		if _, err := os.Stat(logoImagePath); err == nil {
			suffix := filepath.Ext(logoImagePath)
			adocLogoPath = "logo" + suffix
			logoDestPath := filepath.Join(adoc.targetDirectory, "theme", adocLogoPath)
			err = copyFile(logoImagePath, logoDestPath)
			if err != nil {
				log.Fatal("Could not copy file: »" + logoImagePath + "« to »" + logoDestPath + "«: " + err.Error())
			}
		} else {
			log.Println("logo image path does not exist: " + logoImagePath)
		}
	}

	writeLine(theme, `extends: default
page:
  layout: portrait
  margin: [3cm, 2.5cm, 2.7cm, 2.5cm]
title-page:
  authors:
    content: "{author}, {author-homepage}[]"
`)
	if adocLogoPath != "" {
		writeLine(theme,
			`  logo:
    image: image:`+adocLogoPath+`[]`)
	}
	writeLine(theme,
		`header:
  height: 2cm
  line-height: 1
  recto:
    center:
      content: "{document-title} -- `+adoc.model.Title+` -- {section-or-chapter-title}"
  verso:
    center:
      content: "{document-title} -- `+adoc.model.Title+` -- {section-or-chapter-title}"
footer:
  height: 2cm
  line-height: 1.2
  recto:
    center:
      content: -- confidential --
    left:
      content: "Version: {DOC_VERSION}"
    right:
      content: "Page {page-number} of {page-count}"
  verso:
    center:
      content: -- confidential --
    left:
      content: "Version: {DOC_VERSION}"
    right:
      content: Page {page-number} of {page-count}
role:
  LowRisk:
    font-color: `+rgbHexColorLowRisk()+`
  MediumRisk:
    font-color: `+rgbHexColorMediumRisk()+`
  ElevatedRisk:
    font-color: `+rgbHexColorElevatedRisk()+`
  HighRisk:
    font-color: `+rgbHexColorHighRisk()+`
  CriticalRisk:
    font-color: `+rgbHexColorCriticalRisk()+`
  OutOfScope:
    font-color: #7f7f7f
  GreyText:
    font-color: #505050
  LightGreyText:
    font-color: #646464
  ModelFailure:
    font-color: #945200
  RiskStatusFalsePositive:
    font-color: `+rgbHexColorRiskStatusFalsePositive()+`
  RiskStatusMitigated:
    font-color: `+rgbHexColorRiskStatusMitigated()+`
  RiskStatusInProgress:
    font-color: `+rgbHexColorRiskStatusInProgress()+`
  RiskStatusAccepted:
    font-color: `+rgbHexColorRiskStatusAccepted()+`
  RiskStatusInDiscussion:
    font-color: `+rgbHexColorRiskStatusInDiscussion()+`
  RiskStatusUnchecked:
    font-color: `+RgbHexColorRiskStatusUnchecked()+`
  Twilight:
    font-color: `+rgbHexColorTwilight()+`
  SmallGrey:
    font-size: 0.5em
    font-color: #505050
  Silver:
    font-color: #C0C0C0
`)

	return nil
}

func (adoc adocReport) writeMainLine(line string) {
	writeLine(adoc.mainFile, line)
}

func (adoc adocReport) WriteReport(model *types.Model,
	dataFlowDiagramFilenamePNG string,
	dataAssetDiagramFilenamePNG string,
	modelFilename string,
	skipRiskRules []string,
	buildTimestamp string,
	threagileVersion string,
	modelHash string,
	introTextRAA string,
	customRiskRules types.RiskRules,
	logoImagePath string,
	hideChapters map[ChaptersToShowHide]bool) error {

	adoc.model = model
	err := adoc.initReport()
	if err != nil {
		return err
	}
	err = adoc.writeDefaultTheme(logoImagePath)
	if err != nil {
		return err
	}
	// err = adoc.createDefaultTheme() FIXME
	adoc.writeTitleAndPreamble()
	err = adoc.writeManagementSummery()
	if err != nil {
		return err
	}

	err = adoc.writeImpactInitialRisks()
	if err != nil {
		return fmt.Errorf("error creating impact initial risks: %w", err)
	}
	err = adoc.writeRiskMitigationStatus()
	if err != nil {
		return fmt.Errorf("error creating risk mitigation status: %w", err)
	}
	if val := hideChapters[AssetRegister]; !val {
		err = adoc.writeAssetRegister()
		if err != nil {
			return fmt.Errorf("error creating asset register status: %w", err)
		}
	}
	err = adoc.writeImpactRemainingRisks()
	if err != nil {
		return fmt.Errorf("error creating impact remaining risks: %w", err)
	}
	err = adoc.writeTargetDescription(filepath.Dir(modelFilename))
	if err != nil {
		return fmt.Errorf("error creating target description: %w", err)
	}
	err = adoc.writeDataFlowDiagram(dataFlowDiagramFilenamePNG)
	if err != nil {
		return fmt.Errorf("error creating data flow diagram section: %w", err)
	}
	err = adoc.writeSecurityRequirements()
	if err != nil {
		return fmt.Errorf("error creating security requirements: %w", err)
	}
	err = adoc.writeAbuseCases()
	if err != nil {
		return fmt.Errorf("error creating abuse cases: %w", err)
	}
	err = adoc.writeTagListing()
	if err != nil {
		return fmt.Errorf("error creating tag listing: %w", err)
	}
	err = adoc.writeSTRIDE()
	if err != nil {
		return fmt.Errorf("error creating STRIDE: %w", err)
	}
	err = adoc.writeAssignmentByFunction()
	if err != nil {
		return fmt.Errorf("error creating assignment by function: %w", err)
	}
	err = adoc.writeRAA(introTextRAA)
	if err != nil {
		return fmt.Errorf("error creating RAA: %w", err)
	}
	err = adoc.writeDataRiskMapping(dataAssetDiagramFilenamePNG)
	if err != nil {
		return fmt.Errorf("error creating data risk mapping: %w", err)
	}
	err = adoc.writeOutOfScopeAssets()
	if err != nil {
		return fmt.Errorf("error creating Out of Scope Assets: %w", err)
	}
	err = adoc.writeModelFailures()
	if err != nil {
		return fmt.Errorf("error creating model failures: %w", err)
	}
	err = adoc.writeQuestions()
	if err != nil {
		return fmt.Errorf("error creating questions: %w", err)
	}
	err = adoc.writeRiskCategories()
	if err != nil {
		return fmt.Errorf("error creating risk categories: %w", err)
	}
	err = adoc.writeTechnicalAssets()
	if err != nil {
		return fmt.Errorf("error creating technical assets: %w", err)
	}
	err = adoc.writeDataAssets()
	if err != nil {
		return fmt.Errorf("error creating data assets: %w", err)
	}
	err = adoc.writeTrustBoundaries()
	if err != nil {
		return fmt.Errorf("error creating trust boundaries: %w", err)
	}
	err = adoc.writeSharedRuntimes()
	if err != nil {
		return fmt.Errorf("error creating shared runtimes: %w", err)
	}
	if val := hideChapters[RiskRulesCheckedByThreagile]; !val {
		err = adoc.writeRiskRulesChecked(modelFilename, skipRiskRules, buildTimestamp, threagileVersion, modelHash, customRiskRules)
		if err != nil {
			return fmt.Errorf("error creating risk rules checked: %w", err)
		}
	}
	err = adoc.writeDisclaimer()
	if err != nil {
		return fmt.Errorf("error creating disclaimer: %w", err)
	}
	return nil
}

func (adoc *adocReport) initReport() error {
	_ = os.RemoveAll(adoc.targetDirectory)
	err := os.MkdirAll(adoc.targetDirectory, 0750)
	if err != nil {
		return err
	}
	adoc.mainFile, err = os.Create(filepath.Join(adoc.targetDirectory, "000_main.adoc"))
	if err != nil {
		return err
	}

	return nil
}

func (adoc adocReport) writeTitleAndPreamble() {
	adoc.writeMainLine("= Threat Model Report: " + adoc.model.Title)
	adoc.writeMainLine(":title-page:")
	adoc.writeMainLine(":author: " + adoc.model.Author.Name)
	if strings.HasPrefix(adoc.model.Author.Homepage, "http") {
		adoc.writeMainLine(`:author-homepage: ` + adoc.model.Author.Homepage)
	} else {
		adoc.writeMainLine(`:author-homepage: https://` + adoc.model.Author.Homepage)
	}
	adoc.writeMainLine(":email: " + adoc.model.Author.Contact)
	adoc.writeMainLine(":toc:")
	adoc.writeMainLine(":toclevels: " + strconv.Itoa(adoc.tocDepth))
	adoc.writeMainLine(":icons: " + adoc.iconsType)
	reportDate := adoc.model.Date
	if reportDate.IsZero() {
		reportDate = types.Date{Time: time.Now()}
	}
	adoc.writeMainLine(":revdate: " + reportDate.Format("2 January 2006"))
	adoc.writeMainLine("")
}

func (adoc adocReport) writeManagementSummery() error {
	filename := "010_ManagementSummary.adoc"
	ms, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = ms.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	writeLine(ms, "= Management Summary")
	writeLine(ms, "")
	writeLine(ms, "Threagile toolkit was used to model the architecture of \""+adoc.model.Title+"\" and derive risks by analyzing the components and data flows.")
	writeLine(ms, "The risks identified during this analysis are shown in the following chapters.")
	writeLine(ms, "Identified risks during threat modeling do not necessarily mean that the "+
		"vulnerability associated with this risk actually exists: it is more to be seen as a list"+
		" of potential risks and threats, which should be individually reviewed and reduced by removing false positives.")
	writeLine(ms, "For the remaining risks it should be checked in the design and implementation of \""+adoc.model.Title+"\" whether the mitigation advices have been applied or not.")
	writeLine(ms, "\n\n")
	writeLine(ms, "Each risk finding references a chapter of the OWASP ASVS (Application Security Verification Standard) audit checklist.")
	writeLine(ms, "The OWASP ASVS checklist should be considered as an inspiration by architects and developers to further harden the application in a Defense-in-Depth approach.")
	writeLine(ms, "Additionally, for each risk finding a link towards a matching OWASP Cheat Sheet or similar with technical details about how to implement a mitigation is given.")
	writeLine(ms, "\n\n")
	writeLine(ms, "In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" initial risks* in *"+strconv.Itoa(len(adoc.model.GeneratedRisksByCategory))+" categories* have been identified during the threat modeling process:")
	writeLine(ms, "\n\n")

	countCritical := len(filteredBySeverity(adoc.model, types.CriticalSeverity))
	countHigh := len(filteredBySeverity(adoc.model, types.HighSeverity))
	countElevated := len(filteredBySeverity(adoc.model, types.ElevatedSeverity))
	countMedium := len(filteredBySeverity(adoc.model, types.MediumSeverity))
	countLow := len(filteredBySeverity(adoc.model, types.LowSeverity))

	countStatusUnchecked := len(filteredByRiskStatus(adoc.model, types.Unchecked))
	countStatusInDiscussion := len(filteredByRiskStatus(adoc.model, types.InDiscussion))
	countStatusAccepted := len(filteredByRiskStatus(adoc.model, types.Accepted))
	countStatusInProgress := len(filteredByRiskStatus(adoc.model, types.InProgress))
	countStatusMitigated := len(filteredByRiskStatus(adoc.model, types.Mitigated))
	countStatusFalsePositive := len(filteredByRiskStatus(adoc.model, types.FalsePositive))

	pieCharts := `[cols="a,a",frame=none,grid=none]
|===
|
[mermaid]
....
%%{init: {'pie' : {'textPosition' : 0.5}, 'theme': 'base', 'themeVariables': { 'pie1': '` + rgbHexColorCriticalRisk() + `', 'pie2': '` + rgbHexColorHighRisk() + `', 'pie3': '` + rgbHexColorElevatedRisk() + `', 'pie4': '` + rgbHexColorMediumRisk() + `', 'pie5': '` + rgbHexColorLowRisk() + `'}}}%%
pie showData
  "critical risk" : ` + strconv.Itoa(countCritical) + `
  "high risk" : ` + strconv.Itoa(countHigh) + `
  "elevated risk" : ` + strconv.Itoa(countElevated) + `
  "medium risk" : ` + strconv.Itoa(countMedium) + `
  "low risk" : ` + strconv.Itoa(countLow) + `
....

|
[mermaid]
....
%%{init: {'pie' : {'textPosition' : 0.5}, 'theme': 'base', 'themeVariables': { 'pie1': '` + RgbHexColorRiskStatusUnchecked() + `', 'pie2': '` + rgbHexColorRiskStatusInDiscussion() + `', 'pie3': '` + rgbHexColorRiskStatusAccepted() + `', 'pie4': '` + rgbHexColorRiskStatusInProgress() + `', 'pie5': '` + rgbHexColorRiskStatusMitigated() + `', 'pie5': '` + rgbHexColorRiskStatusFalsePositive() + `'}}}%%
pie showData
  "unchecked" : ` + strconv.Itoa(countStatusUnchecked) + `
  "in discussion" : ` + strconv.Itoa(countStatusInDiscussion) + `
  "accepted" : ` + strconv.Itoa(countStatusAccepted) + `
  "in progress" : ` + strconv.Itoa(countStatusInProgress) + `
  "mitigated" : ` + strconv.Itoa(countStatusMitigated) + `
  "false positive" : ` + strconv.Itoa(countStatusFalsePositive) + `
....
|===
`
	writeLine(ms, pieCharts)
	// individual management summary comment
	if len(adoc.model.ManagementSummaryComment) > 0 {
		writeLine(ms, "\n\n\n"+fixBasicHtml(adoc.model.ManagementSummaryComment))
	}

	return nil
}

func colorPrefixBySeverity(severity types.RiskSeverity, smallFont bool) (string, string) {
	start := ""
	switch severity {
	case types.CriticalSeverity:
		start = "[.CriticalRisk"
	case types.HighSeverity:
		start = "[.HighRisk"
	case types.ElevatedSeverity:
		start = "[.ElevatedRisk"
	case types.MediumSeverity:
		start = "[.MediumRisk"
	case types.LowSeverity:
		start = "[.LowRisk"
	default:
		return "", ""
	}
	if smallFont {
		start += ".small"
	}
	return start + "]#", "#"
}

func colorPrefixByDataBreachProbability(probability types.DataBreachProbability, smallFont bool) (string, string) {
	switch probability {
	case types.Probable:
		return colorPrefixBySeverity(types.HighSeverity, smallFont)
	case types.Possible:
		return colorPrefixBySeverity(types.MediumSeverity, smallFont)
	case types.Improbable:
		return colorPrefixBySeverity(types.LowSeverity, smallFont)
	default:
		return "", ""
	}
}

func titleOfSeverity(severity types.RiskSeverity) string {
	switch severity {
	case types.CriticalSeverity:
		return "Critical Risk Severity"
	case types.HighSeverity:
		return "High Risk Severity"
	case types.ElevatedSeverity:
		return "Elevated Risk Severity"
	case types.MediumSeverity:
		return "Medium Risk Severity"
	case types.LowSeverity:
		return "Low Risk Severity"
	default:
		return ""
	}
}

func (adoc adocReport) addCategories(f *os.File, risksByCategory map[string][]*types.Risk, initialRisks bool, severity types.RiskSeverity, bothInitialAndRemainingRisks bool, describeDescription bool) {
	describeImpact := true
	riskCategories := getRiskCategories(adoc.model, reduceToSeverityRisk(risksByCategory, initialRisks, severity))
	sort.Sort(types.ByRiskCategoryTitleSort(riskCategories))
	for _, riskCategory := range riskCategories {
		risksStr := risksByCategory[riskCategory.ID]
		if !initialRisks {
			risksStr = types.ReduceToOnlyStillAtRisk(risksStr)
		}
		if len(risksStr) == 0 {
			continue
		}

		var prefix string
		colorPrefix, colorSuffix := colorPrefixBySeverity(severity, false)
		switch severity {
		case types.CriticalSeverity:
			prefix = "Critical: "
		case types.HighSeverity:
			prefix = "High: "
		case types.ElevatedSeverity:
			prefix = "Elevated: "
		case types.MediumSeverity:
			prefix = "Medium: "
		case types.LowSeverity:
			prefix = "Low: "
		default:
			prefix = ""
		}
		if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
			colorPrefix = ""
			colorSuffix = ""
		}
		fullLine := "<<" + riskCategory.ID + "," + colorPrefix + prefix + "*" + riskCategory.Title + "*: "

		count := len(risksStr)
		initialStr := "Initial"
		if !initialRisks {
			initialStr = "Remaining"
		}
		remainingRisks := types.ReduceToOnlyStillAtRisk(risksStr)
		suffix := strconv.Itoa(count) + " " + initialStr + " Risk"
		if bothInitialAndRemainingRisks {
			suffix = strconv.Itoa(len(remainingRisks)) + " / " + strconv.Itoa(count) + " Risk"
		}
		if count != 1 {
			suffix += "s"
		}
		suffix += " - Exploitation likelihood is _"
		if initialRisks {
			suffix += highestExploitationLikelihood(risksStr).Title() + "_ with _" + highestExploitationImpact(risksStr).Title() + "_ impact."
		} else {
			suffix += highestExploitationLikelihood(remainingRisks).Title() + "_ with _" + highestExploitationImpact(remainingRisks).Title() + "_ impact."
		}

		fullLine += suffix + colorSuffix + ">>::"
		writeLine(f, fullLine)

		if describeImpact {
			writeLine(f, firstParagraph(riskCategory.Impact))
		} else if describeDescription {
			writeLine(f, firstParagraph(riskCategory.Description))
		} else {
			writeLine(f, firstParagraph(riskCategory.Mitigation))
		}
		writeLine(f, "")
	}
}

func (adoc adocReport) impactAnalysis(f *os.File, initialRisks bool) {

	count := 0
	catCount := 0
	initialStr := ""
	if initialRisks {
		count = totalRiskCount(adoc.model)
		catCount = len(adoc.model.GeneratedRisksByCategory)
		initialStr = "initial"
	} else {
		count = len(filteredByStillAtRisk(adoc.model))
		catCount = len(reduceToOnlyStillAtRisk(adoc.model.GeneratedRisksByCategoryWithCurrentStatus()))
		initialStr = "remaining"
	}

	riskText := "risks"
	if count == 1 {
		riskText = "risk"
	}
	catText := "categories"
	if catCount == 1 {
		catText = "category"
	}

	titleCaser := cases.Title(language.English)
	chapTitle := titleCaser.String("= Impact Analysis of " + strconv.Itoa(count) + " " + initialStr + " " + riskText + " in " + strconv.Itoa(catCount) + " " + catText)
	writeLine(f, chapTitle)
	writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")

	writeLine(f,
		"The most prevalent impacts of the *"+strconv.Itoa(count)+" "+initialStr+" "+riskText+"*"+
			" (distributed over *"+strconv.Itoa(catCount)+" risk categories*) are "+
			"(taking the severity ratings into account and using the highest for each category)!{fn-risk-findings}")
	writeLine(f, "")
	adoc.addCategories(f, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), initialRisks, types.CriticalSeverity, false, false)
	adoc.addCategories(f, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), initialRisks, types.HighSeverity, false, false)
	adoc.addCategories(f, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), initialRisks, types.ElevatedSeverity, false, false)
	adoc.addCategories(f, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), initialRisks, types.MediumSeverity, false, false)
	adoc.addCategories(f, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), initialRisks, types.LowSeverity, false, false)
}

func (adoc adocReport) writeImpactInitialRisks() error {
	filename := "020_ImpactIntialRisks.adoc"
	ir, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = ir.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.impactAnalysis(ir, true)
	return nil
}

func (adoc adocReport) riskMitigationStatus(f *os.File) {

	writeLine(f, "= Risk Mitigation")
	writeLine(f, "The following chart gives a high-level overview of the risk tracking status (including mitigated risks):")

	risksCritical := filteredBySeverity(adoc.model, types.CriticalSeverity)
	risksHigh := filteredBySeverity(adoc.model, types.HighSeverity)
	risksElevated := filteredBySeverity(adoc.model, types.ElevatedSeverity)
	risksMedium := filteredBySeverity(adoc.model, types.MediumSeverity)
	risksLow := filteredBySeverity(adoc.model, types.LowSeverity)
	countStatusUnchecked := len(filteredByRiskStatus(adoc.model, types.Unchecked))
	countStatusInDiscussion := len(filteredByRiskStatus(adoc.model, types.InDiscussion))
	countStatusAccepted := len(filteredByRiskStatus(adoc.model, types.Accepted))
	countStatusInProgress := len(filteredByRiskStatus(adoc.model, types.InProgress))
	countStatusMitigated := len(filteredByRiskStatus(adoc.model, types.Mitigated))
	countStatusFalsePositive := len(filteredByRiskStatus(adoc.model, types.FalsePositive))

	lowTitle := types.LowSeverity.Title() + " (" + strconv.Itoa(len(risksLow)) + ")"
	medTitle := types.MediumSeverity.Title() + " (" + strconv.Itoa(len(risksMedium)) + ")"
	elevatedTitle := types.ElevatedSeverity.Title() + " (" + strconv.Itoa(len(risksElevated)) + ")"
	highTitle := types.HighSeverity.Title() + " (" + strconv.Itoa(len(risksHigh)) + ")"
	criticalTitle := types.CriticalSeverity.Title() + " (" + strconv.Itoa(len(risksCritical)) + ")"

	diagram := `
[vegalite]
....
{
  "width": 400,
  "$schema": "https://vega.github.io/schema/vega-lite/v4.json",
  "data": {
    "values": [
      {"risk": "` + lowTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksLow, types.Unchecked))) + `, "status": "Unchecked", "color": "` + RgbHexColorRiskStatusUnchecked() + `"},
      {"risk": "` + lowTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksLow, types.InDiscussion))) + `, "status": "InDiscussion", "color": "` + rgbHexColorRiskStatusInDiscussion() + `"},
      {"risk": "` + lowTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksLow, types.Accepted))) + `, "status": "Accepted", "color": "` + rgbHexColorRiskStatusAccepted() + `"},
      {"risk": "` + lowTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksLow, types.InProgress))) + `, "status": "InProgress", "color": "` + rgbHexColorRiskStatusInProgress() + `"},
      {"risk": "` + lowTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksLow, types.Mitigated))) + `, "status": "Mitigated", "color": "` + rgbHexColorRiskStatusMitigated() + `"},
      {"risk": "` + lowTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksLow, types.FalsePositive))) + `, "status": "FalsePositive", "color": "` + rgbHexColorRiskStatusFalsePositive() + `"},

      {"risk": "` + medTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksMedium, types.Unchecked))) + `, "status": "Unchecked", "color": "` + RgbHexColorRiskStatusUnchecked() + `"},
      {"risk": "` + medTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksMedium, types.InDiscussion))) + `, "status": "InDiscussion", "color": "` + rgbHexColorRiskStatusInDiscussion() + `"},
      {"risk": "` + medTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksMedium, types.Accepted))) + `, "status": "Accepted", "color": "` + rgbHexColorRiskStatusAccepted() + `"},
      {"risk": "` + medTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksMedium, types.InProgress))) + `, "status": "InProgress", "color": "` + rgbHexColorRiskStatusInProgress() + `"},
      {"risk": "` + medTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksMedium, types.Mitigated))) + `, "status": "Mitigated", "color": "` + rgbHexColorRiskStatusMitigated() + `"},
      {"risk": "` + medTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksMedium, types.FalsePositive))) + `, "status": "FalsePositive", "color": "` + rgbHexColorRiskStatusFalsePositive() + `"},

      {"risk": "` + elevatedTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksElevated, types.Unchecked))) + `, "status": "Unchecked", "color": "` + RgbHexColorRiskStatusUnchecked() + `"},
      {"risk": "` + elevatedTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksElevated, types.InDiscussion))) + `, "status": "InDiscussion", "color": "` + rgbHexColorRiskStatusInDiscussion() + `"},
      {"risk": "` + elevatedTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksElevated, types.Accepted))) + `, "status": "Accepted", "color": "` + rgbHexColorRiskStatusAccepted() + `"},
      {"risk": "` + elevatedTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksElevated, types.InProgress))) + `, "status": "InProgress", "color": "` + rgbHexColorRiskStatusInProgress() + `"},
      {"risk": "` + elevatedTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksElevated, types.Mitigated))) + `, "status": "Mitigated", "color": "` + rgbHexColorRiskStatusMitigated() + `"},
      {"risk": "` + elevatedTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksElevated, types.FalsePositive))) + `, "status": "FalsePositive", "color": "` + rgbHexColorRiskStatusFalsePositive() + `"},

      {"risk": "` + highTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksHigh, types.Unchecked))) + `, "status": "Unchecked", "color": "` + RgbHexColorRiskStatusUnchecked() + `"},
      {"risk": "` + highTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksHigh, types.InDiscussion))) + `, "status": "InDiscussion", "color": "` + rgbHexColorRiskStatusInDiscussion() + `"},
      {"risk": "` + highTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksHigh, types.Accepted))) + `, "status": "Accepted", "color": "` + rgbHexColorRiskStatusAccepted() + `"},
      {"risk": "` + highTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksHigh, types.InProgress))) + `, "status": "InProgress", "color": "` + rgbHexColorRiskStatusInProgress() + `"},
      {"risk": "` + highTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksHigh, types.Mitigated))) + `, "status": "Mitigated", "color": "` + rgbHexColorRiskStatusMitigated() + `"},
      {"risk": "` + highTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksHigh, types.FalsePositive))) + `, "status": "FalsePositive", "color": "` + rgbHexColorRiskStatusFalsePositive() + `"},

      {"risk": "` + criticalTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksCritical, types.Unchecked))) + `, "status": "Unchecked", "color": "` + RgbHexColorRiskStatusUnchecked() + `"},
      {"risk": "` + criticalTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksCritical, types.InDiscussion))) + `, "status": "InDiscussion", "color": "` + rgbHexColorRiskStatusInDiscussion() + `"},
      {"risk": "` + criticalTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksCritical, types.Accepted))) + `, "status": "Accepted", "color": "` + rgbHexColorRiskStatusAccepted() + `"},
      {"risk": "` + criticalTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksCritical, types.InProgress))) + `, "status": "InProgress", "color": "` + rgbHexColorRiskStatusInProgress() + `"},
      {"risk": "` + criticalTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksCritical, types.Mitigated))) + `, "status": "Mitigated", "color": "` + rgbHexColorRiskStatusMitigated() + `"},
      {"risk": "` + criticalTitle + `", "value": ` + strconv.Itoa(len(reduceToRiskStatus(risksCritical, types.FalsePositive))) + `, "status": "FalsePositive", "color": "` + rgbHexColorRiskStatusFalsePositive() + `"}
    ]
  },
  "mark": {"type": "bar", "cornerRadiusTopLeft": 3, "cornerRadiusTopRight": 3},
  "encoding": {
    "x": {"field": "risk", "type": "ordinal", "title": "", "sort": [], "axis": {
        "labelAngle": 0
    }},
    "y": {"field": "value", "type": "quantitative", "title": "", "axis": {
      "orient": "right"
    }},
    "color": {
      "field": "status",
      "scale": {
        "domain": ["Unchecked", "InDiscussion", "Accepted", "InProgress", "Mitigated", "FalsePositive"],
        "range": ["` + RgbHexColorRiskStatusUnchecked() + `", "` + rgbHexColorRiskStatusInDiscussion() + `", "` + rgbHexColorRiskStatusAccepted() + `", "` + rgbHexColorRiskStatusInProgress() + `", "` + rgbHexColorRiskStatusMitigated() + `", "` + rgbHexColorRiskStatusFalsePositive() + `"]
      },
      "legend" : {
        "title": "",
        "labelExpr": "datum.label == \"Unchecked\" ? \"` + strconv.Itoa(countStatusUnchecked) +
		` unchecked\" : datum.label == \"InDiscussion\" ? \"` + strconv.Itoa(countStatusInDiscussion) +
		` in discussion\" : datum.label == \"Accepted\" ? \"` + strconv.Itoa(countStatusAccepted) +
		` accepted\" : datum.label == \"InProgress\" ? \"` + strconv.Itoa(countStatusInProgress) +
		` in progress\" : datum.label == \"Mitigated\" ? \"` + strconv.Itoa(countStatusMitigated) +
		` mitigated\" : datum.label == \"FalsePositive\" ? \"` + strconv.Itoa(countStatusFalsePositive) +
		` false positive\" : \"\""
      }
    }
  }
}
....
`
	writeLine(f, diagram)
	writeLine(f, "")
	stillAtRisk := filteredByStillAtRisk(adoc.model)
	count := len(stillAtRisk)
	if count == 0 {
		writeLine(f, "After removal of risks with status _mitigated_ and _false positive_ "+
			"*"+strconv.Itoa(count)+" remain unmitigated*.")
	} else {
		writeLine(f, "After removal of risks with status _mitigated_ and _false positive_ "+
			"the following *"+strconv.Itoa(count)+" remain unmitigated*:")

		countCritical := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.CriticalSeverity)))
		countHigh := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.HighSeverity)))
		countElevated := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.ElevatedSeverity)))
		countMedium := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.MediumSeverity)))
		countLow := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.LowSeverity)))

		countBusinessSide := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(adoc.model, types.BusinessSide)))
		countArchitecture := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(adoc.model, types.Architecture)))
		countDevelopment := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(adoc.model, types.Development)))
		countOperation := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(adoc.model, types.Operations)))

		pieCharts := `[cols="a,a",frame=none,grid=none]
|===
|
[mermaid]
....
%%{init: {'pie' : {'textPosition' : 0.5}, 'theme': 'base', 'themeVariables': { 'pie1': '` + rgbHexColorCriticalRisk() + `', 'pie2': '` + rgbHexColorHighRisk() + `', 'pie3': '` + rgbHexColorElevatedRisk() + `', 'pie4': '` + rgbHexColorMediumRisk() + `', 'pie5': '` + rgbHexColorLowRisk() + `'}}}%%
pie showData
  "unmitigated critical risk" : ` + strconv.Itoa(countCritical) + `
  "unmitigated high risk" : ` + strconv.Itoa(countHigh) + `
  "unmitigated elevated risk" : ` + strconv.Itoa(countElevated) + `
  "unmitigated medium risk" : ` + strconv.Itoa(countMedium) + `
  "unmitigated low risk" : ` + strconv.Itoa(countLow) + `
....

|
[mermaid]
....
%%{init: {'pie' : {'textPosition' : 0.5}, 'theme': 'base', 'themeVariables': { 'pie1': '` + rgbHexColorBusiness() + `', 'pie2': '` + rgbHexColorArchitecture() + `', 'pie3': '` + rgbHexColorDevelopment() + `', 'pie4': '` + rgbHexColorOperation() + `'}}}%%
pie showData
  "business side related" : ` + strconv.Itoa(countBusinessSide) + `
  "architecture related" : ` + strconv.Itoa(countArchitecture) + `
  "development related" : ` + strconv.Itoa(countDevelopment) + `
  "operations related" : ` + strconv.Itoa(countOperation) + `
....
|===
`
		writeLine(f, pieCharts)
	}
}

func (adoc adocReport) writeRiskMitigationStatus() error {
	filename := "030_RiskMitigationStatus.adoc"
	rms, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = rms.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.riskMitigationStatus(rms)
	return nil
}

func (adoc adocReport) assetRegister(f *os.File) {
	writeLine(f, "= Asset Register")
	writeLine(f, "")

	writeLine(f, "== Technical Assets")
	writeLine(f, "")
	for _, technicalAsset := range sortedTechnicalAssetsByTitle(adoc.model) {

		fullLine := "<<" + technicalAsset.Id + ",*" + technicalAsset.Title + "*"
		if technicalAsset.OutOfScope {
			fullLine += ": out-of-scope"
		}
		writeLine(f, fullLine+">>::")
		writeLine(f, "  "+technicalAsset.Description)
		writeLine(f, "")
	}

	writeLine(f, "== Data Assets")
	writeLine(f, "")

	for _, dataAsset := range sortedDataAssetsByTitle(adoc.model) {
		writeLine(f, "<<dataAsset:"+dataAsset.Id+",*"+dataAsset.Title+"*"+">>::")
		writeLine(f, "  "+dataAsset.Description)
		writeLine(f, "")
	}
}

func (adoc adocReport) writeAssetRegister() error {
	filename := "035_AssetRegister.adoc"
	ar, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = ar.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.assetRegister(ar)
	return nil
}

func (adoc adocReport) writeImpactRemainingRisks() error {
	filename := "040_ImpactRemainingRisks.adoc"
	irr, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = irr.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.impactAnalysis(irr, false)
	return nil
}

func addCustomImages(f *os.File, customImages []map[string]string, baseFolder string) {
	for _, customImage := range customImages {
		for imageFilename := range customImage {
			imageFilenameWithoutPath := filepath.Base(imageFilename)
			imageFullFilename := filepath.Join(baseFolder, imageFilenameWithoutPath)
			writeLine(f, "image::"+imageFullFilename+"[]")
		}
	}
}

func (adoc adocReport) targetDescription(f *os.File, baseFolder string) {
	writeLine(f, "= Application Overview")
	writeLine(f, "== Business Criticality\n")
	writeLine(f, "The overall business criticality of \""+adoc.model.Title+"\" was rated as:\n")

	critString := "( "
	criticality := adoc.model.BusinessCriticality
	first := true
	for _, critValue := range types.CriticalityValues() {
		if !first {
			critString += " |"
		}
		if critValue == criticality {
			critString += " [.underline]#*" + strings.ToUpper(critValue.String()) + "*#"
		} else {
			critString += " [GreyText]#" + critValue.String() + "#"
		}
		first = false
	}
	critString += "  )"
	writeLine(f, critString)

	writeLine(f, "\n\n")
	writeLine(f, "== Business Overview")
	writeLine(f, fixBasicHtml(adoc.model.BusinessOverview.Description))
	addCustomImages(f, adoc.model.BusinessOverview.Images, baseFolder)

	writeLine(f, "\n\n")
	writeLine(f, "== Technical Overview")
	writeLine(f, fixBasicHtml(adoc.model.TechnicalOverview.Description))
	addCustomImages(f, adoc.model.TechnicalOverview.Images, baseFolder)
}

func (adoc adocReport) writeTargetDescription(baseFolder string) error {
	filename := "050_TargetDescription.adoc"
	td, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = td.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.targetDescription(td, baseFolder)
	return nil
}

func (adoc adocReport) dataFlowDiagram(f *os.File, diagramFilenamePNG string) {
	writeLine(f, "= Data-Flow Diagram")
	// intermediate newlines are ignored in asciidoctor
	writeLine(f, `
The following diagram was generated by Threagile based on the model input and gives a high-level overview of the data-flow
between technical assets. The RAA value is the calculated _Relative Attacker Attractiveness_ in percent.
For a full high-resolution version of this diagram please refer to the PNG image file alongside this report.
	`)
	writeLine(f, "\nimage::"+diagramFilenamePNG+"[]")
}

func imageIsWiderThanHigh(diagramFilenamePNG string) bool {
	/* #nosec diagramFilenamePNG is not tainted (see caller restricting it to image files of model folder only) */
	imagePath, err := os.Open(diagramFilenamePNG)
	defer func() { _ = imagePath.Close() }()
	if err != nil {
		log.Fatalln("error opening image file: %w", err)
		return false
	}
	srcImage, _, _ := image.Decode(imagePath)
	srcDimensions := srcImage.Bounds()
	// wider than high?
	muchWiderThanHigh := srcDimensions.Dx() > int(float64(srcDimensions.Dy())*1.25)
	return muchWiderThanHigh
}

func (adoc adocReport) writeDataFlowDiagram(diagramFilenamePNG string) error {
	filename := "060_DataFlowDiagram.adoc"
	dfd, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = dfd.Close() }()
	if err != nil {
		return err
	}
	adocDfdFilename := filepath.Join(adoc.imagesDir, "data-flow-diagram.png")
	err = copyFile(diagramFilenamePNG, adocDfdFilename)
	if err != nil {
		log.Fatal("Could not copy file: »" + diagramFilenamePNG + "« to »" + adocDfdFilename + "«: " + err.Error())
	}

	landScape := imageIsWiderThanHigh(adocDfdFilename)
	if landScape {
		adoc.writeMainLine("[page-layout=landscape]")
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.dataFlowDiagram(dfd, "images/data-flow-diagram.png")
	if landScape {
		adoc.writeMainLine("[page-layout=portrait]")
	}
	return nil
}

func (adoc adocReport) securityRequirements(f *os.File) {
	writeLine(f, "= Security Requirements")
	writeLine(f, "This chapter lists the custom security requirements which have been defined for the modeled target.")

	writeLine(f, "\n")
	for _, title := range sortedKeysOfSecurityRequirements(adoc.model) {
		description := adoc.model.SecurityRequirements[title]
		writeLine(f, title+"::")
		writeLine(f, "  "+description)
		writeLine(f, "")
	}
	writeLine(f, "\n\n")
	writeLine(f, "_This list is not complete and regulatory or law relevant security requirements have to be "+
		"taken into account as well. Also custom individual security requirements might exist for the project._")
}

func (adoc adocReport) writeSecurityRequirements() error {
	filename := "070_SecurityRequirements.adoc"
	sr, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = sr.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.securityRequirements(sr)
	return nil
}

func (adoc adocReport) abuseCases(f *os.File) {
	writeLine(f, "= Abuse Cases")
	writeLine(f, "This chapter lists the custom abuse cases which have been defined for the modeled target.")
	writeLine(f, "\n")
	for _, title := range sortedKeysOfAbuseCases(adoc.model) {
		description := adoc.model.AbuseCases[title]
		writeLine(f, title+"::")
		writeLine(f, "  "+description)
		writeLine(f, "")
	}
	writeLine(f, "\n\n")
	writeLine(f, "_This list is not complete and regulatory or law relevant abuse cases have to be "+
		"taken into account as well. Also custom individual abuse cases might exist for the project._")
}

func (adoc adocReport) writeAbuseCases() error {
	filename := "080_AbuseCases.adoc"
	ac, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = ac.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.abuseCases(ac)
	return nil
}

func (adoc adocReport) tagListing(f *os.File) {
	writeLine(f, "= Tag Listing")

	writeLine(f, "This chapter lists what tags are used by which elements.")
	writeLine(f, "\n")
	sorted := adoc.model.TagsAvailable
	sort.Strings(sorted)
	for _, tag := range sorted {
		description := "" // TODO: add some separation texts to distinguish between technical assets and data assets etc. for example?
		for _, techAsset := range sortedTechnicalAssetsByTitle(adoc.model) {
			if contains(techAsset.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += techAsset.Title
			}
			for _, commLink := range techAsset.CommunicationLinksSorted() {
				if contains(commLink.Tags, tag) {
					if len(description) > 0 {
						description += ", "
					}
					description += commLink.Title
				}
			}
		}
		for _, dataAsset := range sortedDataAssetsByTitle(adoc.model) {
			if contains(dataAsset.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += dataAsset.Title
			}
		}
		for _, trustBoundary := range sortedTrustBoundariesByTitle(adoc.model) {
			if contains(trustBoundary.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += trustBoundary.Title
			}
		}
		for _, sharedRuntime := range sortedSharedRuntimesByTitle(adoc.model) {
			if contains(sharedRuntime.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += sharedRuntime.Title
			}
		}
		if len(description) > 0 {
			writeLine(f, tag+"::")
			writeLine(f, "  "+description)
			writeLine(f, "")
		}
	}
}

func (adoc adocReport) writeTagListing() error {
	filename := "090_TagListing.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.tagListing(f)
	return nil
}

func (adoc adocReport) stride(f *os.File) {
	writeLine(f, "= STRIDE Classification of Identified Risks")
	writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")
	writeLine(f, "")

	risksSTRIDESpoofing := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Spoofing)
	risksSTRIDETampering := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Tampering)
	risksSTRIDERepudiation := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Repudiation)
	risksSTRIDEInformationDisclosure := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.InformationDisclosure)
	risksSTRIDEDenialOfService := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.DenialOfService)
	risksSTRIDEElevationOfPrivilege := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.ElevationOfPrivilege)

	countSTRIDESpoofing := countRisks(risksSTRIDESpoofing)
	countSTRIDETampering := countRisks(risksSTRIDETampering)
	countSTRIDERepudiation := countRisks(risksSTRIDERepudiation)
	countSTRIDEInformationDisclosure := countRisks(risksSTRIDEInformationDisclosure)
	countSTRIDEDenialOfService := countRisks(risksSTRIDEDenialOfService)
	countSTRIDEElevationOfPrivilege := countRisks(risksSTRIDEElevationOfPrivilege)

	writeLine(f, "This chapter clusters and classifies the risks by STRIDE categories: "+
		"In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during the threat modeling process "+
		"of which *"+strconv.Itoa(countSTRIDESpoofing)+" in the "+types.Spoofing.Title()+"* category, "+
		"*"+strconv.Itoa(countSTRIDETampering)+" in the "+types.Tampering.Title()+"* category, "+
		"*"+strconv.Itoa(countSTRIDERepudiation)+" in the "+types.Repudiation.Title()+"* category, "+
		"*"+strconv.Itoa(countSTRIDEInformationDisclosure)+" in the "+types.InformationDisclosure.Title()+"* category, "+
		"*"+strconv.Itoa(countSTRIDEDenialOfService)+" in the "+types.DenialOfService.Title()+"* category, "+
		"and *"+strconv.Itoa(countSTRIDEElevationOfPrivilege)+" in the "+types.ElevationOfPrivilege.Title()+"* category.{fn-risk-findings}")
	writeLine(f, "")

	reverseRiskSeverity := []types.RiskSeverity{
		types.CriticalSeverity,
		types.HighSeverity,
		types.ElevatedSeverity,
		types.MediumSeverity,
		types.LowSeverity,
	}
	strides := []types.STRIDE{
		types.Spoofing,
		types.Tampering,
		types.Repudiation,
		types.InformationDisclosure,
		types.DenialOfService,
		types.ElevationOfPrivilege,
	}

	for _, strideValue := range strides {
		writeLine(f, "== "+strideValue.Title())
		risksSTRIDE := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), strideValue)
		for _, critValue := range reverseRiskSeverity {
			adoc.addCategories(f, risksSTRIDE, true, critValue, true, true)
		}
		writeLine(f, "")
	}
}

func (adoc adocReport) writeSTRIDE() error {
	filename := "100_STRIDE.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.stride(f)
	return nil
}

func (adoc adocReport) assignmentByFunction(f *os.File) {
	writeLine(f, "= Assignment by Function")
	writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")
	writeLine(f, "")

	risksBusinessSideFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.BusinessSide)
	risksArchitectureFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Architecture)
	risksDevelopmentFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Development)
	risksOperationFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Operations)

	countBusinessSideFunction := countRisks(risksBusinessSideFunction)
	countArchitectureFunction := countRisks(risksArchitectureFunction)
	countDevelopmentFunction := countRisks(risksDevelopmentFunction)
	countOperationFunction := countRisks(risksOperationFunction)
	writeLine(f, "This chapter clusters and assigns the risks by functions which are most likely able to "+
		"check and mitigate them: "+
		"In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during the threat modeling process "+
		"of which *"+strconv.Itoa(countBusinessSideFunction)+" should be checked by "+types.BusinessSide.Title()+"*, "+
		"*"+strconv.Itoa(countArchitectureFunction)+" should be checked by "+types.Architecture.Title()+"*, "+
		"*"+strconv.Itoa(countDevelopmentFunction)+" should be checked by "+types.Development.Title()+"*, "+
		"and *"+strconv.Itoa(countOperationFunction)+" should be checked by "+types.Operations.Title()+"*.{fn-risk-findings}")
	writeLine(f, "")

	riskFunctionValues := []types.RiskFunction{
		types.BusinessSide,
		types.Architecture,
		types.Development,
		types.Operations,
	}
	reverseRiskSeverity := []types.RiskSeverity{
		types.CriticalSeverity,
		types.HighSeverity,
		types.ElevatedSeverity,
		types.MediumSeverity,
		types.LowSeverity,
	}

	for _, riskFunctionValue := range riskFunctionValues {
		writeLine(f, "== "+riskFunctionValue.Title())
		risksFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), riskFunctionValue)
		for _, critValue := range reverseRiskSeverity {
			adoc.addCategories(f, risksFunction, true, critValue, true, false)
		}
		writeLine(f, "")
	}
}

func (adoc adocReport) writeAssignmentByFunction() error {
	filename := "110_AssignmentByFunction.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.assignmentByFunction(f)
	return nil
}

func (adoc adocReport) raa(f *os.File, introTextRAA string) {
	writeLine(f, "= RAA Analysis")
	writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")
	writeLine(f, "")
	writeLine(f, fixBasicHtml(introTextRAA)+"{fn-risk-findings}")
	writeLine(f, "")

	for _, technicalAsset := range sortedTechnicalAssetsByRAAAndTitle(adoc.model) {
		if technicalAsset.OutOfScope {
			continue
		}
		newRisksStr := adoc.model.GeneratedRisks(technicalAsset)
		colorPrefix := ""
		switch types.HighestSeverityStillAtRisk(newRisksStr) {
		case types.HighSeverity:
			colorPrefix = "[HighRisk]#"
		case types.MediumSeverity:
			colorPrefix = "[MediumRisk]#"
		case types.LowSeverity:
			colorPrefix = "[LowRisk]#"
		default:
			colorPrefix = ""
		}
		if len(types.ReduceToOnlyStillAtRisk(newRisksStr)) == 0 {
			colorPrefix = ""
		}

		fullLine := "<<" + technicalAsset.Id + "," + colorPrefix + "*" + technicalAsset.Title + "*"
		if technicalAsset.OutOfScope {
			fullLine += ": out-of-scope"
		} else {
			fullLine += ": RAA " + fmt.Sprintf("%.0f", technicalAsset.RAA) + "%"
		}
		if len(colorPrefix) > 0 {
			fullLine += "#"
		}
		writeLine(f, fullLine+">>::")
		writeLine(f, "  "+technicalAsset.Description)
		writeLine(f, "")
	}
}

func (adoc adocReport) writeRAA(introTextRAA string) error {
	filename := "120_RAA.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.raa(f, introTextRAA)
	return nil
}

func (adoc adocReport) dataRiskMapping(f *os.File, diagramFilenamePNG string) {
	writeLine(f, "= Data Mapping")

	writeLine(f, `
The following diagram was generated by Threagile based on the model input and gives a high-level distribution of
data assets across technical assets. The color matches the identified data breach probability and risk level (see
the "Data Breach Probabilities" chapter for more details). A solid line stands for _data is stored by the asset_
and a dashed one means _data is processed by the asset_. For a full high-resolution version of this diagram please
refer to the PNG image file alongside this report.`)
	writeLine(f, "\nimage::"+diagramFilenamePNG+"[]")
}

func (adoc adocReport) writeDataRiskMapping(dataAssetDiagramFilenamePNG string) error {
	filename := "130_DataRiskMapping.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adocDataRiskMappingFilename := filepath.Join(adoc.imagesDir, "data-asset-diagram.png")
	err = copyFile(dataAssetDiagramFilenamePNG, adocDataRiskMappingFilename)
	if err != nil {
		log.Fatal("Could not copy file: »" + dataAssetDiagramFilenamePNG + "« to »" + adocDataRiskMappingFilename + "«: " + err.Error())
	}

	landScape := imageIsWiderThanHigh(adocDataRiskMappingFilename)
	if landScape {
		adoc.writeMainLine("[page-layout=landscape]")
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.dataRiskMapping(f, "images/data-asset-diagram.png")
	if landScape {
		adoc.writeMainLine("[page-layout=portrait]")
	}
	return nil
}

func (adoc adocReport) outOfScopeAssets(f *os.File) {
	assets := "Asset"
	count := len(adoc.model.OutOfScopeTechnicalAssets())
	if count > 1 {
		assets += "s"
	}
	writeLine(f, "= Out-of-Scope Assets: "+strconv.Itoa(count)+" "+assets)
	writeLine(f, ":fn-tech-assets: footnote:techAssets[Technical asset paragraphs are clickable and link to the corresponding chapter.]")
	writeLine(f, "")
	writeLine(f, `
This chapter lists all technical assets that have been defined as out-of-scope.
Each one should be checked in the model whether it should better be included in the overall risk analysis{fn-tech-assets}:
`)
	writeLine(f, "")

	outOfScopeAssetCount := 0
	for _, technicalAsset := range sortedTechnicalAssetsByRAAAndTitle(adoc.model) {
		if technicalAsset.OutOfScope {
			outOfScopeAssetCount++
			writeLine(f, "<<"+technicalAsset.Id+",[OutOfScope]#"+technicalAsset.Title+" : out-of-scope#>>::")
			writeLine(f, "  "+technicalAsset.JustificationOutOfScope)
			writeLine(f, "")
		}
	}

	if outOfScopeAssetCount == 0 {
		writeLine(f, "[GreyText]#No technical assets have been defined as out-of-scope.#")
	}
}

func (adoc adocReport) writeOutOfScopeAssets() error {
	filename := "140_OutOfScopeAssets.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.outOfScopeAssets(f)
	return nil
}

func (adoc adocReport) modelFailures(f *os.File) {
	modelFailures := flattenRiskSlice(filterByModelFailures(adoc.model, adoc.model.GeneratedRisksByCategoryWithCurrentStatus()))
	risksStr := "Risk"
	count := len(modelFailures)
	if count > 1 {
		risksStr += "s"
	}
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(modelFailures))
	colorPrefix := ""
	colorSuffix := ""
	if countStillAtRisk > 0 {
		colorPrefix = "[ModelFailure]#"
		colorSuffix = "#"
	}
	writeLine(f, "= "+colorPrefix+"Potential Model Failures: "+strconv.Itoa(countStillAtRisk)+" / "+strconv.Itoa(count)+" "+risksStr+colorSuffix)
	writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")
	writeLine(f, "")

	writeLine(f, `
This chapter lists potential model failures where not all relevant assets have been
modeled or the model might itself contain inconsistencies. Each potential model failure should be checked
in the model against the architecture design:{fn-risk-findings}`)
	writeLine(f, "")

	modelFailuresByCategory := filterByModelFailures(adoc.model, adoc.model.GeneratedRisksByCategoryWithCurrentStatus())
	if len(modelFailuresByCategory) == 0 {
		writeLine(f, "No potential model failures have been identified.")
	} else {
		adoc.addCategories(f, modelFailuresByCategory, true, types.CriticalSeverity, true, true)
		adoc.addCategories(f, modelFailuresByCategory, true, types.HighSeverity, true, true)
		adoc.addCategories(f, modelFailuresByCategory, true, types.ElevatedSeverity, true, true)
		adoc.addCategories(f, modelFailuresByCategory, true, types.MediumSeverity, true, true)
		adoc.addCategories(f, modelFailuresByCategory, true, types.LowSeverity, true, true)
	}
}

func (adoc adocReport) writeModelFailures() error {
	filename := "150_ModelFailures.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.modelFailures(f)
	return nil
}

func (adoc adocReport) questions(f *os.File) {
	questions := "Question"
	count := len(adoc.model.Questions)
	if count > 1 {
		questions += "s"
	}
	colorPrefix := ""
	colorSuffix := ""
	if questionsUnanswered(adoc.model) > 0 {
		colorPrefix = "[ModelFailure]#"
		colorSuffix = "#"
	}
	writeLine(f, "= "+colorPrefix+"Questions: "+strconv.Itoa(questionsUnanswered(adoc.model))+" / "+strconv.Itoa(count)+" "+questions+colorSuffix)
	writeLine(f, "")
	writeLine(f, "This chapter lists custom questions that arose during the threat modeling process.")
	writeLine(f, "")

	if len(adoc.model.Questions) == 0 {
		writeLine(f, "")
		writeLine(f, "[GreyText]#No custom questions arose during the threat modeling process.#")
	}
	writeLine(f, "")

	for _, question := range sortedKeysOfQuestions(adoc.model) {
		answer := adoc.model.Questions[question]
		if len(strings.TrimSpace(answer)) > 0 {
			writeLine(f, "*"+question+"*::")
			writeLine(f, "_"+strings.TrimSpace(answer)+"_")
		} else {
			writeLine(f, "*[ModelFailure]#"+question+"#*::")
			writeLine(f, "[GreyText]#_- answer pending -_#")
		}
		writeLine(f, "")
	}
}

func (adoc adocReport) writeQuestions() error {
	filename := "160_Questions.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.questions(f)
	return nil
}

func (adoc adocReport) riskTrackingStatus(f *os.File, risk *types.Risk) {
	tracking := adoc.model.GetRiskTrackingWithDefault(risk)

	colorName := ""
	switch tracking.Status {
	case types.Unchecked:
		colorName = "RiskStatusUnchecked"
	case types.InDiscussion:
		colorName = "RiskStatusInDiscussion"
	case types.Accepted:
		colorName = "RiskStatusAccepted"
	case types.InProgress:
		colorName = "RiskStatusInProgress"
	case types.Mitigated:
		colorName = "RiskStatusMitigated"
	case types.FalsePositive:
		colorName = "RiskStatusFalsePositive"
	default:
		colorName = ""
	}
	bold := ""
	if tracking.Status == types.Unchecked {
		bold = "*"
	}

	if tracking.Status != types.Unchecked {
		dateStr := tracking.Date.Format("2006-01-02")
		if dateStr == "0001-01-01" {
			dateStr = ""
		}
		justificationStr := tracking.Justification
		ticket := tracking.Ticket
		if len(ticket) == 0 {
			ticket = "-"
		}
		writeLine(f, `
[cols="a,c,c,c",frame=none,grid=none,options="unbreakable"]
|===
| [.`+colorName+`.small]#`+bold+tracking.Status.Title()+bold+`#
| [.GreyText.small]#`+dateStr+`#
| [.GreyText.small]#`+tracking.CheckedBy+`#
| [.GreyText.small]#`+ticket+`#

4+|[.small]#`+justificationStr+`#
|===
`)
	} else {
		writeLine(f, `
[cols="a,c,c,c",frame=none,grid=none,options="unbreakable"]
|===
4+| [.`+colorName+`.small]#`+bold+tracking.Status.Title()+bold+`#
|===
`)
	}
}

func (adoc adocReport) riskCategories(f *os.File) {
	writeLine(f, "= Identified Risks by Vulnerability category")
	writeLine(f, "In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during the threat modeling process "+
		"of which "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.CriticalSeverity)))+" are rated as critical*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.HighSeverity)))+" as high*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.ElevatedSeverity)))+" as elevated*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.MediumSeverity)))+" as medium*, "+
		"and *"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.LowSeverity)))+" as low*. "+
		"\n\nThese risks are distributed across *"+strconv.Itoa(len(adoc.model.GeneratedRisksByCategory))+" vulnerability categories*. ")
	writeLine(f, "The following sub-chapters of this section describe each identified risk category.") // TODO more explanation text
	writeLine(f, "")

	for _, category := range adoc.model.SortedRiskCategories() {
		risksStr := adoc.model.SortedRisksOfCategory(category)

		// category color
		colorPrefix, colorSuffix := colorPrefixBySeverity(types.HighestSeverityStillAtRisk(risksStr), false)
		if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
			colorPrefix = ""
			colorSuffix = ""
		}

		// category title
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		title := colorPrefix + category.Title + ": " + suffix + colorSuffix
		writeLine(f, "[["+category.ID+"]]")
		writeLine(f, "== "+title)
		writeLine(f, "")

		// category details
		cweLink := "n/a"
		if category.CWE > 0 {
			cweLink = "https://cwe.mitre.org/data/definitions/" + strconv.Itoa(category.CWE) + ".html[CWE " +
				strconv.Itoa(category.CWE) + "]"
		}
		writeLine(f, "*Description* ("+category.STRIDE.Title()+"): "+cweLink+"::")
		writeLine(f, fixBasicHtml(category.Description))
		writeLine(f, "")
		writeLine(f, "*Impact*::")
		writeLine(f, fixBasicHtml(category.Impact))
		writeLine(f, "")
		writeLine(f, "*Detection Logic*::")
		writeLine(f, fixBasicHtml(category.DetectionLogic))
		writeLine(f, "")
		writeLine(f, "*Risk Rating*::")
		writeLine(f, fixBasicHtml(category.RiskAssessment))
		writeLine(f, "")

		writeLine(f, "[RiskStatusFalsePositive]#*False Positives*#::")
		if len(category.FalsePositives) > 0 {
			writeLine(f, "[RiskStatusFalsePositive]#"+category.FalsePositives+"#")
		}
		writeLine(f, "")

		writeLine(f, "[RiskStatusMitigated]#*Mitigation*# ("+category.Function.Title()+"): "+category.Action+"::")
		writeLine(f, fixBasicHtml(category.Mitigation))
		writeLine(f, "")

		asvsChapter := category.ASVS
		asvsLink := "n/a"
		if len(asvsChapter) > 0 {
			asvsLink = "https://owasp.org/www-project-application-security-verification-standard/[" + asvsChapter + "]"
		}

		cheatSheetLink := category.CheatSheet
		if len(cheatSheetLink) == 0 {
			cheatSheetLink = "n/a"
		} else {
			lastLinkParts := strings.Split(cheatSheetLink, "/")
			linkText := lastLinkParts[len(lastLinkParts)-1]
			if strings.HasSuffix(linkText, ".html") || strings.HasSuffix(linkText, ".htm") {
				var extension = filepath.Ext(linkText)
				linkText = linkText[0 : len(linkText)-len(extension)]
			}
			cheatSheetLink = cheatSheetLink + "[" + linkText + "]"
		}
		writeLine(f, "")
		writeLine(f, "* [RiskStatusMitigated]#ASVS Chapter#: "+asvsLink)
		writeLine(f, "* [RiskStatusMitigated]#Cheat Sheet#: "+cheatSheetLink)
		writeLine(f, "\n\n*Check*\n")
		writeLine(f, category.Check)

		// risk details
		writeLine(f, "")
		writeLine(f, "<<<")
		writeLine(f, "=== Risk Findings")
		writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")
		times := strconv.Itoa(len(risksStr)) + " time"
		if len(risksStr) > 1 {
			times += "s"
		}
		writeLine(f, "")
		writeLine(f, "The risk *"+category.Title+"* was found *"+times+"* in the analyzed architecture to be "+
			"potentially possible. Each spot should be checked individually by reviewing the implementation whether all "+
			"controls have been applied properly in order to mitigate each risk.{fn-risk-findings}")

		for _, risk := range risksStr {
			colorPrefix, colorSuffix := colorPrefixBySeverity(risk.Severity, false)
			if len(colorPrefix) == 0 {
				colorSuffix = ""
			}

			title := titleOfSeverity(risk.Severity)
			if len(title) > 0 {
				writeLine(f, "")
				writeLine(f, "==== "+colorPrefix+"_"+title+"_"+colorSuffix)
			}

			if !risk.RiskStatus.IsStillAtRisk() {
				colorPrefix = ""
				colorSuffix = ""
			}
			writeLine(f, colorPrefix+fixBasicHtml(risk.Title)+": Exploitation likelihood is _"+risk.ExploitationLikelihood.Title()+"_ with _"+risk.ExploitationImpact.Title()+"_ impact."+colorSuffix)
			linkId := ""
			if len(risk.MostRelevantSharedRuntimeId) > 0 {
				linkId = risk.MostRelevantSharedRuntimeId
			} else if len(risk.MostRelevantTrustBoundaryId) > 0 {
				linkId = risk.MostRelevantTrustBoundaryId
			} else if len(risk.MostRelevantTechnicalAssetId) > 0 {
				linkId = risk.MostRelevantTechnicalAssetId
			}
			writeLine(f, "")
			writeLine(f, "<<"+linkId+",[SmallGrey]#"+risk.SyntheticId+"#>>")

			adoc.riskTrackingStatus(f, risk)
		}
	}
}

func (adoc adocReport) writeRiskCategories() error {
	filename := "170_RiskCategories.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.riskCategories(f)
	return nil
}

func joinedOrNoneString(strs []string, noneValue string) string {
	if noneValue == "" {
		noneValue = "[GrayText]#none#"
	}
	sort.Strings(strs)
	singleLine := strings.Join(strs[:], ", ")
	if len(singleLine) == 0 {
		singleLine = noneValue
	}
	return singleLine
}

func dataAssetListTitleJoinOrNone(assets []*types.DataAsset, noneValue string) string {
	var dataAssetTitles []string
	for _, dataAsset := range assets {
		dataAssetTitles = append(dataAssetTitles, dataAsset.Title)
	}
	return joinedOrNoneString(dataAssetTitles, noneValue)
}

func technicalAssetTitleOrNone(links []*types.TechnicalAsset, noneValue string) string {
	var titles []string
	for _, asset := range links {
		titles = append(titles, asset.Title)
	}
	return joinedOrNoneString(titles, noneValue)
}

func dataFormatTitleJoinOrNone(assets []types.DataFormat, noneValue string) string {
	var dataAssetTitles []string
	for _, dataFormat := range assets {
		dataAssetTitles = append(dataAssetTitles, dataFormat.Title())
	}
	return joinedOrNoneString(dataAssetTitles, noneValue)
}

func communicationLinkTitleOrNone(links []*types.CommunicationLink, noneValue string) string {
	var titles []string
	for _, link := range links {
		titles = append(titles, link.Title)
	}
	return joinedOrNoneString(titles, noneValue)
}

func (adoc adocReport) technicalAssets(f *os.File) {
	writeLine(f, "= Identified Risks by Technical Asset")
	writeLine(f, "In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during the threat modeling process "+
		"of which "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.CriticalSeverity)))+" are rated as critical*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.HighSeverity)))+" as high*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.ElevatedSeverity)))+" as elevated*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.MediumSeverity)))+" as medium*, "+
		"and *"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.LowSeverity)))+" as low*. "+
		"\n\nThese risks are distributed across *"+strconv.Itoa(len(adoc.model.InScopeTechnicalAssets()))+" in-scope technical assets*. ")
	writeLine(f, "The following sub-chapters of this section describe each identified risk grouped by technical asset. ") // TODO more explanation text
	writeLine(f, "The RAA value of a technical asset is the calculated \"Relative Attacker Attractiveness\" value in percent.")

	for _, technicalAsset := range sortedTechnicalAssetsByRiskSeverityAndTitle(adoc.model) {
		risksStr := adoc.model.GeneratedRisks(technicalAsset)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		colorPrefix, colorSuffix := colorPrefixBySeverity(types.HighestSeverityStillAtRisk(risksStr), false)
		if technicalAsset.OutOfScope {
			colorPrefix = "[OutOfScope]#"
			suffix = "out-of-scope"
		} else {
			if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
				colorPrefix = ""
				colorSuffix = ""
			}
		}

		// asset title
		title := colorPrefix + technicalAsset.Title + ": " + suffix + colorSuffix
		writeLine(f, "[["+technicalAsset.Id+"]]")
		writeLine(f, "== "+title)

		// asset description
		writeLine(f, "=== Description")
		writeLine(f, technicalAsset.Description)
		writeLine(f, "")

		// and more metadata of asset in tabular view
		writeLine(f, "=== Identified Risks of Asset")
		if len(risksStr) > 0 {
			writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")
			for _, risk := range risksStr {
				colorPrefix, colorSuffix = colorPrefixBySeverity(types.HighestSeverityStillAtRisk(risksStr), false)
				if !risk.RiskStatus.IsStillAtRisk() {
					colorPrefix = ""
					colorSuffix = ""
				}
				writeLine(f, "\n==== "+colorPrefix+titleOfSeverity(risk.Severity)+colorSuffix+"\n")
				writeLine(f, colorPrefix+fixBasicHtml(risk.Title)+": Exploitation likelihood is _"+risk.ExploitationLikelihood.Title()+"_ with _"+risk.ExploitationImpact.Title()+"_ impact."+colorSuffix)
				writeLine(f, "")

				writeLine(f, "<<"+risk.CategoryId+",[SmallGrey]#"+risk.SyntheticId+"#>>")
				adoc.riskTrackingStatus(f, risk)
			}
		} else {
			text := "No risksStr were identified."
			if technicalAsset.OutOfScope {
				text = "Asset was defined as out-of-scope."
			}
			writeLine(f, "[GrayText]#"+text+"#")
		}

		// ASSET INFORMATION
		writeLine(f, "")
		writeLine(f, "<<<")
		writeLine(f, "")
		writeLine(f, "=== Asset Information")
		textRAA := fmt.Sprintf("%.0f", technicalAsset.RAA) + " %"
		if technicalAsset.OutOfScope {
			textRAA = "[GrayText]#out-of-scope#"
		}

		tagsUsedText := joinedOrNoneString(technicalAsset.Tags, "")
		dataAssetsProcessedText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsProcessedSorted(technicalAsset), "")
		dataAssetsStoredText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsStoredSorted(technicalAsset), "")
		formatsAcceptedText := dataFormatTitleJoinOrNone(technicalAsset.DataFormatsAcceptedSorted(), "[GrayText]#none of the special data formats accepted#")

		writeLine(f, `
[cols="h,5",frame=none,grid=none]
|===
| ID:               | `+technicalAsset.Id+`
| Type:             | `+technicalAsset.Type.String()+`
| Usage:            | `+technicalAsset.Usage.String()+`
| RAA:              | `+textRAA+`
| Size:             | `+technicalAsset.Size.String()+`
| Technology:       | `+technicalAsset.Technologies.String()+`
| Tags:             | `+tagsUsedText+`
| Internet:         | `+strconv.FormatBool(technicalAsset.Internet)+`
| Machine:          | `+technicalAsset.Machine.String()+`
| Encryption:       | `+technicalAsset.Encryption.String()+`
| Encryption:       | `+technicalAsset.Encryption.String()+`
| Multi-Tenant:     | `+strconv.FormatBool(technicalAsset.MultiTenant)+`
| Redundant:        | `+strconv.FormatBool(technicalAsset.Redundant)+`
| Custom-Developed: | `+strconv.FormatBool(technicalAsset.CustomDevelopedParts)+`
| Client by Human:  | `+strconv.FormatBool(technicalAsset.UsedAsClientByHuman)+`
| Data Processed:   | `+dataAssetsProcessedText+`
| Data Stored:      | `+dataAssetsStoredText+`
| Formats Accepted: | `+formatsAcceptedText+`
|===
`)

		writeLine(f, "=== Asset Rating")
		writeLine(f, `
[cols="h,2,1",frame=none,grid=none]
|===
| Owner:             2+| `+technicalAsset.Owner+`
| Confidentiality:     | `+technicalAsset.Confidentiality.String()+` | `+technicalAsset.Confidentiality.RatingStringInScale()+`
| Integrity:           | `+technicalAsset.Integrity.String()+` | `+technicalAsset.Integrity.RatingStringInScale()+`
| Availability:        | `+technicalAsset.Availability.String()+` | `+technicalAsset.Availability.RatingStringInScale()+`
| CIA-Justification: 2+| `+technicalAsset.JustificationCiaRating)
		if technicalAsset.OutOfScope {
			writeLine(f, "| Asset Out-of-Scope Justification: 2+| "+technicalAsset.JustificationOutOfScope)
		}
		writeLine(f, "|===\n")

		if len(technicalAsset.CommunicationLinks) > 0 {
			writeLine(f, "=== Outgoing Communication Links: "+strconv.Itoa(len(technicalAsset.CommunicationLinks)))
			for _, outgoingCommLink := range technicalAsset.CommunicationLinksSorted() {
				writeLine(f, "==== "+outgoingCommLink.Title+" (outgoing)")
				writeLine(f, fixBasicHtml(outgoingCommLink.Description))

				tagsUsedText := joinedOrNoneString(outgoingCommLink.Tags, "")
				dataAssetsSentText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsSentSorted(outgoingCommLink), "")
				dataAssetsReceivedText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsReceivedSorted(outgoingCommLink), "")

				writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| Target:         | <<`+outgoingCommLink.TargetId+`,`+adoc.model.TechnicalAssets[outgoingCommLink.TargetId].Title+`>>
| Protocol:       | `+outgoingCommLink.Protocol.String()+`
| Encrypted:      | `+strconv.FormatBool(outgoingCommLink.Protocol.IsEncrypted())+`
| Authentication: | `+outgoingCommLink.Authentication.String()+`
| Authorization:  | `+outgoingCommLink.Authorization.String()+`
| Read-Only:      | `+strconv.FormatBool(outgoingCommLink.Readonly)+`
| Usage:          | `+outgoingCommLink.Usage.String()+`
| Tags:           | `+tagsUsedText+`
| VPN:            | `+strconv.FormatBool(outgoingCommLink.VPN)+`
| IP-Filtered:    | `+strconv.FormatBool(outgoingCommLink.IpFiltered)+`
| Data Sent:      | `+dataAssetsSentText+`
| Data Received:  | `+dataAssetsReceivedText+`
|===
`)
			}
		}

		incomingCommLinks := adoc.model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		if len(incomingCommLinks) > 0 {
			writeLine(f, "=== Incoming Communication Links: "+strconv.Itoa(len(incomingCommLinks)))
			for _, incomingCommLink := range incomingCommLinks {
				writeLine(f, "==== "+incomingCommLink.Title+" (outgoing)")
				writeLine(f, fixBasicHtml(incomingCommLink.Description))

				tagsUsedText := joinedOrNoneString(incomingCommLink.Tags, "")
				dataAssetsSentText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsSentSorted(incomingCommLink), "")
				dataAssetsReceivedText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsReceivedSorted(incomingCommLink), "")

				writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| Source:         | <<`+incomingCommLink.SourceId+`,`+adoc.model.TechnicalAssets[incomingCommLink.SourceId].Title+`>>
| Protocol:       | `+incomingCommLink.Protocol.String()+`
| Encrypted:      | `+strconv.FormatBool(incomingCommLink.Protocol.IsEncrypted())+`
| Authentication: | `+incomingCommLink.Authentication.String()+`
| Authorization:  | `+incomingCommLink.Authorization.String()+`
| Read-Only:      | `+strconv.FormatBool(incomingCommLink.Readonly)+`
| Usage:          | `+incomingCommLink.Usage.String()+`
| Tags:           | `+tagsUsedText+`
| VPN:            | `+strconv.FormatBool(incomingCommLink.VPN)+`
| IP-Filtered:    | `+strconv.FormatBool(incomingCommLink.IpFiltered)+`
| Data Sent:      | `+dataAssetsSentText+`
| Data Received:  | `+dataAssetsReceivedText+`
|===
`)
			}
		}
	}
}

func (adoc adocReport) writeTechnicalAssets() error {
	filename := "180_TechnicalAssets.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.technicalAssets(f)
	return nil
}

func (adoc adocReport) dataAssets(f *os.File) {
	writeLine(f, "= Identified Data Breach Probabilities by Data Asset")
	writeLine(f, "In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during the threat modeling process "+
		"of which "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.CriticalSeverity)))+" are rated as critical*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.HighSeverity)))+" as high*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.ElevatedSeverity)))+" as elevated*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.MediumSeverity)))+" as medium*, "+
		"and *"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.LowSeverity)))+" as low*. "+
		"\n\nThese risks are distributed across *"+strconv.Itoa(len(adoc.model.DataAssets))+" data assets*. ")
	writeLine(f, "The following sub-chapters of this section describe the derived data breach probabilities grouped by data asset.") // TODO more explanation text
	writeLine(f, "")
	for _, dataAsset := range sortedDataAssetsByDataBreachProbabilityAndTitle(adoc.model) {

		dataBreachProbability := identifiedDataBreachProbabilityStillAtRisk(adoc.model, dataAsset)
		colorPrefix, colorSuffix := colorPrefixByDataBreachProbability(dataBreachProbability, false)
		if !isDataBreachPotentialStillAtRisk(adoc.model, dataAsset) {
			colorPrefix = ""
		}
		risksStr := adoc.model.IdentifiedDataBreachProbabilityRisks(dataAsset)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		writeLine(f, "<<<")
		writeLine(f, "[[dataAsset:"+dataAsset.Id+"]]")
		writeLine(f, "== "+colorPrefix+dataAsset.Title+": "+suffix+colorSuffix)
		writeLine(f, fixBasicHtml(dataAsset.Description)+"\n\n")

		tagsUsedText := joinedOrNoneString(dataAsset.Tags, "")
		processedByText := technicalAssetTitleOrNone(adoc.model.ProcessedByTechnicalAssetsSorted(dataAsset), "")
		storedByText := technicalAssetTitleOrNone(adoc.model.StoredByTechnicalAssetsSorted(dataAsset), "")
		sentViaText := communicationLinkTitleOrNone(adoc.model.SentViaCommLinksSorted(dataAsset), "")
		receivedViaText := communicationLinkTitleOrNone(adoc.model.ReceivedViaCommLinksSorted(dataAsset), "")
		dataBreachRisksStillAtRisk := identifiedDataBreachProbabilityRisksStillAtRisk(adoc.model, dataAsset)
		sortByDataBreachProbability(dataBreachRisksStillAtRisk, adoc.model)
		dataBreachText := "This data asset has no data breach potential."
		if len(dataBreachRisksStillAtRisk) > 0 {
			riskRemainingStr := "risk"
			if countStillAtRisk > 1 {
				riskRemainingStr += "s"
			}
			dataBreachText = "This data asset has data breach potential because of " +
				"" + strconv.Itoa(countStillAtRisk) + " remaining " + riskRemainingStr + ":"
		}

		riskText := dataBreachProbability.String()
		if !isDataBreachPotentialStillAtRisk(adoc.model, dataAsset) {
			colorPrefix = ""
			colorSuffix = ""
			riskText = "none"
		}

		writeLine(f, `
[cols="h,2,1",frame=none,grid=none]
|===
| ID:                2+| `+dataAsset.Id+`
| Usage:             2+| `+dataAsset.Usage.String()+`
| Quantity:          2+| `+dataAsset.Quantity.String()+`
| Tags:              2+| `+tagsUsedText+`
| Origin:            2+| `+dataAsset.Origin+`
| Owner:             2+| `+dataAsset.Owner+`
| Confidentiality:     | `+dataAsset.Confidentiality.String()+` | `+dataAsset.Confidentiality.RatingStringInScale()+`
| Integrity:           | `+dataAsset.Integrity.String()+` | `+dataAsset.Integrity.RatingStringInScale()+`
| Availability:        | `+dataAsset.Availability.String()+` | `+dataAsset.Availability.RatingStringInScale()+`
| CIA-Justification: 2+| `+dataAsset.JustificationCiaRating+`
| Processed by:      2+| `+processedByText+`
| Stored by:         2+| `+storedByText+`
| Sent via:          2+| `+sentViaText+`
| Received via:      2+| `+receivedViaText+`
| Data Breach:       2+| `+colorPrefix+riskText+colorSuffix+`
| Data Breach Risks: 2+| `+dataBreachText)

		if len(dataBreachRisksStillAtRisk) > 0 {
			for _, dataBreachRisk := range dataBreachRisksStillAtRisk {
				colorPrefix, colorSuffix := colorPrefixByDataBreachProbability(dataBreachRisk.DataBreachProbability, true)
				if !dataBreachRisk.RiskStatus.IsStillAtRisk() {
					colorPrefix = ""
				}

				txt := dataBreachRisk.DataBreachProbability.Title() + ": " + dataBreachRisk.SyntheticId
				writeLine(f, "|                    2+| <<"+dataBreachRisk.CategoryId+","+colorPrefix+txt+colorSuffix+">>")
			}
		}

		writeLine(f, `
|===
`)
	}
}

func (adoc adocReport) writeDataAssets() error {
	filename := "190_DataAssets.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.dataAssets(f)
	return nil
}

func (adoc adocReport) trustBoundaries(f *os.File) {
	writeLine(f, "= Trust Boundaries")

	word := "has"
	if len(adoc.model.TrustBoundaries) > 1 {
		word = "have"
	}
	writeLine(f, "In total *"+strconv.Itoa(len(adoc.model.TrustBoundaries))+" trust boundaries* "+word+" been "+
		"modeled during the threat modeling process.")
	writeLine(f, "")
	for _, trustBoundary := range sortedTrustBoundariesByTitle(adoc.model) {
		colorPrefix := "[.Twilight]#"
		colorSuffix := "#"
		if !trustBoundary.Type.IsNetworkBoundary() {
			colorPrefix = "[.LightGreyText]#"
		}
		writeLine(f, "[["+trustBoundary.Id+"]]")
		writeLine(f, "== "+colorPrefix+trustBoundary.Title+colorSuffix)
		writeLine(f, colorPrefix+trustBoundary.Description+colorSuffix)
		writeLine(f, "")

		tagsUsedText := joinedOrNoneString(trustBoundary.Tags, "")
		assetsInsideText := joinedOrNoneString(trustBoundary.TechnicalAssetsInside, "")
		boundariesNestedText := joinedOrNoneString(trustBoundary.TrustBoundariesNested, "")

		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| ID:                | `+trustBoundary.Id+`
| Type:              | `+colorPrefix+trustBoundary.Type.String()+colorSuffix+`
| Tags:              | `+tagsUsedText+`
| Assets inside:     | `+assetsInsideText+`
| Boundaries nested: | `+boundariesNestedText+`
|===
`)
	}

}

func (adoc adocReport) writeTrustBoundaries() error {
	filename := "200_TrustBoundaries.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.trustBoundaries(f)
	return nil
}

func (adoc adocReport) sharedRuntimes(f *os.File) {
	writeLine(f, "= Shared Runtimes")
	word, runtime := "has", "runtime"
	if len(adoc.model.SharedRuntimes) > 1 {
		word, runtime = "have", "runtimes"
	}
	writeLine(f, "In total *"+strconv.Itoa(len(adoc.model.SharedRuntimes))+" shared "+runtime+"* "+word+" been "+
		"modeled during the threat modeling process.")
	writeLine(f, "")
	for _, sharedRuntime := range sortedSharedRuntimesByTitle(adoc.model) {
		writeLine(f, "[["+sharedRuntime.Id+"]]")
		writeLine(f, "== "+sharedRuntime.Title)
		writeLine(f, sharedRuntime.Description)
		writeLine(f, "")

		tagsUsedText := joinedOrNoneString(sharedRuntime.Tags, "")
		assetsRunningText := joinedOrNoneString(sharedRuntime.TechnicalAssetsRunning, "")
		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| ID:             | `+sharedRuntime.Id+`
| Tags:           | `+tagsUsedText+`
| Assets running: | `+assetsRunningText+`
|===
`)
	}
}

func (adoc adocReport) writeSharedRuntimes() error {
	filename := "210_SharedRuntimes.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.sharedRuntimes(f)
	return nil
}

func (adoc adocReport) riskRulesChecked(f *os.File, modelFilename string, skipRiskRules []string, buildTimestamp string, threagileVersion string, modelHash string, customRiskRules types.RiskRules) {
	writeLine(f, "= Risk Rules Checked by Threagile")
	writeLine(f, "")
	timestamp := time.Now()
	writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| Threagile Version:             | `+threagileVersion+`
| Threagile Build Timestamp:     | `+buildTimestamp+`
| Threagile Execution Timestamp: | `+timestamp.Format("20060102150405")+`
| Model Filename:                | `+modelFilename+`
| Model Hash (SHA256):           | `+modelHash+`
|===
`)
	writeLine(f, "\n\n")
	writeLine(f, "Threagile (see https://threagile.io[] for more details) is an open-source toolkit for agile threat modeling, created by Christian Schneider (https://christian-schneider.net[]): It allows to model an architecture with its assets in an agile fashion as a YAML file "+
		"directly inside the IDE. Upon execution of the Threagile toolkit all standard risk rules (as well as individual custom rules if present) "+
		"are checked against the architecture model. At the time the Threagile toolkit was executed on the model input file "+
		"the following risk rules were checked:")
	writeLine(f, "")

	// TODO use the new run system to discover risk rules instead of hard-coding them here:
	skipped := ""

	for id, customRule := range customRiskRules {
		if contains(skipRiskRules, id) {
			skipped = "SKIPPED - "
		} else {
			skipped = ""
		}
		writeLine(f, "== "+skipped+customRule.Category().Title)
		writeLine(f, "[.small]#"+id+"#")
		writeLine(f, "")
		writeLine(f, "_Custom Risk Rule_")
		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| STRIDE:      | `+customRule.Category().STRIDE.Title()+`
| Description: | `+firstParagraph(customRule.Category().Description)+`
| Detection:   | `+customRule.Category().DetectionLogic+`
| Rating:      | `+customRule.Category().RiskAssessment+`
|===
`)
	}

	sort.Sort(types.ByRiskCategoryTitleSort(adoc.model.CustomRiskCategories))
	for _, individualRiskCategory := range adoc.model.CustomRiskCategories {
		writeLine(f, "== "+individualRiskCategory.Title)
		writeLine(f, "[.small]#"+individualRiskCategory.ID+"#")
		writeLine(f, "")
		writeLine(f, "_Individual Risk category_")
		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| STRIDE:      | `+individualRiskCategory.STRIDE.Title()+`
| Description: | `+firstParagraph(individualRiskCategory.Description)+`
| Detection:   | `+individualRiskCategory.DetectionLogic+`
| Rating:      | `+individualRiskCategory.RiskAssessment+`
|===
`)
	}

	for _, rule := range adoc.riskRules {
		if contains(skipRiskRules, rule.Category().ID) {
			skipped = "SKIPPED - "
		} else {
			skipped = ""
		}
		writeLine(f, "== "+skipped+rule.Category().Title)
		writeLine(f, "[.small]#"+rule.Category().ID+"#")
		writeLine(f, "")
		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| STRIDE:      | `+rule.Category().STRIDE.Title()+`
| Description: | `+firstParagraph(rule.Category().Description)+`
| Detection:   | `+rule.Category().DetectionLogic+`
| Rating:      | `+rule.Category().RiskAssessment+`
|===
`)
	}
}

func (adoc adocReport) writeRiskRulesChecked(modelFilename string, skipRiskRules []string, buildTimestamp string, threagileVersion string, modelHash string, customRiskRules types.RiskRules) error {
	filename := "220_RiskRulesChecked.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.riskRulesChecked(f, modelFilename, skipRiskRules, buildTimestamp, threagileVersion, modelHash, customRiskRules)
	return nil
}

func (adoc adocReport) disclaimer(f *os.File) {
	writeLine(f, "= Disclaimer")

	disclaimerColor := "\n[.Silver]\n"

	writeLine(f, disclaimerColor+
		adoc.model.Author.Name+" conducted this threat analysis using the open-source Threagile toolkit "+
		"on the applications and systems that were modeled as of this report's date. "+
		"Information security threats are continually changing, with new "+
		"vulnerabilities discovered on a daily basis, and no application can ever be 100% secure no matter how much "+
		"threat modeling is conducted. It is recommended to execute threat modeling and also penetration testing on a regular basis "+
		"(for example yearly) to ensure a high ongoing level of security and constantly check for new attack vectors. "+
		"\n\n"+
		disclaimerColor+
		"This report cannot and does not protect against personal or business loss as the result of use of the "+
		"applications or systems described. "+adoc.model.Author.Name+" and the Threagile toolkit offers no warranties, representations or "+
		"legal certifications concerning the applications or systems it tests. All software includes defects: nothing "+
		"in this document is intended to represent or warrant that threat modeling was complete and without error, "+
		"nor does this document represent or warrant that the architecture analyzed is suitable to task, free of other "+
		"defects than reported, fully compliant with any industry standards, or fully compatible with any operating "+
		"system, hardware, or other application. Threat modeling tries to analyze the modeled architecture without "+
		"having access to a real working system and thus cannot and does not test the implementation for defects and vulnerabilities. "+
		"These kinds of checks would only be possible with a separate code review and penetration test against "+
		"a working system and not via a threat model."+
		"\n\n"+
		disclaimerColor+
		"By using the resulting information you agree that "+adoc.model.Author.Name+" and the Threagile toolkit "+
		"shall be held harmless in any event."+
		"\n\n"+
		disclaimerColor+
		"This report is confidential and intended for internal, confidential use by the client. The recipient "+
		"is obligated to ensure the highly confidential contents are kept secret. The recipient assumes responsibility "+
		"for further distribution of this document."+
		"\n\n"+
		disclaimerColor+
		"In this particular project, a time box approach was used to define the analysis effort. This means that the "+
		"author allotted a prearranged amount of time to identify and document threats. Because of this, there "+
		"is no guarantee that all possible threats and risks are discovered. Furthermore, the analysis "+
		"applies to a snapshot of the current state of the modeled architecture (based on the architecture information provided "+
		"by the customer) at the examination time."+
		"\n\n"+
		"== Report Distribution"+
		disclaimerColor+
		"Distribution of this report (in full or in part like diagrams or risk findings) requires that this disclaimer "+
		"as well as the chapter about the Threagile toolkit and method used is kept intact as part of the "+
		"distributed report or referenced from the distributed parts.")
}

func (adoc adocReport) writeDisclaimer() error {
	filename := "230_Disclaimer.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.disclaimer(f)
	return nil
}
