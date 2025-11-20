package report

import (
	"fmt"
	"image"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jung-kurt/gofpdf"
	"github.com/jung-kurt/gofpdf/contrib/gofpdi"
	"github.com/threagile/threagile/pkg/types"
	"github.com/wcharczuk/go-chart"
	"github.com/wcharczuk/go-chart/drawing"
)

const fontSizeHeadline, fontSizeHeadlineSmall, fontSizeBody, fontSizeSmall, fontSizeVerySmall = 20, 16, 12, 9, 7
const allowedPdfLandscapePages, embedDiagramLegendPage = true, false

type pdfReporter struct {
	isLandscapePage               bool
	pdf                           *gofpdf.Fpdf
	coverTemplateId               int
	contentTemplateId             int
	diagramLegendTemplateId       int
	pageNo                        int
	linkCounter                   int
	tocLinkIdByAssetId            map[string]int
	homeLink                      int
	currentChapterTitleBreadcrumb string

	riskRules types.RiskRules
}

func newPdfReporter(riskRules types.RiskRules) *pdfReporter {
	return &pdfReporter{
		riskRules: riskRules,
	}
}

func (r *pdfReporter) initReport() {
	r.pdf = nil
	r.isLandscapePage = false
	r.pageNo = 0
	r.linkCounter = 0
	r.homeLink = 0
	r.currentChapterTitleBreadcrumb = ""
	r.tocLinkIdByAssetId = make(map[string]int)
}

func (r *pdfReporter) WriteReportPDF(reportFilename string,
	templateFilename string,
	dataFlowDiagramFilenamePNG string,
	dataAssetDiagramFilenamePNG string,
	modelFilename string,
	skipRiskRules []string,
	buildTimestamp string,
	threagileVersion string,
	modelHash string,
	introTextRAA string,
	customRiskRules types.RiskRules,
	tempFolder string,
	model *types.Model,
	hideChapters map[ChaptersToShowHide]bool) error {
	defer func() {
		value := recover()
		if value != nil {
			fmt.Printf("error creating PDF report: %v", value)
		}
	}()

	r.initReport()
	r.createPdfAndInitMetadata(model)
	r.parseBackgroundTemplate(templateFilename)
	r.createCover(model)
	r.createTableOfContents(model)
	err := r.createManagementSummary(model, tempFolder)
	if err != nil {
		return fmt.Errorf("error creating management summary: %w", err)
	}
	r.createImpactInitialRisks(model)
	err = r.createRiskMitigationStatus(model, tempFolder)
	if err != nil {
		return fmt.Errorf("error creating risk mitigation status: %w", err)
	}
	if val := hideChapters[AssetRegister]; !val {
		r.createAssetRegister(model)
	}
	r.createImpactRemainingRisks(model)
	err = r.createTargetDescription(model, filepath.Dir(modelFilename))
	if err != nil {
		return fmt.Errorf("error creating target description: %w", err)
	}
	r.embedDataFlowDiagram(dataFlowDiagramFilenamePNG, tempFolder)
	r.createSecurityRequirements(model)
	r.createAbuseCases(model)
	r.createTagListing(model)
	r.createSTRIDE(model)
	r.createAssignmentByFunction(model)
	r.createRAA(model, introTextRAA)
	r.embedDataRiskMapping(dataAssetDiagramFilenamePNG, tempFolder)
	//createDataRiskQuickWins()
	r.createOutOfScopeAssets(model)
	r.createModelFailures(model)
	r.createQuestions(model)
	r.createRiskCategories(model)
	r.createTechnicalAssets(model)
	r.createDataAssets(model)
	r.createTrustBoundaries(model)
	r.createSharedRuntimes(model)
	if val := hideChapters[RiskRulesCheckedByThreagile]; !val {
		r.createRiskRulesChecked(model, modelFilename, skipRiskRules, buildTimestamp, threagileVersion, modelHash, customRiskRules)
	}
	r.createDisclaimer(model)
	err = r.writeReportToFile(reportFilename)
	if err != nil {
		return fmt.Errorf("error writing report to file: %w", err)
	}
	return nil
}

func (r *pdfReporter) createPdfAndInitMetadata(model *types.Model) {
	r.pdf = gofpdf.New("P", "mm", "A4", "")
	r.pdf.SetCreator(model.Author.Homepage, true)
	r.pdf.SetAuthor(model.Author.Name, true)
	r.pdf.SetTitle("Threat Model Report: "+model.Title, true)
	r.pdf.SetSubject("Threat Model Report: "+model.Title, true)
	//	r.pdf.SetPageBox("crop", 0, 0, 100, 010)
	r.pdf.SetHeaderFunc(func() {
		if r.isLandscapePage {
			return
		}

		gofpdi.UseImportedTemplate(r.pdf, r.contentTemplateId, 0, 0, 0, 300)
		r.pdf.SetTopMargin(35)
	})
	r.pdf.SetFooterFunc(func() {
		r.addBreadcrumb(model)
		r.pdf.SetFont("Helvetica", "", 10)
		r.pdf.SetTextColor(127, 127, 127)
		r.pdf.Text(8.6, 284, "Threat Model Report via Threagile") //: "+parsedModel.Title)
		r.pdf.Link(8.4, 281, 54.6, 4, r.homeLink)
		r.pageNo++
		text := "Page " + strconv.Itoa(r.pageNo)
		if r.pageNo < 10 {
			text = "    " + text
		} else if r.pageNo < 100 {
			text = "  " + text
		}
		if r.pageNo > 1 {
			r.pdf.Text(186, 284, text)
		}
	})
	r.linkCounter = 1 // link counting starts at 1 via r.pdf.AddLink
}

func (r *pdfReporter) addBreadcrumb(parsedModel *types.Model) {
	if len(r.currentChapterTitleBreadcrumb) > 0 {
		uni := r.pdf.UnicodeTranslatorFromDescriptor("")
		r.pdf.SetFont("Helvetica", "", 10)
		r.pdf.SetTextColor(127, 127, 127)
		r.pdf.Text(46.7, 24.5, uni(r.currentChapterTitleBreadcrumb+"   -   "+parsedModel.Title))
	}
}

func (r *pdfReporter) parseBackgroundTemplate(templateFilename string) {
	/*
		imageBox, err := rice.FindBox("template")
		checkErr(err)
		file, err := os.CreateTemp("", "background-*-.r.pdf")
		checkErr(err)
		defer os.Remove(file.Title())
		backgroundBytes := imageBox.MustBytes("background.r.pdf")
		err = os.WriteFile(file.Title(), backgroundBytes, 0644)
		checkErr(err)
	*/
	r.coverTemplateId = gofpdi.ImportPage(r.pdf, templateFilename, 1, "/MediaBox")
	r.contentTemplateId = gofpdi.ImportPage(r.pdf, templateFilename, 2, "/MediaBox")
	r.diagramLegendTemplateId = gofpdi.ImportPage(r.pdf, templateFilename, 3, "/MediaBox")
}

func (r *pdfReporter) createCover(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.AddPage()
	gofpdi.UseImportedTemplate(r.pdf, r.coverTemplateId, 0, 0, 0, 300)
	r.pdf.SetFont("Helvetica", "B", 28)
	r.pdf.SetTextColor(0, 0, 0)
	r.pdf.Text(40, 110, "Threat Model Report")
	r.pdf.Text(40, 125, uni(parsedModel.Title))
	r.pdf.SetFont("Helvetica", "", 12)
	reportDate := parsedModel.Date
	if reportDate.IsZero() {
		reportDate = types.Date{Time: time.Now()}
	}
	r.pdf.Text(40.7, 145, reportDate.Format("2 January 2006"))
	r.pdf.Text(40.7, 153, uni(parsedModel.Author.Name))
	r.pdf.SetFont("Helvetica", "", 10)
	r.pdf.SetTextColor(80, 80, 80)
	r.pdf.Text(8.6, 275, parsedModel.Author.Homepage)
	r.pdf.SetFont("Helvetica", "", 12)
	r.pdf.SetTextColor(0, 0, 0)
}

func (r *pdfReporter) createTableOfContents(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.AddPage()
	r.currentChapterTitleBreadcrumb = "Table of Contents"
	r.homeLink = r.pdf.AddLink()
	r.defineLinkTarget("{home}")
	gofpdi.UseImportedTemplate(r.pdf, r.contentTemplateId, 0, 0, 0, 300)
	r.pdf.SetFont("Helvetica", "B", fontSizeHeadline)
	r.pdf.Text(11, 40, "Table of Contents")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetY(46)

	r.pdf.SetLineWidth(0.25)
	r.pdf.SetDrawColor(160, 160, 160)
	r.pdf.SetDashPattern([]float64{0.5, 0.5}, 0)

	// ===============

	var y float64 = 50
	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Text(11, y, "Results Overview")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	y += 6
	r.pdf.Text(11, y, "    "+"Management Summary")
	r.pdf.Text(175, y, "{management-summary}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	risksStr := "Risks"
	catStr := "Categories"
	count, catCount := totalRiskCount(parsedModel), len(parsedModel.GeneratedRisksByCategory)
	if count == 1 {
		risksStr = "Risk"
	}
	if catCount == 1 {
		catStr = "category"
	}
	y += 6
	r.pdf.Text(11, y, "    "+"Impact Analysis of "+strconv.Itoa(count)+" Initial "+risksStr+" in "+strconv.Itoa(catCount)+" "+catStr)
	r.pdf.Text(175, y, "{impact-analysis-initial-risks}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Risk Mitigation")
	r.pdf.Text(175, y, "{risk-mitigation-status}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Asset Register")
	r.pdf.Text(175, y, "{asset-register}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	risksStr = "Risks"
	catStr = "Categories"
	count, catCount = len(filteredByStillAtRisk(parsedModel)), len(reduceToOnlyStillAtRisk(parsedModel.GeneratedRisksByCategoryWithCurrentStatus()))
	if count == 1 {
		risksStr = "Risk"
	}
	if catCount == 1 {
		catStr = "category"
	}
	r.pdf.Text(11, y, "    "+"Impact Analysis of "+strconv.Itoa(count)+" Remaining "+risksStr+" in "+strconv.Itoa(catCount)+" "+catStr)
	r.pdf.Text(175, y, "{impact-analysis-remaining-risks}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Application Overview")
	r.pdf.Text(175, y, "{target-overview}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Data-Flow Diagram")
	r.pdf.Text(175, y, "{data-flow-diagram}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Security Requirements")
	r.pdf.Text(175, y, "{security-requirements}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Abuse Cases")
	r.pdf.Text(175, y, "{abuse-cases}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Tag Listing")
	r.pdf.Text(175, y, "{tag-listing}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"STRIDE Classification of Identified Risks")
	r.pdf.Text(175, y, "{stride}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Assignment by Function")
	r.pdf.Text(175, y, "{function-assignment}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"RAA Analysis")
	r.pdf.Text(175, y, "{raa-analysis}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	r.pdf.Text(11, y, "    "+"Data Mapping")
	r.pdf.Text(175, y, "{data-risk-mapping}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	/*
		y += 6
		assets := "assets"
		count = len(model.SortedTechnicalAssetsByQuickWinsAndTitle())
		if count == 1 {
			assets = "asset"
		}
		r.pdf.Text(11, y, "    "+"Data Risk Quick Wins: "+strconv.Itoa(count)+" "+assets)
		r.pdf.Text(175, y, "{data-risk-quick-wins}")
		r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
	*/

	y += 6
	assets := "Assets"
	count = len(parsedModel.OutOfScopeTechnicalAssets())
	if count == 1 {
		assets = "Asset"
	}
	r.pdf.Text(11, y, "    "+"Out-of-Scope Assets: "+strconv.Itoa(count)+" "+assets)
	r.pdf.Text(175, y, "{out-of-scope-assets}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	modelFailures := flattenRiskSlice(filterByModelFailures(parsedModel, parsedModel.GeneratedRisksByCategory))
	risksStr = "Risks"
	count = len(modelFailures)
	if count == 1 {
		risksStr = "Risk"
	}
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(modelFailures))
	if countStillAtRisk > 0 {
		colorModelFailure(r.pdf)
	}
	r.pdf.Text(11, y, "    "+"Potential Model Failures: "+strconv.Itoa(countStillAtRisk)+" / "+strconv.Itoa(count)+" "+risksStr)
	r.pdf.Text(175, y, "{model-failures}")
	r.pdfColorBlack()
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	y += 6
	questions := "Questions"
	count = len(parsedModel.Questions)
	if count == 1 {
		questions = "Question"
	}
	if questionsUnanswered(parsedModel) > 0 {
		colorModelFailure(r.pdf)
	}
	r.pdf.Text(11, y, "    "+"Questions: "+strconv.Itoa(questionsUnanswered(parsedModel))+" / "+strconv.Itoa(count)+" "+questions)
	r.pdf.Text(175, y, "{questions}")
	r.pdfColorBlack()
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())

	// ===============

	if len(parsedModel.GeneratedRisksByCategory) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			r.pageBreakInLists()
			y = 40
		}
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.SetTextColor(0, 0, 0)
		r.pdf.Text(11, y, "Risks by Vulnerability category")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		y += 6
		r.pdf.Text(11, y, "    "+"Identified Risks by Vulnerability category")
		r.pdf.Text(175, y, "{intro-risks-by-vulnerability-category}")
		r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
		for _, category := range parsedModel.SortedRiskCategories() {
			newRisksStr := parsedModel.SortedRisksOfCategory(category)
			switch types.HighestSeverityStillAtRisk(newRisksStr) {
			case types.CriticalSeverity:
				colorCriticalRisk(r.pdf)
			case types.HighSeverity:
				colorHighRisk(r.pdf)
			case types.ElevatedSeverity:
				colorElevatedRisk(r.pdf)
			case types.MediumSeverity:
				colorMediumRisk(r.pdf)
			case types.LowSeverity:
				colorLowRisk(r.pdf)
			default:
				r.pdfColorBlack()
			}
			if len(types.ReduceToOnlyStillAtRisk(newRisksStr)) == 0 {
				r.pdfColorBlack()
			}
			y += 6
			if y > 275 {
				r.pageBreakInLists()
				y = 40
			}
			countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(newRisksStr))
			suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(newRisksStr)) + " Risk"
			if len(newRisksStr) != 1 {
				suffix += "s"
			}
			r.pdf.Text(11, y, "    "+uni(category.Title)+": "+suffix)
			r.pdf.Text(175, y, "{"+category.ID+"}")
			r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			r.tocLinkIdByAssetId[category.ID] = r.pdf.AddLink()
			r.pdf.Link(10, y-5, 172.5, 6.5, r.tocLinkIdByAssetId[category.ID])
		}
	}

	// ===============

	if len(parsedModel.TechnicalAssets) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			r.pageBreakInLists()
			y = 40
		}
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.SetTextColor(0, 0, 0)
		r.pdf.Text(11, y, "Risks by Technical Asset")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		y += 6
		r.pdf.Text(11, y, "    "+"Identified Risks by Technical Asset")
		r.pdf.Text(175, y, "{intro-risks-by-technical-asset}")
		r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
		for _, technicalAsset := range sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel) {
			newRisksStr := parsedModel.GeneratedRisks(technicalAsset)
			y += 6
			if y > 275 {
				r.pageBreakInLists()
				y = 40
			}
			countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(newRisksStr))
			suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(newRisksStr)) + " Risk"
			if len(newRisksStr) != 1 {
				suffix += "s"
			}
			if technicalAsset.OutOfScope {
				r.pdfColorOutOfScope()
				suffix = "out-of-scope"
			} else {
				switch types.HighestSeverityStillAtRisk(newRisksStr) {
				case types.CriticalSeverity:
					colorCriticalRisk(r.pdf)
				case types.HighSeverity:
					colorHighRisk(r.pdf)
				case types.ElevatedSeverity:
					colorElevatedRisk(r.pdf)
				case types.MediumSeverity:
					colorMediumRisk(r.pdf)
				case types.LowSeverity:
					colorLowRisk(r.pdf)
				default:
					r.pdfColorBlack()
				}
				if len(types.ReduceToOnlyStillAtRisk(newRisksStr)) == 0 {
					r.pdfColorBlack()
				}
			}
			r.pdf.Text(11, y, "    "+uni(technicalAsset.Title)+": "+suffix)
			r.pdf.Text(175, y, "{"+technicalAsset.Id+"}")
			r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			r.tocLinkIdByAssetId[technicalAsset.Id] = r.pdf.AddLink()
			r.pdf.Link(10, y-5, 172.5, 6.5, r.tocLinkIdByAssetId[technicalAsset.Id])
		}
	}

	// ===============

	if len(parsedModel.DataAssets) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			r.pageBreakInLists()
			y = 40
		}
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdfColorBlack()
		r.pdf.Text(11, y, "Data Breach Probabilities by Data Asset")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		y += 6
		r.pdf.Text(11, y, "    "+"Identified Data Breach Probabilities by Data Asset")
		r.pdf.Text(175, y, "{intro-risks-by-data-asset}")
		r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
		for _, dataAsset := range sortedDataAssetsByDataBreachProbabilityAndTitle(parsedModel) {
			y += 6
			if y > 275 {
				r.pageBreakInLists()
				y = 40
			}
			newRisksStr := parsedModel.IdentifiedDataBreachProbabilityRisks(dataAsset)
			countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(newRisksStr))
			suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(newRisksStr)) + " Risk"
			if len(newRisksStr) != 1 {
				suffix += "s"
			}
			switch identifiedDataBreachProbabilityStillAtRisk(parsedModel, dataAsset) {
			case types.Probable:
				colorHighRisk(r.pdf)
			case types.Possible:
				colorMediumRisk(r.pdf)
			case types.Improbable:
				colorLowRisk(r.pdf)
			default:
				r.pdfColorBlack()
			}
			if !isDataBreachPotentialStillAtRisk(parsedModel, dataAsset) {
				r.pdfColorBlack()
			}
			r.pdf.Text(11, y, "    "+uni(dataAsset.Title)+": "+suffix)
			r.pdf.Text(175, y, "{data:"+dataAsset.Id+"}")
			r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			r.tocLinkIdByAssetId[dataAsset.Id] = r.pdf.AddLink()
			r.pdf.Link(10, y-5, 172.5, 6.5, r.tocLinkIdByAssetId[dataAsset.Id])
		}
	}

	// ===============

	if len(parsedModel.TrustBoundaries) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			r.pageBreakInLists()
			y = 40
		}
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdfColorBlack()
		r.pdf.Text(11, y, "Trust Boundaries")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		for _, key := range sortedKeysOfTrustBoundaries(parsedModel) {
			trustBoundary := parsedModel.TrustBoundaries[key]
			y += 6
			if y > 275 {
				r.pageBreakInLists()
				y = 40
			}
			colorTwilight(r.pdf)
			if !trustBoundary.Type.IsNetworkBoundary() {
				r.pdfColorLightGray()
			}
			r.pdf.Text(11, y, "    "+uni(trustBoundary.Title))
			r.pdf.Text(175, y, "{boundary:"+trustBoundary.Id+"}")
			r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			r.tocLinkIdByAssetId[trustBoundary.Id] = r.pdf.AddLink()
			r.pdf.Link(10, y-5, 172.5, 6.5, r.tocLinkIdByAssetId[trustBoundary.Id])
		}
		r.pdfColorBlack()
	}

	// ===============

	if len(parsedModel.SharedRuntimes) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			r.pageBreakInLists()
			y = 40
		}
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdfColorBlack()
		r.pdf.Text(11, y, "Shared Runtime")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		for _, key := range sortedKeysOfSharedRuntime(parsedModel) {
			sharedRuntime := parsedModel.SharedRuntimes[key]
			y += 6
			if y > 275 {
				r.pageBreakInLists()
				y = 40
			}
			r.pdf.Text(11, y, "    "+uni(sharedRuntime.Title))
			r.pdf.Text(175, y, "{runtime:"+sharedRuntime.Id+"}")
			r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			r.tocLinkIdByAssetId[sharedRuntime.Id] = r.pdf.AddLink()
			r.pdf.Link(10, y-5, 172.5, 6.5, r.tocLinkIdByAssetId[sharedRuntime.Id])
		}
	}

	// ===============

	y += 6
	y += 6
	if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
		r.pageBreakInLists()
		y = 40
	}
	r.pdfColorBlack()
	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Text(11, y, "About Threagile")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	y += 6
	if y > 275 {
		r.pageBreakInLists()
		y = 40
	}
	r.pdf.Text(11, y, "    "+"Risk Rules Checked by Threagile")
	r.pdf.Text(175, y, "{risk-rules-checked}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
	y += 6
	if y > 275 {
		r.pageBreakInLists()
		y = 40
	}
	r.pdfColorDisclaimer()
	r.pdf.Text(11, y, "    "+"Disclaimer")
	r.pdf.Text(175, y, "{disclaimer}")
	r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
	r.pdfColorBlack()

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)

	// Now write all the sections/pages. Before we start writing, we use `RegisterAlias` to
	// ensure that the alias written in the table of contents will be replaced
	// by the current page number. --> See the "r.pdf.RegisterAlias()" calls during the PDF creation in this file
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func sortedKeysOfTrustBoundaries(model *types.Model) []string {
	keys := make([]string, 0)
	for k := range model.TrustBoundaries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
func sortedKeysOfSharedRuntime(model *types.Model) []string {
	keys := make([]string, 0)
	for k := range model.SharedRuntimes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortByTechnicalAssetRiskSeverityAndTitleStillAtRisk(assets []*types.TechnicalAsset, parsedModel *types.Model) {
	sort.Slice(assets, func(i, j int) bool {
		risksLeft := types.ReduceToOnlyStillAtRisk(parsedModel.GeneratedRisks(assets[i]))
		risksRight := types.ReduceToOnlyStillAtRisk(parsedModel.GeneratedRisks(assets[j]))
		highestSeverityLeft := types.HighestSeverityStillAtRisk(risksLeft)
		highestSeverityRight := types.HighestSeverityStillAtRisk(risksRight)
		var result bool
		if highestSeverityLeft == highestSeverityRight {
			if len(risksLeft) == 0 && len(risksRight) > 0 {
				return false
			} else if len(risksLeft) > 0 && len(risksRight) == 0 {
				return true
			} else {
				result = assets[i].Title < assets[j].Title
			}
		} else {
			result = highestSeverityLeft > highestSeverityRight
		}
		if assets[i].OutOfScope && assets[j].OutOfScope {
			result = assets[i].Title < assets[j].Title
		} else if assets[i].OutOfScope {
			result = false
		} else if assets[j].OutOfScope {
			result = true
		}
		return result
	})
}

func sortedDataAssetsByDataBreachProbabilityAndTitle(parsedModel *types.Model) []*types.DataAsset {
	assets := make([]*types.DataAsset, 0)
	for _, asset := range parsedModel.DataAssets {
		assets = append(assets, asset)
	}

	sortByDataAssetDataBreachProbabilityAndTitleStillAtRisk(parsedModel, assets)
	return assets
}

func sortByDataAssetDataBreachProbabilityAndTitleStillAtRisk(parsedModel *types.Model, assets []*types.DataAsset) {
	sort.Slice(assets, func(i, j int) bool {
		risksLeft := identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel, assets[i])
		risksRight := identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel, assets[j])
		highestDataBreachProbabilityLeft := identifiedDataBreachProbabilityStillAtRisk(parsedModel, assets[i])
		highestDataBreachProbabilityRight := identifiedDataBreachProbabilityStillAtRisk(parsedModel, assets[j])
		if highestDataBreachProbabilityLeft == highestDataBreachProbabilityRight {
			if len(risksLeft) == 0 && len(risksRight) > 0 {
				return false
			}
			if len(risksLeft) > 0 && len(risksRight) == 0 {
				return true
			}
			return assets[i].Title < assets[j].Title
		}
		return highestDataBreachProbabilityLeft > highestDataBreachProbabilityRight
	})
}

func (r *pdfReporter) defineLinkTarget(alias string) {
	pageNumbStr := strconv.Itoa(r.pdf.PageNo())
	if len(pageNumbStr) == 1 {
		pageNumbStr = "    " + pageNumbStr
	} else if len(pageNumbStr) == 2 {
		pageNumbStr = "  " + pageNumbStr
	}
	r.pdf.RegisterAlias(alias, pageNumbStr)
	r.pdf.SetLink(r.linkCounter, 0, -1)
	r.linkCounter++
}

func (r *pdfReporter) createDisclaimer(parsedModel *types.Model) {
	r.pdf.AddPage()
	r.currentChapterTitleBreadcrumb = "Disclaimer"
	r.defineLinkTarget("{disclaimer}")
	gofpdi.UseImportedTemplate(r.pdf, r.contentTemplateId, 0, 0, 0, 300)
	r.pdfColorDisclaimer()
	r.pdf.SetFont("Helvetica", "B", fontSizeHeadline)
	r.pdf.Text(11, 40, "Disclaimer")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetY(46)

	var disclaimer strings.Builder
	disclaimer.WriteString(parsedModel.Author.Name + " conducted this threat analysis using the open-source Threagile toolkit " +
		"on the applications and systems that were modeled as of this report's date. " +
		"Information security threats are continually changing, with new " +
		"vulnerabilities discovered on a daily basis, and no application can ever be 100% secure no matter how much " +
		"threat modeling is conducted. It is recommended to execute threat modeling and also penetration testing on a regular basis " +
		"(for example yearly) to ensure a high ongoing level of security and constantly check for new attack vectors. " +
		"<br><br>" +
		"This report cannot and does not protect against personal or business loss as the result of use of the " +
		"applications or systems described. " + parsedModel.Author.Name + " and the Threagile toolkit offers no warranties, representations or " +
		"legal certifications concerning the applications or systems it tests. All software includes defects: nothing " +
		"in this document is intended to represent or warrant that threat modeling was complete and without error, " +
		"nor does this document represent or warrant that the architecture analyzed is suitable to task, free of other " +
		"defects than reported, fully compliant with any industry standards, or fully compatible with any operating " +
		"system, hardware, or other application. Threat modeling tries to analyze the modeled architecture without " +
		"having access to a real working system and thus cannot and does not test the implementation for defects and vulnerabilities. " +
		"These kinds of checks would only be possible with a separate code review and penetration test against " +
		"a working system and not via a threat model." +
		"<br><br>" +
		"By using the resulting information you agree that " + parsedModel.Author.Name + " and the Threagile toolkit " +
		"shall be held harmless in any event." +
		"<br><br>" +
		"This report is confidential and intended for internal, confidential use by the client. The recipient " +
		"is obligated to ensure the highly confidential contents are kept secret. The recipient assumes responsibility " +
		"for further distribution of this document." +
		"<br><br>" +
		"In this particular project, a time box approach was used to define the analysis effort. This means that the " +
		"author allotted a prearranged amount of time to identify and document threats. Because of this, there " +
		"is no guarantee that all possible threats and risks are discovered. Furthermore, the analysis " +
		"applies to a snapshot of the current state of the modeled architecture (based on the architecture information provided " +
		"by the customer) at the examination time." +
		"<br><br><br>" +
		"<b>Report Distribution</b>" +
		"<br><br>" +
		"Distribution of this report (in full or in part like diagrams or risk findings) requires that this disclaimer " +
		"as well as the chapter about the Threagile toolkit and method used is kept intact as part of the " +
		"distributed report or referenced from the distributed parts.")
	html := r.pdf.HTMLBasicNew()
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	html.Write(5, uni(disclaimer.String()))
	r.pdfColorBlack()
}

func (r *pdfReporter) createManagementSummary(parsedModel *types.Model, tempFolder string) error {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	title := "Management Summary"
	r.addHeadline(title, false)
	r.defineLinkTarget("{management-summary}")
	r.currentChapterTitleBreadcrumb = title
	countCritical := len(filteredBySeverity(parsedModel, types.CriticalSeverity))
	countHigh := len(filteredBySeverity(parsedModel, types.HighSeverity))
	countElevated := len(filteredBySeverity(parsedModel, types.ElevatedSeverity))
	countMedium := len(filteredBySeverity(parsedModel, types.MediumSeverity))
	countLow := len(filteredBySeverity(parsedModel, types.LowSeverity))

	countStatusUnchecked := len(filteredByRiskStatus(parsedModel, types.Unchecked))
	countStatusInDiscussion := len(filteredByRiskStatus(parsedModel, types.InDiscussion))
	countStatusAccepted := len(filteredByRiskStatus(parsedModel, types.Accepted))
	countStatusInProgress := len(filteredByRiskStatus(parsedModel, types.InProgress))
	countStatusMitigated := len(filteredByRiskStatus(parsedModel, types.Mitigated))
	countStatusFalsePositive := len(filteredByRiskStatus(parsedModel, types.FalsePositive))

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "Threagile toolkit was used to model the architecture of \""+uni(parsedModel.Title)+"\" "+
		"and derive risks by analyzing the components and data flows. The risks identified during this analysis are shown "+
		"in the following chapters. Identified risks during threat modeling do not necessarily mean that the "+
		"vulnerability associated with this risk actually exists: it is more to be seen as a list of potential risks and "+
		"threats, which should be individually reviewed and reduced by removing false positives. For the remaining risks it should "+
		"be checked in the design and implementation of \""+uni(parsedModel.Title)+"\" whether the mitigation advices "+
		"have been applied or not."+
		"<br><br>"+
		"Each risk finding references a chapter of the OWASP ASVS (Application Security Verification Standard) audit checklist. "+
		"The OWASP ASVS checklist should be considered as an inspiration by architects and developers to further harden "+
		"the application in a Defense-in-Depth approach. Additionally, for each risk finding a "+
		"link towards a matching OWASP Cheat Sheet or similar with technical details about how to implement a mitigation is given."+
		"<br><br>"+
		"In total <b>"+strconv.Itoa(totalRiskCount(parsedModel))+" initial risks</b> in <b>"+strconv.Itoa(len(parsedModel.GeneratedRisksByCategory))+" categories</b> have "+
		"been identified during the threat modeling process:<br><br>") // TODO plural singular stuff risk/s category/ies has/have

	r.pdf.SetFont("Helvetica", "B", fontSizeBody)

	r.pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(60, 6, "", "0", 0, "", false, 0, "")
	colorRiskStatusUnchecked(r.pdf)
	r.pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusUnchecked), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "unchecked", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)

	colorCriticalRisk(r.pdf)
	r.pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countCritical), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "critical risk", "0", 0, "", false, 0, "")
	colorRiskStatusInDiscussion(r.pdf)
	r.pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusInDiscussion), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "in discussion", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)

	colorHighRisk(r.pdf)
	r.pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countHigh), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "high risk", "0", 0, "", false, 0, "")
	colorRiskStatusAccepted(r.pdf)
	r.pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusAccepted), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "accepted", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)

	colorElevatedRisk(r.pdf)
	r.pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countElevated), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "elevated risk", "0", 0, "", false, 0, "")
	colorRiskStatusInProgress(r.pdf)
	r.pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusInProgress), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "in progress", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)

	colorMediumRisk(r.pdf)
	r.pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countMedium), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "medium risk", "0", 0, "", false, 0, "")
	colorRiskStatusMitigated(r.pdf)
	r.pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusMitigated), "0", 0, "R", false, 0, "")
	r.pdf.SetFont("Helvetica", "BI", fontSizeBody)
	r.pdf.CellFormat(60, 6, "mitigated", "0", 0, "", false, 0, "")
	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Ln(-1)

	colorLowRisk(r.pdf)
	r.pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countLow), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "low risk", "0", 0, "", false, 0, "")
	colorRiskStatusFalsePositive(r.pdf)
	r.pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusFalsePositive), "0", 0, "R", false, 0, "")
	r.pdf.SetFont("Helvetica", "BI", fontSizeBody)
	r.pdf.CellFormat(60, 6, "false positive", "0", 0, "", false, 0, "")
	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Ln(-1)

	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	// pie chart: risk severity
	pieChartRiskSeverity := chart.PieChart{
		Width:  1500,
		Height: 1500,
		Values: []chart.Value{
			{Value: float64(countLow), //Label: strconv.Itoa(countLow) + " Low",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorLowRisk()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorLowRisk()),
					FontSize: 65}},
			{Value: float64(countMedium), //Label: strconv.Itoa(countMedium) + " Medium",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorMediumRisk()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorMediumRisk()),
					FontSize: 65}},
			{Value: float64(countElevated), //Label: strconv.Itoa(countElevated) + " Elevated",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorElevatedRisk()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorElevatedRisk()),
					FontSize: 65}},
			{Value: float64(countHigh), //Label: strconv.Itoa(countHigh) + " High",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorHighRisk()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorHighRisk()),
					FontSize: 65}},
			{Value: float64(countCritical), //Label: strconv.Itoa(countCritical) + " Critical",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorCriticalRisk()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorCriticalRisk()),
					FontSize: 65}},
		},
	}

	// pie chart: risk status
	pieChartRiskStatus := chart.PieChart{
		Width:  1500,
		Height: 1500,
		Values: []chart.Value{
			{Value: float64(countStatusFalsePositive), //Label: strconv.Itoa(countStatusFalsePositive) + " False Positive",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorRiskStatusFalsePositive()),
					FontSize: 65}},
			{Value: float64(countStatusMitigated), //Label: strconv.Itoa(countStatusMitigated) + " Mitigated",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorRiskStatusMitigated()),
					FontSize: 65}},
			{Value: float64(countStatusInProgress), //Label: strconv.Itoa(countStatusInProgress) + " InProgress",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorRiskStatusInProgress()),
					FontSize: 65}},
			{Value: float64(countStatusAccepted), //Label: strconv.Itoa(countStatusAccepted) + " Accepted",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorRiskStatusAccepted()),
					FontSize: 65}},
			{Value: float64(countStatusInDiscussion), //Label: strconv.Itoa(countStatusInDiscussion) + " InDiscussion",
				Style: chart.Style{
					FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98),
					//FontColor: makeColor(rgbHexColorRiskStatusInDiscussion()),
					FontSize: 65}},
			{Value: float64(countStatusUnchecked), //Label: strconv.Itoa(countStatusUnchecked) + " Unchecked",
				Style: chart.Style{
					FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98),
					//FontColor: makeColor(RgbHexColorRiskStatusUnchecked()),
					FontSize: 65}},
		},
	}

	y := r.pdf.GetY() + 5
	err := r.embedPieChart(pieChartRiskSeverity, 15.0, y, tempFolder)
	if err != nil {
		return fmt.Errorf("unable to embed pie chart: %w", err)
	}

	err = r.embedPieChart(pieChartRiskStatus, 110.0, y, tempFolder)
	if err != nil {
		return fmt.Errorf("unable to embed pie chart: %w", err)
	}

	// individual management summary comment
	r.pdfColorBlack()
	if len(parsedModel.ManagementSummaryComment) > 0 {
		html.Write(5, "<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>"+
			parsedModel.ManagementSummaryComment)
	}
	return nil
}

func (r *pdfReporter) createRiskMitigationStatus(parsedModel *types.Model, tempFolder string) error {
	r.pdf.SetTextColor(0, 0, 0)
	stillAtRisk := filteredByStillAtRisk(parsedModel)
	count := len(stillAtRisk)
	title := "Risk Mitigation"
	r.addHeadline(title, false)
	r.defineLinkTarget("{risk-mitigation-status}")
	r.currentChapterTitleBreadcrumb = title

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "The following chart gives a high-level overview of the risk tracking status (including mitigated risks):")

	risksCritical := filteredBySeverity(parsedModel, types.CriticalSeverity)
	risksHigh := filteredBySeverity(parsedModel, types.HighSeverity)
	risksElevated := filteredBySeverity(parsedModel, types.ElevatedSeverity)
	risksMedium := filteredBySeverity(parsedModel, types.MediumSeverity)
	risksLow := filteredBySeverity(parsedModel, types.LowSeverity)

	countStatusUnchecked := len(filteredByRiskStatus(parsedModel, types.Unchecked))
	countStatusInDiscussion := len(filteredByRiskStatus(parsedModel, types.InDiscussion))
	countStatusAccepted := len(filteredByRiskStatus(parsedModel, types.Accepted))
	countStatusInProgress := len(filteredByRiskStatus(parsedModel, types.InProgress))
	countStatusMitigated := len(filteredByRiskStatus(parsedModel, types.Mitigated))
	countStatusFalsePositive := len(filteredByRiskStatus(parsedModel, types.FalsePositive))

	stackedBarChartRiskTracking := chart.StackedBarChart{
		Width: 4000,
		//Height: 2500,
		XAxis: chart.Style{Show: false, FontSize: 26, TextVerticalAlign: chart.TextVerticalAlignBottom},
		YAxis: chart.Style{Show: true, FontSize: 26, TextVerticalAlign: chart.TextVerticalAlignBottom},
		Bars: []chart.StackedBar{
			{
				Name:  types.LowSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(reduceToRiskStatus(risksLow, types.Unchecked))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksLow, types.InDiscussion))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksLow, types.Accepted))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksLow, types.InProgress))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksLow, types.Mitigated))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksLow, types.FalsePositive))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.MediumSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(reduceToRiskStatus(risksMedium, types.Unchecked))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksMedium, types.InDiscussion))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksMedium, types.Accepted))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksMedium, types.InProgress))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksMedium, types.Mitigated))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksMedium, types.FalsePositive))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.ElevatedSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(reduceToRiskStatus(risksElevated, types.Unchecked))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksElevated, types.InDiscussion))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksElevated, types.Accepted))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksElevated, types.InProgress))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksElevated, types.Mitigated))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksElevated, types.FalsePositive))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.HighSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(reduceToRiskStatus(risksHigh, types.Unchecked))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksHigh, types.InDiscussion))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksHigh, types.Accepted))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksHigh, types.InProgress))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksHigh, types.Mitigated))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksHigh, types.FalsePositive))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.CriticalSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(reduceToRiskStatus(risksCritical, types.Unchecked))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksCritical, types.InDiscussion))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksCritical, types.Accepted))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksCritical, types.InProgress))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksCritical, types.Mitigated))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(reduceToRiskStatus(risksCritical, types.FalsePositive))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
		},
	}

	y := r.pdf.GetY() + 12
	err := r.embedStackedBarChart(stackedBarChartRiskTracking, 15.0, y, tempFolder)
	if err != nil {
		return err
	}

	// draw the X-Axis legend on my own
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorBlack()
	r.pdf.Text(24.02, 169, "Low ("+strconv.Itoa(len(risksLow))+")")
	r.pdf.Text(46.10, 169, "Medium ("+strconv.Itoa(len(risksMedium))+")")
	r.pdf.Text(69.74, 169, "Elevated ("+strconv.Itoa(len(risksElevated))+")")
	r.pdf.Text(97.95, 169, "High ("+strconv.Itoa(len(risksHigh))+")")
	r.pdf.Text(121.65, 169, "Critical ("+strconv.Itoa(len(risksCritical))+")")

	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Ln(20)

	colorRiskStatusUnchecked(r.pdf)
	r.pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusUnchecked), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "unchecked", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)
	colorRiskStatusInDiscussion(r.pdf)
	r.pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusInDiscussion), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "in discussion", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)
	colorRiskStatusAccepted(r.pdf)
	r.pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusAccepted), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "accepted", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)
	colorRiskStatusInProgress(r.pdf)
	r.pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusInProgress), "0", 0, "R", false, 0, "")
	r.pdf.CellFormat(60, 6, "in progress", "0", 0, "", false, 0, "")
	r.pdf.Ln(-1)
	colorRiskStatusMitigated(r.pdf)
	r.pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusMitigated), "0", 0, "R", false, 0, "")
	r.pdf.SetFont("Helvetica", "BI", fontSizeBody)
	r.pdf.CellFormat(60, 6, "mitigated", "0", 0, "", false, 0, "")
	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Ln(-1)
	colorRiskStatusFalsePositive(r.pdf)
	r.pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	r.pdf.CellFormat(10, 6, strconv.Itoa(countStatusFalsePositive), "0", 0, "R", false, 0, "")
	r.pdf.SetFont("Helvetica", "BI", fontSizeBody)
	r.pdf.CellFormat(60, 6, "false positive", "0", 0, "", false, 0, "")
	r.pdf.SetFont("Helvetica", "B", fontSizeBody)
	r.pdf.Ln(-1)

	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	r.pdfColorBlack()
	if count == 0 {
		html.Write(5, "<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>"+
			"After removal of risks with status <i>mitigated</i> and <i>false positive</i> "+
			"<b>"+strconv.Itoa(count)+" remain unmitigated</b>.")
	} else {
		html.Write(5, "<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>"+
			"After removal of risks with status <i>mitigated</i> and <i>false positive</i> "+
			"the following <b>"+strconv.Itoa(count)+" remain unmitigated</b>:")

		countCritical := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(parsedModel, types.CriticalSeverity)))
		countHigh := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(parsedModel, types.HighSeverity)))
		countElevated := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(parsedModel, types.ElevatedSeverity)))
		countMedium := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(parsedModel, types.MediumSeverity)))
		countLow := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(parsedModel, types.LowSeverity)))

		countBusinessSide := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(parsedModel, types.BusinessSide)))
		countArchitecture := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(parsedModel, types.Architecture)))
		countDevelopment := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(parsedModel, types.Development)))
		countOperation := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(parsedModel, types.Operations)))

		pieChartRemainingRiskSeverity := chart.PieChart{
			Width:  1500,
			Height: 1500,
			Values: []chart.Value{
				{Value: float64(countLow), //Label: strconv.Itoa(countLow) + " Low",
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorLowRisk()).WithAlpha(98),
						//FontColor: makeColor(rgbHexColorLowRisk()),
						FontSize: 65}},
				{Value: float64(countMedium), //Label: strconv.Itoa(countMedium) + " Medium",
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorMediumRisk()).WithAlpha(98),
						//FontColor: makeColor(rgbHexColorMediumRisk()),
						FontSize: 65}},
				{Value: float64(countElevated), //Label: strconv.Itoa(countElevated) + " Elevated",
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorElevatedRisk()).WithAlpha(98),
						//FontColor: makeColor(rgbHexColorElevatedRisk()),
						FontSize: 65}},
				{Value: float64(countHigh), //Label: strconv.Itoa(countHigh) + " High",
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorHighRisk()).WithAlpha(98),
						//FontColor: makeColor(rgbHexColorHighRisk()),
						FontSize: 65}},
				{Value: float64(countCritical), //Label: strconv.Itoa(countCritical) + " Critical",
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorCriticalRisk()).WithAlpha(98),
						//FontColor: makeColor(rgbHexColorCriticalRisk()),
						FontSize: 65}},
			},
		}

		pieChartRemainingRisksByFunction := chart.PieChart{
			Width:  1500,
			Height: 1500,
			Values: []chart.Value{
				{Value: float64(countBusinessSide),
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorBusiness()).WithAlpha(98),
						FontSize:  65}},
				{Value: float64(countArchitecture),
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorArchitecture()).WithAlpha(98),
						FontSize:  65}},
				{Value: float64(countDevelopment),
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorDevelopment()).WithAlpha(98),
						FontSize:  65}},
				{Value: float64(countOperation),
					Style: chart.Style{
						FillColor: makeColor(rgbHexColorOperation()).WithAlpha(98),
						FontSize:  65}},
			},
		}

		_ = r.embedPieChart(pieChartRemainingRiskSeverity, 15.0, 216, tempFolder)
		_ = r.embedPieChart(pieChartRemainingRisksByFunction, 110.0, 216, tempFolder)

		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.Ln(8)

		colorCriticalRisk(r.pdf)
		r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countCritical), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "unmitigated critical risk", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, "", "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		colorHighRisk(r.pdf)
		r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countHigh), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "unmitigated high risk", "0", 0, "", false, 0, "")
		colorBusiness(r.pdf)
		r.pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countBusinessSide), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "business side related", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		colorElevatedRisk(r.pdf)
		r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countElevated), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "unmitigated elevated risk", "0", 0, "", false, 0, "")
		colorArchitecture(r.pdf)
		r.pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countArchitecture), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "architecture related", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		colorMediumRisk(r.pdf)
		r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countMedium), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "unmitigated medium risk", "0", 0, "", false, 0, "")
		colorDevelopment(r.pdf)
		r.pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countDevelopment), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "development related", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		colorLowRisk(r.pdf)
		r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countLow), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "unmitigated low risk", "0", 0, "", false, 0, "")
		colorOperation(r.pdf)
		r.pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(10, 6, strconv.Itoa(countOperation), "0", 0, "R", false, 0, "")
		r.pdf.CellFormat(60, 6, "operations related", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
	}
	return nil
}

func (r *pdfReporter) createAssetRegister(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	chapTitle := "Asset Register"
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{asset-register}")
	r.currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	subTitle := "Technical Assets"
	r.addHeadline(subTitle, true)
	r.currentChapterTitleBreadcrumb = subTitle
	for _, technicalAsset := range sortedTechnicalAssetsByTitle(parsedModel) {
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}

		r.pdf.SetTextColor(0, 0, 0)

		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := r.pdf.GetY()
		strBuilder.WriteString("<b>")
		strBuilder.WriteString(uni(technicalAsset.Title))
		strBuilder.WriteString("</b>")
		if technicalAsset.OutOfScope {
			strBuilder.WriteString(": out-of-scope")
		}
		strBuilder.WriteString("<br>")
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		strBuilder.WriteString(uni(technicalAsset.Description))
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, r.tocLinkIdByAssetId[technicalAsset.Id])
	}

	subTitle = "Data Assets"
	r.addHeadline(subTitle, true)
	r.currentChapterTitleBreadcrumb = subTitle

	for _, dataAsset := range sortedDataAssetsByTitle(parsedModel) {
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}

		r.pdf.SetTextColor(0, 0, 0)

		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := r.pdf.GetY()
		strBuilder.WriteString("<b>")
		strBuilder.WriteString(uni(dataAsset.Title))
		strBuilder.WriteString("</b>")
		strBuilder.WriteString("<br>")
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		strBuilder.WriteString(uni(dataAsset.Description))
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, r.tocLinkIdByAssetId[dataAsset.Id])
	}

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

// CAUTION: Long labels might cause endless loop, then remove labels and render them manually later inside the PDF
func (r *pdfReporter) embedStackedBarChart(sbcChart chart.StackedBarChart, x float64, y float64, tempFolder string) error {
	tmpFilePNG, err := os.CreateTemp(tempFolder, "chart-*-.png")
	if err != nil {
		return fmt.Errorf("error creating temporary file for chart: %w", err)
	}
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()
	file, _ := os.Create(tmpFilePNG.Name())
	defer func() { _ = file.Close() }()
	err = sbcChart.Render(chart.PNG, file)
	if err != nil {
		return fmt.Errorf("error rendering chart: %w", err)
	}
	var options gofpdf.ImageOptions
	options.ImageType = ""
	r.pdf.RegisterImage(tmpFilePNG.Name(), "")
	r.pdf.ImageOptions(tmpFilePNG.Name(), x, y, 0, 110, false, options, 0, "")
	return nil
}

func (r *pdfReporter) embedPieChart(pieChart chart.PieChart, x float64, y float64, tempFolder string) error {
	tmpFilePNG, err := os.CreateTemp(tempFolder, "chart-*-.png")
	if err != nil {
		return fmt.Errorf("error creating temporary file for chart: %w", err)
	}
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()
	file, err := os.Create(tmpFilePNG.Name())
	if err != nil {
		return fmt.Errorf("error creating temporary file for chart: %w", err)
	}
	defer func() { _ = file.Close() }()
	err = pieChart.Render(chart.PNG, file)
	if err != nil {
		return fmt.Errorf("error rendering chart: %w", err)
	}
	var options gofpdf.ImageOptions
	options.ImageType = ""
	r.pdf.RegisterImage(tmpFilePNG.Name(), "")
	r.pdf.ImageOptions(tmpFilePNG.Name(), x, y, 60, 0, false, options, 0, "")
	return nil
}

func makeColor(hexColor string) drawing.Color {
	_, i := utf8.DecodeRuneInString(hexColor)
	return drawing.ColorFromHex(hexColor[i:]) // = remove first char, which is # in rgb hex here
}

func (r *pdfReporter) createImpactInitialRisks(parsedModel *types.Model) {
	r.renderImpactAnalysis(parsedModel, true)
}

func (r *pdfReporter) createImpactRemainingRisks(parsedModel *types.Model) {
	r.renderImpactAnalysis(parsedModel, false)
}

func (r *pdfReporter) renderImpactAnalysis(parsedModel *types.Model, initialRisks bool) {
	r.pdf.SetTextColor(0, 0, 0)
	count, catCount := totalRiskCount(parsedModel), len(parsedModel.GeneratedRisksByCategory)
	if !initialRisks {
		count, catCount = len(filteredByStillAtRisk(parsedModel)), len(reduceToOnlyStillAtRisk(parsedModel.GeneratedRisksByCategoryWithCurrentStatus()))
	}
	riskStr, catStr := "Risks", "Categories"
	if count == 1 {
		riskStr = "Risk"
	}
	if catCount == 1 {
		catStr = "category"
	}
	if initialRisks {
		chapTitle := "Impact Analysis of " + strconv.Itoa(count) + " Initial " + riskStr + " in " + strconv.Itoa(catCount) + " " + catStr
		r.addHeadline(chapTitle, false)
		r.defineLinkTarget("{impact-analysis-initial-risks}")
		r.currentChapterTitleBreadcrumb = chapTitle
	} else {
		chapTitle := "Impact Analysis of " + strconv.Itoa(count) + " Remaining " + riskStr + " in " + strconv.Itoa(catCount) + " " + catStr
		r.addHeadline(chapTitle, false)
		r.defineLinkTarget("{impact-analysis-remaining-risks}")
		r.currentChapterTitleBreadcrumb = chapTitle
	}

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	riskStr = "risks"
	if count == 1 {
		riskStr = "risk"
	}
	initialStr := "initial"
	if !initialRisks {
		initialStr = "remaining"
	}
	strBuilder.WriteString("The most prevalent impacts of the <b>" + strconv.Itoa(count) + " " +
		initialStr + " " + riskStr + "</b> (distributed over <b>" + strconv.Itoa(catCount) + " risk categories</b>) are " +
		"(taking the severity ratings into account and using the highest for each category):<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(parsedModel.GeneratedRisksByCategory, initialRisks, types.CriticalSeverity)),
		types.CriticalSeverity, false, initialRisks, true, false)
	r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(parsedModel.GeneratedRisksByCategory, initialRisks, types.HighSeverity)),
		types.HighSeverity, false, initialRisks, true, false)
	r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(parsedModel.GeneratedRisksByCategory, initialRisks, types.ElevatedSeverity)),
		types.ElevatedSeverity, false, initialRisks, true, false)
	r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(parsedModel.GeneratedRisksByCategory, initialRisks, types.MediumSeverity)),
		types.MediumSeverity, false, initialRisks, true, false)
	r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(parsedModel.GeneratedRisksByCategory, initialRisks, types.LowSeverity)),
		types.LowSeverity, false, initialRisks, true, false)

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func (r *pdfReporter) createOutOfScopeAssets(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	assets := "Assets"
	count := len(parsedModel.OutOfScopeTechnicalAssets())
	if count == 1 {
		assets = "Asset"
	}
	chapTitle := "Out-of-Scope Assets: " + strconv.Itoa(count) + " " + assets
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{out-of-scope-assets}")
	r.currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	strBuilder.WriteString("This chapter lists all technical assets that have been defined as out-of-scope. " +
		"Each one should be checked in the model whether it should better be included in the " +
		"overall risk analysis:<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Technical asset paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	outOfScopeAssetCount := 0
	for _, technicalAsset := range sortedTechnicalAssetsByRAAAndTitle(parsedModel) {
		if technicalAsset.OutOfScope {
			outOfScopeAssetCount++
			if r.pdf.GetY() > 250 {
				r.pageBreak()
				r.pdf.SetY(36)
			} else {
				strBuilder.WriteString("<br><br>")
			}
			html.Write(5, strBuilder.String())
			strBuilder.Reset()
			posY := r.pdf.GetY()
			r.pdfColorOutOfScope()
			strBuilder.WriteString("<b>")
			strBuilder.WriteString(uni(technicalAsset.Title))
			strBuilder.WriteString("</b>")
			strBuilder.WriteString(": out-of-scope")
			strBuilder.WriteString("<br>")
			html.Write(5, strBuilder.String())
			strBuilder.Reset()
			r.pdf.SetTextColor(0, 0, 0)
			strBuilder.WriteString(uni(technicalAsset.JustificationOutOfScope))
			html.Write(5, strBuilder.String())
			strBuilder.Reset()
			r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, r.tocLinkIdByAssetId[technicalAsset.Id])
		}
	}

	if outOfScopeAssetCount == 0 {
		r.pdfColorGray()
		html.Write(5, "<br><br>No technical assets have been defined as out-of-scope.")
	}

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func (r *pdfReporter) createModelFailures(parsedModel *types.Model) {
	r.pdf.SetTextColor(0, 0, 0)
	modelFailures := flattenRiskSlice(filterByModelFailures(parsedModel, parsedModel.GeneratedRisksByCategory))
	risksStr := "Risks"
	count := len(modelFailures)
	if count == 1 {
		risksStr = "Risk"
	}
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(modelFailures))
	if countStillAtRisk > 0 {
		colorModelFailure(r.pdf)
	}
	chapTitle := "Potential Model Failures: " + strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(count) + " " + risksStr
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{model-failures}")
	r.currentChapterTitleBreadcrumb = chapTitle
	r.pdfColorBlack()

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	strBuilder.WriteString("This chapter lists potential model failures where not all relevant assets have been " +
		"modeled or the model might itself contain inconsistencies. Each potential model failure should be checked " +
		"in the model against the architecture design:<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	modelFailuresByCategory := filterByModelFailures(parsedModel, parsedModel.GeneratedRisksByCategory)
	if len(modelFailuresByCategory) == 0 {
		r.pdfColorGray()
		html.Write(5, "<br><br>No potential model failures have been identified.")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(modelFailuresByCategory, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(modelFailuresByCategory, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(modelFailuresByCategory, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(modelFailuresByCategory, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(modelFailuresByCategory, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func filterByModelFailures(parsedModel *types.Model, risksByCat map[string][]*types.Risk) map[string][]*types.Risk {
	result := make(map[string][]*types.Risk)
	for categoryId, risks := range risksByCat {
		category := parsedModel.GetRiskCategory(categoryId)
		if category.ModelFailurePossibleReason {
			result[categoryId] = risks
		}
	}

	return result
}

func flattenRiskSlice(risksByCat map[string][]*types.Risk) []*types.Risk {
	result := make([]*types.Risk, 0)
	for _, risks := range risksByCat {
		result = append(result, risks...)
	}
	return result
}

func (r *pdfReporter) createRAA(parsedModel *types.Model, introTextRAA string) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	chapTitle := "RAA Analysis"
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{raa-analysis}")
	r.currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	strBuilder.WriteString(introTextRAA)
	strBuilder.WriteString("<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Technical asset paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	for _, technicalAsset := range sortedTechnicalAssetsByRAAAndTitle(parsedModel) {
		if technicalAsset.OutOfScope {
			continue
		}
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}
		newRisksStr := parsedModel.GeneratedRisks(technicalAsset)
		switch types.HighestSeverityStillAtRisk(newRisksStr) {
		case types.HighSeverity:
			colorHighRisk(r.pdf)
		case types.MediumSeverity:
			colorMediumRisk(r.pdf)
		case types.LowSeverity:
			colorLowRisk(r.pdf)
		default:
			r.pdfColorBlack()
		}
		if len(types.ReduceToOnlyStillAtRisk(newRisksStr)) == 0 {
			r.pdfColorBlack()
		}

		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := r.pdf.GetY()
		strBuilder.WriteString("<b>")
		strBuilder.WriteString(uni(technicalAsset.Title))
		strBuilder.WriteString("</b>")
		if technicalAsset.OutOfScope {
			strBuilder.WriteString(": out-of-scope")
		} else {
			strBuilder.WriteString(": RAA ")
			strBuilder.WriteString(fmt.Sprintf("%.0f", technicalAsset.RAA))
			strBuilder.WriteString("%")
		}
		strBuilder.WriteString("<br>")
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.SetTextColor(0, 0, 0)
		strBuilder.WriteString(uni(technicalAsset.Description))
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, r.tocLinkIdByAssetId[technicalAsset.Id])
	}

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

/*
func createDataRiskQuickWins() {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	assets := "assets"
	count := len(model.SortedTechnicalAssetsByQuickWinsAndTitle())
	if count == 1 {
		assets = "asset"
	}
	chapTitle := "Data Risk Quick Wins: " + strconv.Itoa(count) + " " + assets
	r.addHeadline(chapTitle, false)
	defineLinkTarget("{data-risk-quick-wins}")
	currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	strBuilder.WriteString("For each technical asset it was checked how many data assets at risk might " +
		"get their risk-rating reduced (partly or fully) when the risks of the technical asset are mitigated. " +
		"In general, that means the higher the quick win value is, the more data assets (left side of the Data Risk Mapping diagram) " +
		"turn from red to amber or from amber to blue by mitigating the technical asset's risks. " +
		"This list can be used to prioritize on efforts with the greatest effects of reducing data asset risks:<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Technical asset paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	for _, technicalAsset := range model.SortedTechnicalAssetsByQuickWinsAndTitle() {
		quickWins := technicalAsset.QuickWins()
		if r.pdf.GetY() > 260 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}
		risks := technicalAsset.GeneratedRisks()
		switch model.HighestSeverityStillAtRisk(risks) {
		case model.High:
			colorHighRisk(r.pdf)
		case model.Medium:
			colorMediumRisk(r.pdf)
		case model.Low:
			colorLowRisk(r.pdf)
		default:
			r.pdfColorBlack()
		}
		if len(model.ReduceToOnlyStillAtRisk(risks)) == 0 {
			r.pdfColorBlack()
		}

		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := r.pdf.GetY()
		strBuilder.WriteString("<b>")
		strBuilder.WriteString(uni(technicalAsset.Title))
		strBuilder.WriteString("</b>")
		strBuilder.WriteString(": ")
		strBuilder.WriteString(fmt.Sprintf("%.2f", quickWins))
		strBuilder.WriteString(" Quick Wins")
		strBuilder.WriteString("<br>")
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.SetTextColor(0, 0, 0)
		strBuilder.WriteString(uni(technicalAsset.Description))
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, tocLinkIdByAssetId[technicalAsset.ID])
	}

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}
*/

func (r *pdfReporter) addCategories(parsedModel *types.Model, riskCategories []*types.RiskCategory, severity types.RiskSeverity, bothInitialAndRemainingRisks bool, initialRisks bool, describeImpact bool, describeDescription bool) {
	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	sort.Sort(types.ByRiskCategoryTitleSort(riskCategories))
	for _, riskCategory := range riskCategories {
		risksStr := parsedModel.GeneratedRisksByCategory[riskCategory.ID]
		if !initialRisks {
			risksStr = types.ReduceToOnlyStillAtRisk(risksStr)
		}
		if len(risksStr) == 0 {
			continue
		}
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}
		var prefix string
		switch severity {
		case types.CriticalSeverity:
			colorCriticalRisk(r.pdf)
			prefix = "Critical: "
		case types.HighSeverity:
			colorHighRisk(r.pdf)
			prefix = "High: "
		case types.ElevatedSeverity:
			colorElevatedRisk(r.pdf)
			prefix = "Elevated: "
		case types.MediumSeverity:
			colorMediumRisk(r.pdf)
			prefix = "Medium: "
		case types.LowSeverity:
			colorLowRisk(r.pdf)
			prefix = "Low: "
		default:
			r.pdfColorBlack()
			prefix = ""
		}
		switch types.HighestSeverityStillAtRisk(risksStr) {
		case types.CriticalSeverity:
			colorCriticalRisk(r.pdf)
		case types.HighSeverity:
			colorHighRisk(r.pdf)
		case types.ElevatedSeverity:
			colorElevatedRisk(r.pdf)
		case types.MediumSeverity:
			colorMediumRisk(r.pdf)
		case types.LowSeverity:
			colorLowRisk(r.pdf)
		}
		if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
			r.pdfColorBlack()
		}
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := r.pdf.GetY()
		strBuilder.WriteString(prefix)
		strBuilder.WriteString("<b>")
		strBuilder.WriteString(riskCategory.Title)
		strBuilder.WriteString("</b>: ")
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
		suffix += " - Exploitation likelihood is <i>"
		if initialRisks {
			suffix += highestExploitationLikelihood(risksStr).Title() + "</i> with <i>" + highestExploitationImpact(risksStr).Title() + "</i> impact."
		} else {
			suffix += highestExploitationLikelihood(remainingRisks).Title() + "</i> with <i>" + highestExploitationImpact(remainingRisks).Title() + "</i> impact."
		}
		strBuilder.WriteString(suffix + "<br>")
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.SetTextColor(0, 0, 0)
		if describeImpact {
			strBuilder.WriteString(firstParagraph(riskCategory.Impact))
		} else if describeDescription {
			strBuilder.WriteString(firstParagraph(riskCategory.Description))
		} else {
			strBuilder.WriteString(firstParagraph(riskCategory.Mitigation))
		}
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, r.tocLinkIdByAssetId[riskCategory.ID])
	}
}

func highestExploitationLikelihood(risks []*types.Risk) types.RiskExploitationLikelihood {
	result := types.Unlikely
	for _, risk := range risks {
		if risk.ExploitationLikelihood > result {
			result = risk.ExploitationLikelihood
		}
	}
	return result
}

func highestExploitationImpact(risks []*types.Risk) types.RiskExploitationImpact {
	result := types.LowImpact
	for _, risk := range risks {
		if risk.ExploitationImpact > result {
			result = risk.ExploitationImpact
		}
	}
	return result
}

func firstParagraph(text string) string {
	firstParagraphRegEx := regexp.MustCompile(`(.*?)((<br>)|(<p>))`)
	match := firstParagraphRegEx.FindStringSubmatch(text)
	if len(match) == 0 {
		return text
	}
	return match[1]
}

func (r *pdfReporter) createAssignmentByFunction(parsedModel *types.Model) {
	r.pdf.SetTextColor(0, 0, 0)
	title := "Assignment by Function"
	r.addHeadline(title, false)
	r.defineLinkTarget("{function-assignment}")
	r.currentChapterTitleBreadcrumb = title

	risksBusinessSideFunction := reduceToFunctionRisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.BusinessSide)
	risksArchitectureFunction := reduceToFunctionRisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.Architecture)
	risksDevelopmentFunction := reduceToFunctionRisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.Development)
	risksOperationFunction := reduceToFunctionRisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.Operations)

	countBusinessSideFunction := countRisks(risksBusinessSideFunction)
	countArchitectureFunction := countRisks(risksArchitectureFunction)
	countDevelopmentFunction := countRisks(risksDevelopmentFunction)
	countOperationFunction := countRisks(risksOperationFunction)
	var intro strings.Builder
	intro.WriteString("This chapter clusters and assigns the risks by functions which are most likely able to " +
		"check and mitigate them: " +
		"In total <b>" + strconv.Itoa(totalRiskCount(parsedModel)) + " potential risks</b> have been identified during the threat modeling process " +
		"of which <b>" + strconv.Itoa(countBusinessSideFunction) + " should be checked by " + types.BusinessSide.Title() + "</b>, " +
		"<b>" + strconv.Itoa(countArchitectureFunction) + " should be checked by " + types.Architecture.Title() + "</b>, " +
		"<b>" + strconv.Itoa(countDevelopmentFunction) + " should be checked by " + types.Development.Title() + "</b>, " +
		"and <b>" + strconv.Itoa(countOperationFunction) + " should be checked by " + types.Operations.Title() + "</b>.<br>")
	html := r.pdf.HTMLBasicNew()
	html.Write(5, intro.String())
	intro.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	oldLeft, _, _, _ := r.pdf.GetMargins()

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.BusinessSide.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksBusinessSideFunction) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksBusinessSideFunction, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksBusinessSideFunction, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksBusinessSideFunction, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksBusinessSideFunction, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksBusinessSideFunction, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, false)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Architecture.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksArchitectureFunction) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksArchitectureFunction, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksArchitectureFunction, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksArchitectureFunction, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksArchitectureFunction, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksArchitectureFunction, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, false)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Development.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksDevelopmentFunction) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksDevelopmentFunction, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksDevelopmentFunction, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksDevelopmentFunction, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksDevelopmentFunction, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksDevelopmentFunction, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, false)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Operations.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksOperationFunction) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksOperationFunction, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksOperationFunction, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksOperationFunction, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksOperationFunction, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, false)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksOperationFunction, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, false)
	}
	r.pdf.SetLeftMargin(oldLeft)

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func (r *pdfReporter) createSTRIDE(parsedModel *types.Model) {
	r.pdf.SetTextColor(0, 0, 0)
	title := "STRIDE Classification of Identified Risks"
	r.addHeadline(title, false)
	r.defineLinkTarget("{stride}")
	r.currentChapterTitleBreadcrumb = title

	risksSTRIDESpoofing := reduceToSTRIDERisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.Spoofing)
	risksSTRIDETampering := reduceToSTRIDERisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.Tampering)
	risksSTRIDERepudiation := reduceToSTRIDERisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.Repudiation)
	risksSTRIDEInformationDisclosure := reduceToSTRIDERisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.InformationDisclosure)
	risksSTRIDEDenialOfService := reduceToSTRIDERisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.DenialOfService)
	risksSTRIDEElevationOfPrivilege := reduceToSTRIDERisk(parsedModel, parsedModel.GeneratedRisksByCategory, types.ElevationOfPrivilege)

	countSTRIDESpoofing := countRisks(risksSTRIDESpoofing)
	countSTRIDETampering := countRisks(risksSTRIDETampering)
	countSTRIDERepudiation := countRisks(risksSTRIDERepudiation)
	countSTRIDEInformationDisclosure := countRisks(risksSTRIDEInformationDisclosure)
	countSTRIDEDenialOfService := countRisks(risksSTRIDEDenialOfService)
	countSTRIDEElevationOfPrivilege := countRisks(risksSTRIDEElevationOfPrivilege)
	var intro strings.Builder
	intro.WriteString("This chapter clusters and classifies the risks by STRIDE categories: " +
		"In total <b>" + strconv.Itoa(totalRiskCount(parsedModel)) + " potential risks</b> have been identified during the threat modeling process " +
		"of which <b>" + strconv.Itoa(countSTRIDESpoofing) + " in the " + types.Spoofing.Title() + "</b> category, " +
		"<b>" + strconv.Itoa(countSTRIDETampering) + " in the " + types.Tampering.Title() + "</b> category, " +
		"<b>" + strconv.Itoa(countSTRIDERepudiation) + " in the " + types.Repudiation.Title() + "</b> category, " +
		"<b>" + strconv.Itoa(countSTRIDEInformationDisclosure) + " in the " + types.InformationDisclosure.Title() + "</b> category, " +
		"<b>" + strconv.Itoa(countSTRIDEDenialOfService) + " in the " + types.DenialOfService.Title() + "</b> category, " +
		"and <b>" + strconv.Itoa(countSTRIDEElevationOfPrivilege) + " in the " + types.ElevationOfPrivilege.Title() + "</b> category.<br>")
	html := r.pdf.HTMLBasicNew()
	html.Write(5, intro.String())
	intro.Reset()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)

	oldLeft, _, _, _ := r.pdf.GetMargins()

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Spoofing.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksSTRIDESpoofing) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDESpoofing, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDESpoofing, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDESpoofing, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDESpoofing, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDESpoofing, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Tampering.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksSTRIDETampering) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDETampering, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDETampering, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDETampering, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDETampering, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDETampering, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Repudiation.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksSTRIDERepudiation) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDERepudiation, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDERepudiation, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDERepudiation, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDERepudiation, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDERepudiation, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.InformationDisclosure.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksSTRIDEInformationDisclosure) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEInformationDisclosure, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEInformationDisclosure, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEInformationDisclosure, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEInformationDisclosure, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEInformationDisclosure, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.DenialOfService.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksSTRIDEDenialOfService) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEDenialOfService, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEDenialOfService, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEDenialOfService, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEDenialOfService, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEDenialOfService, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.ElevationOfPrivilege.Title()+"</b>")
	r.pdf.SetLeftMargin(15)
	if len(risksSTRIDEElevationOfPrivilege) == 0 {
		r.pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEElevationOfPrivilege, true, types.CriticalSeverity)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEElevationOfPrivilege, true, types.HighSeverity)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEElevationOfPrivilege, true, types.ElevatedSeverity)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEElevationOfPrivilege, true, types.MediumSeverity)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, getRiskCategories(parsedModel, reduceToSeverityRisk(risksSTRIDEElevationOfPrivilege, true, types.LowSeverity)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func getRiskCategories(parsedModel *types.Model, categoryIDs []string) []*types.RiskCategory {
	categoryMap := make(map[string]*types.RiskCategory)
	for _, categoryId := range categoryIDs {
		category := parsedModel.GetRiskCategory(categoryId)
		if category != nil {
			categoryMap[categoryId] = category
		}
	}

	categories := make([]*types.RiskCategory, 0)
	for categoryId := range categoryMap {
		categories = append(categories, categoryMap[categoryId])
	}

	return categories
}

func reduceToSeverityRisk(risksByCategory map[string][]*types.Risk, initialRisks bool, severity types.RiskSeverity) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.RiskStatus.IsStillAtRisk() {
				continue
			}
			if risk.Severity == severity {
				categories[categoryId] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func reduceToOnlyStillAtRisk(risksByCategory map[string][]*types.Risk) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			if !risk.RiskStatus.IsStillAtRisk() {
				continue
			}
			categories[categoryId] = struct{}{}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func keysAsSlice(categories map[string]struct{}) []string {
	result := make([]string, 0, len(categories))
	for k := range categories {
		result = append(result, k)
	}
	return result
}

func (r *pdfReporter) createSecurityRequirements(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	chapTitle := "Security Requirements"
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{security-requirements}")
	r.currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "This chapter lists the custom security requirements which have been defined for the modeled target.")
	r.pdfColorBlack()
	for _, title := range sortedKeysOfSecurityRequirements(parsedModel) {
		description := parsedModel.SecurityRequirements[title]
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		html.Write(5, "<b>"+uni(title)+"</b><br>")
		html.Write(5, uni(description))
	}
	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	html.Write(5, "<i>This list is not complete and regulatory or law relevant security requirements have to be "+
		"taken into account as well. Also custom individual security requirements might exist for the project.</i>")
}

func sortedKeysOfSecurityRequirements(parsedModel *types.Model) []string {
	keys := make([]string, 0)
	for k := range parsedModel.SecurityRequirements {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *pdfReporter) createAbuseCases(parsedModel *types.Model) {
	r.pdf.SetTextColor(0, 0, 0)
	chapTitle := "Abuse Cases"
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{abuse-cases}")
	r.currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "This chapter lists the custom abuse cases which have been defined for the modeled target.")
	r.pdfColorBlack()
	for _, title := range sortedKeysOfAbuseCases(parsedModel) {
		description := parsedModel.AbuseCases[title]
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		html.Write(5, "<b>"+title+"</b><br>")
		html.Write(5, description)
	}
	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	html.Write(5, "<i>This list is not complete and regulatory or law relevant abuse cases have to be "+
		"taken into account as well. Also custom individual abuse cases might exist for the project.</i>")
}

func sortedKeysOfAbuseCases(parsedModel *types.Model) []string {
	keys := make([]string, 0)
	for k := range parsedModel.AbuseCases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *pdfReporter) createQuestions(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	questions := "Questions"
	count := len(parsedModel.Questions)
	if count == 1 {
		questions = "Question"
	}
	if questionsUnanswered(parsedModel) > 0 {
		colorModelFailure(r.pdf)
	}
	chapTitle := "Questions: " + strconv.Itoa(questionsUnanswered(parsedModel)) + " / " + strconv.Itoa(count) + " " + questions
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{questions}")
	r.currentChapterTitleBreadcrumb = chapTitle
	r.pdfColorBlack()

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "This chapter lists custom questions that arose during the threat modeling process.")

	if len(parsedModel.Questions) == 0 {
		r.pdfColorLightGray()
		html.Write(5, "<br><br><br>")
		html.Write(5, "No custom questions arose during the threat modeling process.")
	}
	r.pdfColorBlack()
	for _, question := range sortedKeysOfQuestions(parsedModel) {
		answer := parsedModel.Questions[question]
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		r.pdfColorBlack()
		if len(strings.TrimSpace(answer)) > 0 {
			html.Write(5, "<b>"+uni(question)+"</b><br>")
			html.Write(5, "<i>"+uni(strings.TrimSpace(answer))+"</i>")
		} else {
			colorModelFailure(r.pdf)
			html.Write(5, "<b>"+uni(question)+"</b><br>")
			r.pdfColorLightGray()
			html.Write(5, "<i>- answer pending -</i>")
			r.pdfColorBlack()
		}
	}
}

func (r *pdfReporter) createTagListing(parsedModel *types.Model) {
	r.pdf.SetTextColor(0, 0, 0)
	chapTitle := "Tag Listing"
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{tag-listing}")
	r.currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "This chapter lists what tags are used by which elements.")
	r.pdfColorBlack()
	sorted := parsedModel.TagsAvailable
	sort.Strings(sorted)
	for _, tag := range sorted {
		description := "" // TODO: add some separation texts to distinguish between technical assets and data assets etc. for example?
		for _, techAsset := range sortedTechnicalAssetsByTitle(parsedModel) {
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
		for _, dataAsset := range sortedDataAssetsByTitle(parsedModel) {
			if contains(dataAsset.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += dataAsset.Title
			}
		}
		for _, trustBoundary := range sortedTrustBoundariesByTitle(parsedModel) {
			if contains(trustBoundary.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += trustBoundary.Title
			}
		}
		for _, sharedRuntime := range sortedSharedRuntimesByTitle(parsedModel) {
			if contains(sharedRuntime.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += sharedRuntime.Title
			}
		}
		if len(description) > 0 {
			if r.pdf.GetY() > 250 {
				r.pageBreak()
				r.pdf.SetY(36)
			} else {
				html.Write(5, "<br><br><br>")
			}
			r.pdfColorBlack()
			uni := r.pdf.UnicodeTranslatorFromDescriptor("")
			html.Write(5, "<b>"+uni(tag)+"</b><br>")
			html.Write(5, uni(description))
		}
	}
}

func sortedSharedRuntimesByTitle(parsedModel *types.Model) []*types.SharedRuntime {
	result := make([]*types.SharedRuntime, 0)
	for _, runtime := range parsedModel.SharedRuntimes {
		result = append(result, runtime)
	}
	sort.Sort(bySharedRuntimeTitleSort(result))
	return result
}

type bySharedRuntimeTitleSort []*types.SharedRuntime

func (what bySharedRuntimeTitleSort) Len() int      { return len(what) }
func (what bySharedRuntimeTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what bySharedRuntimeTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

func sortedTechnicalAssetsByTitle(parsedModel *types.Model) []*types.TechnicalAsset {
	assets := make([]*types.TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		assets = append(assets, asset)
	}
	sort.Sort(types.ByTechnicalAssetTitleSort(assets))
	return assets
}

func (r *pdfReporter) createRiskCategories(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	// category title
	title := "Identified Risks by Vulnerability category"
	r.pdfColorBlack()
	r.addHeadline(title, false)
	r.defineLinkTarget("{intro-risks-by-vulnerability-category}")
	html := r.pdf.HTMLBasicNew()
	var text strings.Builder
	text.WriteString("In total <b>" + strconv.Itoa(totalRiskCount(parsedModel)) + " potential risks</b> have been identified during the threat modeling process " +
		"of which " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.CriticalSeverity))) + " are rated as critical</b>, " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.HighSeverity))) + " as high</b>, " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.ElevatedSeverity))) + " as elevated</b>, " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.MediumSeverity))) + " as medium</b>, " +
		"and <b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.LowSeverity))) + " as low</b>. " +
		"<br><br>These risks are distributed across <b>" + strconv.Itoa(len(parsedModel.GeneratedRisksByCategory)) + " vulnerability categories</b>. ")
	text.WriteString("The following sub-chapters of this section describe each identified risk category.") // TODO more explanation text
	html.Write(5, text.String())
	text.Reset()
	r.currentChapterTitleBreadcrumb = title
	for _, category := range parsedModel.SortedRiskCategories() {
		risksStr := parsedModel.SortedRisksOfCategory(category)

		// category color
		switch types.HighestSeverityStillAtRisk(risksStr) {
		case types.CriticalSeverity:
			colorCriticalRisk(r.pdf)
		case types.HighSeverity:
			colorHighRisk(r.pdf)
		case types.ElevatedSeverity:
			colorElevatedRisk(r.pdf)
		case types.MediumSeverity:
			colorMediumRisk(r.pdf)
		case types.LowSeverity:
			colorLowRisk(r.pdf)
		default:
			r.pdfColorBlack()
		}
		if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
			r.pdfColorBlack()
		}

		// category title
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		title := category.Title + ": " + suffix
		r.addHeadline(uni(title), true)
		r.pdfColorBlack()
		r.defineLinkTarget("{" + category.ID + "}")
		r.currentChapterTitleBreadcrumb = title

		// category details
		var text strings.Builder
		cweLink := "n/a"
		if category.CWE > 0 {
			cweLink = "<a href=\"https://cwe.mitre.org/data/definitions/" + strconv.Itoa(category.CWE) + ".html\">CWE " +
				strconv.Itoa(category.CWE) + "</a>"
		}
		text.WriteString("<b>Description</b> (" + category.STRIDE.Title() + "): " + cweLink + "<br><br>")
		text.WriteString(category.Description)
		text.WriteString("<br><br><br><b>Impact</b><br><br>")
		text.WriteString(category.Impact)
		text.WriteString("<br><br><br><b>Detection Logic</b><br><br>")
		text.WriteString(category.DetectionLogic)
		text.WriteString("<br><br><br><b>Risk Rating</b><br><br>")
		text.WriteString(category.RiskAssessment)
		html.Write(5, text.String())
		text.Reset()
		colorRiskStatusFalsePositive(r.pdf)
		text.WriteString("<br><br><br><b>False Positives</b><br><br>")
		text.WriteString(category.FalsePositives)
		html.Write(5, text.String())
		text.Reset()
		colorRiskStatusMitigated(r.pdf)
		text.WriteString("<br><br><br><b>Mitigation</b> (" + category.Function.Title() + "): " + category.Action + "<br><br>")
		text.WriteString(category.Mitigation)

		asvsChapter := category.ASVS
		if len(asvsChapter) == 0 {
			text.WriteString("<br><br>ASVS Chapter: n/a")
		} else {
			text.WriteString("<br><br>ASVS Chapter: <a href=\"https://owasp.org/www-project-application-security-verification-standard/\">" + asvsChapter + "</a>")
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
			cheatSheetLink = "<a href=\"" + cheatSheetLink + "\">" + linkText + "</a>"
		}
		text.WriteString("<br>Cheat Sheet: " + cheatSheetLink)

		text.WriteString("<br><br><br><b>Check</b><br><br>")
		text.WriteString(category.Check)

		html.Write(5, text.String())
		text.Reset()
		r.pdf.SetTextColor(0, 0, 0)

		// risk details
		r.pageBreak()
		r.pdf.SetY(36)
		text.WriteString("<b>Risk Findings</b><br><br>")
		times := strconv.Itoa(len(risksStr)) + " time"
		if len(risksStr) > 1 {
			times += "s"
		}
		text.WriteString("The risk <b>" + category.Title + "</b> was found <b>" + times + "</b> in the analyzed architecture to be " +
			"potentially possible. Each spot should be checked individually by reviewing the implementation whether all " +
			"controls have been applied properly in order to mitigate each risk.<br>")
		html.Write(5, text.String())
		text.Reset()
		r.pdf.SetFont("Helvetica", "", fontSizeSmall)
		r.pdfColorGray()
		html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.<br>")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		oldLeft, _, _, _ := r.pdf.GetMargins()
		headlineCriticalWritten, headlineHighWritten, headlineElevatedWritten, headlineMediumWritten, headlineLowWritten := false, false, false, false, false
		for _, risk := range risksStr {
			text.WriteString("<br>")
			html.Write(5, text.String())
			text.Reset()
			if r.pdf.GetY() > 250 {
				r.pageBreak()
				r.pdf.SetY(36)
			}
			switch risk.Severity {
			case types.CriticalSeverity:
				colorCriticalRisk(r.pdf)
				if !headlineCriticalWritten {
					r.pdf.SetFont("Helvetica", "", fontSizeBody)
					r.pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>Critical Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineCriticalWritten = true
				}
			case types.HighSeverity:
				colorHighRisk(r.pdf)
				if !headlineHighWritten {
					r.pdf.SetFont("Helvetica", "", fontSizeBody)
					r.pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>High Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineHighWritten = true
				}
			case types.ElevatedSeverity:
				colorElevatedRisk(r.pdf)
				if !headlineElevatedWritten {
					r.pdf.SetFont("Helvetica", "", fontSizeBody)
					r.pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>Elevated Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineElevatedWritten = true
				}
			case types.MediumSeverity:
				colorMediumRisk(r.pdf)
				if !headlineMediumWritten {
					r.pdf.SetFont("Helvetica", "", fontSizeBody)
					r.pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>Medium Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineMediumWritten = true
				}
			case types.LowSeverity:
				colorLowRisk(r.pdf)
				if !headlineLowWritten {
					r.pdf.SetFont("Helvetica", "", fontSizeBody)
					r.pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>Low Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineLowWritten = true
				}
			default:
				r.pdfColorBlack()
			}
			if !risk.RiskStatus.IsStillAtRisk() {
				r.pdfColorBlack()
			}
			posY := r.pdf.GetY()
			r.pdf.SetLeftMargin(oldLeft + 10)
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			text.WriteString(uni(risk.Title) + ": Exploitation likelihood is <i>" + risk.ExploitationLikelihood.Title() + "</i> with <i>" + risk.ExploitationImpact.Title() + "</i> impact.")
			text.WriteString("<br>")
			html.Write(5, text.String())
			text.Reset()
			r.pdfColorGray()
			r.pdf.SetFont("Helvetica", "", fontSizeVerySmall)
			r.pdf.MultiCell(215, 5, uni(risk.SyntheticId), "0", "0", false)
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			if len(risk.MostRelevantSharedRuntimeId) > 0 {
				r.pdf.Link(20, posY, 180, r.pdf.GetY()-posY, r.tocLinkIdByAssetId[risk.MostRelevantSharedRuntimeId])
			} else if len(risk.MostRelevantTrustBoundaryId) > 0 {
				r.pdf.Link(20, posY, 180, r.pdf.GetY()-posY, r.tocLinkIdByAssetId[risk.MostRelevantTrustBoundaryId])
			} else if len(risk.MostRelevantTechnicalAssetId) > 0 {
				r.pdf.Link(20, posY, 180, r.pdf.GetY()-posY, r.tocLinkIdByAssetId[risk.MostRelevantTechnicalAssetId])
			}
			r.writeRiskTrackingStatus(parsedModel, risk)
			r.pdf.SetLeftMargin(oldLeft)
			html.Write(5, text.String())
			text.Reset()
		}
		r.pdf.SetLeftMargin(oldLeft)
	}
}

func (r *pdfReporter) writeRiskTrackingStatus(parsedModel *types.Model, risk *types.Risk) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	tracking := parsedModel.GetRiskTrackingWithDefault(risk)
	r.pdfColorBlack()
	r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
	switch tracking.Status {
	case types.Unchecked:
		colorRiskStatusUnchecked(r.pdf)
	case types.InDiscussion:
		colorRiskStatusInDiscussion(r.pdf)
	case types.Accepted:
		colorRiskStatusAccepted(r.pdf)
	case types.InProgress:
		colorRiskStatusInProgress(r.pdf)
	case types.Mitigated:
		colorRiskStatusMitigated(r.pdf)
	case types.FalsePositive:
		colorRiskStatusFalsePositive(r.pdf)
	default:
		r.pdfColorBlack()
	}
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	if tracking.Status == types.Unchecked {
		r.pdf.SetFont("Helvetica", "B", fontSizeSmall)
	}
	r.pdf.CellFormat(25, 4, tracking.Status.Title(), "0", 0, "B", false, 0, "")
	if tracking.Status != types.Unchecked {
		dateStr := tracking.Date.Format("2006-01-02")
		if dateStr == "0001-01-01" {
			dateStr = ""
		}
		justificationStr := tracking.Justification
		r.pdfColorGray()
		r.pdf.CellFormat(20, 4, dateStr, "0", 0, "B", false, 0, "")
		r.pdf.CellFormat(35, 4, uni(tracking.CheckedBy), "0", 0, "B", false, 0, "")
		r.pdf.CellFormat(35, 4, uni(tracking.Ticket), "0", 0, "B", false, 0, "")
		r.pdf.Ln(-1)
		r.pdfColorBlack()
		r.pdf.CellFormat(10, 4, "", "0", 0, "", false, 0, "")
		r.pdf.MultiCell(170, 4, uni(justificationStr), "0", "0", false)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
	} else {
		r.pdf.Ln(-1)
	}
	r.pdfColorBlack()
}

func (r *pdfReporter) createTechnicalAssets(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	// category title
	title := "Identified Risks by Technical Asset"
	r.pdfColorBlack()
	r.addHeadline(title, false)
	r.defineLinkTarget("{intro-risks-by-technical-asset}")
	html := r.pdf.HTMLBasicNew()
	var text strings.Builder
	text.WriteString("In total <b>" + strconv.Itoa(totalRiskCount(parsedModel)) + " potential risks</b> have been identified during the threat modeling process " +
		"of which " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.CriticalSeverity))) + " are rated as critical</b>, " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.HighSeverity))) + " as high</b>, " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.ElevatedSeverity))) + " as elevated</b>, " +
		"<b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.MediumSeverity))) + " as medium</b>, " +
		"and <b>" + strconv.Itoa(len(filteredBySeverity(parsedModel, types.LowSeverity))) + " as low</b>. " +
		"<br><br>These risks are distributed across <b>" + strconv.Itoa(len(parsedModel.InScopeTechnicalAssets())) + " in-scope technical assets</b>. ")
	text.WriteString("The following sub-chapters of this section describe each identified risk grouped by technical asset. ") // TODO more explanation text
	text.WriteString("The RAA value of a technical asset is the calculated \"Relative Attacker Attractiveness\" value in percent.")
	html.Write(5, text.String())
	text.Reset()
	r.currentChapterTitleBreadcrumb = title
	for _, technicalAsset := range sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel) {
		risksStr := parsedModel.GeneratedRisks(technicalAsset)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		if technicalAsset.OutOfScope {
			r.pdfColorOutOfScope()
			suffix = "out-of-scope"
		} else {
			switch types.HighestSeverityStillAtRisk(risksStr) {
			case types.CriticalSeverity:
				colorCriticalRisk(r.pdf)
			case types.HighSeverity:
				colorHighRisk(r.pdf)
			case types.ElevatedSeverity:
				colorElevatedRisk(r.pdf)
			case types.MediumSeverity:
				colorMediumRisk(r.pdf)
			case types.LowSeverity:
				colorLowRisk(r.pdf)
			default:
				r.pdfColorBlack()
			}
			if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
				r.pdfColorBlack()
			}
		}

		// asset title
		title := technicalAsset.Title + ": " + suffix
		r.addHeadline(uni(title), true)
		r.pdfColorBlack()
		r.defineLinkTarget("{" + technicalAsset.Id + "}")
		r.currentChapterTitleBreadcrumb = title

		// asset description
		html := r.pdf.HTMLBasicNew()
		var text strings.Builder
		text.WriteString("<b>Description</b><br><br>")
		text.WriteString(uni(technicalAsset.Description))
		html.Write(5, text.String())
		text.Reset()
		r.pdf.SetTextColor(0, 0, 0)

		// and more metadata of asset in tabular view
		r.pdf.Ln(-1)
		r.pdf.Ln(-1)
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdfColorBlack()
		r.pdf.CellFormat(190, 6, "Identified Risks of Asset", "0", 0, "", false, 0, "")
		r.pdfColorGray()
		oldLeft, _, _, _ := r.pdf.GetMargins()
		if len(risksStr) > 0 {
			r.pdf.SetFont("Helvetica", "", fontSizeSmall)
			html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			r.pdf.SetLeftMargin(15)
			/*
				r.pdf.Ln(-1)
				r.pdf.Ln(-1)
				r.pdfColorGray()
				r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(185, 6, strconv.Itoa(len(risksStr))+" risksStr in total were identified", "0", 0, "", false, 0, "")
			*/
			headlineCriticalWritten, headlineHighWritten, headlineElevatedWritten, headlineMediumWritten, headlineLowWritten := false, false, false, false, false
			r.pdf.Ln(-1)
			for _, risk := range risksStr {
				text.WriteString("<br>")
				html.Write(5, text.String())
				text.Reset()
				if r.pdf.GetY() > 250 { // 250 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
					r.pageBreak()
					r.pdf.SetY(36)
				}
				switch risk.Severity {
				case types.CriticalSeverity:
					colorCriticalRisk(r.pdf)
					if !headlineCriticalWritten {
						r.pdf.SetFont("Helvetica", "", fontSizeBody)
						r.pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>Critical Risk Severity</i></b><br><br>")
						headlineCriticalWritten = true
					}
				case types.HighSeverity:
					colorHighRisk(r.pdf)
					if !headlineHighWritten {
						r.pdf.SetFont("Helvetica", "", fontSizeBody)
						r.pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>High Risk Severity</i></b><br><br>")
						headlineHighWritten = true
					}
				case types.ElevatedSeverity:
					colorElevatedRisk(r.pdf)
					if !headlineElevatedWritten {
						r.pdf.SetFont("Helvetica", "", fontSizeBody)
						r.pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>Elevated Risk Severity</i></b><br><br>")
						headlineElevatedWritten = true
					}
				case types.MediumSeverity:
					colorMediumRisk(r.pdf)
					if !headlineMediumWritten {
						r.pdf.SetFont("Helvetica", "", fontSizeBody)
						r.pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>Medium Risk Severity</i></b><br><br>")
						headlineMediumWritten = true
					}
				case types.LowSeverity:
					colorLowRisk(r.pdf)
					if !headlineLowWritten {
						r.pdf.SetFont("Helvetica", "", fontSizeBody)
						r.pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>Low Risk Severity</i></b><br><br>")
						headlineLowWritten = true
					}
				default:
					r.pdfColorBlack()
				}
				if !risk.RiskStatus.IsStillAtRisk() {
					r.pdfColorBlack()
				}
				posY := r.pdf.GetY()
				r.pdf.SetLeftMargin(oldLeft + 10)
				r.pdf.SetFont("Helvetica", "", fontSizeBody)
				text.WriteString(uni(risk.Title) + ": Exploitation likelihood is <i>" + risk.ExploitationLikelihood.Title() + "</i> with <i>" + risk.ExploitationImpact.Title() + "</i> impact.")
				text.WriteString("<br>")
				html.Write(5, text.String())
				text.Reset()

				r.pdf.SetFont("Helvetica", "", fontSizeVerySmall)
				r.pdfColorGray()
				r.pdf.MultiCell(215, 5, uni(risk.SyntheticId), "0", "0", false)
				r.pdf.Link(20, posY, 180, r.pdf.GetY()-posY, r.tocLinkIdByAssetId[risk.CategoryId])
				r.pdf.SetFont("Helvetica", "", fontSizeBody)
				r.writeRiskTrackingStatus(parsedModel, risk)
				r.pdf.SetLeftMargin(oldLeft)
			}
		} else {
			r.pdf.Ln(-1)
			r.pdf.Ln(-1)
			r.pdfColorGray()
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			r.pdf.SetLeftMargin(15)
			text := "No risksStr were identified."
			if technicalAsset.OutOfScope {
				text = "Asset was defined as out-of-scope."
			}
			html.Write(5, text)
			r.pdf.Ln(-1)
		}
		r.pdf.SetLeftMargin(oldLeft)

		r.pdf.Ln(-1)
		r.pdf.Ln(4)
		if r.pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorBlack()
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.CellFormat(190, 6, "Asset Information", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "ID:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Id, "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Type:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Type.String(), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Usage:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Usage.String(), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "RAA:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		textRAA := fmt.Sprintf("%.0f", technicalAsset.RAA) + " %"
		if technicalAsset.OutOfScope {
			r.pdfColorGray()
			textRAA = "out-of-scope"
		}
		r.pdf.MultiCell(145, 6, textRAA, "0", "0", false)
		r.pdfColorBlack()
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Size:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Size.String(), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Technology:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Technologies.String(), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Tags:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		tagsUsedText := ""
		sorted := technicalAsset.Tags
		sort.Strings(sorted)
		for _, tag := range sorted {
			if len(tagsUsedText) > 0 {
				tagsUsedText += ", "
			}
			tagsUsedText += tag
		}
		if len(tagsUsedText) == 0 {
			r.pdfColorGray()
			tagsUsedText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(tagsUsedText), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Internet:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.Internet), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Machine:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Machine.String(), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Encryption:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, technicalAsset.Encryption.String(), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Multi-Tenant:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.MultiTenant), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Redundant:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.Redundant), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Custom-Developed:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.CustomDevelopedParts), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Client by Human:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.UsedAsClientByHuman), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Data Processed:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		dataAssetsProcessedText := ""
		for _, dataAsset := range parsedModel.DataAssetsProcessedSorted(technicalAsset) {
			if len(dataAssetsProcessedText) > 0 {
				dataAssetsProcessedText += ", "
			}
			dataAssetsProcessedText += dataAsset.Title
		}
		if len(dataAssetsProcessedText) == 0 {
			r.pdfColorGray()
			dataAssetsProcessedText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(dataAssetsProcessedText), "0", "0", false)

		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Data Stored:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		dataAssetsStoredText := ""
		for _, dataAsset := range parsedModel.DataAssetsStoredSorted(technicalAsset) {
			if len(dataAssetsStoredText) > 0 {
				dataAssetsStoredText += ", "
			}
			dataAssetsStoredText += dataAsset.Title
		}
		if len(dataAssetsStoredText) == 0 {
			r.pdfColorGray()
			dataAssetsStoredText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(dataAssetsStoredText), "0", "0", false)

		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Formats Accepted:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		formatsAcceptedText := ""
		for _, formatAccepted := range technicalAsset.DataFormatsAcceptedSorted() {
			if len(formatsAcceptedText) > 0 {
				formatsAcceptedText += ", "
			}
			formatsAcceptedText += formatAccepted.Title()
		}
		if len(formatsAcceptedText) == 0 {
			r.pdfColorGray()
			formatsAcceptedText = "none of the special data formats accepted"
		}
		r.pdf.MultiCell(145, 6, formatsAcceptedText, "0", "0", false)

		r.pdf.Ln(-1)
		r.pdf.Ln(4)
		if r.pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorBlack()
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.CellFormat(190, 6, "Asset Rating", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Owner:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, uni(technicalAsset.Owner), "0", "0", false)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Confidentiality:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.CellFormat(40, 6, technicalAsset.Confidentiality.String(), "0", 0, "", false, 0, "")
		r.pdfColorGray()
		r.pdf.CellFormat(115, 6, technicalAsset.Confidentiality.RatingStringInScale(), "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Integrity:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.CellFormat(40, 6, technicalAsset.Integrity.String(), "0", 0, "", false, 0, "")
		r.pdfColorGray()
		r.pdf.CellFormat(115, 6, technicalAsset.Integrity.RatingStringInScale(), "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Availability:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.CellFormat(40, 6, technicalAsset.Availability.String(), "0", 0, "", false, 0, "")
		r.pdfColorGray()
		r.pdf.CellFormat(115, 6, technicalAsset.Availability.RatingStringInScale(), "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 270 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "CIA-Justification:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, uni(technicalAsset.JustificationCiaRating), "0", "0", false)

		if technicalAsset.OutOfScope {
			r.pdf.Ln(-1)
			r.pdf.Ln(4)
			if r.pdf.GetY() > 270 {
				r.pageBreak()
				r.pdf.SetY(36)
			}
			r.pdfColorBlack()
			r.pdf.SetFont("Helvetica", "B", fontSizeBody)
			r.pdf.CellFormat(190, 6, "Asset Out-of-Scope Justification", "0", 0, "", false, 0, "")
			r.pdf.Ln(-1)
			r.pdf.Ln(-1)
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			r.pdf.MultiCell(190, 6, uni(technicalAsset.JustificationOutOfScope), "0", "0", false)
			r.pdf.Ln(-1)
		}
		r.pdf.Ln(-1)

		if len(technicalAsset.CommunicationLinks) > 0 {
			r.pdf.Ln(-1)
			if r.pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
				r.pageBreak()
				r.pdf.SetY(36)
			}
			r.pdfColorBlack()
			r.pdf.SetFont("Helvetica", "B", fontSizeBody)
			r.pdf.CellFormat(190, 6, "Outgoing Communication Links: "+strconv.Itoa(len(technicalAsset.CommunicationLinks)), "0", 0, "", false, 0, "")
			r.pdf.SetFont("Helvetica", "", fontSizeSmall)
			r.pdfColorGray()
			html.Write(5, "Target technical asset names are clickable and link to the corresponding chapter.")
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			r.pdf.Ln(-1)
			r.pdf.Ln(-1)
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			for _, outgoingCommLink := range technicalAsset.CommunicationLinksSorted() {
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorBlack()
				r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(185, 6, uni(outgoingCommLink.Title)+" (outgoing)", "0", 0, "", false, 0, "")
				r.pdf.Ln(-1)
				r.pdfColorGray()
				r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				r.pdf.MultiCell(185, 6, uni(outgoingCommLink.Description), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdf.Ln(-1)
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Target:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(125, 6, uni(parsedModel.TechnicalAssets[outgoingCommLink.TargetId].Title), "0", "0", false)
				r.pdf.Link(60, r.pdf.GetY()-5, 70, 5, r.tocLinkIdByAssetId[outgoingCommLink.TargetId])
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Protocol:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, outgoingCommLink.Protocol.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Encrypted:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(outgoingCommLink.Protocol.IsEncrypted()), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Authentication:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, outgoingCommLink.Authentication.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Authorization:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, outgoingCommLink.Authorization.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Read-Only:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(outgoingCommLink.Readonly), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Usage:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, outgoingCommLink.Usage.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Tags:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				tagsUsedText := ""
				sorted := outgoingCommLink.Tags
				sort.Strings(sorted)
				for _, tag := range sorted {
					if len(tagsUsedText) > 0 {
						tagsUsedText += ", "
					}
					tagsUsedText += tag
				}
				if len(tagsUsedText) == 0 {
					r.pdfColorGray()
					tagsUsedText = "none"
				}
				r.pdf.MultiCell(140, 6, uni(tagsUsedText), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "VPN:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(outgoingCommLink.VPN), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "IP-Filtered:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(outgoingCommLink.IpFiltered), "0", "0", false)
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Data Sent:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				dataAssetsSentText := ""
				for _, dataAsset := range parsedModel.DataAssetsSentSorted(outgoingCommLink) {
					if len(dataAssetsSentText) > 0 {
						dataAssetsSentText += ", "
					}
					dataAssetsSentText += dataAsset.Title
				}
				if len(dataAssetsSentText) == 0 {
					r.pdfColorGray()
					dataAssetsSentText = "none"
				}
				r.pdf.MultiCell(140, 6, uni(dataAssetsSentText), "0", "0", false)
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Data Received:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				dataAssetsReceivedText := ""
				for _, dataAsset := range parsedModel.DataAssetsReceivedSorted(outgoingCommLink) {
					if len(dataAssetsReceivedText) > 0 {
						dataAssetsReceivedText += ", "
					}
					dataAssetsReceivedText += dataAsset.Title
				}
				if len(dataAssetsReceivedText) == 0 {
					r.pdfColorGray()
					dataAssetsReceivedText = "none"
				}
				r.pdf.MultiCell(140, 6, uni(dataAssetsReceivedText), "0", "0", false)
				r.pdf.Ln(-1)
			}
		}

		incomingCommLinks := parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		if len(incomingCommLinks) > 0 {
			r.pdf.Ln(-1)
			if r.pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
				r.pageBreak()
				r.pdf.SetY(36)
			}
			r.pdfColorBlack()
			r.pdf.SetFont("Helvetica", "B", fontSizeBody)
			r.pdf.CellFormat(190, 6, "Incoming Communication Links: "+strconv.Itoa(len(incomingCommLinks)), "0", 0, "", false, 0, "")
			r.pdf.SetFont("Helvetica", "", fontSizeSmall)
			r.pdfColorGray()
			html.Write(5, "Source technical asset names are clickable and link to the corresponding chapter.")
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			r.pdf.Ln(-1)
			r.pdf.Ln(-1)
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			for _, incomingCommLink := range incomingCommLinks {
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorBlack()
				r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(185, 6, uni(incomingCommLink.Title)+" (incoming)", "0", 0, "", false, 0, "")
				r.pdf.Ln(-1)
				r.pdfColorGray()
				r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				r.pdf.MultiCell(185, 6, uni(incomingCommLink.Description), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdf.Ln(-1)
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Source:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, uni(parsedModel.TechnicalAssets[incomingCommLink.SourceId].Title), "0", "0", false)
				r.pdf.Link(60, r.pdf.GetY()-5, 70, 5, r.tocLinkIdByAssetId[incomingCommLink.SourceId])
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Protocol:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, incomingCommLink.Protocol.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Encrypted:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(incomingCommLink.Protocol.IsEncrypted()), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Authentication:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, incomingCommLink.Authentication.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Authorization:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, incomingCommLink.Authorization.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Read-Only:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(incomingCommLink.Readonly), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Usage:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, incomingCommLink.Usage.String(), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Tags:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				tagsUsedText := ""
				sorted := incomingCommLink.Tags
				sort.Strings(sorted)
				for _, tag := range sorted {
					if len(tagsUsedText) > 0 {
						tagsUsedText += ", "
					}
					tagsUsedText += tag
				}
				if len(tagsUsedText) == 0 {
					r.pdfColorGray()
					tagsUsedText = "none"
				}
				r.pdf.MultiCell(140, 6, uni(tagsUsedText), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "VPN:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(incomingCommLink.VPN), "0", "0", false)
				if r.pdf.GetY() > 270 {
					r.pageBreak()
					r.pdf.SetY(36)
				}
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "IP-Filtered:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				r.pdf.MultiCell(140, 6, strconv.FormatBool(incomingCommLink.IpFiltered), "0", "0", false)
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Data Received:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				dataAssetsSentText := ""
				// yep, here we reverse the sent/received direction, as it's the incoming stuff
				for _, dataAsset := range parsedModel.DataAssetsSentSorted(incomingCommLink) {
					if len(dataAssetsSentText) > 0 {
						dataAssetsSentText += ", "
					}
					dataAssetsSentText += dataAsset.Title
				}
				if len(dataAssetsSentText) == 0 {
					r.pdfColorGray()
					dataAssetsSentText = "none"
				}
				r.pdf.MultiCell(140, 6, uni(dataAssetsSentText), "0", "0", false)
				r.pdfColorGray()
				r.pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				r.pdf.CellFormat(35, 6, "Data Sent:", "0", 0, "", false, 0, "")
				r.pdfColorBlack()
				dataAssetsReceivedText := ""
				// yep, here we reverse the sent/received direction, as it's the incoming stuff
				for _, dataAsset := range parsedModel.DataAssetsReceivedSorted(incomingCommLink) {
					if len(dataAssetsReceivedText) > 0 {
						dataAssetsReceivedText += ", "
					}
					dataAssetsReceivedText += dataAsset.Title
				}
				if len(dataAssetsReceivedText) == 0 {
					r.pdfColorGray()
					dataAssetsReceivedText = "none"
				}
				r.pdf.MultiCell(140, 6, uni(dataAssetsReceivedText), "0", "0", false)
				r.pdf.Ln(-1)
			}
		}
	}
}

func (r *pdfReporter) createDataAssets(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	title := "Identified Data Breach Probabilities by Data Asset"
	r.pdfColorBlack()
	r.addHeadline(title, false)
	r.defineLinkTarget("{intro-risks-by-data-asset}")
	html := r.pdf.HTMLBasicNew()
	html.Write(5, "In total <b>"+strconv.Itoa(totalRiskCount(parsedModel))+" potential risks</b> have been identified during the threat modeling process "+
		"of which "+
		"<b>"+strconv.Itoa(len(filteredBySeverity(parsedModel, types.CriticalSeverity)))+" are rated as critical</b>, "+
		"<b>"+strconv.Itoa(len(filteredBySeverity(parsedModel, types.HighSeverity)))+" as high</b>, "+
		"<b>"+strconv.Itoa(len(filteredBySeverity(parsedModel, types.ElevatedSeverity)))+" as elevated</b>, "+
		"<b>"+strconv.Itoa(len(filteredBySeverity(parsedModel, types.MediumSeverity)))+" as medium</b>, "+
		"and <b>"+strconv.Itoa(len(filteredBySeverity(parsedModel, types.LowSeverity)))+" as low</b>. "+
		"<br><br>These risks are distributed across <b>"+strconv.Itoa(len(parsedModel.DataAssets))+" data assets</b>. ")
	html.Write(5, "The following sub-chapters of this section describe the derived data breach probabilities grouped by data asset.<br>") // TODO more explanation text
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	r.pdfColorGray()
	html.Write(5, "Technical asset names and risk IDs are clickable and link to the corresponding chapter.")
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.currentChapterTitleBreadcrumb = title
	for _, dataAsset := range sortedDataAssetsByDataBreachProbabilityAndTitle(parsedModel) {
		if r.pdf.GetY() > 280 { // 280 as only small font previously (not 250)
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		r.pdfColorBlack()
		switch identifiedDataBreachProbabilityStillAtRisk(parsedModel, dataAsset) {
		case types.Probable:
			colorHighRisk(r.pdf)
		case types.Possible:
			colorMediumRisk(r.pdf)
		case types.Improbable:
			colorLowRisk(r.pdf)
		default:
			r.pdfColorBlack()
		}
		if !isDataBreachPotentialStillAtRisk(parsedModel, dataAsset) {
			r.pdfColorBlack()
		}
		risksStr := parsedModel.IdentifiedDataBreachProbabilityRisks(dataAsset)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		title := uni(dataAsset.Title) + ": " + suffix
		r.addHeadline(title, true)
		r.defineLinkTarget("{data:" + dataAsset.Id + "}")
		r.pdfColorBlack()
		html.Write(5, uni(dataAsset.Description))
		html.Write(5, "<br><br>")

		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "ID:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, dataAsset.Id, "0", "0", false)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Usage:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, dataAsset.Usage.String(), "0", "0", false)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Quantity:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, dataAsset.Quantity.String(), "0", "0", false)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Tags:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		tagsUsedText := ""
		sorted := dataAsset.Tags
		sort.Strings(sorted)
		for _, tag := range sorted {
			if len(tagsUsedText) > 0 {
				tagsUsedText += ", "
			}
			tagsUsedText += tag
		}
		if len(tagsUsedText) == 0 {
			r.pdfColorGray()
			tagsUsedText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(tagsUsedText), "0", "0", false)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Origin:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, uni(dataAsset.Origin), "0", "0", false)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Owner:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, uni(dataAsset.Owner), "0", "0", false)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Confidentiality:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.CellFormat(40, 6, dataAsset.Confidentiality.String(), "0", 0, "", false, 0, "")
		r.pdfColorGray()
		r.pdf.CellFormat(115, 6, dataAsset.Confidentiality.RatingStringInScale(), "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Integrity:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.CellFormat(40, 6, dataAsset.Integrity.String(), "0", 0, "", false, 0, "")
		r.pdfColorGray()
		r.pdf.CellFormat(115, 6, dataAsset.Integrity.RatingStringInScale(), "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Availability:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.CellFormat(40, 6, dataAsset.Availability.String(), "0", 0, "", false, 0, "")
		r.pdfColorGray()
		r.pdf.CellFormat(115, 6, dataAsset.Availability.RatingStringInScale(), "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.Ln(-1)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "CIA-Justification:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, uni(dataAsset.JustificationCiaRating), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Processed by:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		processedByText := ""
		for _, dataAsset := range parsedModel.ProcessedByTechnicalAssetsSorted(dataAsset) {
			if len(processedByText) > 0 {
				processedByText += ", "
			}
			processedByText += dataAsset.Title // TODO add link to technical asset detail chapter and back
		}
		if len(processedByText) == 0 {
			r.pdfColorGray()
			processedByText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(processedByText), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Stored by:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		storedByText := ""
		for _, dataAsset := range parsedModel.StoredByTechnicalAssetsSorted(dataAsset) {
			if len(storedByText) > 0 {
				storedByText += ", "
			}
			storedByText += dataAsset.Title // TODO add link to technical asset detail chapter and back
		}
		if len(storedByText) == 0 {
			r.pdfColorGray()
			storedByText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(storedByText), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Sent via:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		sentViaText := ""
		for _, commLink := range parsedModel.SentViaCommLinksSorted(dataAsset) {
			if len(sentViaText) > 0 {
				sentViaText += ", "
			}
			sentViaText += commLink.Title // TODO add link to technical asset detail chapter and back
		}
		if len(sentViaText) == 0 {
			r.pdfColorGray()
			sentViaText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(sentViaText), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Received via:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		receivedViaText := ""
		for _, commLink := range parsedModel.ReceivedViaCommLinksSorted(dataAsset) {
			if len(receivedViaText) > 0 {
				receivedViaText += ", "
			}
			receivedViaText += commLink.Title // TODO add link to technical asset detail chapter and back
		}
		if len(receivedViaText) == 0 {
			r.pdfColorGray()
			receivedViaText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(receivedViaText), "0", "0", false)

		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Data Breach:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		dataBreachProbability := identifiedDataBreachProbabilityStillAtRisk(parsedModel, dataAsset)
		riskText := dataBreachProbability.String()
		switch dataBreachProbability {
		case types.Probable:
			colorHighRisk(r.pdf)
		case types.Possible:
			colorMediumRisk(r.pdf)
		case types.Improbable:
			colorLowRisk(r.pdf)
		default:
			r.pdfColorBlack()
		}
		if !isDataBreachPotentialStillAtRisk(parsedModel, dataAsset) {
			r.pdfColorBlack()
			riskText = "none"
		}
		r.pdf.MultiCell(145, 6, riskText, "0", "0", false)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}

		// how can is this data asset be indirectly lost (i.e. why)
		dataBreachRisksStillAtRisk := identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel, dataAsset)
		sortByDataBreachProbability(dataBreachRisksStillAtRisk, parsedModel)
		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Data Breach Risks:", "0", 0, "", false, 0, "")
		if len(dataBreachRisksStillAtRisk) == 0 {
			r.pdfColorGray()
			r.pdf.MultiCell(145, 6, "This data asset has no data breach potential.", "0", "0", false)
		} else {
			r.pdfColorBlack()
			riskRemainingStr := "risks"
			if countStillAtRisk == 1 {
				riskRemainingStr = "risk"
			}
			r.pdf.MultiCell(145, 6, "This data asset has data breach potential because of "+
				""+strconv.Itoa(countStillAtRisk)+" remaining "+riskRemainingStr+":", "0", "0", false)
			for _, dataBreachRisk := range dataBreachRisksStillAtRisk {
				if r.pdf.GetY() > 280 { // 280 as only small font here
					r.pageBreak()
					r.pdf.SetY(36)
				}
				switch dataBreachRisk.DataBreachProbability {
				case types.Probable:
					colorHighRisk(r.pdf)
				case types.Possible:
					colorMediumRisk(r.pdf)
				case types.Improbable:
					colorLowRisk(r.pdf)
				default:
					r.pdfColorBlack()
				}
				if !dataBreachRisk.RiskStatus.IsStillAtRisk() {
					r.pdfColorBlack()
				}
				r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
				posY := r.pdf.GetY()
				r.pdf.SetFont("Helvetica", "", fontSizeVerySmall)
				r.pdf.MultiCell(185, 5, dataBreachRisk.DataBreachProbability.Title()+": "+uni(dataBreachRisk.SyntheticId), "0", "0", false)
				r.pdf.SetFont("Helvetica", "", fontSizeBody)
				r.pdf.Link(20, posY, 180, r.pdf.GetY()-posY, r.tocLinkIdByAssetId[dataBreachRisk.CategoryId])
			}
			r.pdfColorBlack()
		}
	}
}

func sortByDataBreachProbability(risks []*types.Risk, parsedModel *types.Model) {
	sort.Slice(risks, func(i, j int) bool {

		if risks[i].DataBreachProbability == risks[j].DataBreachProbability {
			trackingStatusLeft := risks[i].RiskStatus
			trackingStatusRight := risks[j].RiskStatus
			if trackingStatusLeft == trackingStatusRight {
				return risks[i].Title < risks[j].Title
			} else {
				return trackingStatusLeft < trackingStatusRight
			}
		}
		return risks[i].DataBreachProbability > risks[j].DataBreachProbability
	})
}

func identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel *types.Model, dataAsset *types.DataAsset) []*types.Risk {
	result := make([]*types.Risk, 0)
	for _, risk := range filteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, dataAsset.Id) {
				result = append(result, risk)
				break
			}
		}
	}
	return result
}

func isDataBreachPotentialStillAtRisk(parsedModel *types.Model, dataAsset *types.DataAsset) bool {
	for _, risk := range filteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, dataAsset.Id) {
				return true
			}
		}
	}
	return false
}

func (r *pdfReporter) createTrustBoundaries(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	title := "Trust Boundaries"
	r.pdfColorBlack()
	r.addHeadline(title, false)

	html := r.pdf.HTMLBasicNew()
	word := "has"
	if len(parsedModel.TrustBoundaries) > 1 {
		word = "have"
	}
	html.Write(5, "In total <b>"+strconv.Itoa(len(parsedModel.TrustBoundaries))+" trust boundaries</b> "+word+" been "+
		"modeled during the threat modeling process.")
	r.currentChapterTitleBreadcrumb = title
	for _, trustBoundary := range sortedTrustBoundariesByTitle(parsedModel) {
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		colorTwilight(r.pdf)
		if !trustBoundary.Type.IsNetworkBoundary() {
			r.pdfColorLightGray()
		}
		html.Write(5, "<b>"+uni(trustBoundary.Title)+"</b><br>")
		r.defineLinkTarget("{boundary:" + trustBoundary.Id + "}")
		html.Write(5, uni(trustBoundary.Description))
		html.Write(5, "<br><br>")

		r.pdf.SetFont("Helvetica", "", fontSizeBody)

		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "ID:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, trustBoundary.Id, "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Type:", "0", 0, "", false, 0, "")
		colorTwilight(r.pdf)
		if !trustBoundary.Type.IsNetworkBoundary() {
			r.pdfColorLightGray()
		}
		r.pdf.MultiCell(145, 6, trustBoundary.Type.String(), "0", "0", false)
		r.pdfColorBlack()

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Tags:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		tagsUsedText := ""
		sorted := trustBoundary.Tags
		sort.Strings(sorted)
		for _, tag := range sorted {
			if len(tagsUsedText) > 0 {
				tagsUsedText += ", "
			}
			tagsUsedText += tag
		}
		if len(tagsUsedText) == 0 {
			r.pdfColorGray()
			tagsUsedText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(tagsUsedText), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Assets inside:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		assetsInsideText := ""
		for _, assetKey := range trustBoundary.TechnicalAssetsInside {
			if len(assetsInsideText) > 0 {
				assetsInsideText += ", "
			}
			assetsInsideText += parsedModel.TechnicalAssets[assetKey].Title // TODO add link to technical asset detail chapter and back
		}
		if len(assetsInsideText) == 0 {
			r.pdfColorGray()
			assetsInsideText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(assetsInsideText), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Boundaries nested:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		boundariesNestedText := ""
		for _, assetKey := range trustBoundary.TrustBoundariesNested {
			if len(boundariesNestedText) > 0 {
				boundariesNestedText += ", "
			}
			boundariesNestedText += parsedModel.TrustBoundaries[assetKey].Title
		}
		if len(boundariesNestedText) == 0 {
			r.pdfColorGray()
			boundariesNestedText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(boundariesNestedText), "0", "0", false)
	}
}

func questionsUnanswered(parsedModel *types.Model) int {
	result := 0
	for _, answer := range parsedModel.Questions {
		if len(strings.TrimSpace(answer)) == 0 {
			result++
		}
	}
	return result
}

func (r *pdfReporter) createSharedRuntimes(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	title := "Shared Runtimes"
	r.pdfColorBlack()
	r.addHeadline(title, false)

	html := r.pdf.HTMLBasicNew()
	word, runtime := "has", "runtime"
	if len(parsedModel.SharedRuntimes) > 1 {
		word, runtime = "have", "runtimes"
	}
	html.Write(5, "In total <b>"+strconv.Itoa(len(parsedModel.SharedRuntimes))+" shared "+runtime+"</b> "+word+" been "+
		"modeled during the threat modeling process.")
	r.currentChapterTitleBreadcrumb = title
	for _, sharedRuntime := range sortedSharedRuntimesByTitle(parsedModel) {
		r.pdfColorBlack()
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		html.Write(5, "<b>"+uni(sharedRuntime.Title)+"</b><br>")
		r.defineLinkTarget("{runtime:" + sharedRuntime.Id + "}")
		html.Write(5, uni(sharedRuntime.Description))
		html.Write(5, "<br><br>")

		r.pdf.SetFont("Helvetica", "", fontSizeBody)

		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "ID:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(145, 6, sharedRuntime.Id, "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Tags:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		tagsUsedText := ""
		sorted := sharedRuntime.Tags
		sort.Strings(sorted)
		for _, tag := range sorted {
			if len(tagsUsedText) > 0 {
				tagsUsedText += ", "
			}
			tagsUsedText += tag
		}
		if len(tagsUsedText) == 0 {
			r.pdfColorGray()
			tagsUsedText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(tagsUsedText), "0", "0", false)

		if r.pdf.GetY() > 265 {
			r.pageBreak()
			r.pdf.SetY(36)
		}
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Assets running:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		assetsInsideText := ""
		for _, assetKey := range sharedRuntime.TechnicalAssetsRunning {
			if len(assetsInsideText) > 0 {
				assetsInsideText += ", "
			}
			assetsInsideText += parsedModel.TechnicalAssets[assetKey].Title // TODO add link to technical asset detail chapter and back
		}
		if len(assetsInsideText) == 0 {
			r.pdfColorGray()
			assetsInsideText = "none"
		}
		r.pdf.MultiCell(145, 6, uni(assetsInsideText), "0", "0", false)
	}
}

func (r *pdfReporter) createRiskRulesChecked(parsedModel *types.Model, modelFilename string, skipRiskRules []string, buildTimestamp string, threagileVersion string, modelHash string, customRiskRules types.RiskRules) {
	r.pdf.SetTextColor(0, 0, 0)
	title := "Risk Rules Checked by Threagile"
	r.addHeadline(title, false)
	r.defineLinkTarget("{risk-rules-checked}")
	r.currentChapterTitleBreadcrumb = title

	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	r.pdfColorGray()
	r.pdf.SetFont("Helvetica", "", fontSizeSmall)
	timestamp := time.Now()
	strBuilder.WriteString("<b>Threagile Version:</b> " + threagileVersion)
	strBuilder.WriteString("<br><b>Threagile Build Timestamp:</b> " + buildTimestamp)
	strBuilder.WriteString("<br><b>Threagile Execution Timestamp:</b> " + timestamp.Format("20060102150405"))
	strBuilder.WriteString("<br><b>Model Filename:</b> " + modelFilename)
	strBuilder.WriteString("<br><b>Model Hash (SHA256):</b> " + modelHash)
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	r.pdfColorBlack()
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	strBuilder.WriteString("<br><br>Threagile (see <a href=\"https://threagile.io\">https://threagile.io</a> for more details) is an open-source toolkit for agile threat modeling, created by Christian Schneider (<a href=\"https://christian-schneider.net\">https://christian-schneider.net</a>): It allows to model an architecture with its assets in an agile fashion as a YAML file " +
		"directly inside the IDE. Upon execution of the Threagile toolkit all standard risk rules (as well as individual custom rules if present) " +
		"are checked against the architecture model. At the time the Threagile toolkit was executed on the model input file " +
		"the following risk rules were checked:")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()

	// TODO use the new run system to discover risk rules instead of hard-coding them here:
	skipped := ""
	r.pdf.Ln(-1)

	for id, customRule := range customRiskRules {
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		if contains(skipRiskRules, id) {
			skipped = "SKIPPED - "
		} else {
			skipped = ""
		}
		r.pdf.CellFormat(190, 3, skipped+customRule.Category().Title, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeSmall)
		r.pdf.CellFormat(190, 6, id, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "I", fontSizeBody)
		r.pdf.CellFormat(190, 6, "Custom Risk Rule", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, customRule.Category().STRIDE.Title(), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, firstParagraph(customRule.Category().Description), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, customRule.Category().DetectionLogic, "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, customRule.Category().RiskAssessment, "0", "0", false)
	}

	sort.Sort(types.ByRiskCategoryTitleSort(parsedModel.CustomRiskCategories))
	for _, individualRiskCategory := range parsedModel.CustomRiskCategories {
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.CellFormat(190, 3, individualRiskCategory.Title, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeSmall)
		r.pdf.CellFormat(190, 6, individualRiskCategory.ID, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "I", fontSizeBody)
		r.pdf.CellFormat(190, 6, "Individual Risk category", "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, individualRiskCategory.STRIDE.Title(), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, firstParagraph(individualRiskCategory.Description), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, individualRiskCategory.DetectionLogic, "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, individualRiskCategory.RiskAssessment, "0", "0", false)
	}

	for _, rule := range r.riskRules {
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		if contains(skipRiskRules, rule.Category().ID) {
			skipped = "SKIPPED - "
		} else {
			skipped = ""
		}
		r.pdf.CellFormat(190, 3, skipped+rule.Category().Title, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeSmall)
		r.pdf.CellFormat(190, 6, rule.Category().ID, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, rule.Category().STRIDE.Title(), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, firstParagraph(rule.Category().Description), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, rule.Category().DetectionLogic, "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, rule.Category().RiskAssessment, "0", "0", false)
	}
}

func (r *pdfReporter) createTargetDescription(parsedModel *types.Model, baseFolder string) error {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	title := "Application Overview"
	r.addHeadline(title, false)
	r.defineLinkTarget("{target-overview}")
	r.currentChapterTitleBreadcrumb = title

	var intro strings.Builder
	html := r.pdf.HTMLBasicNew()

	intro.WriteString("<b>Business Criticality</b><br><br>")
	intro.WriteString("The overall business criticality of \"" + uni(parsedModel.Title) + "\" was rated as:<br><br>")
	html.Write(5, intro.String())
	criticality := parsedModel.BusinessCriticality
	intro.Reset()
	r.pdfColorGray()
	intro.WriteString("(  ")
	if criticality == types.Archive {
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.Archive.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorGray()
	} else {
		intro.WriteString(types.Archive.String())
	}
	intro.WriteString("  |  ")
	if criticality == types.Operational {
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.Operational.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorGray()
	} else {
		intro.WriteString(types.Operational.String())
	}
	intro.WriteString("  |  ")
	if criticality == types.Important {
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.Important.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorGray()
	} else {
		intro.WriteString(types.Important.String())
	}
	intro.WriteString("  |  ")
	if criticality == types.Critical {
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.Critical.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorGray()
	} else {
		intro.WriteString(types.Critical.String())
	}
	intro.WriteString("  |  ")
	if criticality == types.MissionCritical {
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.MissionCritical.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		r.pdfColorGray()
	} else {
		intro.WriteString(types.MissionCritical.String())
	}
	intro.WriteString("  )")
	html.Write(5, intro.String())
	intro.Reset()
	r.pdfColorBlack()

	intro.WriteString("<br><br><br><b>Business Overview</b><br><br>")
	intro.WriteString(uni(parsedModel.BusinessOverview.Description))
	html.Write(5, intro.String())
	intro.Reset()
	err := r.addCustomImages(parsedModel.BusinessOverview.Images, baseFolder, html)
	if err != nil {
		return fmt.Errorf("error adding custom images: %w", err)
	}

	intro.WriteString("<br><br><br><b>Technical Overview</b><br><br>")
	intro.WriteString(uni(parsedModel.TechnicalOverview.Description))
	html.Write(5, intro.String())
	intro.Reset()
	err = r.addCustomImages(parsedModel.TechnicalOverview.Images, baseFolder, html)
	if err != nil {
		return fmt.Errorf("error adding custom images: %w", err)
	}
	return nil
}

func (r *pdfReporter) addCustomImages(customImages []map[string]string, baseFolder string, html gofpdf.HTMLBasicType) error {
	var text strings.Builder
	for _, customImage := range customImages {
		for imageFilename := range customImage {
			imageFilenameWithoutPath := filepath.Base(imageFilename)
			// check JPEG, PNG or GIF
			extension := strings.ToLower(filepath.Ext(imageFilenameWithoutPath))
			if extension == ".jpeg" || extension == ".jpg" || extension == ".png" || extension == ".gif" {
				imageFullFilename := filepath.Join(baseFolder, imageFilenameWithoutPath)
				heightWhenWidthIsFix, err := getHeightWhenWidthIsFix(imageFullFilename, 180)
				if err != nil {
					return fmt.Errorf("error getting height of image file: %w", err)
				}
				if r.pdf.GetY()+heightWhenWidthIsFix > 250 {
					r.pageBreak()
					r.pdf.SetY(36)
				} else {
					text.WriteString("<br><br>")
				}
				text.WriteString(customImage[imageFilename] + ":<br><br>")
				html.Write(5, text.String())
				text.Reset()

				var options gofpdf.ImageOptions
				options.ImageType = ""
				r.pdf.RegisterImage(imageFullFilename, "")
				r.pdf.ImageOptions(imageFullFilename, 15, r.pdf.GetY()+50, 170, 0, true, options, 0, "")
			} else {
				log.Print("Ignoring custom image file: ", imageFilenameWithoutPath)
			}
		}
	}
	return nil
}

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func getHeightWhenWidthIsFix(imageFullFilename string, width float64) (float64, error) {
	if !fileExists(imageFullFilename) {
		return 0, fmt.Errorf("image file does not exist (or is not readable as file): %s", filepath.Base(imageFullFilename))
	}
	/* #nosec imageFullFilename is not tainted (see caller restricting it to image files of model folder only) */
	file, err := os.Open(imageFullFilename)
	defer func() { _ = file.Close() }()
	if err != nil {
		return 0, fmt.Errorf("error opening image file: %w", err)
	}
	img, _, err := image.DecodeConfig(file)
	if err != nil {
		return 0, fmt.Errorf("error decoding image file: %w", err)
	}
	return float64(img.Height) / (float64(img.Width) / width), nil
}

func (r *pdfReporter) embedDataFlowDiagram(diagramFilenamePNG string, tempFolder string) {
	r.pdf.SetTextColor(0, 0, 0)
	title := "Data-Flow Diagram"
	r.addHeadline(title, false)
	r.defineLinkTarget("{data-flow-diagram}")
	r.currentChapterTitleBreadcrumb = title

	var intro strings.Builder
	intro.WriteString("The following diagram was generated by Threagile based on the model input and gives a high-level " +
		"overview of the data-flow between technical assets. " +
		"The RAA value is the calculated <i>Relative Attacker Attractiveness</i> in percent. " +
		"For a full high-resolution version of this diagram please refer to the PNG image file alongside this report.")

	html := r.pdf.HTMLBasicNew()
	html.Write(5, intro.String())

	// check to rotate the image if it is wider than high
	/* #nosec diagramFilenamePNG is not tainted */
	imagePath, _ := os.Open(diagramFilenamePNG)
	defer func() { _ = imagePath.Close() }()
	srcImage, _, _ := image.Decode(imagePath)
	srcDimensions := srcImage.Bounds()
	// wider than high?
	muchWiderThanHigh := srcDimensions.Dx() > int(float64(srcDimensions.Dy())*1.25)
	// fresh page (eventually landscape)?
	r.isLandscapePage = false
	_ = tempFolder
	/*
		pinnedWidth, pinnedHeight := 190.0, 210.0
		if dataFlowDiagramFullscreen {
			pinnedHeight = 235.0
			if muchWiderThanHigh {
				if allowedPdfLandscapePages {
					pinnedWidth = 275.0
					isLandscapePage = true
					r.pdf.AddPageFormat("L", r.pdf.GetPageSizeStr("A4"))
				} else {
					// so rotate the image left by 90 degrees
				// ok, use temp PNG then
				// now rotate left by 90 degrees
				rotatedFile, err := os.CreateTemp(tempFolder, "diagram-*-.png")
				checkErr(err)
				defer os.Remove(rotatedFile.Title())
				dstImage := image.NewRGBA(image.Rect(0, 0, srcDimensions.Dy(), srcDimensions.Dx()))
				err = graphics.Rotate(dstImage, srcImage, &graphics.RotateOptions{-1 * math.Pi / 2.0})
				checkErr(err)
				newImage, _ := os.Create(rotatedFile.Title())
					defer newImage.Close()
					err = png.Encode(newImage, dstImage)
					checkErr(err)
					diagramFilenamePNG = rotatedFile.Title()
				}
			} else {
				r.pdf.AddPage()
			}
		} else {
			r.pdf.Ln(10)
		}*/
	// embed in PDF
	var options gofpdf.ImageOptions
	options.ImageType = ""
	r.pdf.RegisterImage(diagramFilenamePNG, "")
	var maxWidth, maxHeight, newWidth int
	var embedWidth, embedHeight float64
	if allowedPdfLandscapePages && muchWiderThanHigh {
		maxWidth, maxHeight = 275, 150
		r.isLandscapePage = true
		r.pdf.AddPageFormat("L", r.pdf.GetPageSizeStr("A4"))
	} else {
		r.pdf.Ln(10)
		maxWidth, maxHeight = 190, 200 // reduced height as a text paragraph is above
	}
	newWidth = srcDimensions.Dx() / (srcDimensions.Dy() / maxHeight)
	if newWidth <= maxWidth {
		embedWidth, embedHeight = 0, float64(maxHeight)
	} else {
		embedWidth, embedHeight = float64(maxWidth), 0
	}
	r.pdf.ImageOptions(diagramFilenamePNG, 10, r.pdf.GetY(), embedWidth, embedHeight, true, options, 0, "")
	r.isLandscapePage = false

	// add diagram legend page
	if embedDiagramLegendPage {
		r.pdf.AddPage()
		gofpdi.UseImportedTemplate(r.pdf, r.diagramLegendTemplateId, 0, 0, 0, 300)
	}
}

func (r *pdfReporter) embedDataRiskMapping(diagramFilenamePNG string, tempFolder string) {
	r.pdf.SetTextColor(0, 0, 0)
	title := "Data Mapping"
	r.addHeadline(title, false)
	r.defineLinkTarget("{data-risk-mapping}")
	r.currentChapterTitleBreadcrumb = title

	var intro strings.Builder
	intro.WriteString("The following diagram was generated by Threagile based on the model input and gives a high-level " +
		"distribution of data assets across technical assets. The color matches the identified data breach probability and risk level " +
		"(see the \"Data Breach Probabilities\" chapter for more details). " +
		"A solid line stands for <i>data is stored by the asset</i> and a dashed one means " +
		"<i>data is processed by the asset</i>. For a full high-resolution version of this diagram please refer to the PNG image " +
		"file alongside this report.")

	html := r.pdf.HTMLBasicNew()
	html.Write(5, intro.String())

	// TODO dedupe with code from other diagram embedding (almost same code)
	// check to rotate the image if it is wider than high
	/* #nosec diagramFilenamePNG is not tainted */
	imagePath, _ := os.Open(diagramFilenamePNG)
	defer func() { _ = imagePath.Close() }()
	srcImage, _, _ := image.Decode(imagePath)
	srcDimensions := srcImage.Bounds()
	// wider than high?
	widerThanHigh := srcDimensions.Dx() > srcDimensions.Dy()
	pinnedWidth, pinnedHeight := 190.0, 195.0
	// fresh page (eventually landscape)?
	r.isLandscapePage = false
	_ = tempFolder
	/*
		if dataFlowDiagramFullscreen {
			pinnedHeight = 235.0
			if widerThanHigh {
				if allowedPdfLandscapePages {
					pinnedWidth = 275.0
					isLandscapePage = true
					r.pdf.AddPageFormat("L", r.pdf.GetPageSizeStr("A4"))
				} else {
					// so rotate the image left by 90 degrees
					// ok, use temp PNG then
				// now rotate left by 90 degrees
				rotatedFile, err := os.CreateTemp(tempFolder, "diagram-*-.png")
				checkErr(err)
				defer os.Remove(rotatedFile.Title())
				dstImage := image.NewRGBA(image.Rect(0, 0, srcDimensions.Dy(), srcDimensions.Dx()))
				err = graphics.Rotate(dstImage, srcImage, &graphics.RotateOptions{-1 * math.Pi / 2.0})
				checkErr(err)
				newImage, _ := os.Create(rotatedFile.Title())
				defer newImage.Close()
					err = png.Encode(newImage, dstImage)
					checkErr(err)
					diagramFilenamePNG = rotatedFile.Title()
				}
			} else {
				r.pdf.AddPage()
			}
		} else {
			r.pdf.Ln(10)
		}
	*/
	// embed in PDF
	r.pdf.Ln(10)
	var options gofpdf.ImageOptions
	options.ImageType = ""
	r.pdf.RegisterImage(diagramFilenamePNG, "")
	if widerThanHigh {
		pinnedHeight = 0
	} else {
		pinnedWidth = 0
	}
	r.pdf.ImageOptions(diagramFilenamePNG, 10, r.pdf.GetY(), pinnedWidth, pinnedHeight, true, options, 0, "")
	r.isLandscapePage = false
}

func (r *pdfReporter) writeReportToFile(reportFilename string) error {
	err := r.pdf.OutputFileAndClose(reportFilename)
	if err != nil {
		return fmt.Errorf("error writing PDF report file: %w", err)
	}
	return nil
}

func (r *pdfReporter) addHeadline(headline string, small bool) {
	r.pdf.AddPage()
	gofpdi.UseImportedTemplate(r.pdf, r.contentTemplateId, 0, 0, 0, 300)
	fontSize := fontSizeHeadline
	if small {
		fontSize = fontSizeHeadlineSmall
	}
	r.pdf.SetFont("Helvetica", "B", float64(fontSize))
	r.pdf.Text(11, 40, headline)
	r.pdf.SetFont("Helvetica", "", fontSizeBody)
	r.pdf.SetX(17)
	r.pdf.SetY(46)
}

func (r *pdfReporter) pageBreak() {
	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
	r.pdf.AddPage()
	gofpdi.UseImportedTemplate(r.pdf, r.contentTemplateId, 0, 0, 0, 300)
	r.pdf.SetX(17)
	r.pdf.SetY(20)
}

func (r *pdfReporter) pageBreakInLists() {
	r.pageBreak()
	r.pdf.SetLineWidth(0.25)
	r.pdf.SetDrawColor(160, 160, 160)
	r.pdf.SetDashPattern([]float64{0.5, 0.5}, 0)
}

func (r *pdfReporter) pdfColorDisclaimer() {
	r.pdf.SetTextColor(140, 140, 140)
}

func (r *pdfReporter) pdfColorOutOfScope() {
	r.pdf.SetTextColor(127, 127, 127)
}

func (r *pdfReporter) pdfColorGray() {
	r.pdf.SetTextColor(80, 80, 80)
}

func (r *pdfReporter) pdfColorLightGray() {
	r.pdf.SetTextColor(100, 100, 100)
}

func (r *pdfReporter) pdfColorBlack() {
	r.pdf.SetTextColor(0, 0, 0)
}
