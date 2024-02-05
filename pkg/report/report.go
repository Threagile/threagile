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
	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/security/risks"
	"github.com/threagile/threagile/pkg/security/types"
	"github.com/wcharczuk/go-chart"
	"github.com/wcharczuk/go-chart/drawing"
)

const fontSizeHeadline, fontSizeHeadlineSmall, fontSizeBody, fontSizeSmall, fontSizeVerySmall = 20, 16, 12, 9, 7
const /*dataFlowDiagramFullscreen,*/ allowedPdfLandscapePages, embedDiagramLegendPage = /*false,*/ true, false

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
	skipRiskRules string,
	buildTimestamp string,
	modelHash string,
	introTextRAA string,
	customRiskRules map[string]*model.CustomRisk,
	tempFolder string,
	model *types.ParsedModel) error {
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
	r.createRiskRulesChecked(model, modelFilename, skipRiskRules, buildTimestamp, modelHash, customRiskRules)
	r.createDisclaimer(model)
	err = r.writeReportToFile(reportFilename)
	if err != nil {
		return fmt.Errorf("error writing report to file: %w", err)
	}
	return nil
}

func (r *pdfReporter) createPdfAndInitMetadata(model *types.ParsedModel) {
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

func (r *pdfReporter) addBreadcrumb(parsedModel *types.ParsedModel) {
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
		defer os.Remove(file.Name())
		backgroundBytes := imageBox.MustBytes("background.r.pdf")
		err = os.WriteFile(file.Name(), backgroundBytes, 0644)
		checkErr(err)
	*/
	r.coverTemplateId = gofpdi.ImportPage(r.pdf, templateFilename, 1, "/MediaBox")
	r.contentTemplateId = gofpdi.ImportPage(r.pdf, templateFilename, 2, "/MediaBox")
	r.diagramLegendTemplateId = gofpdi.ImportPage(r.pdf, templateFilename, 3, "/MediaBox")
}

func (r *pdfReporter) createCover(parsedModel *types.ParsedModel) {
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

func (r *pdfReporter) createTableOfContents(parsedModel *types.ParsedModel) {
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
	count, catCount := types.TotalRiskCount(parsedModel), len(parsedModel.GeneratedRisksByCategory)
	if count == 1 {
		risksStr = "Risk"
	}
	if catCount == 1 {
		catStr = "Category"
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
	risksStr = "Risks"
	catStr = "Categories"
	count, catCount = len(types.FilteredByStillAtRisk(parsedModel)), len(types.CategoriesOfOnlyRisksStillAtRisk(parsedModel, parsedModel.GeneratedRisksByCategory))
	if count == 1 {
		risksStr = "Risk"
	}
	if catCount == 1 {
		catStr = "Category"
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
	modelFailures := types.FlattenRiskSlice(types.FilterByModelFailures(parsedModel, parsedModel.GeneratedRisksByCategory))
	risksStr = "Risks"
	count = len(modelFailures)
	if count == 1 {
		risksStr = "Risk"
	}
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, modelFailures))
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
		r.pdf.Text(11, y, "Risks by Vulnerability Category")
		r.pdf.SetFont("Helvetica", "", fontSizeBody)
		y += 6
		r.pdf.Text(11, y, "    "+"Identified Risks by Vulnerability Category")
		r.pdf.Text(175, y, "{intro-risks-by-vulnerability-category}")
		r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		r.pdf.Link(10, y-5, 172.5, 6.5, r.pdf.AddLink())
		for _, category := range types.SortedRiskCategories(parsedModel) {
			newRisksStr := types.SortedRisksOfCategory(parsedModel, category)
			switch types.HighestSeverityStillAtRisk(parsedModel, newRisksStr) {
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
			if len(types.ReduceToOnlyStillAtRisk(parsedModel, newRisksStr)) == 0 {
				r.pdfColorBlack()
			}
			y += 6
			if y > 275 {
				r.pageBreakInLists()
				y = 40
			}
			countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, newRisksStr))
			suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(newRisksStr)) + " Risk"
			if len(newRisksStr) != 1 {
				suffix += "s"
			}
			r.pdf.Text(11, y, "    "+uni(category.Title)+": "+suffix)
			r.pdf.Text(175, y, "{"+category.Id+"}")
			r.pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			r.tocLinkIdByAssetId[category.Id] = r.pdf.AddLink()
			r.pdf.Link(10, y-5, 172.5, 6.5, r.tocLinkIdByAssetId[category.Id])
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
			newRisksStr := technicalAsset.GeneratedRisks(parsedModel)
			y += 6
			if y > 275 {
				r.pageBreakInLists()
				y = 40
			}
			countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, newRisksStr))
			suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(newRisksStr)) + " Risk"
			if len(newRisksStr) != 1 {
				suffix += "s"
			}
			if technicalAsset.OutOfScope {
				r.pdfColorOutOfScope()
				suffix = "out-of-scope"
			} else {
				switch types.HighestSeverityStillAtRisk(parsedModel, newRisksStr) {
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
				if len(types.ReduceToOnlyStillAtRisk(parsedModel, newRisksStr)) == 0 {
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
			newRisksStr := dataAsset.IdentifiedDataBreachProbabilityRisks(parsedModel)
			countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, newRisksStr))
			suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(newRisksStr)) + " Risk"
			if len(newRisksStr) != 1 {
				suffix += "s"
			}
			switch dataAsset.IdentifiedDataBreachProbabilityStillAtRisk(parsedModel) {
			case types.Probable:
				colorHighRisk(r.pdf)
			case types.Possible:
				colorMediumRisk(r.pdf)
			case types.Improbable:
				colorLowRisk(r.pdf)
			default:
				r.pdfColorBlack()
			}
			if !dataAsset.IsDataBreachPotentialStillAtRisk(parsedModel) {
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
		for _, key := range types.SortedKeysOfTrustBoundaries(parsedModel) {
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
		for _, key := range types.SortedKeysOfSharedRuntime(parsedModel) {
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

func sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel *types.ParsedModel) []types.TechnicalAsset {
	assets := make([]types.TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		assets = append(assets, asset)
	}
	types.SortByTechnicalAssetRiskSeverityAndTitleStillAtRisk(assets, parsedModel)
	return assets
}

func sortedDataAssetsByDataBreachProbabilityAndTitle(parsedModel *types.ParsedModel) []types.DataAsset {
	assets := make([]types.DataAsset, 0)
	for _, asset := range parsedModel.DataAssets {
		assets = append(assets, asset)
	}

	types.SortByDataAssetDataBreachProbabilityAndTitleStillAtRisk(parsedModel, assets)
	return assets
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

func (r *pdfReporter) createDisclaimer(parsedModel *types.ParsedModel) {
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
	html.Write(5, disclaimer.String())
	r.pdfColorBlack()
}

func (r *pdfReporter) createManagementSummary(parsedModel *types.ParsedModel, tempFolder string) error {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	title := "Management Summary"
	r.addHeadline(title, false)
	r.defineLinkTarget("{management-summary}")
	r.currentChapterTitleBreadcrumb = title
	countCritical := len(types.FilteredByOnlyCriticalRisks(parsedModel))
	countHigh := len(types.FilteredByOnlyHighRisks(parsedModel))
	countElevated := len(types.FilteredByOnlyElevatedRisks(parsedModel))
	countMedium := len(types.FilteredByOnlyMediumRisks(parsedModel))
	countLow := len(types.FilteredByOnlyLowRisks(parsedModel))

	countStatusUnchecked := len(types.FilteredByRiskTrackingUnchecked(parsedModel))
	countStatusInDiscussion := len(types.FilteredByRiskTrackingInDiscussion(parsedModel))
	countStatusAccepted := len(types.FilteredByRiskTrackingAccepted(parsedModel))
	countStatusInProgress := len(types.FilteredByRiskTrackingInProgress(parsedModel))
	countStatusMitigated := len(types.FilteredByRiskTrackingMitigated(parsedModel))
	countStatusFalsePositive := len(types.FilteredByRiskTrackingFalsePositive(parsedModel))

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
		"In total <b>"+strconv.Itoa(types.TotalRiskCount(parsedModel))+" initial risks</b> in <b>"+strconv.Itoa(len(parsedModel.GeneratedRisksByCategory))+" categories</b> have "+
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

func (r *pdfReporter) createRiskMitigationStatus(parsedModel *types.ParsedModel, tempFolder string) error {
	r.pdf.SetTextColor(0, 0, 0)
	stillAtRisk := types.FilteredByStillAtRisk(parsedModel)
	count := len(stillAtRisk)
	title := "Risk Mitigation"
	r.addHeadline(title, false)
	r.defineLinkTarget("{risk-mitigation-status}")
	r.currentChapterTitleBreadcrumb = title

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "The following chart gives a high-level overview of the risk tracking status (including mitigated risks):")

	risksCritical := types.FilteredByOnlyCriticalRisks(parsedModel)
	risksHigh := types.FilteredByOnlyHighRisks(parsedModel)
	risksElevated := types.FilteredByOnlyElevatedRisks(parsedModel)
	risksMedium := types.FilteredByOnlyMediumRisks(parsedModel)
	risksLow := types.FilteredByOnlyLowRisks(parsedModel)

	countStatusUnchecked := len(types.FilteredByRiskTrackingUnchecked(parsedModel))
	countStatusInDiscussion := len(types.FilteredByRiskTrackingInDiscussion(parsedModel))
	countStatusAccepted := len(types.FilteredByRiskTrackingAccepted(parsedModel))
	countStatusInProgress := len(types.FilteredByRiskTrackingInProgress(parsedModel))
	countStatusMitigated := len(types.FilteredByRiskTrackingMitigated(parsedModel))
	countStatusFalsePositive := len(types.FilteredByRiskTrackingFalsePositive(parsedModel))

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
					{Value: float64(len(types.ReduceToOnlyRiskTrackingUnchecked(parsedModel, risksLow))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInDiscussion(parsedModel, risksLow))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingAccepted(parsedModel, risksLow))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInProgress(parsedModel, risksLow))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingMitigated(parsedModel, risksLow))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingFalsePositive(parsedModel, risksLow))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.MediumSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(types.ReduceToOnlyRiskTrackingUnchecked(parsedModel, risksMedium))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInDiscussion(parsedModel, risksMedium))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingAccepted(parsedModel, risksMedium))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInProgress(parsedModel, risksMedium))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingMitigated(parsedModel, risksMedium))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingFalsePositive(parsedModel, risksMedium))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.ElevatedSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(types.ReduceToOnlyRiskTrackingUnchecked(parsedModel, risksElevated))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInDiscussion(parsedModel, risksElevated))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingAccepted(parsedModel, risksElevated))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInProgress(parsedModel, risksElevated))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingMitigated(parsedModel, risksElevated))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingFalsePositive(parsedModel, risksElevated))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.HighSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(types.ReduceToOnlyRiskTrackingUnchecked(parsedModel, risksHigh))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInDiscussion(parsedModel, risksHigh))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingAccepted(parsedModel, risksHigh))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInProgress(parsedModel, risksHigh))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingMitigated(parsedModel, risksHigh))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingFalsePositive(parsedModel, risksHigh))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.CriticalSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(types.ReduceToOnlyRiskTrackingUnchecked(parsedModel, risksCritical))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInDiscussion(parsedModel, risksCritical))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingAccepted(parsedModel, risksCritical))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInProgress(parsedModel, risksCritical))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingMitigated(parsedModel, risksCritical))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(rgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingFalsePositive(parsedModel, risksCritical))), Label: types.FalsePositive.Title(),
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

		countCritical := len(types.ReduceToOnlyStillAtRisk(parsedModel, types.FilteredByOnlyCriticalRisks(parsedModel)))
		countHigh := len(types.ReduceToOnlyStillAtRisk(parsedModel, types.FilteredByOnlyHighRisks(parsedModel)))
		countElevated := len(types.ReduceToOnlyStillAtRisk(parsedModel, types.FilteredByOnlyElevatedRisks(parsedModel)))
		countMedium := len(types.ReduceToOnlyStillAtRisk(parsedModel, types.FilteredByOnlyMediumRisks(parsedModel)))
		countLow := len(types.ReduceToOnlyStillAtRisk(parsedModel, types.FilteredByOnlyLowRisks(parsedModel)))

		countBusinessSide := len(types.ReduceToOnlyStillAtRisk(parsedModel, types.FilteredByOnlyBusinessSide(parsedModel)))
		countArchitecture := len(types.ReduceToOnlyStillAtRisk(parsedModel, types.FilteredByOnlyArchitecture(parsedModel)))
		countDevelopment := len(types.ReduceToOnlyStillAtRisk(parsedModel, types.FilteredByOnlyDevelopment(parsedModel)))
		countOperation := len(types.ReduceToOnlyStillAtRisk(parsedModel, types.FilteredByOnlyOperation(parsedModel)))

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

func (r *pdfReporter) createImpactInitialRisks(parsedModel *types.ParsedModel) {
	r.renderImpactAnalysis(parsedModel, true)
}

func (r *pdfReporter) createImpactRemainingRisks(parsedModel *types.ParsedModel) {
	r.renderImpactAnalysis(parsedModel, false)
}

func (r *pdfReporter) renderImpactAnalysis(parsedModel *types.ParsedModel, initialRisks bool) {
	r.pdf.SetTextColor(0, 0, 0)
	count, catCount := types.TotalRiskCount(parsedModel), len(parsedModel.GeneratedRisksByCategory)
	if !initialRisks {
		count, catCount = len(types.FilteredByStillAtRisk(parsedModel)), len(types.CategoriesOfOnlyRisksStillAtRisk(parsedModel, parsedModel.GeneratedRisksByCategory))
	}
	riskStr, catStr := "Risks", "Categories"
	if count == 1 {
		riskStr = "Risk"
	}
	if catCount == 1 {
		catStr = "Category"
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

	r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, parsedModel.GeneratedRisksByCategory, initialRisks)),
		types.CriticalSeverity, false, initialRisks, true, false)
	r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, parsedModel.GeneratedRisksByCategory, initialRisks)),
		types.HighSeverity, false, initialRisks, true, false)
	r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, parsedModel.GeneratedRisksByCategory, initialRisks)),
		types.ElevatedSeverity, false, initialRisks, true, false)
	r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, parsedModel.GeneratedRisksByCategory, initialRisks)),
		types.MediumSeverity, false, initialRisks, true, false)
	r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, parsedModel.GeneratedRisksByCategory, initialRisks)),
		types.LowSeverity, false, initialRisks, true, false)

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func (r *pdfReporter) createOutOfScopeAssets(parsedModel *types.ParsedModel) {
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

func sortedTechnicalAssetsByRAAAndTitle(parsedModel *types.ParsedModel) []types.TechnicalAsset {
	assets := make([]types.TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		assets = append(assets, asset)
	}
	sort.Sort(types.ByTechnicalAssetRAAAndTitleSort(assets))
	return assets
}

func (r *pdfReporter) createModelFailures(parsedModel *types.ParsedModel) {
	r.pdf.SetTextColor(0, 0, 0)
	modelFailures := types.FlattenRiskSlice(types.FilterByModelFailures(parsedModel, parsedModel.GeneratedRisksByCategory))
	risksStr := "Risks"
	count := len(modelFailures)
	if count == 1 {
		risksStr = "Risk"
	}
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, modelFailures))
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

	modelFailuresByCategory := types.FilterByModelFailures(parsedModel, parsedModel.GeneratedRisksByCategory)
	if len(modelFailuresByCategory) == 0 {
		r.pdfColorGray()
		html.Write(5, "<br><br>No potential model failures have been identified.")
	} else {
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, modelFailuresByCategory, true)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, modelFailuresByCategory, true)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, modelFailuresByCategory, true)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, modelFailuresByCategory, true)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, modelFailuresByCategory, true)),
			types.LowSeverity, true, true, false, true)
	}

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func (r *pdfReporter) createRAA(parsedModel *types.ParsedModel, introTextRAA string) {
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
		newRisksStr := technicalAsset.GeneratedRisks(parsedModel)
		switch types.HighestSeverityStillAtRisk(parsedModel, newRisksStr) {
		case types.HighSeverity:
			colorHighRisk(r.pdf)
		case types.MediumSeverity:
			colorMediumRisk(r.pdf)
		case types.LowSeverity:
			colorLowRisk(r.pdf)
		default:
			r.pdfColorBlack()
		}
		if len(types.ReduceToOnlyStillAtRisk(parsedModel, newRisksStr)) == 0 {
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
		r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, tocLinkIdByAssetId[technicalAsset.Id])
	}

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}
*/

func (r *pdfReporter) addCategories(parsedModel *types.ParsedModel, riskCategories []types.RiskCategory, severity types.RiskSeverity, bothInitialAndRemainingRisks bool, initialRisks bool, describeImpact bool, describeDescription bool) {
	html := r.pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	sort.Sort(types.ByRiskCategoryTitleSort(riskCategories))
	for _, riskCategory := range riskCategories {
		risksStr := parsedModel.GeneratedRisksByCategory[riskCategory.Id]
		if !initialRisks {
			risksStr = types.ReduceToOnlyStillAtRisk(parsedModel, risksStr)
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
		switch types.HighestSeverityStillAtRisk(parsedModel, risksStr) {
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
		if len(types.ReduceToOnlyStillAtRisk(parsedModel, risksStr)) == 0 {
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
		remainingRisks := types.ReduceToOnlyStillAtRisk(parsedModel, risksStr)
		suffix := strconv.Itoa(count) + " " + initialStr + " Risk"
		if bothInitialAndRemainingRisks {
			suffix = strconv.Itoa(len(remainingRisks)) + " / " + strconv.Itoa(count) + " Risk"
		}
		if count != 1 {
			suffix += "s"
		}
		suffix += " - Exploitation likelihood is <i>"
		if initialRisks {
			suffix += types.HighestExploitationLikelihood(risksStr).Title() + "</i> with <i>" + types.HighestExploitationImpact(risksStr).Title() + "</i> impact."
		} else {
			suffix += types.HighestExploitationLikelihood(remainingRisks).Title() + "</i> with <i>" + types.HighestExploitationImpact(remainingRisks).Title() + "</i> impact."
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
		r.pdf.Link(9, posY, 190, r.pdf.GetY()-posY+4, r.tocLinkIdByAssetId[riskCategory.Id])
	}
}

func firstParagraph(text string) string {
	firstParagraphRegEx := regexp.MustCompile(`(.*?)((<br>)|(<p>))`)
	match := firstParagraphRegEx.FindStringSubmatch(text)
	if len(match) == 0 {
		return text
	}
	return match[1]
}

func (r *pdfReporter) createAssignmentByFunction(parsedModel *types.ParsedModel) {
	r.pdf.SetTextColor(0, 0, 0)
	title := "Assignment by Function"
	r.addHeadline(title, false)
	r.defineLinkTarget("{function-assignment}")
	r.currentChapterTitleBreadcrumb = title

	risksBusinessSideFunction := types.RisksOfOnlyBusinessSide(parsedModel, parsedModel.GeneratedRisksByCategory)
	risksArchitectureFunction := types.RisksOfOnlyArchitecture(parsedModel, parsedModel.GeneratedRisksByCategory)
	risksDevelopmentFunction := types.RisksOfOnlyDevelopment(parsedModel, parsedModel.GeneratedRisksByCategory)
	risksOperationFunction := types.RisksOfOnlyOperation(parsedModel, parsedModel.GeneratedRisksByCategory)

	countBusinessSideFunction := types.CountRisks(risksBusinessSideFunction)
	countArchitectureFunction := types.CountRisks(risksArchitectureFunction)
	countDevelopmentFunction := types.CountRisks(risksDevelopmentFunction)
	countOperationFunction := types.CountRisks(risksOperationFunction)
	var intro strings.Builder
	intro.WriteString("This chapter clusters and assigns the risks by functions which are most likely able to " +
		"check and mitigate them: " +
		"In total <b>" + strconv.Itoa(types.TotalRiskCount(parsedModel)) + " potential risks</b> have been identified during the threat modeling process " +
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
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksBusinessSideFunction, true)),
			types.CriticalSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksBusinessSideFunction, true)),
			types.HighSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksBusinessSideFunction, true)),
			types.ElevatedSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksBusinessSideFunction, true)),
			types.MediumSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksBusinessSideFunction, true)),
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
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksArchitectureFunction, true)),
			types.CriticalSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksArchitectureFunction, true)),
			types.HighSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksArchitectureFunction, true)),
			types.ElevatedSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksArchitectureFunction, true)),
			types.MediumSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksArchitectureFunction, true)),
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
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksDevelopmentFunction, true)),
			types.CriticalSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksDevelopmentFunction, true)),
			types.HighSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksDevelopmentFunction, true)),
			types.ElevatedSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksDevelopmentFunction, true)),
			types.MediumSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksDevelopmentFunction, true)),
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
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksOperationFunction, true)),
			types.CriticalSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksOperationFunction, true)),
			types.HighSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksOperationFunction, true)),
			types.ElevatedSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksOperationFunction, true)),
			types.MediumSeverity, true, true, false, false)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksOperationFunction, true)),
			types.LowSeverity, true, true, false, false)
	}
	r.pdf.SetLeftMargin(oldLeft)

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func (r *pdfReporter) createSTRIDE(parsedModel *types.ParsedModel) {
	r.pdf.SetTextColor(0, 0, 0)
	title := "STRIDE Classification of Identified Risks"
	r.addHeadline(title, false)
	r.defineLinkTarget("{stride}")
	r.currentChapterTitleBreadcrumb = title

	risksSTRIDESpoofing := types.RisksOfOnlySTRIDESpoofing(parsedModel, parsedModel.GeneratedRisksByCategory)
	risksSTRIDETampering := types.RisksOfOnlySTRIDETampering(parsedModel, parsedModel.GeneratedRisksByCategory)
	risksSTRIDERepudiation := types.RisksOfOnlySTRIDERepudiation(parsedModel, parsedModel.GeneratedRisksByCategory)
	risksSTRIDEInformationDisclosure := types.RisksOfOnlySTRIDEInformationDisclosure(parsedModel, parsedModel.GeneratedRisksByCategory)
	risksSTRIDEDenialOfService := types.RisksOfOnlySTRIDEDenialOfService(parsedModel, parsedModel.GeneratedRisksByCategory)
	risksSTRIDEElevationOfPrivilege := types.RisksOfOnlySTRIDEElevationOfPrivilege(parsedModel, parsedModel.GeneratedRisksByCategory)

	countSTRIDESpoofing := types.CountRisks(risksSTRIDESpoofing)
	countSTRIDETampering := types.CountRisks(risksSTRIDETampering)
	countSTRIDERepudiation := types.CountRisks(risksSTRIDERepudiation)
	countSTRIDEInformationDisclosure := types.CountRisks(risksSTRIDEInformationDisclosure)
	countSTRIDEDenialOfService := types.CountRisks(risksSTRIDEDenialOfService)
	countSTRIDEElevationOfPrivilege := types.CountRisks(risksSTRIDEElevationOfPrivilege)
	var intro strings.Builder
	intro.WriteString("This chapter clusters and classifies the risks by STRIDE categories: " +
		"In total <b>" + strconv.Itoa(types.TotalRiskCount(parsedModel)) + " potential risks</b> have been identified during the threat modeling process " +
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
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksSTRIDESpoofing, true)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksSTRIDESpoofing, true)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksSTRIDESpoofing, true)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksSTRIDESpoofing, true)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksSTRIDESpoofing, true)),
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
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksSTRIDETampering, true)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksSTRIDETampering, true)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksSTRIDETampering, true)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksSTRIDETampering, true)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksSTRIDETampering, true)),
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
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksSTRIDERepudiation, true)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksSTRIDERepudiation, true)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksSTRIDERepudiation, true)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksSTRIDERepudiation, true)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksSTRIDERepudiation, true)),
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
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksSTRIDEInformationDisclosure, true)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksSTRIDEInformationDisclosure, true)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksSTRIDEInformationDisclosure, true)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksSTRIDEInformationDisclosure, true)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksSTRIDEInformationDisclosure, true)),
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
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksSTRIDEDenialOfService, true)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksSTRIDEDenialOfService, true)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksSTRIDEDenialOfService, true)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksSTRIDEDenialOfService, true)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksSTRIDEDenialOfService, true)),
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
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksSTRIDEElevationOfPrivilege, true)),
			types.CriticalSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksSTRIDEElevationOfPrivilege, true)),
			types.HighSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksSTRIDEElevationOfPrivilege, true)),
			types.ElevatedSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksSTRIDEElevationOfPrivilege, true)),
			types.MediumSeverity, true, true, false, true)
		r.addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksSTRIDEElevationOfPrivilege, true)),
			types.LowSeverity, true, true, false, true)
	}
	r.pdf.SetLeftMargin(oldLeft)

	r.pdf.SetDrawColor(0, 0, 0)
	r.pdf.SetDashPattern([]float64{}, 0)
}

func (r *pdfReporter) createSecurityRequirements(parsedModel *types.ParsedModel) {
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

func sortedKeysOfSecurityRequirements(parsedModel *types.ParsedModel) []string {
	keys := make([]string, 0)
	for k := range parsedModel.SecurityRequirements {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *pdfReporter) createAbuseCases(parsedModel *types.ParsedModel) {
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

func sortedKeysOfAbuseCases(parsedModel *types.ParsedModel) []string {
	keys := make([]string, 0)
	for k := range parsedModel.AbuseCases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *pdfReporter) createQuestions(parsedModel *types.ParsedModel) {
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

func sortedKeysOfQuestions(parsedModel *types.ParsedModel) []string {
	keys := make([]string, 0)
	for k := range parsedModel.Questions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *pdfReporter) createTagListing(parsedModel *types.ParsedModel) {
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
			html.Write(5, "<b>"+tag+"</b><br>")
			html.Write(5, description)
		}
	}
}

func sortedSharedRuntimesByTitle(parsedModel *types.ParsedModel) []types.SharedRuntime {
	result := make([]types.SharedRuntime, 0)
	for _, runtime := range parsedModel.SharedRuntimes {
		result = append(result, runtime)
	}
	sort.Sort(types.BySharedRuntimeTitleSort(result))
	return result
}

func sortedTechnicalAssetsByTitle(parsedModel *types.ParsedModel) []types.TechnicalAsset {
	assets := make([]types.TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		assets = append(assets, asset)
	}
	sort.Sort(types.ByTechnicalAssetTitleSort(assets))
	return assets
}

func (r *pdfReporter) createRiskCategories(parsedModel *types.ParsedModel) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	// category title
	title := "Identified Risks by Vulnerability Category"
	r.pdfColorBlack()
	r.addHeadline(title, false)
	r.defineLinkTarget("{intro-risks-by-vulnerability-category}")
	html := r.pdf.HTMLBasicNew()
	var text strings.Builder
	text.WriteString("In total <b>" + strconv.Itoa(types.TotalRiskCount(parsedModel)) + " potential risks</b> have been identified during the threat modeling process " +
		"of which " +
		"<b>" + strconv.Itoa(len(types.FilteredByOnlyCriticalRisks(parsedModel))) + " are rated as critical</b>, " +
		"<b>" + strconv.Itoa(len(types.FilteredByOnlyHighRisks(parsedModel))) + " as high</b>, " +
		"<b>" + strconv.Itoa(len(types.FilteredByOnlyElevatedRisks(parsedModel))) + " as elevated</b>, " +
		"<b>" + strconv.Itoa(len(types.FilteredByOnlyMediumRisks(parsedModel))) + " as medium</b>, " +
		"and <b>" + strconv.Itoa(len(types.FilteredByOnlyLowRisks(parsedModel))) + " as low</b>. " +
		"<br><br>These risks are distributed across <b>" + strconv.Itoa(len(parsedModel.GeneratedRisksByCategory)) + " vulnerability categories</b>. ")
	text.WriteString("The following sub-chapters of this section describe each identified risk category.") // TODO more explanation text
	html.Write(5, text.String())
	text.Reset()
	r.currentChapterTitleBreadcrumb = title
	for _, category := range types.SortedRiskCategories(parsedModel) {
		risksStr := types.SortedRisksOfCategory(parsedModel, category)

		// category color
		switch types.HighestSeverityStillAtRisk(parsedModel, risksStr) {
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
		if len(types.ReduceToOnlyStillAtRisk(parsedModel, risksStr)) == 0 {
			r.pdfColorBlack()
		}

		// category title
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		title := category.Title + ": " + suffix
		r.addHeadline(uni(title), true)
		r.pdfColorBlack()
		r.defineLinkTarget("{" + category.Id + "}")
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
			if !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
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

func (r *pdfReporter) writeRiskTrackingStatus(parsedModel *types.ParsedModel, risk types.Risk) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	tracking := risk.GetRiskTracking(parsedModel)
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

func (r *pdfReporter) createTechnicalAssets(parsedModel *types.ParsedModel) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	// category title
	title := "Identified Risks by Technical Asset"
	r.pdfColorBlack()
	r.addHeadline(title, false)
	r.defineLinkTarget("{intro-risks-by-technical-asset}")
	html := r.pdf.HTMLBasicNew()
	var text strings.Builder
	text.WriteString("In total <b>" + strconv.Itoa(types.TotalRiskCount(parsedModel)) + " potential risks</b> have been identified during the threat modeling process " +
		"of which " +
		"<b>" + strconv.Itoa(len(types.FilteredByOnlyCriticalRisks(parsedModel))) + " are rated as critical</b>, " +
		"<b>" + strconv.Itoa(len(types.FilteredByOnlyHighRisks(parsedModel))) + " as high</b>, " +
		"<b>" + strconv.Itoa(len(types.FilteredByOnlyElevatedRisks(parsedModel))) + " as elevated</b>, " +
		"<b>" + strconv.Itoa(len(types.FilteredByOnlyMediumRisks(parsedModel))) + " as medium</b>, " +
		"and <b>" + strconv.Itoa(len(types.FilteredByOnlyLowRisks(parsedModel))) + " as low</b>. " +
		"<br><br>These risks are distributed across <b>" + strconv.Itoa(len(parsedModel.InScopeTechnicalAssets())) + " in-scope technical assets</b>. ")
	text.WriteString("The following sub-chapters of this section describe each identified risk grouped by technical asset. ") // TODO more explanation text
	text.WriteString("The RAA value of a technical asset is the calculated \"Relative Attacker Attractiveness\" value in percent.")
	html.Write(5, text.String())
	text.Reset()
	r.currentChapterTitleBreadcrumb = title
	for _, technicalAsset := range sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel) {
		risksStr := technicalAsset.GeneratedRisks(parsedModel)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		if technicalAsset.OutOfScope {
			r.pdfColorOutOfScope()
			suffix = "out-of-scope"
		} else {
			switch types.HighestSeverityStillAtRisk(parsedModel, risksStr) {
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
			if len(types.ReduceToOnlyStillAtRisk(parsedModel, risksStr)) == 0 {
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
				if !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
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
		r.pdf.MultiCell(145, 6, technicalAsset.Technology.String(), "0", "0", false)
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
		for _, dataAsset := range technicalAsset.DataAssetsProcessedSorted(parsedModel) {
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
		for _, dataAsset := range technicalAsset.DataAssetsStoredSorted(parsedModel) {
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
				for _, dataAsset := range outgoingCommLink.DataAssetsSentSorted(parsedModel) {
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
				for _, dataAsset := range outgoingCommLink.DataAssetsReceivedSorted(parsedModel) {
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
				for _, dataAsset := range incomingCommLink.DataAssetsSentSorted(parsedModel) {
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
				for _, dataAsset := range incomingCommLink.DataAssetsReceivedSorted(parsedModel) {
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

func (r *pdfReporter) createDataAssets(parsedModel *types.ParsedModel) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	title := "Identified Data Breach Probabilities by Data Asset"
	r.pdfColorBlack()
	r.addHeadline(title, false)
	r.defineLinkTarget("{intro-risks-by-data-asset}")
	html := r.pdf.HTMLBasicNew()
	html.Write(5, "In total <b>"+strconv.Itoa(types.TotalRiskCount(parsedModel))+" potential risks</b> have been identified during the threat modeling process "+
		"of which "+
		"<b>"+strconv.Itoa(len(types.FilteredByOnlyCriticalRisks(parsedModel)))+" are rated as critical</b>, "+
		"<b>"+strconv.Itoa(len(types.FilteredByOnlyHighRisks(parsedModel)))+" as high</b>, "+
		"<b>"+strconv.Itoa(len(types.FilteredByOnlyElevatedRisks(parsedModel)))+" as elevated</b>, "+
		"<b>"+strconv.Itoa(len(types.FilteredByOnlyMediumRisks(parsedModel)))+" as medium</b>, "+
		"and <b>"+strconv.Itoa(len(types.FilteredByOnlyLowRisks(parsedModel)))+" as low</b>. "+
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
		switch dataAsset.IdentifiedDataBreachProbabilityStillAtRisk(parsedModel) {
		case types.Probable:
			colorHighRisk(r.pdf)
		case types.Possible:
			colorMediumRisk(r.pdf)
		case types.Improbable:
			colorLowRisk(r.pdf)
		default:
			r.pdfColorBlack()
		}
		if !dataAsset.IsDataBreachPotentialStillAtRisk(parsedModel) {
			r.pdfColorBlack()
		}
		risksStr := dataAsset.IdentifiedDataBreachProbabilityRisks(parsedModel)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, risksStr))
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
		/*
			r.pdfColorGray()
			r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
			r.pdf.CellFormat(40, 6, "Indirect Breach:", "0", 0, "", false, 0, "")
			r.pdfColorBlack()
			r.pdf.SetFont("Helvetica", "B", fontSizeBody)
			probability := dataAsset.IdentifiedDataBreachProbability()
			dataBreachText := probability.String()
			switch probability {
			case model.Probable:
				colorHighRisk(r.pdf)
			case model.Possible:
				colorMediumRisk(r.pdf)
			case model.Improbable:
				colorLowRisk(r.pdf)
			default:
				r.pdfColorBlack()
			}
			if !dataAsset.IsDataBreachPotentialStillAtRisk() {
				r.pdfColorBlack()
				dataBreachText = "none"
			}
			r.pdf.MultiCell(145, 6, dataBreachText, "0", "0", false)
			r.pdf.SetFont("Helvetica", "", fontSizeBody)
			if r.pdf.GetY() > 265 {
				r.pageBreak()
				r.pdf.SetY(36)
			}
		*/
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
		for _, dataAsset := range dataAsset.ProcessedByTechnicalAssetsSorted(parsedModel) {
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
		for _, dataAsset := range dataAsset.StoredByTechnicalAssetsSorted(parsedModel) {
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
		for _, commLink := range dataAsset.SentViaCommLinksSorted(parsedModel) {
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
		for _, commLink := range dataAsset.ReceivedViaCommLinksSorted(parsedModel) {
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

		/*
			// where is this data asset at risk (i.e. why)
			risksByTechAssetId := dataAsset.IdentifiedRisksByResponsibleTechnicalAssetId()
			techAssetsResponsible := make([]model.TechnicalAsset, 0)
			for techAssetId, _ := range risksByTechAssetId {
				techAssetsResponsible = append(techAssetsResponsible, parsedModel.TechnicalAssets[techAssetId])
			}
			sort.Sort(model.ByTechnicalAssetRiskSeverityAndTitleSortStillAtRisk(techAssetsResponsible))
			assetStr := "assets"
			if len(techAssetsResponsible) == 1 {
				assetStr = "asset"
			}
			if r.pdf.GetY() > 265 {
				r.pageBreak()
				r.pdf.SetY(36)
			}
			r.pdfColorGray()
			r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
			r.pdf.CellFormat(40, 6, "Risk via:", "0", 0, "", false, 0, "")
			if len(techAssetsResponsible) == 0 {
				r.pdfColorGray()
				r.pdf.MultiCell(145, 6, "This data asset is not directly at risk via any technical asset.", "0", "0", false)
			} else {
				r.pdfColorBlack()
				r.pdf.MultiCell(145, 6, "This data asset is at direct risk via "+strconv.Itoa(len(techAssetsResponsible))+" technical "+assetStr+":", "0", "0", false)
				for _, techAssetResponsible := range techAssetsResponsible {
					if r.pdf.GetY() > 265 {
						r.pageBreak()
						r.pdf.SetY(36)
					}
					switch model.HighestSeverityStillAtRisk(techAssetResponsible.GeneratedRisks()) {
					case model.High:
						colorHighRisk(r.pdf)
					case model.Medium:
						colorMediumRisk(r.pdf)
					case model.Low:
						colorLowRisk(r.pdf)
					default:
						r.pdfColorBlack()
					}
					risksStr := techAssetResponsible.GeneratedRisks()
					if len(model.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
						r.pdfColorBlack()
					}
					riskStr := "risksStr"
					if len(risksStr) == 1 {
						riskStr = "risk"
					}
					r.pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
					posY := r.pdf.GetY()
					risksResponsible := techAssetResponsible.GeneratedRisks()
					risksResponsibleStillAtRisk := model.ReduceToOnlyStillAtRisk(risksResponsible)
					r.pdf.SetFont("Helvetica", "", fontSizeSmall)
					r.pdf.MultiCell(185, 6, uni(techAssetResponsible.Title)+": "+strconv.Itoa(len(risksResponsibleStillAtRisk))+" / "+strconv.Itoa(len(risksResponsible))+" "+riskStr, "0", "0", false)
					r.pdf.SetFont("Helvetica", "", fontSizeBody)
					r.pdf.Link(20, posY, 180, r.pdf.GetY()-posY, tocLinkIdByAssetId[techAssetResponsible.Id])
				}
				r.pdfColorBlack()
			}
		*/

		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(40, 6, "Data Breach:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		dataBreachProbability := dataAsset.IdentifiedDataBreachProbabilityStillAtRisk(parsedModel)
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
		if !dataAsset.IsDataBreachPotentialStillAtRisk(parsedModel) {
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
		dataBreachRisksStillAtRisk := dataAsset.IdentifiedDataBreachProbabilityRisksStillAtRisk(parsedModel)
		types.SortByDataBreachProbability(dataBreachRisksStillAtRisk, parsedModel)
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
			riskRemainingStr := "risksStr"
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
				if !dataBreachRisk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
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

func (r *pdfReporter) createTrustBoundaries(parsedModel *types.ParsedModel) {
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

func questionsUnanswered(parsedModel *types.ParsedModel) int {
	result := 0
	for _, answer := range parsedModel.Questions {
		if len(strings.TrimSpace(answer)) == 0 {
			result++
		}
	}
	return result
}

func (r *pdfReporter) createSharedRuntimes(parsedModel *types.ParsedModel) {
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

func (r *pdfReporter) createRiskRulesChecked(parsedModel *types.ParsedModel, modelFilename string, skipRiskRules string, buildTimestamp string, modelHash string, customRiskRules map[string]*model.CustomRisk) {
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
	strBuilder.WriteString("<b>Threagile Version:</b> " + docs.ThreagileVersion)
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
	skippedRules := strings.Split(skipRiskRules, ",")
	skipped := ""
	r.pdf.Ln(-1)

	for id, customRule := range customRiskRules {
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		if contains(skippedRules, id) {
			skipped = "SKIPPED - "
		} else {
			skipped = ""
		}
		r.pdf.CellFormat(190, 3, skipped+customRule.Category.Title, "0", 0, "", false, 0, "")
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
		r.pdf.MultiCell(160, 6, customRule.Category.STRIDE.Title(), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, firstParagraph(customRule.Category.Description), "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, customRule.Category.DetectionLogic, "0", "0", false)
		r.pdfColorGray()
		r.pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		r.pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
		r.pdfColorBlack()
		r.pdf.MultiCell(160, 6, customRule.Category.RiskAssessment, "0", "0", false)
	}

	for _, key := range sortedKeysOfIndividualRiskCategories(parsedModel) {
		individualRiskCategory := parsedModel.IndividualRiskCategories[key]
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		r.pdf.CellFormat(190, 3, individualRiskCategory.Title, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeSmall)
		r.pdf.CellFormat(190, 6, individualRiskCategory.Id, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "I", fontSizeBody)
		r.pdf.CellFormat(190, 6, "Individual Risk Category", "0", 0, "", false, 0, "")
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

	for _, rule := range risks.GetBuiltInRiskRules() {
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "B", fontSizeBody)
		if contains(skippedRules, rule.Category().Id) {
			skipped = "SKIPPED - "
		} else {
			skipped = ""
		}
		r.pdf.CellFormat(190, 3, skipped+rule.Category().Title, "0", 0, "", false, 0, "")
		r.pdf.Ln(-1)
		r.pdf.SetFont("Helvetica", "", fontSizeSmall)
		r.pdf.CellFormat(190, 6, rule.Category().Id, "0", 0, "", false, 0, "")
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

func (r *pdfReporter) createTargetDescription(parsedModel *types.ParsedModel, baseFolder string) error {
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
				defer os.Remove(rotatedFile.Name())
				dstImage := image.NewRGBA(image.Rect(0, 0, srcDimensions.Dy(), srcDimensions.Dx()))
				err = graphics.Rotate(dstImage, srcImage, &graphics.RotateOptions{-1 * math.Pi / 2.0})
				checkErr(err)
				newImage, _ := os.Create(rotatedFile.Name())
					defer newImage.Close()
					err = png.Encode(newImage, dstImage)
					checkErr(err)
					diagramFilenamePNG = rotatedFile.Name()
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

func sortedKeysOfIndividualRiskCategories(parsedModel *types.ParsedModel) []string {
	keys := make([]string, 0)
	for k := range parsedModel.IndividualRiskCategories {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
				defer os.Remove(rotatedFile.Name())
				dstImage := image.NewRGBA(image.Rect(0, 0, srcDimensions.Dy(), srcDimensions.Dx()))
				err = graphics.Rotate(dstImage, srcImage, &graphics.RotateOptions{-1 * math.Pi / 2.0})
				checkErr(err)
				newImage, _ := os.Create(rotatedFile.Name())
				defer newImage.Close()
					err = png.Encode(newImage, dstImage)
					checkErr(err)
					diagramFilenamePNG = rotatedFile.Name()
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
