package report

import (
	"errors"
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
	"github.com/threagile/threagile/pkg/colors"
	"github.com/threagile/threagile/pkg/docs"
	accidental_secret_leak "github.com/threagile/threagile/pkg/security/risks/built-in/accidental-secret-leak"
	code_backdooring "github.com/threagile/threagile/pkg/security/risks/built-in/code-backdooring"
	container_baseimage_backdooring "github.com/threagile/threagile/pkg/security/risks/built-in/container-baseimage-backdooring"
	container_platform_escape "github.com/threagile/threagile/pkg/security/risks/built-in/container-platform-escape"
	cross_site_request_forgery "github.com/threagile/threagile/pkg/security/risks/built-in/cross-site-request-forgery"
	cross_site_scripting "github.com/threagile/threagile/pkg/security/risks/built-in/cross-site-scripting"
	dos_risky_access_across_trust_boundary "github.com/threagile/threagile/pkg/security/risks/built-in/dos-risky-access-across-trust-boundary"
	incomplete_model "github.com/threagile/threagile/pkg/security/risks/built-in/incomplete-model"
	ldap_injection "github.com/threagile/threagile/pkg/security/risks/built-in/ldap-injection"
	missing_authentication "github.com/threagile/threagile/pkg/security/risks/built-in/missing-authentication"
	missing_authentication_second_factor "github.com/threagile/threagile/pkg/security/risks/built-in/missing-authentication-second-factor"
	missing_build_infrastructure "github.com/threagile/threagile/pkg/security/risks/built-in/missing-build-infrastructure"
	missing_cloud_hardening "github.com/threagile/threagile/pkg/security/risks/built-in/missing-cloud-hardening"
	missing_file_validation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-file-validation"
	missing_hardening "github.com/threagile/threagile/pkg/security/risks/built-in/missing-hardening"
	missing_identity_propagation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-identity-propagation"
	missing_identity_provider_isolation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-identity-provider-isolation"
	missing_identity_store "github.com/threagile/threagile/pkg/security/risks/built-in/missing-identity-store"
	missing_network_segmentation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-network-segmentation"
	missing_vault "github.com/threagile/threagile/pkg/security/risks/built-in/missing-vault"
	missing_vault_isolation "github.com/threagile/threagile/pkg/security/risks/built-in/missing-vault-isolation"
	missing_waf "github.com/threagile/threagile/pkg/security/risks/built-in/missing-waf"
	mixed_targets_on_shared_runtime "github.com/threagile/threagile/pkg/security/risks/built-in/mixed-targets-on-shared-runtime"
	path_traversal "github.com/threagile/threagile/pkg/security/risks/built-in/path-traversal"
	push_instead_of_pull_deployment "github.com/threagile/threagile/pkg/security/risks/built-in/push-instead-of-pull-deployment"
	search_query_injection "github.com/threagile/threagile/pkg/security/risks/built-in/search-query-injection"
	server_side_request_forgery "github.com/threagile/threagile/pkg/security/risks/built-in/server-side-request-forgery"
	service_registry_poisoning "github.com/threagile/threagile/pkg/security/risks/built-in/service-registry-poisoning"
	sql_nosql_injection "github.com/threagile/threagile/pkg/security/risks/built-in/sql-nosql-injection"
	unchecked_deployment "github.com/threagile/threagile/pkg/security/risks/built-in/unchecked-deployment"
	unencrypted_asset "github.com/threagile/threagile/pkg/security/risks/built-in/unencrypted-asset"
	unencrypted_communication "github.com/threagile/threagile/pkg/security/risks/built-in/unencrypted-communication"
	unguarded_access_from_internet "github.com/threagile/threagile/pkg/security/risks/built-in/unguarded-access-from-internet"
	unguarded_direct_datastore_access "github.com/threagile/threagile/pkg/security/risks/built-in/unguarded-direct-datastore-access"
	unnecessary_communication_link "github.com/threagile/threagile/pkg/security/risks/built-in/unnecessary-communication-link"
	unnecessary_data_asset "github.com/threagile/threagile/pkg/security/risks/built-in/unnecessary-data-asset"
	unnecessary_data_transfer "github.com/threagile/threagile/pkg/security/risks/built-in/unnecessary-data-transfer"
	unnecessary_technical_asset "github.com/threagile/threagile/pkg/security/risks/built-in/unnecessary-technical-asset"
	untrusted_deserialization "github.com/threagile/threagile/pkg/security/risks/built-in/untrusted-deserialization"
	wrong_communication_link_content "github.com/threagile/threagile/pkg/security/risks/built-in/wrong-communication-link-content"
	wrong_trust_boundary_content "github.com/threagile/threagile/pkg/security/risks/built-in/wrong-trust-boundary-content"
	xml_external_entity "github.com/threagile/threagile/pkg/security/risks/built-in/xml-external-entity"
	"github.com/threagile/threagile/pkg/security/types"
	"github.com/wcharczuk/go-chart"
	"github.com/wcharczuk/go-chart/drawing"
)

const fontSizeHeadline, fontSizeHeadlineSmall, fontSizeBody, fontSizeSmall, fontSizeVerySmall = 20, 16, 12, 9, 7
const /*dataFlowDiagramFullscreen,*/ allowedPdfLandscapePages, embedDiagramLegendPage = /*false,*/ true, false

var isLandscapePage bool

var pdf *gofpdf.Fpdf

// var alreadyTemplateImported = false
var coverTemplateId, contentTemplateId, diagramLegendTemplateId int
var pageNo int
var linkCounter int
var tocLinkIdByAssetId map[string]int
var homeLink int
var currentChapterTitleBreadcrumb string

var firstParagraphRegEx = regexp.MustCompile(`(.*?)((<br>)|(<p>))`)

func initReport() {
	pdf = nil
	isLandscapePage = false
	pageNo = 0
	linkCounter = 0
	homeLink = 0
	currentChapterTitleBreadcrumb = ""
	tocLinkIdByAssetId = make(map[string]int)
}

func WriteReportPDF(reportFilename string,
	templateFilename string,
	dataFlowDiagramFilenamePNG string,
	dataAssetDiagramFilenamePNG string,
	modelFilename string,
	skipRiskRules string,
	buildTimestamp string,
	modelHash string,
	introTextRAA string,
	customRiskRules map[string]*types.CustomRisk,
	tempFolder string,
	model *types.ParsedModel) {
	initReport()
	createPdfAndInitMetadata(model)
	parseBackgroundTemplate(templateFilename)
	createCover(model)
	createTableOfContents(model)
	createManagementSummary(model, tempFolder)
	createImpactInitialRisks(model)
	createRiskMitigationStatus(model, tempFolder)
	createImpactRemainingRisks(model)
	createTargetDescription(model, filepath.Dir(modelFilename))
	embedDataFlowDiagram(dataFlowDiagramFilenamePNG, tempFolder)
	createSecurityRequirements(model)
	createAbuseCases(model)
	createTagListing(model)
	createSTRIDE(model)
	createAssignmentByFunction(model)
	createRAA(model, introTextRAA)
	embedDataRiskMapping(dataAssetDiagramFilenamePNG, tempFolder)
	//createDataRiskQuickWins()
	createOutOfScopeAssets(model)
	createModelFailures(model)
	createQuestions(model)
	createRiskCategories(model)
	createTechnicalAssets(model)
	createDataAssets(model)
	createTrustBoundaries(model)
	createSharedRuntimes(model)
	createRiskRulesChecked(model, modelFilename, skipRiskRules, buildTimestamp, modelHash, customRiskRules)
	createDisclaimer(model)
	writeReportToFile(reportFilename)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func createPdfAndInitMetadata(model *types.ParsedModel) {
	pdf = gofpdf.New("P", "mm", "A4", "")
	pdf.SetCreator(model.Author.Homepage, true)
	pdf.SetAuthor(model.Author.Name, true)
	pdf.SetTitle("Threat Model Report: "+model.Title, true)
	pdf.SetSubject("Threat Model Report: "+model.Title, true)
	//	pdf.SetPageBox("crop", 0, 0, 100, 010)
	pdf.SetHeaderFunc(headerFunc)
	pdf.SetFooterFunc(func() {
		addBreadcrumb(model)
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(127, 127, 127)
		pdf.Text(8.6, 284, "Threat Model Report via Threagile") //: "+parsedModel.Title)
		pdf.Link(8.4, 281, 54.6, 4, homeLink)
		pageNo++
		text := "Page " + strconv.Itoa(pageNo)
		if pageNo < 10 {
			text = "    " + text
		} else if pageNo < 100 {
			text = "  " + text
		}
		if pageNo > 1 {
			pdf.Text(186, 284, text)
		}
	})
	linkCounter = 1 // link counting starts at 1 via pdf.AddLink
}

func headerFunc() {
	if !isLandscapePage {
		gofpdi.UseImportedTemplate(pdf, contentTemplateId, 0, 0, 0, 300)
		pdf.SetTopMargin(35)
	}
}

func addBreadcrumb(parsedModel *types.ParsedModel) {
	if len(currentChapterTitleBreadcrumb) > 0 {
		uni := pdf.UnicodeTranslatorFromDescriptor("")
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(127, 127, 127)
		pdf.Text(46.7, 24.5, uni(currentChapterTitleBreadcrumb+"   -   "+parsedModel.Title))
	}
}

func parseBackgroundTemplate(templateFilename string) {
	/*
		imageBox, err := rice.FindBox("template")
		checkErr(err)
		file, err := os.CreateTemp("", "background-*-.pdf")
		checkErr(err)
		defer os.Remove(file.Name())
		backgroundBytes := imageBox.MustBytes("background.pdf")
		err = os.WriteFile(file.Name(), backgroundBytes, 0644)
		checkErr(err)
	*/
	coverTemplateId = gofpdi.ImportPage(pdf, templateFilename, 1, "/MediaBox")
	contentTemplateId = gofpdi.ImportPage(pdf, templateFilename, 2, "/MediaBox")
	diagramLegendTemplateId = gofpdi.ImportPage(pdf, templateFilename, 3, "/MediaBox")
}

func createCover(parsedModel *types.ParsedModel) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.AddPage()
	gofpdi.UseImportedTemplate(pdf, coverTemplateId, 0, 0, 0, 300)
	pdf.SetFont("Helvetica", "B", 28)
	pdf.SetTextColor(0, 0, 0)
	pdf.Text(40, 110, "Threat Model Report")
	pdf.Text(40, 125, uni(parsedModel.Title))
	pdf.SetFont("Helvetica", "", 12)
	reportDate := parsedModel.Date
	if reportDate.IsZero() {
		reportDate = time.Now()
	}
	pdf.Text(40.7, 145, reportDate.Format("2 January 2006"))
	pdf.Text(40.7, 153, uni(parsedModel.Author.Name))
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(80, 80, 80)
	pdf.Text(8.6, 275, parsedModel.Author.Homepage)
	pdf.SetFont("Helvetica", "", 12)
	pdf.SetTextColor(0, 0, 0)
}

func createTableOfContents(parsedModel *types.ParsedModel) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.AddPage()
	currentChapterTitleBreadcrumb = "Table of Contents"
	homeLink = pdf.AddLink()
	defineLinkTarget("{home}")
	gofpdi.UseImportedTemplate(pdf, contentTemplateId, 0, 0, 0, 300)
	pdf.SetFont("Helvetica", "B", fontSizeHeadline)
	pdf.Text(11, 40, "Table of Contents")
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetY(46)

	pdf.SetLineWidth(0.25)
	pdf.SetDrawColor(160, 160, 160)
	pdf.SetDashPattern([]float64{0.5, 0.5}, 0)

	// ===============

	var y float64 = 50
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	pdf.Text(11, y, "Results Overview")
	pdf.SetFont("Helvetica", "", fontSizeBody)

	y += 6
	pdf.Text(11, y, "    "+"Management Summary")
	pdf.Text(175, y, "{management-summary}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

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
	pdf.Text(11, y, "    "+"Impact Analysis of "+strconv.Itoa(count)+" Initial "+risksStr+" in "+strconv.Itoa(catCount)+" "+catStr)
	pdf.Text(175, y, "{impact-analysis-initial-risks}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	y += 6
	pdf.Text(11, y, "    "+"Risk Mitigation")
	pdf.Text(175, y, "{risk-mitigation-status}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

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
	pdf.Text(11, y, "    "+"Impact Analysis of "+strconv.Itoa(count)+" Remaining "+risksStr+" in "+strconv.Itoa(catCount)+" "+catStr)
	pdf.Text(175, y, "{impact-analysis-remaining-risks}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	y += 6
	pdf.Text(11, y, "    "+"Application Overview")
	pdf.Text(175, y, "{target-overview}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	y += 6
	pdf.Text(11, y, "    "+"Data-Flow Diagram")
	pdf.Text(175, y, "{data-flow-diagram}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	y += 6
	pdf.Text(11, y, "    "+"Security Requirements")
	pdf.Text(175, y, "{security-requirements}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	y += 6
	pdf.Text(11, y, "    "+"Abuse Cases")
	pdf.Text(175, y, "{abuse-cases}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	y += 6
	pdf.Text(11, y, "    "+"Tag Listing")
	pdf.Text(175, y, "{tag-listing}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	y += 6
	pdf.Text(11, y, "    "+"STRIDE Classification of Identified Risks")
	pdf.Text(175, y, "{stride}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	y += 6
	pdf.Text(11, y, "    "+"Assignment by Function")
	pdf.Text(175, y, "{function-assignment}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	y += 6
	pdf.Text(11, y, "    "+"RAA Analysis")
	pdf.Text(175, y, "{raa-analysis}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	y += 6
	pdf.Text(11, y, "    "+"Data Mapping")
	pdf.Text(175, y, "{data-risk-mapping}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	/*
		y += 6
		assets := "assets"
		count = len(model.SortedTechnicalAssetsByQuickWinsAndTitle())
		if count == 1 {
			assets = "asset"
		}
		pdf.Text(11, y, "    "+"Data Risk Quick Wins: "+strconv.Itoa(count)+" "+assets)
		pdf.Text(175, y, "{data-risk-quick-wins}")
		pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())
	*/

	y += 6
	assets := "Assets"
	count = len(parsedModel.OutOfScopeTechnicalAssets())
	if count == 1 {
		assets = "Asset"
	}
	pdf.Text(11, y, "    "+"Out-of-Scope Assets: "+strconv.Itoa(count)+" "+assets)
	pdf.Text(175, y, "{out-of-scope-assets}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	y += 6
	modelFailures := types.FlattenRiskSlice(types.FilterByModelFailures(parsedModel, parsedModel.GeneratedRisksByCategory))
	risksStr = "Risks"
	count = len(modelFailures)
	if count == 1 {
		risksStr = "Risk"
	}
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, modelFailures))
	if countStillAtRisk > 0 {
		colors.ColorModelFailure(pdf)
	}
	pdf.Text(11, y, "    "+"Potential Model Failures: "+strconv.Itoa(countStillAtRisk)+" / "+strconv.Itoa(count)+" "+risksStr)
	pdf.Text(175, y, "{model-failures}")
	pdfColorBlack()
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	y += 6
	questions := "Questions"
	count = len(parsedModel.Questions)
	if count == 1 {
		questions = "Question"
	}
	if questionsUnanswered(parsedModel) > 0 {
		colors.ColorModelFailure(pdf)
	}
	pdf.Text(11, y, "    "+"Questions: "+strconv.Itoa(questionsUnanswered(parsedModel))+" / "+strconv.Itoa(count)+" "+questions)
	pdf.Text(175, y, "{questions}")
	pdfColorBlack()
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())

	// ===============

	if len(parsedModel.GeneratedRisksByCategory) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			pageBreakInLists()
			y = 40
		}
		pdf.SetFont("Helvetica", "B", fontSizeBody)
		pdf.SetTextColor(0, 0, 0)
		pdf.Text(11, y, "Risks by Vulnerability Category")
		pdf.SetFont("Helvetica", "", fontSizeBody)
		y += 6
		pdf.Text(11, y, "    "+"Identified Risks by Vulnerability Category")
		pdf.Text(175, y, "{intro-risks-by-vulnerability-category}")
		pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())
		for _, category := range types.SortedRiskCategories(parsedModel) {
			newRisksStr := types.SortedRisksOfCategory(parsedModel, category)
			switch types.HighestSeverityStillAtRisk(parsedModel, newRisksStr) {
			case types.CriticalSeverity:
				colors.ColorCriticalRisk(pdf)
			case types.HighSeverity:
				colors.ColorHighRisk(pdf)
			case types.ElevatedSeverity:
				colors.ColorElevatedRisk(pdf)
			case types.MediumSeverity:
				colors.ColorMediumRisk(pdf)
			case types.LowSeverity:
				colors.ColorLowRisk(pdf)
			default:
				pdfColorBlack()
			}
			if len(types.ReduceToOnlyStillAtRisk(parsedModel, newRisksStr)) == 0 {
				pdfColorBlack()
			}
			y += 6
			if y > 275 {
				pageBreakInLists()
				y = 40
			}
			countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, newRisksStr))
			suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(newRisksStr)) + " Risk"
			if len(newRisksStr) != 1 {
				suffix += "s"
			}
			pdf.Text(11, y, "    "+uni(category.Title)+": "+suffix)
			pdf.Text(175, y, "{"+category.Id+"}")
			pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			tocLinkIdByAssetId[category.Id] = pdf.AddLink()
			pdf.Link(10, y-5, 172.5, 6.5, tocLinkIdByAssetId[category.Id])
		}
	}

	// ===============

	if len(parsedModel.TechnicalAssets) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			pageBreakInLists()
			y = 40
		}
		pdf.SetFont("Helvetica", "B", fontSizeBody)
		pdf.SetTextColor(0, 0, 0)
		pdf.Text(11, y, "Risks by Technical Asset")
		pdf.SetFont("Helvetica", "", fontSizeBody)
		y += 6
		pdf.Text(11, y, "    "+"Identified Risks by Technical Asset")
		pdf.Text(175, y, "{intro-risks-by-technical-asset}")
		pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())
		for _, technicalAsset := range sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel) {
			newRisksStr := technicalAsset.GeneratedRisks(parsedModel)
			y += 6
			if y > 275 {
				pageBreakInLists()
				y = 40
			}
			countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, newRisksStr))
			suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(newRisksStr)) + " Risk"
			if len(newRisksStr) != 1 {
				suffix += "s"
			}
			if technicalAsset.OutOfScope {
				pdfColorOutOfScope()
				suffix = "out-of-scope"
			} else {
				switch types.HighestSeverityStillAtRisk(parsedModel, newRisksStr) {
				case types.CriticalSeverity:
					colors.ColorCriticalRisk(pdf)
				case types.HighSeverity:
					colors.ColorHighRisk(pdf)
				case types.ElevatedSeverity:
					colors.ColorElevatedRisk(pdf)
				case types.MediumSeverity:
					colors.ColorMediumRisk(pdf)
				case types.LowSeverity:
					colors.ColorLowRisk(pdf)
				default:
					pdfColorBlack()
				}
				if len(types.ReduceToOnlyStillAtRisk(parsedModel, newRisksStr)) == 0 {
					pdfColorBlack()
				}
			}
			pdf.Text(11, y, "    "+uni(technicalAsset.Title)+": "+suffix)
			pdf.Text(175, y, "{"+technicalAsset.Id+"}")
			pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			tocLinkIdByAssetId[technicalAsset.Id] = pdf.AddLink()
			pdf.Link(10, y-5, 172.5, 6.5, tocLinkIdByAssetId[technicalAsset.Id])
		}
	}

	// ===============

	if len(parsedModel.DataAssets) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			pageBreakInLists()
			y = 40
		}
		pdf.SetFont("Helvetica", "B", fontSizeBody)
		pdfColorBlack()
		pdf.Text(11, y, "Data Breach Probabilities by Data Asset")
		pdf.SetFont("Helvetica", "", fontSizeBody)
		y += 6
		pdf.Text(11, y, "    "+"Identified Data Breach Probabilities by Data Asset")
		pdf.Text(175, y, "{intro-risks-by-data-asset}")
		pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
		pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())
		for _, dataAsset := range sortedDataAssetsByDataBreachProbabilityAndTitle(parsedModel) {
			y += 6
			if y > 275 {
				pageBreakInLists()
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
				colors.ColorHighRisk(pdf)
			case types.Possible:
				colors.ColorMediumRisk(pdf)
			case types.Improbable:
				colors.ColorLowRisk(pdf)
			default:
				pdfColorBlack()
			}
			if !dataAsset.IsDataBreachPotentialStillAtRisk(parsedModel) {
				pdfColorBlack()
			}
			pdf.Text(11, y, "    "+uni(dataAsset.Title)+": "+suffix)
			pdf.Text(175, y, "{data:"+dataAsset.Id+"}")
			pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			tocLinkIdByAssetId[dataAsset.Id] = pdf.AddLink()
			pdf.Link(10, y-5, 172.5, 6.5, tocLinkIdByAssetId[dataAsset.Id])
		}
	}

	// ===============

	if len(parsedModel.TrustBoundaries) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			pageBreakInLists()
			y = 40
		}
		pdf.SetFont("Helvetica", "B", fontSizeBody)
		pdfColorBlack()
		pdf.Text(11, y, "Trust Boundaries")
		pdf.SetFont("Helvetica", "", fontSizeBody)
		for _, key := range types.SortedKeysOfTrustBoundaries(parsedModel) {
			trustBoundary := parsedModel.TrustBoundaries[key]
			y += 6
			if y > 275 {
				pageBreakInLists()
				y = 40
			}
			colors.ColorTwilight(pdf)
			if !trustBoundary.Type.IsNetworkBoundary() {
				pdfColorLightGray()
			}
			pdf.Text(11, y, "    "+uni(trustBoundary.Title))
			pdf.Text(175, y, "{boundary:"+trustBoundary.Id+"}")
			pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			tocLinkIdByAssetId[trustBoundary.Id] = pdf.AddLink()
			pdf.Link(10, y-5, 172.5, 6.5, tocLinkIdByAssetId[trustBoundary.Id])
		}
		pdfColorBlack()
	}

	// ===============

	if len(parsedModel.SharedRuntimes) > 0 {
		y += 6
		y += 6
		if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
			pageBreakInLists()
			y = 40
		}
		pdf.SetFont("Helvetica", "B", fontSizeBody)
		pdfColorBlack()
		pdf.Text(11, y, "Shared Runtime")
		pdf.SetFont("Helvetica", "", fontSizeBody)
		for _, key := range types.SortedKeysOfSharedRuntime(parsedModel) {
			sharedRuntime := parsedModel.SharedRuntimes[key]
			y += 6
			if y > 275 {
				pageBreakInLists()
				y = 40
			}
			pdf.Text(11, y, "    "+uni(sharedRuntime.Title))
			pdf.Text(175, y, "{runtime:"+sharedRuntime.Id+"}")
			pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
			tocLinkIdByAssetId[sharedRuntime.Id] = pdf.AddLink()
			pdf.Link(10, y-5, 172.5, 6.5, tocLinkIdByAssetId[sharedRuntime.Id])
		}
	}

	// ===============

	y += 6
	y += 6
	if y > 260 { // 260 instead of 275 for major group headlines to avoid "Schusterjungen"
		pageBreakInLists()
		y = 40
	}
	pdfColorBlack()
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	pdf.Text(11, y, "About Threagile")
	pdf.SetFont("Helvetica", "", fontSizeBody)
	y += 6
	if y > 275 {
		pageBreakInLists()
		y = 40
	}
	pdf.Text(11, y, "    "+"Risk Rules Checked by Threagile")
	pdf.Text(175, y, "{risk-rules-checked}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())
	y += 6
	if y > 275 {
		pageBreakInLists()
		y = 40
	}
	pdfColorDisclaimer()
	pdf.Text(11, y, "    "+"Disclaimer")
	pdf.Text(175, y, "{disclaimer}")
	pdf.Line(15.6, y+1.3, 11+171.5, y+1.3)
	pdf.Link(10, y-5, 172.5, 6.5, pdf.AddLink())
	pdfColorBlack()

	pdf.SetDrawColor(0, 0, 0)
	pdf.SetDashPattern([]float64{}, 0)

	// Now write all the sections/pages. Before we start writing, we use `RegisterAlias` to
	// ensure that the alias written in the table of contents will be replaced
	// by the current page number. --> See the "pdf.RegisterAlias()" calls during the PDF creation in this file
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

func defineLinkTarget(alias string) {
	pageNumbStr := strconv.Itoa(pdf.PageNo())
	if len(pageNumbStr) == 1 {
		pageNumbStr = "    " + pageNumbStr
	} else if len(pageNumbStr) == 2 {
		pageNumbStr = "  " + pageNumbStr
	}
	pdf.RegisterAlias(alias, pageNumbStr)
	pdf.SetLink(linkCounter, 0, -1)
	linkCounter++
}

func createDisclaimer(parsedModel *types.ParsedModel) {
	pdf.AddPage()
	currentChapterTitleBreadcrumb = "Disclaimer"
	defineLinkTarget("{disclaimer}")
	gofpdi.UseImportedTemplate(pdf, contentTemplateId, 0, 0, 0, 300)
	pdfColorDisclaimer()
	pdf.SetFont("Helvetica", "B", fontSizeHeadline)
	pdf.Text(11, 40, "Disclaimer")
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetY(46)

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
	html := pdf.HTMLBasicNew()
	html.Write(5, disclaimer.String())
	pdfColorBlack()
}

func createManagementSummary(parsedModel *types.ParsedModel, tempFolder string) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.SetTextColor(0, 0, 0)
	title := "Management Summary"
	addHeadline(title, false)
	defineLinkTarget("{management-summary}")
	currentChapterTitleBreadcrumb = title
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

	html := pdf.HTMLBasicNew()
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

	pdf.SetFont("Helvetica", "B", fontSizeBody)

	pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(60, 6, "", "0", 0, "", false, 0, "")
	colors.ColorRiskStatusUnchecked(pdf)
	pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countStatusUnchecked), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "unchecked", "0", 0, "", false, 0, "")
	pdf.Ln(-1)

	colors.ColorCriticalRisk(pdf)
	pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countCritical), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "critical risk", "0", 0, "", false, 0, "")
	colors.ColorRiskStatusInDiscussion(pdf)
	pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countStatusInDiscussion), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "in discussion", "0", 0, "", false, 0, "")
	pdf.Ln(-1)

	colors.ColorHighRisk(pdf)
	pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countHigh), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "high risk", "0", 0, "", false, 0, "")
	colors.ColorRiskStatusAccepted(pdf)
	pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countStatusAccepted), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "accepted", "0", 0, "", false, 0, "")
	pdf.Ln(-1)

	colors.ColorElevatedRisk(pdf)
	pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countElevated), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "elevated risk", "0", 0, "", false, 0, "")
	colors.ColorRiskStatusInProgress(pdf)
	pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countStatusInProgress), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "in progress", "0", 0, "", false, 0, "")
	pdf.Ln(-1)

	colors.ColorMediumRisk(pdf)
	pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countMedium), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "medium risk", "0", 0, "", false, 0, "")
	colors.ColorRiskStatusMitigated(pdf)
	pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countStatusMitigated), "0", 0, "R", false, 0, "")
	pdf.SetFont("Helvetica", "BI", fontSizeBody)
	pdf.CellFormat(60, 6, "mitigated", "0", 0, "", false, 0, "")
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	pdf.Ln(-1)

	colors.ColorLowRisk(pdf)
	pdf.CellFormat(17, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countLow), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "low risk", "0", 0, "", false, 0, "")
	colors.ColorRiskStatusFalsePositive(pdf)
	pdf.CellFormat(23, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countStatusFalsePositive), "0", 0, "R", false, 0, "")
	pdf.SetFont("Helvetica", "BI", fontSizeBody)
	pdf.CellFormat(60, 6, "false positive", "0", 0, "", false, 0, "")
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	pdf.Ln(-1)

	pdf.SetFont("Helvetica", "", fontSizeBody)

	// pie chart: risk severity
	pieChartRiskSeverity := chart.PieChart{
		Width:  1500,
		Height: 1500,
		Values: []chart.Value{
			{Value: float64(countLow), //Label: strconv.Itoa(countLow) + " Low",
				Style: chart.Style{
					FillColor: makeColor(colors.RgbHexColorLowRisk()).WithAlpha(98),
					//FontColor: makeColor(colors.RgbHexColorLowRisk()),
					FontSize: 65}},
			{Value: float64(countMedium), //Label: strconv.Itoa(countMedium) + " Medium",
				Style: chart.Style{
					FillColor: makeColor(colors.RgbHexColorMediumRisk()).WithAlpha(98),
					//FontColor: makeColor(colors.RgbHexColorMediumRisk()),
					FontSize: 65}},
			{Value: float64(countElevated), //Label: strconv.Itoa(countElevated) + " Elevated",
				Style: chart.Style{
					FillColor: makeColor(colors.RgbHexColorElevatedRisk()).WithAlpha(98),
					//FontColor: makeColor(colors.RgbHexColorElevatedRisk()),
					FontSize: 65}},
			{Value: float64(countHigh), //Label: strconv.Itoa(countHigh) + " High",
				Style: chart.Style{
					FillColor: makeColor(colors.RgbHexColorHighRisk()).WithAlpha(98),
					//FontColor: makeColor(colors.RgbHexColorHighRisk()),
					FontSize: 65}},
			{Value: float64(countCritical), //Label: strconv.Itoa(countCritical) + " Critical",
				Style: chart.Style{
					FillColor: makeColor(colors.RgbHexColorCriticalRisk()).WithAlpha(98),
					//FontColor: makeColor(colors.RgbHexColorCriticalRisk()),
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
					FillColor: makeColor(colors.RgbHexColorRiskStatusFalsePositive()).WithAlpha(98),
					//FontColor: makeColor(colors.RgbHexColorRiskStatusFalsePositive()),
					FontSize: 65}},
			{Value: float64(countStatusMitigated), //Label: strconv.Itoa(countStatusMitigated) + " Mitigated",
				Style: chart.Style{
					FillColor: makeColor(colors.RgbHexColorRiskStatusMitigated()).WithAlpha(98),
					//FontColor: makeColor(colors.RgbHexColorRiskStatusMitigated()),
					FontSize: 65}},
			{Value: float64(countStatusInProgress), //Label: strconv.Itoa(countStatusInProgress) + " InProgress",
				Style: chart.Style{
					FillColor: makeColor(colors.RgbHexColorRiskStatusInProgress()).WithAlpha(98),
					//FontColor: makeColor(colors.RgbHexColorRiskStatusInProgress()),
					FontSize: 65}},
			{Value: float64(countStatusAccepted), //Label: strconv.Itoa(countStatusAccepted) + " Accepted",
				Style: chart.Style{
					FillColor: makeColor(colors.RgbHexColorRiskStatusAccepted()).WithAlpha(98),
					//FontColor: makeColor(colors.RgbHexColorRiskStatusAccepted()),
					FontSize: 65}},
			{Value: float64(countStatusInDiscussion), //Label: strconv.Itoa(countStatusInDiscussion) + " InDiscussion",
				Style: chart.Style{
					FillColor: makeColor(colors.RgbHexColorRiskStatusInDiscussion()).WithAlpha(98),
					//FontColor: makeColor(colors.RgbHexColorRiskStatusInDiscussion()),
					FontSize: 65}},
			{Value: float64(countStatusUnchecked), //Label: strconv.Itoa(countStatusUnchecked) + " Unchecked",
				Style: chart.Style{
					FillColor: makeColor(colors.RgbHexColorRiskStatusUnchecked()).WithAlpha(98),
					//FontColor: makeColor(colors.RgbHexColorRiskStatusUnchecked()),
					FontSize: 65}},
		},
	}

	y := pdf.GetY() + 5
	embedPieChart(pieChartRiskSeverity, 15.0, y, tempFolder)
	embedPieChart(pieChartRiskStatus, 110.0, y, tempFolder)

	// individual management summary comment
	pdfColorBlack()
	if len(parsedModel.ManagementSummaryComment) > 0 {
		html.Write(5, "<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>"+
			parsedModel.ManagementSummaryComment)
	}
}

func createRiskMitigationStatus(parsedModel *types.ParsedModel, tempFolder string) {
	pdf.SetTextColor(0, 0, 0)
	stillAtRisk := types.FilteredByStillAtRisk(parsedModel)
	count := len(stillAtRisk)
	title := "Risk Mitigation"
	addHeadline(title, false)
	defineLinkTarget("{risk-mitigation-status}")
	currentChapterTitleBreadcrumb = title

	html := pdf.HTMLBasicNew()
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
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInDiscussion(parsedModel, risksLow))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingAccepted(parsedModel, risksLow))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInProgress(parsedModel, risksLow))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingMitigated(parsedModel, risksLow))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingFalsePositive(parsedModel, risksLow))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.MediumSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(types.ReduceToOnlyRiskTrackingUnchecked(parsedModel, risksMedium))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInDiscussion(parsedModel, risksMedium))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingAccepted(parsedModel, risksMedium))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInProgress(parsedModel, risksMedium))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingMitigated(parsedModel, risksMedium))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingFalsePositive(parsedModel, risksMedium))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.ElevatedSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(types.ReduceToOnlyRiskTrackingUnchecked(parsedModel, risksElevated))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInDiscussion(parsedModel, risksElevated))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingAccepted(parsedModel, risksElevated))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInProgress(parsedModel, risksElevated))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingMitigated(parsedModel, risksElevated))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingFalsePositive(parsedModel, risksElevated))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.HighSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(types.ReduceToOnlyRiskTrackingUnchecked(parsedModel, risksHigh))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInDiscussion(parsedModel, risksHigh))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingAccepted(parsedModel, risksHigh))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInProgress(parsedModel, risksHigh))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingMitigated(parsedModel, risksHigh))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingFalsePositive(parsedModel, risksHigh))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
			{
				Name:  types.CriticalSeverity.Title(),
				Width: 130,
				Values: []chart.Value{
					{Value: float64(len(types.ReduceToOnlyRiskTrackingUnchecked(parsedModel, risksCritical))), Label: types.Unchecked.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusUnchecked()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInDiscussion(parsedModel, risksCritical))), Label: types.InDiscussion.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusInDiscussion()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingAccepted(parsedModel, risksCritical))), Label: types.Accepted.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusAccepted()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingInProgress(parsedModel, risksCritical))), Label: types.InProgress.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusInProgress()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingMitigated(parsedModel, risksCritical))), Label: types.Mitigated.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusMitigated()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
					{Value: float64(len(types.ReduceToOnlyRiskTrackingFalsePositive(parsedModel, risksCritical))), Label: types.FalsePositive.Title(),
						Style: chart.Style{FillColor: makeColor(colors.RgbHexColorRiskStatusFalsePositive()).WithAlpha(98), StrokeColor: drawing.ColorFromHex("999")}},
				},
			},
		},
	}

	y := pdf.GetY() + 12
	embedStackedBarChart(stackedBarChartRiskTracking, 15.0, y, tempFolder)

	// draw the X-Axis legend on my own
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdfColorBlack()
	pdf.Text(24.02, 169, "Low ("+strconv.Itoa(len(risksLow))+")")
	pdf.Text(46.10, 169, "Medium ("+strconv.Itoa(len(risksMedium))+")")
	pdf.Text(69.74, 169, "Elevated ("+strconv.Itoa(len(risksElevated))+")")
	pdf.Text(97.95, 169, "High ("+strconv.Itoa(len(risksHigh))+")")
	pdf.Text(121.65, 169, "Critical ("+strconv.Itoa(len(risksCritical))+")")

	pdf.SetFont("Helvetica", "B", fontSizeBody)
	pdf.Ln(20)

	colors.ColorRiskStatusUnchecked(pdf)
	pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countStatusUnchecked), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "unchecked", "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	colors.ColorRiskStatusInDiscussion(pdf)
	pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countStatusInDiscussion), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "in discussion", "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	colors.ColorRiskStatusAccepted(pdf)
	pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countStatusAccepted), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "accepted", "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	colors.ColorRiskStatusInProgress(pdf)
	pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countStatusInProgress), "0", 0, "R", false, 0, "")
	pdf.CellFormat(60, 6, "in progress", "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	colors.ColorRiskStatusMitigated(pdf)
	pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countStatusMitigated), "0", 0, "R", false, 0, "")
	pdf.SetFont("Helvetica", "BI", fontSizeBody)
	pdf.CellFormat(60, 6, "mitigated", "0", 0, "", false, 0, "")
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	pdf.Ln(-1)
	colors.ColorRiskStatusFalsePositive(pdf)
	pdf.CellFormat(150, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(10, 6, strconv.Itoa(countStatusFalsePositive), "0", 0, "R", false, 0, "")
	pdf.SetFont("Helvetica", "BI", fontSizeBody)
	pdf.CellFormat(60, 6, "false positive", "0", 0, "", false, 0, "")
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	pdf.Ln(-1)

	pdf.SetFont("Helvetica", "", fontSizeBody)

	pdfColorBlack()
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
						FillColor: makeColor(colors.RgbHexColorLowRisk()).WithAlpha(98),
						//FontColor: makeColor(colors.RgbHexColorLowRisk()),
						FontSize: 65}},
				{Value: float64(countMedium), //Label: strconv.Itoa(countMedium) + " Medium",
					Style: chart.Style{
						FillColor: makeColor(colors.RgbHexColorMediumRisk()).WithAlpha(98),
						//FontColor: makeColor(colors.RgbHexColorMediumRisk()),
						FontSize: 65}},
				{Value: float64(countElevated), //Label: strconv.Itoa(countElevated) + " Elevated",
					Style: chart.Style{
						FillColor: makeColor(colors.RgbHexColorElevatedRisk()).WithAlpha(98),
						//FontColor: makeColor(colors.RgbHexColorElevatedRisk()),
						FontSize: 65}},
				{Value: float64(countHigh), //Label: strconv.Itoa(countHigh) + " High",
					Style: chart.Style{
						FillColor: makeColor(colors.RgbHexColorHighRisk()).WithAlpha(98),
						//FontColor: makeColor(colors.RgbHexColorHighRisk()),
						FontSize: 65}},
				{Value: float64(countCritical), //Label: strconv.Itoa(countCritical) + " Critical",
					Style: chart.Style{
						FillColor: makeColor(colors.RgbHexColorCriticalRisk()).WithAlpha(98),
						//FontColor: makeColor(colors.RgbHexColorCriticalRisk()),
						FontSize: 65}},
			},
		}

		pieChartRemainingRisksByFunction := chart.PieChart{
			Width:  1500,
			Height: 1500,
			Values: []chart.Value{
				{Value: float64(countBusinessSide),
					Style: chart.Style{
						FillColor: makeColor(colors.RgbHexColorBusiness()).WithAlpha(98),
						FontSize:  65}},
				{Value: float64(countArchitecture),
					Style: chart.Style{
						FillColor: makeColor(colors.RgbHexColorArchitecture()).WithAlpha(98),
						FontSize:  65}},
				{Value: float64(countDevelopment),
					Style: chart.Style{
						FillColor: makeColor(colors.RgbHexColorDevelopment()).WithAlpha(98),
						FontSize:  65}},
				{Value: float64(countOperation),
					Style: chart.Style{
						FillColor: makeColor(colors.RgbHexColorOperation()).WithAlpha(98),
						FontSize:  65}},
			},
		}

		embedPieChart(pieChartRemainingRiskSeverity, 15.0, 216, tempFolder)
		embedPieChart(pieChartRemainingRisksByFunction, 110.0, 216, tempFolder)

		pdf.SetFont("Helvetica", "B", fontSizeBody)
		pdf.Ln(8)

		colors.ColorCriticalRisk(pdf)
		pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(10, 6, strconv.Itoa(countCritical), "0", 0, "R", false, 0, "")
		pdf.CellFormat(60, 6, "unmitigated critical risk", "0", 0, "", false, 0, "")
		pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(10, 6, "", "0", 0, "R", false, 0, "")
		pdf.CellFormat(60, 6, "", "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		colors.ColorHighRisk(pdf)
		pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(10, 6, strconv.Itoa(countHigh), "0", 0, "R", false, 0, "")
		pdf.CellFormat(60, 6, "unmitigated high risk", "0", 0, "", false, 0, "")
		colors.ColorBusiness(pdf)
		pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(10, 6, strconv.Itoa(countBusinessSide), "0", 0, "R", false, 0, "")
		pdf.CellFormat(60, 6, "business side related", "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		colors.ColorElevatedRisk(pdf)
		pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(10, 6, strconv.Itoa(countElevated), "0", 0, "R", false, 0, "")
		pdf.CellFormat(60, 6, "unmitigated elevated risk", "0", 0, "", false, 0, "")
		colors.ColorArchitecture(pdf)
		pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(10, 6, strconv.Itoa(countArchitecture), "0", 0, "R", false, 0, "")
		pdf.CellFormat(60, 6, "architecture related", "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		colors.ColorMediumRisk(pdf)
		pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(10, 6, strconv.Itoa(countMedium), "0", 0, "R", false, 0, "")
		pdf.CellFormat(60, 6, "unmitigated medium risk", "0", 0, "", false, 0, "")
		colors.ColorDevelopment(pdf)
		pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(10, 6, strconv.Itoa(countDevelopment), "0", 0, "R", false, 0, "")
		pdf.CellFormat(60, 6, "development related", "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		colors.ColorLowRisk(pdf)
		pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(10, 6, strconv.Itoa(countLow), "0", 0, "R", false, 0, "")
		pdf.CellFormat(60, 6, "unmitigated low risk", "0", 0, "", false, 0, "")
		colors.ColorOperation(pdf)
		pdf.CellFormat(22, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(10, 6, strconv.Itoa(countOperation), "0", 0, "R", false, 0, "")
		pdf.CellFormat(60, 6, "operations related", "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "", fontSizeBody)
	}
}

// CAUTION: Long labels might cause endless loop, then remove labels and render them manually later inside the PDF
func embedStackedBarChart(sbcChart chart.StackedBarChart, x float64, y float64, tempFolder string) {
	tmpFilePNG, err := os.CreateTemp(tempFolder, "chart-*-.png")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()
	file, _ := os.Create(tmpFilePNG.Name())
	defer func() { _ = file.Close() }()
	err = sbcChart.Render(chart.PNG, file)
	checkErr(err)
	var options gofpdf.ImageOptions
	options.ImageType = ""
	pdf.RegisterImage(tmpFilePNG.Name(), "")
	pdf.ImageOptions(tmpFilePNG.Name(), x, y, 0, 110, false, options, 0, "")
}

func embedPieChart(pieChart chart.PieChart, x float64, y float64, tempFolder string) {
	tmpFilePNG, err := os.CreateTemp(tempFolder, "chart-*-.png")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()
	file, err := os.Create(tmpFilePNG.Name())
	checkErr(err)
	defer func() { _ = file.Close() }()
	err = pieChart.Render(chart.PNG, file)
	checkErr(err)
	var options gofpdf.ImageOptions
	options.ImageType = ""
	pdf.RegisterImage(tmpFilePNG.Name(), "")
	pdf.ImageOptions(tmpFilePNG.Name(), x, y, 60, 0, false, options, 0, "")
}

func makeColor(hexColor string) drawing.Color {
	_, i := utf8.DecodeRuneInString(hexColor)
	return drawing.ColorFromHex(hexColor[i:]) // = remove first char, which is # in rgb hex here
}

func createImpactInitialRisks(parsedModel *types.ParsedModel) {
	renderImpactAnalysis(parsedModel, true)
}

func createImpactRemainingRisks(parsedModel *types.ParsedModel) {
	renderImpactAnalysis(parsedModel, false)
}

func renderImpactAnalysis(parsedModel *types.ParsedModel, initialRisks bool) {
	pdf.SetTextColor(0, 0, 0)
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
		addHeadline(chapTitle, false)
		defineLinkTarget("{impact-analysis-initial-risks}")
		currentChapterTitleBreadcrumb = chapTitle
	} else {
		chapTitle := "Impact Analysis of " + strconv.Itoa(count) + " Remaining " + riskStr + " in " + strconv.Itoa(catCount) + " " + catStr
		addHeadline(chapTitle, false)
		defineLinkTarget("{impact-analysis-remaining-risks}")
		currentChapterTitleBreadcrumb = chapTitle
	}

	html := pdf.HTMLBasicNew()
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
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdfColorGray()
	html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
	pdf.SetFont("Helvetica", "", fontSizeBody)

	addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, parsedModel.GeneratedRisksByCategory, initialRisks)),
		types.CriticalSeverity, false, initialRisks, true, false)
	addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, parsedModel.GeneratedRisksByCategory, initialRisks)),
		types.HighSeverity, false, initialRisks, true, false)
	addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, parsedModel.GeneratedRisksByCategory, initialRisks)),
		types.ElevatedSeverity, false, initialRisks, true, false)
	addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, parsedModel.GeneratedRisksByCategory, initialRisks)),
		types.MediumSeverity, false, initialRisks, true, false)
	addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, parsedModel.GeneratedRisksByCategory, initialRisks)),
		types.LowSeverity, false, initialRisks, true, false)

	pdf.SetDrawColor(0, 0, 0)
	pdf.SetDashPattern([]float64{}, 0)
}

func createOutOfScopeAssets(parsedModel *types.ParsedModel) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.SetTextColor(0, 0, 0)
	assets := "Assets"
	count := len(parsedModel.OutOfScopeTechnicalAssets())
	if count == 1 {
		assets = "Asset"
	}
	chapTitle := "Out-of-Scope Assets: " + strconv.Itoa(count) + " " + assets
	addHeadline(chapTitle, false)
	defineLinkTarget("{out-of-scope-assets}")
	currentChapterTitleBreadcrumb = chapTitle

	html := pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	strBuilder.WriteString("This chapter lists all technical assets that have been defined as out-of-scope. " +
		"Each one should be checked in the model whether it should better be included in the " +
		"overall risk analysis:<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdfColorGray()
	html.Write(5, "Technical asset paragraphs are clickable and link to the corresponding chapter.")
	pdf.SetFont("Helvetica", "", fontSizeBody)

	outOfScopeAssetCount := 0
	for _, technicalAsset := range sortedTechnicalAssetsByRAAAndTitle(parsedModel) {
		if technicalAsset.OutOfScope {
			outOfScopeAssetCount++
			if pdf.GetY() > 250 {
				pageBreak()
				pdf.SetY(36)
			} else {
				strBuilder.WriteString("<br><br>")
			}
			html.Write(5, strBuilder.String())
			strBuilder.Reset()
			posY := pdf.GetY()
			pdfColorOutOfScope()
			strBuilder.WriteString("<b>")
			strBuilder.WriteString(uni(technicalAsset.Title))
			strBuilder.WriteString("</b>")
			strBuilder.WriteString(": out-of-scope")
			strBuilder.WriteString("<br>")
			html.Write(5, strBuilder.String())
			strBuilder.Reset()
			pdf.SetTextColor(0, 0, 0)
			strBuilder.WriteString(uni(technicalAsset.JustificationOutOfScope))
			html.Write(5, strBuilder.String())
			strBuilder.Reset()
			pdf.Link(9, posY, 190, pdf.GetY()-posY+4, tocLinkIdByAssetId[technicalAsset.Id])
		}
	}

	if outOfScopeAssetCount == 0 {
		pdfColorGray()
		html.Write(5, "<br><br>No technical assets have been defined as out-of-scope.")
	}

	pdf.SetDrawColor(0, 0, 0)
	pdf.SetDashPattern([]float64{}, 0)
}

func sortedTechnicalAssetsByRAAAndTitle(parsedModel *types.ParsedModel) []types.TechnicalAsset {
	assets := make([]types.TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		assets = append(assets, asset)
	}
	sort.Sort(types.ByTechnicalAssetRAAAndTitleSort(assets))
	return assets
}

func createModelFailures(parsedModel *types.ParsedModel) {
	pdf.SetTextColor(0, 0, 0)
	modelFailures := types.FlattenRiskSlice(types.FilterByModelFailures(parsedModel, parsedModel.GeneratedRisksByCategory))
	risksStr := "Risks"
	count := len(modelFailures)
	if count == 1 {
		risksStr = "Risk"
	}
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, modelFailures))
	if countStillAtRisk > 0 {
		colors.ColorModelFailure(pdf)
	}
	chapTitle := "Potential Model Failures: " + strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(count) + " " + risksStr
	addHeadline(chapTitle, false)
	defineLinkTarget("{model-failures}")
	currentChapterTitleBreadcrumb = chapTitle
	pdfColorBlack()

	html := pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	strBuilder.WriteString("This chapter lists potential model failures where not all relevant assets have been " +
		"modeled or the model might itself contain inconsistencies. Each potential model failure should be checked " +
		"in the model against the architecture design:<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdfColorGray()
	html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
	pdf.SetFont("Helvetica", "", fontSizeBody)

	modelFailuresByCategory := types.FilterByModelFailures(parsedModel, parsedModel.GeneratedRisksByCategory)
	if len(modelFailuresByCategory) == 0 {
		pdfColorGray()
		html.Write(5, "<br><br>No potential model failures have been identified.")
	} else {
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, modelFailuresByCategory, true)),
			types.CriticalSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, modelFailuresByCategory, true)),
			types.HighSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, modelFailuresByCategory, true)),
			types.ElevatedSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, modelFailuresByCategory, true)),
			types.MediumSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, modelFailuresByCategory, true)),
			types.LowSeverity, true, true, false, true)
	}

	pdf.SetDrawColor(0, 0, 0)
	pdf.SetDashPattern([]float64{}, 0)
}

func createRAA(parsedModel *types.ParsedModel, introTextRAA string) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.SetTextColor(0, 0, 0)
	chapTitle := "RAA Analysis"
	addHeadline(chapTitle, false)
	defineLinkTarget("{raa-analysis}")
	currentChapterTitleBreadcrumb = chapTitle

	html := pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	strBuilder.WriteString(introTextRAA)
	strBuilder.WriteString("<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdfColorGray()
	html.Write(5, "Technical asset paragraphs are clickable and link to the corresponding chapter.")
	pdf.SetFont("Helvetica", "", fontSizeBody)

	for _, technicalAsset := range sortedTechnicalAssetsByRAAAndTitle(parsedModel) {
		if technicalAsset.OutOfScope {
			continue
		}
		if pdf.GetY() > 250 {
			pageBreak()
			pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}
		newRisksStr := technicalAsset.GeneratedRisks(parsedModel)
		switch types.HighestSeverityStillAtRisk(parsedModel, newRisksStr) {
		case types.HighSeverity:
			colors.ColorHighRisk(pdf)
		case types.MediumSeverity:
			colors.ColorMediumRisk(pdf)
		case types.LowSeverity:
			colors.ColorLowRisk(pdf)
		default:
			pdfColorBlack()
		}
		if len(types.ReduceToOnlyStillAtRisk(parsedModel, newRisksStr)) == 0 {
			pdfColorBlack()
		}

		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := pdf.GetY()
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
		pdf.SetTextColor(0, 0, 0)
		strBuilder.WriteString(uni(technicalAsset.Description))
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		pdf.Link(9, posY, 190, pdf.GetY()-posY+4, tocLinkIdByAssetId[technicalAsset.Id])
	}

	pdf.SetDrawColor(0, 0, 0)
	pdf.SetDashPattern([]float64{}, 0)
}

/*
func createDataRiskQuickWins() {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.SetTextColor(0, 0, 0)
	assets := "assets"
	count := len(model.SortedTechnicalAssetsByQuickWinsAndTitle())
	if count == 1 {
		assets = "asset"
	}
	chapTitle := "Data Risk Quick Wins: " + strconv.Itoa(count) + " " + assets
	addHeadline(chapTitle, false)
	defineLinkTarget("{data-risk-quick-wins}")
	currentChapterTitleBreadcrumb = chapTitle

	html := pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	strBuilder.WriteString("For each technical asset it was checked how many data assets at risk might " +
		"get their risk-rating reduced (partly or fully) when the risks of the technical asset are mitigated. " +
		"In general, that means the higher the quick win value is, the more data assets (left side of the Data Risk Mapping diagram) " +
		"turn from red to amber or from amber to blue by mitigating the technical asset's risks. " +
		"This list can be used to prioritize on efforts with the greatest effects of reducing data asset risks:<br>")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdfColorGray()
	html.Write(5, "Technical asset paragraphs are clickable and link to the corresponding chapter.")
	pdf.SetFont("Helvetica", "", fontSizeBody)

	for _, technicalAsset := range model.SortedTechnicalAssetsByQuickWinsAndTitle() {
		quickWins := technicalAsset.QuickWins()
		if pdf.GetY() > 260 {
			pageBreak()
			pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}
		risks := technicalAsset.GeneratedRisks()
		switch model.HighestSeverityStillAtRisk(risks) {
		case model.High:
			colors.ColorHighRisk(pdf)
		case model.Medium:
			colors.ColorMediumRisk(pdf)
		case model.Low:
			colors.ColorLowRisk(pdf)
		default:
			pdfColorBlack()
		}
		if len(model.ReduceToOnlyStillAtRisk(risks)) == 0 {
			pdfColorBlack()
		}

		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := pdf.GetY()
		strBuilder.WriteString("<b>")
		strBuilder.WriteString(uni(technicalAsset.Title))
		strBuilder.WriteString("</b>")
		strBuilder.WriteString(": ")
		strBuilder.WriteString(fmt.Sprintf("%.2f", quickWins))
		strBuilder.WriteString(" Quick Wins")
		strBuilder.WriteString("<br>")
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		pdf.SetTextColor(0, 0, 0)
		strBuilder.WriteString(uni(technicalAsset.Description))
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		pdf.Link(9, posY, 190, pdf.GetY()-posY+4, tocLinkIdByAssetId[technicalAsset.Id])
	}

	pdf.SetDrawColor(0, 0, 0)
	pdf.SetDashPattern([]float64{}, 0)
}
*/

func addCategories(parsedModel *types.ParsedModel, riskCategories []types.RiskCategory, severity types.RiskSeverity, bothInitialAndRemainingRisks bool, initialRisks bool, describeImpact bool, describeDescription bool) {
	html := pdf.HTMLBasicNew()
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
		if pdf.GetY() > 250 {
			pageBreak()
			pdf.SetY(36)
		} else {
			strBuilder.WriteString("<br><br>")
		}
		var prefix string
		switch severity {
		case types.CriticalSeverity:
			colors.ColorCriticalRisk(pdf)
			prefix = "Critical: "
		case types.HighSeverity:
			colors.ColorHighRisk(pdf)
			prefix = "High: "
		case types.ElevatedSeverity:
			colors.ColorElevatedRisk(pdf)
			prefix = "Elevated: "
		case types.MediumSeverity:
			colors.ColorMediumRisk(pdf)
			prefix = "Medium: "
		case types.LowSeverity:
			colors.ColorLowRisk(pdf)
			prefix = "Low: "
		default:
			pdfColorBlack()
			prefix = ""
		}
		switch types.HighestSeverityStillAtRisk(parsedModel, risksStr) {
		case types.CriticalSeverity:
			colors.ColorCriticalRisk(pdf)
		case types.HighSeverity:
			colors.ColorHighRisk(pdf)
		case types.ElevatedSeverity:
			colors.ColorElevatedRisk(pdf)
		case types.MediumSeverity:
			colors.ColorMediumRisk(pdf)
		case types.LowSeverity:
			colors.ColorLowRisk(pdf)
		}
		if len(types.ReduceToOnlyStillAtRisk(parsedModel, risksStr)) == 0 {
			pdfColorBlack()
		}
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		posY := pdf.GetY()
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
		pdf.SetTextColor(0, 0, 0)
		if describeImpact {
			strBuilder.WriteString(firstParagraph(riskCategory.Impact))
		} else if describeDescription {
			strBuilder.WriteString(firstParagraph(riskCategory.Description))
		} else {
			strBuilder.WriteString(firstParagraph(riskCategory.Mitigation))
		}
		html.Write(5, strBuilder.String())
		strBuilder.Reset()
		pdf.Link(9, posY, 190, pdf.GetY()-posY+4, tocLinkIdByAssetId[riskCategory.Id])
	}
}

func firstParagraph(text string) string {
	match := firstParagraphRegEx.FindStringSubmatch(text)
	if len(match) == 0 {
		return text
	}
	return match[1]
}

func createAssignmentByFunction(parsedModel *types.ParsedModel) {
	pdf.SetTextColor(0, 0, 0)
	title := "Assignment by Function"
	addHeadline(title, false)
	defineLinkTarget("{function-assignment}")
	currentChapterTitleBreadcrumb = title

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
	html := pdf.HTMLBasicNew()
	html.Write(5, intro.String())
	intro.Reset()
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdfColorGray()
	html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
	pdf.SetFont("Helvetica", "", fontSizeBody)

	oldLeft, _, _, _ := pdf.GetMargins()

	if pdf.GetY() > 250 {
		pageBreak()
		pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.BusinessSide.Title()+"</b>")
	pdf.SetLeftMargin(15)
	if len(risksBusinessSideFunction) == 0 {
		pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksBusinessSideFunction, true)),
			types.CriticalSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksBusinessSideFunction, true)),
			types.HighSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksBusinessSideFunction, true)),
			types.ElevatedSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksBusinessSideFunction, true)),
			types.MediumSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksBusinessSideFunction, true)),
			types.LowSeverity, true, true, false, false)
	}
	pdf.SetLeftMargin(oldLeft)

	if pdf.GetY() > 250 {
		pageBreak()
		pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Architecture.Title()+"</b>")
	pdf.SetLeftMargin(15)
	if len(risksArchitectureFunction) == 0 {
		pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksArchitectureFunction, true)),
			types.CriticalSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksArchitectureFunction, true)),
			types.HighSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksArchitectureFunction, true)),
			types.ElevatedSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksArchitectureFunction, true)),
			types.MediumSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksArchitectureFunction, true)),
			types.LowSeverity, true, true, false, false)
	}
	pdf.SetLeftMargin(oldLeft)

	if pdf.GetY() > 250 {
		pageBreak()
		pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Development.Title()+"</b>")
	pdf.SetLeftMargin(15)
	if len(risksDevelopmentFunction) == 0 {
		pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksDevelopmentFunction, true)),
			types.CriticalSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksDevelopmentFunction, true)),
			types.HighSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksDevelopmentFunction, true)),
			types.ElevatedSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksDevelopmentFunction, true)),
			types.MediumSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksDevelopmentFunction, true)),
			types.LowSeverity, true, true, false, false)
	}
	pdf.SetLeftMargin(oldLeft)

	if pdf.GetY() > 250 {
		pageBreak()
		pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Operations.Title()+"</b>")
	pdf.SetLeftMargin(15)
	if len(risksOperationFunction) == 0 {
		pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksOperationFunction, true)),
			types.CriticalSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksOperationFunction, true)),
			types.HighSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksOperationFunction, true)),
			types.ElevatedSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksOperationFunction, true)),
			types.MediumSeverity, true, true, false, false)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksOperationFunction, true)),
			types.LowSeverity, true, true, false, false)
	}
	pdf.SetLeftMargin(oldLeft)

	pdf.SetDrawColor(0, 0, 0)
	pdf.SetDashPattern([]float64{}, 0)
}

func createSTRIDE(parsedModel *types.ParsedModel) {
	pdf.SetTextColor(0, 0, 0)
	title := "STRIDE Classification of Identified Risks"
	addHeadline(title, false)
	defineLinkTarget("{stride}")
	currentChapterTitleBreadcrumb = title

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
	html := pdf.HTMLBasicNew()
	html.Write(5, intro.String())
	intro.Reset()
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdfColorGray()
	html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
	pdf.SetFont("Helvetica", "", fontSizeBody)

	oldLeft, _, _, _ := pdf.GetMargins()

	if pdf.GetY() > 250 {
		pageBreak()
		pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Spoofing.Title()+"</b>")
	pdf.SetLeftMargin(15)
	if len(risksSTRIDESpoofing) == 0 {
		pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksSTRIDESpoofing, true)),
			types.CriticalSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksSTRIDESpoofing, true)),
			types.HighSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksSTRIDESpoofing, true)),
			types.ElevatedSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksSTRIDESpoofing, true)),
			types.MediumSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksSTRIDESpoofing, true)),
			types.LowSeverity, true, true, false, true)
	}
	pdf.SetLeftMargin(oldLeft)

	if pdf.GetY() > 250 {
		pageBreak()
		pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Tampering.Title()+"</b>")
	pdf.SetLeftMargin(15)
	if len(risksSTRIDETampering) == 0 {
		pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksSTRIDETampering, true)),
			types.CriticalSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksSTRIDETampering, true)),
			types.HighSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksSTRIDETampering, true)),
			types.ElevatedSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksSTRIDETampering, true)),
			types.MediumSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksSTRIDETampering, true)),
			types.LowSeverity, true, true, false, true)
	}
	pdf.SetLeftMargin(oldLeft)

	if pdf.GetY() > 250 {
		pageBreak()
		pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.Repudiation.Title()+"</b>")
	pdf.SetLeftMargin(15)
	if len(risksSTRIDERepudiation) == 0 {
		pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksSTRIDERepudiation, true)),
			types.CriticalSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksSTRIDERepudiation, true)),
			types.HighSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksSTRIDERepudiation, true)),
			types.ElevatedSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksSTRIDERepudiation, true)),
			types.MediumSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksSTRIDERepudiation, true)),
			types.LowSeverity, true, true, false, true)
	}
	pdf.SetLeftMargin(oldLeft)

	if pdf.GetY() > 250 {
		pageBreak()
		pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.InformationDisclosure.Title()+"</b>")
	pdf.SetLeftMargin(15)
	if len(risksSTRIDEInformationDisclosure) == 0 {
		pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksSTRIDEInformationDisclosure, true)),
			types.CriticalSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksSTRIDEInformationDisclosure, true)),
			types.HighSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksSTRIDEInformationDisclosure, true)),
			types.ElevatedSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksSTRIDEInformationDisclosure, true)),
			types.MediumSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksSTRIDEInformationDisclosure, true)),
			types.LowSeverity, true, true, false, true)
	}
	pdf.SetLeftMargin(oldLeft)

	if pdf.GetY() > 250 {
		pageBreak()
		pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.DenialOfService.Title()+"</b>")
	pdf.SetLeftMargin(15)
	if len(risksSTRIDEDenialOfService) == 0 {
		pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksSTRIDEDenialOfService, true)),
			types.CriticalSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksSTRIDEDenialOfService, true)),
			types.HighSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksSTRIDEDenialOfService, true)),
			types.ElevatedSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksSTRIDEDenialOfService, true)),
			types.MediumSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksSTRIDEDenialOfService, true)),
			types.LowSeverity, true, true, false, true)
	}
	pdf.SetLeftMargin(oldLeft)

	if pdf.GetY() > 250 {
		pageBreak()
		pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetTextColor(0, 0, 0)
	html.Write(5, "<b>"+types.ElevationOfPrivilege.Title()+"</b>")
	pdf.SetLeftMargin(15)
	if len(risksSTRIDEElevationOfPrivilege) == 0 {
		pdf.SetTextColor(150, 150, 150)
		html.Write(5, "<br><br>n/a")
	} else {
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyCriticalRisks(parsedModel, risksSTRIDEElevationOfPrivilege, true)),
			types.CriticalSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyHighRisks(parsedModel, risksSTRIDEElevationOfPrivilege, true)),
			types.HighSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyElevatedRisks(parsedModel, risksSTRIDEElevationOfPrivilege, true)),
			types.ElevatedSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyMediumRisks(parsedModel, risksSTRIDEElevationOfPrivilege, true)),
			types.MediumSeverity, true, true, false, true)
		addCategories(parsedModel, types.GetRiskCategories(parsedModel, types.CategoriesOfOnlyLowRisks(parsedModel, risksSTRIDEElevationOfPrivilege, true)),
			types.LowSeverity, true, true, false, true)
	}
	pdf.SetLeftMargin(oldLeft)

	pdf.SetDrawColor(0, 0, 0)
	pdf.SetDashPattern([]float64{}, 0)
}

func createSecurityRequirements(parsedModel *types.ParsedModel) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.SetTextColor(0, 0, 0)
	chapTitle := "Security Requirements"
	addHeadline(chapTitle, false)
	defineLinkTarget("{security-requirements}")
	currentChapterTitleBreadcrumb = chapTitle

	html := pdf.HTMLBasicNew()
	html.Write(5, "This chapter lists the custom security requirements which have been defined for the modeled target.")
	pdfColorBlack()
	for _, title := range sortedKeysOfSecurityRequirements(parsedModel) {
		description := parsedModel.SecurityRequirements[title]
		if pdf.GetY() > 250 {
			pageBreak()
			pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		html.Write(5, "<b>"+uni(title)+"</b><br>")
		html.Write(5, uni(description))
	}
	if pdf.GetY() > 250 {
		pageBreak()
		pdf.SetY(36)
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

func createAbuseCases(parsedModel *types.ParsedModel) {
	pdf.SetTextColor(0, 0, 0)
	chapTitle := "Abuse Cases"
	addHeadline(chapTitle, false)
	defineLinkTarget("{abuse-cases}")
	currentChapterTitleBreadcrumb = chapTitle

	html := pdf.HTMLBasicNew()
	html.Write(5, "This chapter lists the custom abuse cases which have been defined for the modeled target.")
	pdfColorBlack()
	for _, title := range sortedKeysOfAbuseCases(parsedModel) {
		description := parsedModel.AbuseCases[title]
		if pdf.GetY() > 250 {
			pageBreak()
			pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		html.Write(5, "<b>"+title+"</b><br>")
		html.Write(5, description)
	}
	if pdf.GetY() > 250 {
		pageBreak()
		pdf.SetY(36)
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

func createQuestions(parsedModel *types.ParsedModel) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.SetTextColor(0, 0, 0)
	questions := "Questions"
	count := len(parsedModel.Questions)
	if count == 1 {
		questions = "Question"
	}
	if questionsUnanswered(parsedModel) > 0 {
		colors.ColorModelFailure(pdf)
	}
	chapTitle := "Questions: " + strconv.Itoa(questionsUnanswered(parsedModel)) + " / " + strconv.Itoa(count) + " " + questions
	addHeadline(chapTitle, false)
	defineLinkTarget("{questions}")
	currentChapterTitleBreadcrumb = chapTitle
	pdfColorBlack()

	html := pdf.HTMLBasicNew()
	html.Write(5, "This chapter lists custom questions that arose during the threat modeling process.")

	if len(parsedModel.Questions) == 0 {
		pdfColorLightGray()
		html.Write(5, "<br><br><br>")
		html.Write(5, "No custom questions arose during the threat modeling process.")
	}
	pdfColorBlack()
	for _, question := range sortedKeysOfQuestions(parsedModel) {
		answer := parsedModel.Questions[question]
		if pdf.GetY() > 250 {
			pageBreak()
			pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		pdfColorBlack()
		if len(strings.TrimSpace(answer)) > 0 {
			html.Write(5, "<b>"+uni(question)+"</b><br>")
			html.Write(5, "<i>"+uni(strings.TrimSpace(answer))+"</i>")
		} else {
			colors.ColorModelFailure(pdf)
			html.Write(5, "<b>"+uni(question)+"</b><br>")
			pdfColorLightGray()
			html.Write(5, "<i>- answer pending -</i>")
			pdfColorBlack()
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

func createTagListing(parsedModel *types.ParsedModel) {
	pdf.SetTextColor(0, 0, 0)
	chapTitle := "Tag Listing"
	addHeadline(chapTitle, false)
	defineLinkTarget("{tag-listing}")
	currentChapterTitleBreadcrumb = chapTitle

	html := pdf.HTMLBasicNew()
	html.Write(5, "This chapter lists what tags are used by which elements.")
	pdfColorBlack()
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
			if pdf.GetY() > 250 {
				pageBreak()
				pdf.SetY(36)
			} else {
				html.Write(5, "<br><br><br>")
			}
			pdfColorBlack()
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

func createRiskCategories(parsedModel *types.ParsedModel) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	// category title
	title := "Identified Risks by Vulnerability Category"
	pdfColorBlack()
	addHeadline(title, false)
	defineLinkTarget("{intro-risks-by-vulnerability-category}")
	html := pdf.HTMLBasicNew()
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
	currentChapterTitleBreadcrumb = title
	for _, category := range types.SortedRiskCategories(parsedModel) {
		risksStr := types.SortedRisksOfCategory(parsedModel, category)

		// category color
		switch types.HighestSeverityStillAtRisk(parsedModel, risksStr) {
		case types.CriticalSeverity:
			colors.ColorCriticalRisk(pdf)
		case types.HighSeverity:
			colors.ColorHighRisk(pdf)
		case types.ElevatedSeverity:
			colors.ColorElevatedRisk(pdf)
		case types.MediumSeverity:
			colors.ColorMediumRisk(pdf)
		case types.LowSeverity:
			colors.ColorLowRisk(pdf)
		default:
			pdfColorBlack()
		}
		if len(types.ReduceToOnlyStillAtRisk(parsedModel, risksStr)) == 0 {
			pdfColorBlack()
		}

		// category title
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		title := category.Title + ": " + suffix
		addHeadline(uni(title), true)
		pdfColorBlack()
		defineLinkTarget("{" + category.Id + "}")
		currentChapterTitleBreadcrumb = title

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
		colors.ColorRiskStatusFalsePositive(pdf)
		text.WriteString("<br><br><br><b>False Positives</b><br><br>")
		text.WriteString(category.FalsePositives)
		html.Write(5, text.String())
		text.Reset()
		colors.ColorRiskStatusMitigated(pdf)
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
		pdf.SetTextColor(0, 0, 0)

		// risk details
		pageBreak()
		pdf.SetY(36)
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
		pdf.SetFont("Helvetica", "", fontSizeSmall)
		pdfColorGray()
		html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.<br>")
		pdf.SetFont("Helvetica", "", fontSizeBody)
		oldLeft, _, _, _ := pdf.GetMargins()
		headlineCriticalWritten, headlineHighWritten, headlineElevatedWritten, headlineMediumWritten, headlineLowWritten := false, false, false, false, false
		for _, risk := range risksStr {
			text.WriteString("<br>")
			html.Write(5, text.String())
			text.Reset()
			if pdf.GetY() > 250 {
				pageBreak()
				pdf.SetY(36)
			}
			switch risk.Severity {
			case types.CriticalSeverity:
				colors.ColorCriticalRisk(pdf)
				if !headlineCriticalWritten {
					pdf.SetFont("Helvetica", "", fontSizeBody)
					pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>Critical Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineCriticalWritten = true
				}
			case types.HighSeverity:
				colors.ColorHighRisk(pdf)
				if !headlineHighWritten {
					pdf.SetFont("Helvetica", "", fontSizeBody)
					pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>High Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineHighWritten = true
				}
			case types.ElevatedSeverity:
				colors.ColorElevatedRisk(pdf)
				if !headlineElevatedWritten {
					pdf.SetFont("Helvetica", "", fontSizeBody)
					pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>Elevated Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineElevatedWritten = true
				}
			case types.MediumSeverity:
				colors.ColorMediumRisk(pdf)
				if !headlineMediumWritten {
					pdf.SetFont("Helvetica", "", fontSizeBody)
					pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>Medium Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineMediumWritten = true
				}
			case types.LowSeverity:
				colors.ColorLowRisk(pdf)
				if !headlineLowWritten {
					pdf.SetFont("Helvetica", "", fontSizeBody)
					pdf.SetLeftMargin(oldLeft)
					text.WriteString("<br><b><i>Low Risk Severity</i></b><br><br>")
					html.Write(5, text.String())
					text.Reset()
					headlineLowWritten = true
				}
			default:
				pdfColorBlack()
			}
			if !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
				pdfColorBlack()
			}
			posY := pdf.GetY()
			pdf.SetLeftMargin(oldLeft + 10)
			pdf.SetFont("Helvetica", "", fontSizeBody)
			text.WriteString(uni(risk.Title) + ": Exploitation likelihood is <i>" + risk.ExploitationLikelihood.Title() + "</i> with <i>" + risk.ExploitationImpact.Title() + "</i> impact.")
			text.WriteString("<br>")
			html.Write(5, text.String())
			text.Reset()
			pdfColorGray()
			pdf.SetFont("Helvetica", "", fontSizeVerySmall)
			pdf.MultiCell(215, 5, uni(risk.SyntheticId), "0", "0", false)
			pdf.SetFont("Helvetica", "", fontSizeBody)
			if len(risk.MostRelevantSharedRuntimeId) > 0 {
				pdf.Link(20, posY, 180, pdf.GetY()-posY, tocLinkIdByAssetId[risk.MostRelevantSharedRuntimeId])
			} else if len(risk.MostRelevantTrustBoundaryId) > 0 {
				pdf.Link(20, posY, 180, pdf.GetY()-posY, tocLinkIdByAssetId[risk.MostRelevantTrustBoundaryId])
			} else if len(risk.MostRelevantTechnicalAssetId) > 0 {
				pdf.Link(20, posY, 180, pdf.GetY()-posY, tocLinkIdByAssetId[risk.MostRelevantTechnicalAssetId])
			}
			writeRiskTrackingStatus(parsedModel, risk)
			pdf.SetLeftMargin(oldLeft)
			html.Write(5, text.String())
			text.Reset()
		}
		pdf.SetLeftMargin(oldLeft)
	}
}

func writeRiskTrackingStatus(parsedModel *types.ParsedModel, risk types.Risk) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	tracking := risk.GetRiskTracking(parsedModel)
	pdfColorBlack()
	pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
	switch tracking.Status {
	case types.Unchecked:
		colors.ColorRiskStatusUnchecked(pdf)
	case types.InDiscussion:
		colors.ColorRiskStatusInDiscussion(pdf)
	case types.Accepted:
		colors.ColorRiskStatusAccepted(pdf)
	case types.InProgress:
		colors.ColorRiskStatusInProgress(pdf)
	case types.Mitigated:
		colors.ColorRiskStatusMitigated(pdf)
	case types.FalsePositive:
		colors.ColorRiskStatusFalsePositive(pdf)
	default:
		pdfColorBlack()
	}
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	if tracking.Status == types.Unchecked {
		pdf.SetFont("Helvetica", "B", fontSizeSmall)
	}
	pdf.CellFormat(25, 4, tracking.Status.Title(), "0", 0, "B", false, 0, "")
	if tracking.Status != types.Unchecked {
		dateStr := tracking.Date.Format("2006-01-02")
		if dateStr == "0001-01-01" {
			dateStr = ""
		}
		justificationStr := tracking.Justification
		pdfColorGray()
		pdf.CellFormat(20, 4, dateStr, "0", 0, "B", false, 0, "")
		pdf.CellFormat(35, 4, uni(tracking.CheckedBy), "0", 0, "B", false, 0, "")
		pdf.CellFormat(35, 4, uni(tracking.Ticket), "0", 0, "B", false, 0, "")
		pdf.Ln(-1)
		pdfColorBlack()
		pdf.CellFormat(10, 4, "", "0", 0, "", false, 0, "")
		pdf.MultiCell(170, 4, uni(justificationStr), "0", "0", false)
		pdf.SetFont("Helvetica", "", fontSizeBody)
	} else {
		pdf.Ln(-1)
	}
	pdfColorBlack()
}

func createTechnicalAssets(parsedModel *types.ParsedModel) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	// category title
	title := "Identified Risks by Technical Asset"
	pdfColorBlack()
	addHeadline(title, false)
	defineLinkTarget("{intro-risks-by-technical-asset}")
	html := pdf.HTMLBasicNew()
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
	currentChapterTitleBreadcrumb = title
	for _, technicalAsset := range sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel) {
		risksStr := technicalAsset.GeneratedRisks(parsedModel)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		if technicalAsset.OutOfScope {
			pdfColorOutOfScope()
			suffix = "out-of-scope"
		} else {
			switch types.HighestSeverityStillAtRisk(parsedModel, risksStr) {
			case types.CriticalSeverity:
				colors.ColorCriticalRisk(pdf)
			case types.HighSeverity:
				colors.ColorHighRisk(pdf)
			case types.ElevatedSeverity:
				colors.ColorElevatedRisk(pdf)
			case types.MediumSeverity:
				colors.ColorMediumRisk(pdf)
			case types.LowSeverity:
				colors.ColorLowRisk(pdf)
			default:
				pdfColorBlack()
			}
			if len(types.ReduceToOnlyStillAtRisk(parsedModel, risksStr)) == 0 {
				pdfColorBlack()
			}
		}

		// asset title
		title := technicalAsset.Title + ": " + suffix
		addHeadline(uni(title), true)
		pdfColorBlack()
		defineLinkTarget("{" + technicalAsset.Id + "}")
		currentChapterTitleBreadcrumb = title

		// asset description
		html := pdf.HTMLBasicNew()
		var text strings.Builder
		text.WriteString("<b>Description</b><br><br>")
		text.WriteString(uni(technicalAsset.Description))
		html.Write(5, text.String())
		text.Reset()
		pdf.SetTextColor(0, 0, 0)

		// and more metadata of asset in tabular view
		pdf.Ln(-1)
		pdf.Ln(-1)
		pdf.Ln(-1)
		if pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
			pageBreak()
			pdf.SetY(36)
		}
		pdf.SetFont("Helvetica", "B", fontSizeBody)
		pdfColorBlack()
		pdf.CellFormat(190, 6, "Identified Risks of Asset", "0", 0, "", false, 0, "")
		pdfColorGray()
		oldLeft, _, _, _ := pdf.GetMargins()
		if len(risksStr) > 0 {
			pdf.SetFont("Helvetica", "", fontSizeSmall)
			html.Write(5, "Risk finding paragraphs are clickable and link to the corresponding chapter.")
			pdf.SetFont("Helvetica", "", fontSizeBody)
			pdf.SetLeftMargin(15)
			/*
				pdf.Ln(-1)
				pdf.Ln(-1)
				pdfColorGray()
				pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(185, 6, strconv.Itoa(len(risksStr))+" risksStr in total were identified", "0", 0, "", false, 0, "")
			*/
			headlineCriticalWritten, headlineHighWritten, headlineElevatedWritten, headlineMediumWritten, headlineLowWritten := false, false, false, false, false
			pdf.Ln(-1)
			for _, risk := range risksStr {
				text.WriteString("<br>")
				html.Write(5, text.String())
				text.Reset()
				if pdf.GetY() > 250 { // 250 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
					pageBreak()
					pdf.SetY(36)
				}
				switch risk.Severity {
				case types.CriticalSeverity:
					colors.ColorCriticalRisk(pdf)
					if !headlineCriticalWritten {
						pdf.SetFont("Helvetica", "", fontSizeBody)
						pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>Critical Risk Severity</i></b><br><br>")
						headlineCriticalWritten = true
					}
				case types.HighSeverity:
					colors.ColorHighRisk(pdf)
					if !headlineHighWritten {
						pdf.SetFont("Helvetica", "", fontSizeBody)
						pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>High Risk Severity</i></b><br><br>")
						headlineHighWritten = true
					}
				case types.ElevatedSeverity:
					colors.ColorElevatedRisk(pdf)
					if !headlineElevatedWritten {
						pdf.SetFont("Helvetica", "", fontSizeBody)
						pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>Elevated Risk Severity</i></b><br><br>")
						headlineElevatedWritten = true
					}
				case types.MediumSeverity:
					colors.ColorMediumRisk(pdf)
					if !headlineMediumWritten {
						pdf.SetFont("Helvetica", "", fontSizeBody)
						pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>Medium Risk Severity</i></b><br><br>")
						headlineMediumWritten = true
					}
				case types.LowSeverity:
					colors.ColorLowRisk(pdf)
					if !headlineLowWritten {
						pdf.SetFont("Helvetica", "", fontSizeBody)
						pdf.SetLeftMargin(oldLeft + 3)
						html.Write(5, "<br><b><i>Low Risk Severity</i></b><br><br>")
						headlineLowWritten = true
					}
				default:
					pdfColorBlack()
				}
				if !risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
					pdfColorBlack()
				}
				posY := pdf.GetY()
				pdf.SetLeftMargin(oldLeft + 10)
				pdf.SetFont("Helvetica", "", fontSizeBody)
				text.WriteString(uni(risk.Title) + ": Exploitation likelihood is <i>" + risk.ExploitationLikelihood.Title() + "</i> with <i>" + risk.ExploitationImpact.Title() + "</i> impact.")
				text.WriteString("<br>")
				html.Write(5, text.String())
				text.Reset()

				pdf.SetFont("Helvetica", "", fontSizeVerySmall)
				pdfColorGray()
				pdf.MultiCell(215, 5, uni(risk.SyntheticId), "0", "0", false)
				pdf.Link(20, posY, 180, pdf.GetY()-posY, tocLinkIdByAssetId[risk.CategoryId])
				pdf.SetFont("Helvetica", "", fontSizeBody)
				writeRiskTrackingStatus(parsedModel, risk)
				pdf.SetLeftMargin(oldLeft)
			}
		} else {
			pdf.Ln(-1)
			pdf.Ln(-1)
			pdfColorGray()
			pdf.SetFont("Helvetica", "", fontSizeBody)
			pdf.SetLeftMargin(15)
			text := "No risksStr were identified."
			if technicalAsset.OutOfScope {
				text = "Asset was defined as out-of-scope."
			}
			html.Write(5, text)
			pdf.Ln(-1)
		}
		pdf.SetLeftMargin(oldLeft)

		pdf.Ln(-1)
		pdf.Ln(4)
		if pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorBlack()
		pdf.SetFont("Helvetica", "B", fontSizeBody)
		pdf.CellFormat(190, 6, "Asset Information", "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "", fontSizeBody)
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "ID:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, technicalAsset.Id, "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Type:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, technicalAsset.Type.String(), "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Usage:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, technicalAsset.Usage.String(), "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "RAA:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		textRAA := fmt.Sprintf("%.0f", technicalAsset.RAA) + " %"
		if technicalAsset.OutOfScope {
			pdfColorGray()
			textRAA = "out-of-scope"
		}
		pdf.MultiCell(145, 6, textRAA, "0", "0", false)
		pdfColorBlack()
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Size:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, technicalAsset.Size.String(), "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Technology:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, technicalAsset.Technology.String(), "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Tags:", "0", 0, "", false, 0, "")
		pdfColorBlack()
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
			pdfColorGray()
			tagsUsedText = "none"
		}
		pdf.MultiCell(145, 6, uni(tagsUsedText), "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Internet:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.Internet), "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Machine:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, technicalAsset.Machine.String(), "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Encryption:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, technicalAsset.Encryption.String(), "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Multi-Tenant:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.MultiTenant), "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Redundant:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.Redundant), "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Custom-Developed:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.CustomDevelopedParts), "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Client by Human:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, strconv.FormatBool(technicalAsset.UsedAsClientByHuman), "0", "0", false)
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Data Processed:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		dataAssetsProcessedText := ""
		for _, dataAsset := range technicalAsset.DataAssetsProcessedSorted(parsedModel) {
			if len(dataAssetsProcessedText) > 0 {
				dataAssetsProcessedText += ", "
			}
			dataAssetsProcessedText += dataAsset.Title
		}
		if len(dataAssetsProcessedText) == 0 {
			pdfColorGray()
			dataAssetsProcessedText = "none"
		}
		pdf.MultiCell(145, 6, uni(dataAssetsProcessedText), "0", "0", false)

		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Data Stored:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		dataAssetsStoredText := ""
		for _, dataAsset := range technicalAsset.DataAssetsStoredSorted(parsedModel) {
			if len(dataAssetsStoredText) > 0 {
				dataAssetsStoredText += ", "
			}
			dataAssetsStoredText += dataAsset.Title
		}
		if len(dataAssetsStoredText) == 0 {
			pdfColorGray()
			dataAssetsStoredText = "none"
		}
		pdf.MultiCell(145, 6, uni(dataAssetsStoredText), "0", "0", false)

		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Formats Accepted:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		formatsAcceptedText := ""
		for _, formatAccepted := range technicalAsset.DataFormatsAcceptedSorted() {
			if len(formatsAcceptedText) > 0 {
				formatsAcceptedText += ", "
			}
			formatsAcceptedText += formatAccepted.Title()
		}
		if len(formatsAcceptedText) == 0 {
			pdfColorGray()
			formatsAcceptedText = "none of the special data formats accepted"
		}
		pdf.MultiCell(145, 6, formatsAcceptedText, "0", "0", false)

		pdf.Ln(-1)
		pdf.Ln(4)
		if pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorBlack()
		pdf.SetFont("Helvetica", "B", fontSizeBody)
		pdf.CellFormat(190, 6, "Asset Rating", "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "", fontSizeBody)
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Owner:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, uni(technicalAsset.Owner), "0", "0", false)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Confidentiality:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.CellFormat(40, 6, technicalAsset.Confidentiality.String(), "0", 0, "", false, 0, "")
		pdfColorGray()
		pdf.CellFormat(115, 6, technicalAsset.Confidentiality.RatingStringInScale(), "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.Ln(-1)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Integrity:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.CellFormat(40, 6, technicalAsset.Integrity.String(), "0", 0, "", false, 0, "")
		pdfColorGray()
		pdf.CellFormat(115, 6, technicalAsset.Integrity.RatingStringInScale(), "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.Ln(-1)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Availability:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.CellFormat(40, 6, technicalAsset.Availability.String(), "0", 0, "", false, 0, "")
		pdfColorGray()
		pdf.CellFormat(115, 6, technicalAsset.Availability.RatingStringInScale(), "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.Ln(-1)
		if pdf.GetY() > 270 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "CIA-Justification:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, uni(technicalAsset.JustificationCiaRating), "0", "0", false)

		if technicalAsset.OutOfScope {
			pdf.Ln(-1)
			pdf.Ln(4)
			if pdf.GetY() > 270 {
				pageBreak()
				pdf.SetY(36)
			}
			pdfColorBlack()
			pdf.SetFont("Helvetica", "B", fontSizeBody)
			pdf.CellFormat(190, 6, "Asset Out-of-Scope Justification", "0", 0, "", false, 0, "")
			pdf.Ln(-1)
			pdf.Ln(-1)
			pdf.SetFont("Helvetica", "", fontSizeBody)
			pdf.MultiCell(190, 6, uni(technicalAsset.JustificationOutOfScope), "0", "0", false)
			pdf.Ln(-1)
		}
		pdf.Ln(-1)

		if len(technicalAsset.CommunicationLinks) > 0 {
			pdf.Ln(-1)
			if pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
				pageBreak()
				pdf.SetY(36)
			}
			pdfColorBlack()
			pdf.SetFont("Helvetica", "B", fontSizeBody)
			pdf.CellFormat(190, 6, "Outgoing Communication Links: "+strconv.Itoa(len(technicalAsset.CommunicationLinks)), "0", 0, "", false, 0, "")
			pdf.SetFont("Helvetica", "", fontSizeSmall)
			pdfColorGray()
			html.Write(5, "Target technical asset names are clickable and link to the corresponding chapter.")
			pdf.SetFont("Helvetica", "", fontSizeBody)
			pdf.Ln(-1)
			pdf.Ln(-1)
			pdf.SetFont("Helvetica", "", fontSizeBody)
			for _, outgoingCommLink := range technicalAsset.CommunicationLinksSorted() {
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorBlack()
				pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(185, 6, uni(outgoingCommLink.Title)+" (outgoing)", "0", 0, "", false, 0, "")
				pdf.Ln(-1)
				pdfColorGray()
				pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				pdf.MultiCell(185, 6, uni(outgoingCommLink.Description), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdf.Ln(-1)
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Target:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(125, 6, uni(parsedModel.TechnicalAssets[outgoingCommLink.TargetId].Title), "0", "0", false)
				pdf.Link(60, pdf.GetY()-5, 70, 5, tocLinkIdByAssetId[outgoingCommLink.TargetId])
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Protocol:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, outgoingCommLink.Protocol.String(), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Encrypted:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, strconv.FormatBool(outgoingCommLink.Protocol.IsEncrypted()), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Authentication:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, outgoingCommLink.Authentication.String(), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Authorization:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, outgoingCommLink.Authorization.String(), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Read-Only:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, strconv.FormatBool(outgoingCommLink.Readonly), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Usage:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, outgoingCommLink.Usage.String(), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Tags:", "0", 0, "", false, 0, "")
				pdfColorBlack()
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
					pdfColorGray()
					tagsUsedText = "none"
				}
				pdf.MultiCell(140, 6, uni(tagsUsedText), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "VPN:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, strconv.FormatBool(outgoingCommLink.VPN), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "IP-Filtered:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, strconv.FormatBool(outgoingCommLink.IpFiltered), "0", "0", false)
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Data Sent:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				dataAssetsSentText := ""
				for _, dataAsset := range outgoingCommLink.DataAssetsSentSorted(parsedModel) {
					if len(dataAssetsSentText) > 0 {
						dataAssetsSentText += ", "
					}
					dataAssetsSentText += dataAsset.Title
				}
				if len(dataAssetsSentText) == 0 {
					pdfColorGray()
					dataAssetsSentText = "none"
				}
				pdf.MultiCell(140, 6, uni(dataAssetsSentText), "0", "0", false)
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Data Received:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				dataAssetsReceivedText := ""
				for _, dataAsset := range outgoingCommLink.DataAssetsReceivedSorted(parsedModel) {
					if len(dataAssetsReceivedText) > 0 {
						dataAssetsReceivedText += ", "
					}
					dataAssetsReceivedText += dataAsset.Title
				}
				if len(dataAssetsReceivedText) == 0 {
					pdfColorGray()
					dataAssetsReceivedText = "none"
				}
				pdf.MultiCell(140, 6, uni(dataAssetsReceivedText), "0", "0", false)
				pdf.Ln(-1)
			}
		}

		incomingCommLinks := parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		if len(incomingCommLinks) > 0 {
			pdf.Ln(-1)
			if pdf.GetY() > 260 { // 260 only for major titles (to avoid "Schusterjungen"), for the rest attributes 270
				pageBreak()
				pdf.SetY(36)
			}
			pdfColorBlack()
			pdf.SetFont("Helvetica", "B", fontSizeBody)
			pdf.CellFormat(190, 6, "Incoming Communication Links: "+strconv.Itoa(len(incomingCommLinks)), "0", 0, "", false, 0, "")
			pdf.SetFont("Helvetica", "", fontSizeSmall)
			pdfColorGray()
			html.Write(5, "Source technical asset names are clickable and link to the corresponding chapter.")
			pdf.SetFont("Helvetica", "", fontSizeBody)
			pdf.Ln(-1)
			pdf.Ln(-1)
			pdf.SetFont("Helvetica", "", fontSizeBody)
			for _, incomingCommLink := range incomingCommLinks {
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorBlack()
				pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(185, 6, uni(incomingCommLink.Title)+" (incoming)", "0", 0, "", false, 0, "")
				pdf.Ln(-1)
				pdfColorGray()
				pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
				pdf.MultiCell(185, 6, uni(incomingCommLink.Description), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdf.Ln(-1)
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Source:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, uni(parsedModel.TechnicalAssets[incomingCommLink.SourceId].Title), "0", "0", false)
				pdf.Link(60, pdf.GetY()-5, 70, 5, tocLinkIdByAssetId[incomingCommLink.SourceId])
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Protocol:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, incomingCommLink.Protocol.String(), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Encrypted:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, strconv.FormatBool(incomingCommLink.Protocol.IsEncrypted()), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Authentication:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, incomingCommLink.Authentication.String(), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Authorization:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, incomingCommLink.Authorization.String(), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Read-Only:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, strconv.FormatBool(incomingCommLink.Readonly), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Usage:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, incomingCommLink.Usage.String(), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Tags:", "0", 0, "", false, 0, "")
				pdfColorBlack()
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
					pdfColorGray()
					tagsUsedText = "none"
				}
				pdf.MultiCell(140, 6, uni(tagsUsedText), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "VPN:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, strconv.FormatBool(incomingCommLink.VPN), "0", "0", false)
				if pdf.GetY() > 270 {
					pageBreak()
					pdf.SetY(36)
				}
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "IP-Filtered:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				pdf.MultiCell(140, 6, strconv.FormatBool(incomingCommLink.IpFiltered), "0", "0", false)
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Data Received:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				dataAssetsSentText := ""
				// yep, here we reverse the sent/received direction, as it's the incoming stuff
				for _, dataAsset := range incomingCommLink.DataAssetsSentSorted(parsedModel) {
					if len(dataAssetsSentText) > 0 {
						dataAssetsSentText += ", "
					}
					dataAssetsSentText += dataAsset.Title
				}
				if len(dataAssetsSentText) == 0 {
					pdfColorGray()
					dataAssetsSentText = "none"
				}
				pdf.MultiCell(140, 6, uni(dataAssetsSentText), "0", "0", false)
				pdfColorGray()
				pdf.CellFormat(15, 6, "", "0", 0, "", false, 0, "")
				pdf.CellFormat(35, 6, "Data Sent:", "0", 0, "", false, 0, "")
				pdfColorBlack()
				dataAssetsReceivedText := ""
				// yep, here we reverse the sent/received direction, as it's the incoming stuff
				for _, dataAsset := range incomingCommLink.DataAssetsReceivedSorted(parsedModel) {
					if len(dataAssetsReceivedText) > 0 {
						dataAssetsReceivedText += ", "
					}
					dataAssetsReceivedText += dataAsset.Title
				}
				if len(dataAssetsReceivedText) == 0 {
					pdfColorGray()
					dataAssetsReceivedText = "none"
				}
				pdf.MultiCell(140, 6, uni(dataAssetsReceivedText), "0", "0", false)
				pdf.Ln(-1)
			}
		}
	}
}

func createDataAssets(parsedModel *types.ParsedModel) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	title := "Identified Data Breach Probabilities by Data Asset"
	pdfColorBlack()
	addHeadline(title, false)
	defineLinkTarget("{intro-risks-by-data-asset}")
	html := pdf.HTMLBasicNew()
	html.Write(5, "In total <b>"+strconv.Itoa(types.TotalRiskCount(parsedModel))+" potential risks</b> have been identified during the threat modeling process "+
		"of which "+
		"<b>"+strconv.Itoa(len(types.FilteredByOnlyCriticalRisks(parsedModel)))+" are rated as critical</b>, "+
		"<b>"+strconv.Itoa(len(types.FilteredByOnlyHighRisks(parsedModel)))+" as high</b>, "+
		"<b>"+strconv.Itoa(len(types.FilteredByOnlyElevatedRisks(parsedModel)))+" as elevated</b>, "+
		"<b>"+strconv.Itoa(len(types.FilteredByOnlyMediumRisks(parsedModel)))+" as medium</b>, "+
		"and <b>"+strconv.Itoa(len(types.FilteredByOnlyLowRisks(parsedModel)))+" as low</b>. "+
		"<br><br>These risks are distributed across <b>"+strconv.Itoa(len(parsedModel.DataAssets))+" data assets</b>. ")
	html.Write(5, "The following sub-chapters of this section describe the derived data breach probabilities grouped by data asset.<br>") // TODO more explanation text
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdfColorGray()
	html.Write(5, "Technical asset names and risk IDs are clickable and link to the corresponding chapter.")
	pdf.SetFont("Helvetica", "", fontSizeBody)
	currentChapterTitleBreadcrumb = title
	for _, dataAsset := range sortedDataAssetsByDataBreachProbabilityAndTitle(parsedModel) {
		if pdf.GetY() > 280 { // 280 as only small font previously (not 250)
			pageBreak()
			pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		pdfColorBlack()
		switch dataAsset.IdentifiedDataBreachProbabilityStillAtRisk(parsedModel) {
		case types.Probable:
			colors.ColorHighRisk(pdf)
		case types.Possible:
			colors.ColorMediumRisk(pdf)
		case types.Improbable:
			colors.ColorLowRisk(pdf)
		default:
			pdfColorBlack()
		}
		if !dataAsset.IsDataBreachPotentialStillAtRisk(parsedModel) {
			pdfColorBlack()
		}
		risksStr := dataAsset.IdentifiedDataBreachProbabilityRisks(parsedModel)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(parsedModel, risksStr))
		suffix := strconv.Itoa(countStillAtRisk) + " / " + strconv.Itoa(len(risksStr)) + " Risk"
		if len(risksStr) != 1 {
			suffix += "s"
		}
		title := uni(dataAsset.Title) + ": " + suffix
		addHeadline(title, true)
		defineLinkTarget("{data:" + dataAsset.Id + "}")
		pdfColorBlack()
		html.Write(5, uni(dataAsset.Description))
		html.Write(5, "<br><br>")

		pdf.SetFont("Helvetica", "", fontSizeBody)
		/*
			pdfColorGray()
			pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
			pdf.CellFormat(40, 6, "Indirect Breach:", "0", 0, "", false, 0, "")
			pdfColorBlack()
			pdf.SetFont("Helvetica", "B", fontSizeBody)
			probability := dataAsset.IdentifiedDataBreachProbability()
			dataBreachText := probability.String()
			switch probability {
			case model.Probable:
				colors.ColorHighRisk(pdf)
			case model.Possible:
				colors.ColorMediumRisk(pdf)
			case model.Improbable:
				colors.ColorLowRisk(pdf)
			default:
				pdfColorBlack()
			}
			if !dataAsset.IsDataBreachPotentialStillAtRisk() {
				pdfColorBlack()
				dataBreachText = "none"
			}
			pdf.MultiCell(145, 6, dataBreachText, "0", "0", false)
			pdf.SetFont("Helvetica", "", fontSizeBody)
			if pdf.GetY() > 265 {
				pageBreak()
				pdf.SetY(36)
			}
		*/
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "ID:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, dataAsset.Id, "0", "0", false)
		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Usage:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, dataAsset.Usage.String(), "0", "0", false)
		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Quantity:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, dataAsset.Quantity.String(), "0", "0", false)
		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Tags:", "0", 0, "", false, 0, "")
		pdfColorBlack()
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
			pdfColorGray()
			tagsUsedText = "none"
		}
		pdf.MultiCell(145, 6, uni(tagsUsedText), "0", "0", false)
		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Origin:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, uni(dataAsset.Origin), "0", "0", false)
		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Owner:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, uni(dataAsset.Owner), "0", "0", false)
		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Confidentiality:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.CellFormat(40, 6, dataAsset.Confidentiality.String(), "0", 0, "", false, 0, "")
		pdfColorGray()
		pdf.CellFormat(115, 6, dataAsset.Confidentiality.RatingStringInScale(), "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.Ln(-1)
		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Integrity:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.CellFormat(40, 6, dataAsset.Integrity.String(), "0", 0, "", false, 0, "")
		pdfColorGray()
		pdf.CellFormat(115, 6, dataAsset.Integrity.RatingStringInScale(), "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.Ln(-1)
		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Availability:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.CellFormat(40, 6, dataAsset.Availability.String(), "0", 0, "", false, 0, "")
		pdfColorGray()
		pdf.CellFormat(115, 6, dataAsset.Availability.RatingStringInScale(), "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.Ln(-1)
		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "CIA-Justification:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, uni(dataAsset.JustificationCiaRating), "0", "0", false)

		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Processed by:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		processedByText := ""
		for _, dataAsset := range dataAsset.ProcessedByTechnicalAssetsSorted(parsedModel) {
			if len(processedByText) > 0 {
				processedByText += ", "
			}
			processedByText += dataAsset.Title // TODO add link to technical asset detail chapter and back
		}
		if len(processedByText) == 0 {
			pdfColorGray()
			processedByText = "none"
		}
		pdf.MultiCell(145, 6, uni(processedByText), "0", "0", false)

		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Stored by:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		storedByText := ""
		for _, dataAsset := range dataAsset.StoredByTechnicalAssetsSorted(parsedModel) {
			if len(storedByText) > 0 {
				storedByText += ", "
			}
			storedByText += dataAsset.Title // TODO add link to technical asset detail chapter and back
		}
		if len(storedByText) == 0 {
			pdfColorGray()
			storedByText = "none"
		}
		pdf.MultiCell(145, 6, uni(storedByText), "0", "0", false)

		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Sent via:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		sentViaText := ""
		for _, commLink := range dataAsset.SentViaCommLinksSorted(parsedModel) {
			if len(sentViaText) > 0 {
				sentViaText += ", "
			}
			sentViaText += commLink.Title // TODO add link to technical asset detail chapter and back
		}
		if len(sentViaText) == 0 {
			pdfColorGray()
			sentViaText = "none"
		}
		pdf.MultiCell(145, 6, uni(sentViaText), "0", "0", false)

		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Received via:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		receivedViaText := ""
		for _, commLink := range dataAsset.ReceivedViaCommLinksSorted(parsedModel) {
			if len(receivedViaText) > 0 {
				receivedViaText += ", "
			}
			receivedViaText += commLink.Title // TODO add link to technical asset detail chapter and back
		}
		if len(receivedViaText) == 0 {
			pdfColorGray()
			receivedViaText = "none"
		}
		pdf.MultiCell(145, 6, uni(receivedViaText), "0", "0", false)

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
			if pdf.GetY() > 265 {
				pageBreak()
				pdf.SetY(36)
			}
			pdfColorGray()
			pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
			pdf.CellFormat(40, 6, "Risk via:", "0", 0, "", false, 0, "")
			if len(techAssetsResponsible) == 0 {
				pdfColorGray()
				pdf.MultiCell(145, 6, "This data asset is not directly at risk via any technical asset.", "0", "0", false)
			} else {
				pdfColorBlack()
				pdf.MultiCell(145, 6, "This data asset is at direct risk via "+strconv.Itoa(len(techAssetsResponsible))+" technical "+assetStr+":", "0", "0", false)
				for _, techAssetResponsible := range techAssetsResponsible {
					if pdf.GetY() > 265 {
						pageBreak()
						pdf.SetY(36)
					}
					switch model.HighestSeverityStillAtRisk(techAssetResponsible.GeneratedRisks()) {
					case model.High:
						colors.ColorHighRisk(pdf)
					case model.Medium:
						colors.ColorMediumRisk(pdf)
					case model.Low:
						colors.ColorLowRisk(pdf)
					default:
						pdfColorBlack()
					}
					risksStr := techAssetResponsible.GeneratedRisks()
					if len(model.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
						pdfColorBlack()
					}
					riskStr := "risksStr"
					if len(risksStr) == 1 {
						riskStr = "risk"
					}
					pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
					posY := pdf.GetY()
					risksResponsible := techAssetResponsible.GeneratedRisks()
					risksResponsibleStillAtRisk := model.ReduceToOnlyStillAtRisk(risksResponsible)
					pdf.SetFont("Helvetica", "", fontSizeSmall)
					pdf.MultiCell(185, 6, uni(techAssetResponsible.Title)+": "+strconv.Itoa(len(risksResponsibleStillAtRisk))+" / "+strconv.Itoa(len(risksResponsible))+" "+riskStr, "0", "0", false)
					pdf.SetFont("Helvetica", "", fontSizeBody)
					pdf.Link(20, posY, 180, pdf.GetY()-posY, tocLinkIdByAssetId[techAssetResponsible.Id])
				}
				pdfColorBlack()
			}
		*/

		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Data Breach:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.SetFont("Helvetica", "B", fontSizeBody)
		dataBreachProbability := dataAsset.IdentifiedDataBreachProbabilityStillAtRisk(parsedModel)
		riskText := dataBreachProbability.String()
		switch dataBreachProbability {
		case types.Probable:
			colors.ColorHighRisk(pdf)
		case types.Possible:
			colors.ColorMediumRisk(pdf)
		case types.Improbable:
			colors.ColorLowRisk(pdf)
		default:
			pdfColorBlack()
		}
		if !dataAsset.IsDataBreachPotentialStillAtRisk(parsedModel) {
			pdfColorBlack()
			riskText = "none"
		}
		pdf.MultiCell(145, 6, riskText, "0", "0", false)
		pdf.SetFont("Helvetica", "", fontSizeBody)
		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}

		// how can is this data asset be indirectly lost (i.e. why)
		dataBreachRisksStillAtRisk := dataAsset.IdentifiedDataBreachProbabilityRisksStillAtRisk(parsedModel)
		types.SortByDataBreachProbability(dataBreachRisksStillAtRisk, parsedModel)
		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Data Breach Risks:", "0", 0, "", false, 0, "")
		if len(dataBreachRisksStillAtRisk) == 0 {
			pdfColorGray()
			pdf.MultiCell(145, 6, "This data asset has no data breach potential.", "0", "0", false)
		} else {
			pdfColorBlack()
			riskRemainingStr := "risksStr"
			if countStillAtRisk == 1 {
				riskRemainingStr = "risk"
			}
			pdf.MultiCell(145, 6, "This data asset has data breach potential because of "+
				""+strconv.Itoa(countStillAtRisk)+" remaining "+riskRemainingStr+":", "0", "0", false)
			for _, dataBreachRisk := range dataBreachRisksStillAtRisk {
				if pdf.GetY() > 280 { // 280 as only small font here
					pageBreak()
					pdf.SetY(36)
				}
				switch dataBreachRisk.DataBreachProbability {
				case types.Probable:
					colors.ColorHighRisk(pdf)
				case types.Possible:
					colors.ColorMediumRisk(pdf)
				case types.Improbable:
					colors.ColorLowRisk(pdf)
				default:
					pdfColorBlack()
				}
				if !dataBreachRisk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel).IsStillAtRisk() {
					pdfColorBlack()
				}
				pdf.CellFormat(10, 6, "", "0", 0, "", false, 0, "")
				posY := pdf.GetY()
				pdf.SetFont("Helvetica", "", fontSizeVerySmall)
				pdf.MultiCell(185, 5, dataBreachRisk.DataBreachProbability.Title()+": "+uni(dataBreachRisk.SyntheticId), "0", "0", false)
				pdf.SetFont("Helvetica", "", fontSizeBody)
				pdf.Link(20, posY, 180, pdf.GetY()-posY, tocLinkIdByAssetId[dataBreachRisk.CategoryId])
			}
			pdfColorBlack()
		}
	}
}

func createTrustBoundaries(parsedModel *types.ParsedModel) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	title := "Trust Boundaries"
	pdfColorBlack()
	addHeadline(title, false)

	html := pdf.HTMLBasicNew()
	word := "has"
	if len(parsedModel.TrustBoundaries) > 1 {
		word = "have"
	}
	html.Write(5, "In total <b>"+strconv.Itoa(len(parsedModel.TrustBoundaries))+" trust boundaries</b> "+word+" been "+
		"modeled during the threat modeling process.")
	currentChapterTitleBreadcrumb = title
	for _, trustBoundary := range sortedTrustBoundariesByTitle(parsedModel) {
		if pdf.GetY() > 250 {
			pageBreak()
			pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		colors.ColorTwilight(pdf)
		if !trustBoundary.Type.IsNetworkBoundary() {
			pdfColorLightGray()
		}
		html.Write(5, "<b>"+uni(trustBoundary.Title)+"</b><br>")
		defineLinkTarget("{boundary:" + trustBoundary.Id + "}")
		html.Write(5, uni(trustBoundary.Description))
		html.Write(5, "<br><br>")

		pdf.SetFont("Helvetica", "", fontSizeBody)

		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "ID:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, trustBoundary.Id, "0", "0", false)

		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Type:", "0", 0, "", false, 0, "")
		colors.ColorTwilight(pdf)
		if !trustBoundary.Type.IsNetworkBoundary() {
			pdfColorLightGray()
		}
		pdf.MultiCell(145, 6, trustBoundary.Type.String(), "0", "0", false)
		pdfColorBlack()

		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Tags:", "0", 0, "", false, 0, "")
		pdfColorBlack()
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
			pdfColorGray()
			tagsUsedText = "none"
		}
		pdf.MultiCell(145, 6, uni(tagsUsedText), "0", "0", false)

		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Assets inside:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		assetsInsideText := ""
		for _, assetKey := range trustBoundary.TechnicalAssetsInside {
			if len(assetsInsideText) > 0 {
				assetsInsideText += ", "
			}
			assetsInsideText += parsedModel.TechnicalAssets[assetKey].Title // TODO add link to technical asset detail chapter and back
		}
		if len(assetsInsideText) == 0 {
			pdfColorGray()
			assetsInsideText = "none"
		}
		pdf.MultiCell(145, 6, uni(assetsInsideText), "0", "0", false)

		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Boundaries nested:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		boundariesNestedText := ""
		for _, assetKey := range trustBoundary.TrustBoundariesNested {
			if len(boundariesNestedText) > 0 {
				boundariesNestedText += ", "
			}
			boundariesNestedText += parsedModel.TrustBoundaries[assetKey].Title
		}
		if len(boundariesNestedText) == 0 {
			pdfColorGray()
			boundariesNestedText = "none"
		}
		pdf.MultiCell(145, 6, uni(boundariesNestedText), "0", "0", false)
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

func createSharedRuntimes(parsedModel *types.ParsedModel) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	title := "Shared Runtimes"
	pdfColorBlack()
	addHeadline(title, false)

	html := pdf.HTMLBasicNew()
	word, runtime := "has", "runtime"
	if len(parsedModel.SharedRuntimes) > 1 {
		word, runtime = "have", "runtimes"
	}
	html.Write(5, "In total <b>"+strconv.Itoa(len(parsedModel.SharedRuntimes))+" shared "+runtime+"</b> "+word+" been "+
		"modeled during the threat modeling process.")
	currentChapterTitleBreadcrumb = title
	for _, sharedRuntime := range sortedSharedRuntimesByTitle(parsedModel) {
		pdfColorBlack()
		if pdf.GetY() > 250 {
			pageBreak()
			pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		html.Write(5, "<b>"+uni(sharedRuntime.Title)+"</b><br>")
		defineLinkTarget("{runtime:" + sharedRuntime.Id + "}")
		html.Write(5, uni(sharedRuntime.Description))
		html.Write(5, "<br><br>")

		pdf.SetFont("Helvetica", "", fontSizeBody)

		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "ID:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(145, 6, sharedRuntime.Id, "0", "0", false)

		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Tags:", "0", 0, "", false, 0, "")
		pdfColorBlack()
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
			pdfColorGray()
			tagsUsedText = "none"
		}
		pdf.MultiCell(145, 6, uni(tagsUsedText), "0", "0", false)

		if pdf.GetY() > 265 {
			pageBreak()
			pdf.SetY(36)
		}
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(40, 6, "Assets running:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		assetsInsideText := ""
		for _, assetKey := range sharedRuntime.TechnicalAssetsRunning {
			if len(assetsInsideText) > 0 {
				assetsInsideText += ", "
			}
			assetsInsideText += parsedModel.TechnicalAssets[assetKey].Title // TODO add link to technical asset detail chapter and back
		}
		if len(assetsInsideText) == 0 {
			pdfColorGray()
			assetsInsideText = "none"
		}
		pdf.MultiCell(145, 6, uni(assetsInsideText), "0", "0", false)
	}
}

func createRiskRulesChecked(parsedModel *types.ParsedModel, modelFilename string, skipRiskRules string, buildTimestamp string, modelHash string, customRiskRules map[string]*types.CustomRisk) {
	pdf.SetTextColor(0, 0, 0)
	title := "Risk Rules Checked by Threagile"
	addHeadline(title, false)
	defineLinkTarget("{risk-rules-checked}")
	currentChapterTitleBreadcrumb = title

	html := pdf.HTMLBasicNew()
	var strBuilder strings.Builder
	pdfColorGray()
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	timestamp := time.Now()
	strBuilder.WriteString("<b>Threagile Version:</b> " + docs.ThreagileVersion)
	strBuilder.WriteString("<br><b>Threagile Build Timestamp:</b> " + buildTimestamp)
	strBuilder.WriteString("<br><b>Threagile Execution Timestamp:</b> " + timestamp.Format("20060102150405"))
	strBuilder.WriteString("<br><b>Model Filename:</b> " + modelFilename)
	strBuilder.WriteString("<br><b>Model Hash (SHA256):</b> " + modelHash)
	html.Write(5, strBuilder.String())
	strBuilder.Reset()
	pdfColorBlack()
	pdf.SetFont("Helvetica", "", fontSizeBody)
	strBuilder.WriteString("<br><br>Threagile (see <a href=\"https://threagile.io\">https://threagile.io</a> for more details) is an open-source toolkit for agile threat modeling, created by Christian Schneider (<a href=\"https://christian-schneider.net\">https://christian-schneider.net</a>): It allows to model an architecture with its assets in an agile fashion as a YAML file " +
		"directly inside the IDE. Upon execution of the Threagile toolkit all standard risk rules (as well as individual custom rules if present) " +
		"are checked against the architecture model. At the time the Threagile toolkit was executed on the model input file " +
		"the following risk rules were checked:")
	html.Write(5, strBuilder.String())
	strBuilder.Reset()

	// TODO use the new run system to discover risk rules instead of hard-coding them here:
	skippedRules := strings.Split(skipRiskRules, ",")
	skipped := ""
	pdf.Ln(-1)

	for id, customRule := range customRiskRules {
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "B", fontSizeBody)
		if contains(skippedRules, id) {
			skipped = "SKIPPED - "
		} else {
			skipped = ""
		}
		pdf.CellFormat(190, 3, skipped+customRule.Category.Title, "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "", fontSizeSmall)
		pdf.CellFormat(190, 6, id, "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "I", fontSizeBody)
		pdf.CellFormat(190, 6, "Custom Risk Rule", "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "", fontSizeBody)
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(160, 6, customRule.Category.STRIDE.Title(), "0", "0", false)
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(160, 6, firstParagraph(customRule.Category.Description), "0", "0", false)
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(160, 6, customRule.Category.DetectionLogic, "0", "0", false)
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(160, 6, customRule.Category.RiskAssessment, "0", "0", false)
	}

	for _, key := range sortedKeysOfIndividualRiskCategories(parsedModel) {
		individualRiskCategory := parsedModel.IndividualRiskCategories[key]
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "B", fontSizeBody)
		pdf.CellFormat(190, 3, individualRiskCategory.Title, "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "", fontSizeSmall)
		pdf.CellFormat(190, 6, individualRiskCategory.Id, "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "I", fontSizeBody)
		pdf.CellFormat(190, 6, "Individual Risk Category", "0", 0, "", false, 0, "")
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "", fontSizeBody)
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(160, 6, individualRiskCategory.STRIDE.Title(), "0", "0", false)
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(160, 6, firstParagraph(individualRiskCategory.Description), "0", "0", false)
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(160, 6, individualRiskCategory.DetectionLogic, "0", "0", false)
		pdfColorGray()
		pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
		pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
		pdfColorBlack()
		pdf.MultiCell(160, 6, individualRiskCategory.RiskAssessment, "0", "0", false)
	}

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, accidental_secret_leak.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+accidental_secret_leak.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, accidental_secret_leak.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, accidental_secret_leak.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(accidental_secret_leak.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, accidental_secret_leak.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, accidental_secret_leak.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, code_backdooring.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+code_backdooring.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, code_backdooring.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, code_backdooring.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(code_backdooring.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, code_backdooring.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, code_backdooring.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, container_baseimage_backdooring.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+container_baseimage_backdooring.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, container_baseimage_backdooring.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, container_baseimage_backdooring.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(container_baseimage_backdooring.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, container_baseimage_backdooring.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, container_baseimage_backdooring.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, container_platform_escape.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+container_platform_escape.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, container_platform_escape.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, container_platform_escape.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(container_platform_escape.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, container_platform_escape.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, container_platform_escape.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, cross_site_request_forgery.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+cross_site_request_forgery.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, cross_site_request_forgery.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, cross_site_request_forgery.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(cross_site_request_forgery.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, cross_site_request_forgery.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, cross_site_request_forgery.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, cross_site_scripting.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+cross_site_scripting.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, cross_site_scripting.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, cross_site_scripting.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(cross_site_scripting.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, cross_site_scripting.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, cross_site_scripting.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, dos_risky_access_across_trust_boundary.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+dos_risky_access_across_trust_boundary.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, dos_risky_access_across_trust_boundary.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, dos_risky_access_across_trust_boundary.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(dos_risky_access_across_trust_boundary.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, dos_risky_access_across_trust_boundary.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, dos_risky_access_across_trust_boundary.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, incomplete_model.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+incomplete_model.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, incomplete_model.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, incomplete_model.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(incomplete_model.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, incomplete_model.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, incomplete_model.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, ldap_injection.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+ldap_injection.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, ldap_injection.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, ldap_injection.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(ldap_injection.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, ldap_injection.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, ldap_injection.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_authentication.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_authentication.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_authentication.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_authentication.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_authentication.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_authentication.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_authentication.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_authentication_second_factor.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_authentication_second_factor.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_authentication_second_factor.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_authentication_second_factor.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_authentication_second_factor.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_authentication_second_factor.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_authentication_second_factor.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_build_infrastructure.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_build_infrastructure.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_build_infrastructure.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_build_infrastructure.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_build_infrastructure.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_build_infrastructure.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_build_infrastructure.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_cloud_hardening.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_cloud_hardening.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_cloud_hardening.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_cloud_hardening.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_cloud_hardening.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_cloud_hardening.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_cloud_hardening.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_file_validation.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_file_validation.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_file_validation.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_file_validation.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_file_validation.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_file_validation.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_file_validation.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_hardening.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_hardening.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_hardening.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_hardening.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_hardening.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_hardening.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_hardening.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_identity_propagation.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_identity_propagation.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_identity_propagation.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_identity_propagation.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_identity_propagation.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_identity_propagation.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_identity_propagation.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_identity_provider_isolation.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_identity_provider_isolation.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_identity_provider_isolation.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_identity_provider_isolation.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_identity_provider_isolation.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_identity_provider_isolation.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_identity_provider_isolation.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_identity_store.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_identity_store.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_identity_store.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_identity_store.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_identity_store.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_identity_store.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_identity_store.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_network_segmentation.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_network_segmentation.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_network_segmentation.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_network_segmentation.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_network_segmentation.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_network_segmentation.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_network_segmentation.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_vault.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_vault.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_vault.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_vault.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_vault.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_vault.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_vault.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_vault_isolation.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_vault_isolation.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_vault_isolation.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_vault_isolation.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_vault_isolation.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_vault_isolation.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_vault_isolation.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, missing_waf.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+missing_waf.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, missing_waf.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_waf.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(missing_waf.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_waf.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, missing_waf.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, mixed_targets_on_shared_runtime.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+mixed_targets_on_shared_runtime.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, mixed_targets_on_shared_runtime.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, mixed_targets_on_shared_runtime.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(mixed_targets_on_shared_runtime.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, mixed_targets_on_shared_runtime.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, mixed_targets_on_shared_runtime.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, path_traversal.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+path_traversal.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, path_traversal.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, path_traversal.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(path_traversal.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, path_traversal.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, path_traversal.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, push_instead_of_pull_deployment.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+push_instead_of_pull_deployment.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, push_instead_of_pull_deployment.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, push_instead_of_pull_deployment.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(push_instead_of_pull_deployment.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, push_instead_of_pull_deployment.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, push_instead_of_pull_deployment.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, search_query_injection.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+search_query_injection.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, search_query_injection.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, search_query_injection.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(search_query_injection.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, search_query_injection.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, search_query_injection.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, server_side_request_forgery.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+server_side_request_forgery.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, server_side_request_forgery.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, server_side_request_forgery.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(server_side_request_forgery.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, server_side_request_forgery.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, server_side_request_forgery.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, service_registry_poisoning.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+service_registry_poisoning.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, service_registry_poisoning.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, service_registry_poisoning.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(service_registry_poisoning.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, service_registry_poisoning.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, service_registry_poisoning.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, sql_nosql_injection.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+sql_nosql_injection.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, sql_nosql_injection.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, sql_nosql_injection.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(sql_nosql_injection.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, sql_nosql_injection.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, sql_nosql_injection.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, unchecked_deployment.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+unchecked_deployment.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, unchecked_deployment.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unchecked_deployment.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(unchecked_deployment.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unchecked_deployment.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unchecked_deployment.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, unencrypted_asset.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+unencrypted_asset.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, unencrypted_asset.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unencrypted_asset.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(unencrypted_asset.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unencrypted_asset.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unencrypted_asset.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, unencrypted_communication.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+unencrypted_communication.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, unencrypted_communication.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unencrypted_communication.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(unencrypted_communication.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unencrypted_communication.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unencrypted_communication.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, unguarded_access_from_internet.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+unguarded_access_from_internet.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, unguarded_access_from_internet.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unguarded_access_from_internet.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(unguarded_access_from_internet.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unguarded_access_from_internet.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unguarded_access_from_internet.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, unguarded_direct_datastore_access.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+unguarded_direct_datastore_access.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, unguarded_direct_datastore_access.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unguarded_direct_datastore_access.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(unguarded_direct_datastore_access.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unguarded_direct_datastore_access.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unguarded_direct_datastore_access.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, unnecessary_communication_link.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+unnecessary_communication_link.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, unnecessary_communication_link.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unnecessary_communication_link.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(unnecessary_communication_link.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unnecessary_communication_link.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unnecessary_communication_link.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, unnecessary_data_asset.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+unnecessary_data_asset.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, unnecessary_data_asset.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unnecessary_data_asset.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(unnecessary_data_asset.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unnecessary_data_asset.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unnecessary_data_asset.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, unnecessary_data_transfer.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+unnecessary_data_transfer.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, unnecessary_data_transfer.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unnecessary_data_transfer.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(unnecessary_data_transfer.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unnecessary_data_transfer.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unnecessary_data_transfer.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, unnecessary_technical_asset.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+unnecessary_technical_asset.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, unnecessary_technical_asset.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unnecessary_technical_asset.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(unnecessary_technical_asset.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unnecessary_technical_asset.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, unnecessary_technical_asset.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, untrusted_deserialization.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+untrusted_deserialization.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, untrusted_deserialization.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, untrusted_deserialization.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(untrusted_deserialization.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, untrusted_deserialization.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, untrusted_deserialization.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, wrong_communication_link_content.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+wrong_communication_link_content.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, wrong_communication_link_content.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, wrong_communication_link_content.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(wrong_communication_link_content.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, wrong_communication_link_content.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, wrong_communication_link_content.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, wrong_trust_boundary_content.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+wrong_trust_boundary_content.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, wrong_trust_boundary_content.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, wrong_trust_boundary_content.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(wrong_trust_boundary_content.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, wrong_trust_boundary_content.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, wrong_trust_boundary_content.Category().RiskAssessment, "0", "0", false)

	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "B", fontSizeBody)
	if contains(skippedRules, xml_external_entity.Category().Id) {
		skipped = "SKIPPED - "
	} else {
		skipped = ""
	}
	pdf.CellFormat(190, 3, skipped+xml_external_entity.Category().Title, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeSmall)
	pdf.CellFormat(190, 6, xml_external_entity.Category().Id, "0", 0, "", false, 0, "")
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "STRIDE:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, xml_external_entity.Category().STRIDE.Title(), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Description:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, firstParagraph(xml_external_entity.Category().Description), "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Detection:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, xml_external_entity.Category().DetectionLogic, "0", "0", false)
	pdfColorGray()
	pdf.CellFormat(5, 6, "", "0", 0, "", false, 0, "")
	pdf.CellFormat(25, 6, "Rating:", "0", 0, "", false, 0, "")
	pdfColorBlack()
	pdf.MultiCell(160, 6, xml_external_entity.Category().RiskAssessment, "0", "0", false)
}

func createTargetDescription(parsedModel *types.ParsedModel, baseFolder string) {
	uni := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.SetTextColor(0, 0, 0)
	title := "Application Overview"
	addHeadline(title, false)
	defineLinkTarget("{target-overview}")
	currentChapterTitleBreadcrumb = title

	var intro strings.Builder
	html := pdf.HTMLBasicNew()

	intro.WriteString("<b>Business Criticality</b><br><br>")
	intro.WriteString("The overall business criticality of \"" + uni(parsedModel.Title) + "\" was rated as:<br><br>")
	html.Write(5, intro.String())
	criticality := parsedModel.BusinessCriticality
	intro.Reset()
	pdfColorGray()
	intro.WriteString("(  ")
	if criticality == types.Archive {
		html.Write(5, intro.String())
		intro.Reset()
		pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.Archive.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		pdfColorGray()
	} else {
		intro.WriteString(types.Archive.String())
	}
	intro.WriteString("  |  ")
	if criticality == types.Operational {
		html.Write(5, intro.String())
		intro.Reset()
		pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.Operational.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		pdfColorGray()
	} else {
		intro.WriteString(types.Operational.String())
	}
	intro.WriteString("  |  ")
	if criticality == types.Important {
		html.Write(5, intro.String())
		intro.Reset()
		pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.Important.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		pdfColorGray()
	} else {
		intro.WriteString(types.Important.String())
	}
	intro.WriteString("  |  ")
	if criticality == types.Critical {
		html.Write(5, intro.String())
		intro.Reset()
		pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.Critical.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		pdfColorGray()
	} else {
		intro.WriteString(types.Critical.String())
	}
	intro.WriteString("  |  ")
	if criticality == types.MissionCritical {
		html.Write(5, intro.String())
		intro.Reset()
		pdfColorBlack()
		intro.WriteString("<b><u>" + strings.ToUpper(types.MissionCritical.String()) + "</u></b>")
		html.Write(5, intro.String())
		intro.Reset()
		pdfColorGray()
	} else {
		intro.WriteString(types.MissionCritical.String())
	}
	intro.WriteString("  )")
	html.Write(5, intro.String())
	intro.Reset()
	pdfColorBlack()

	intro.WriteString("<br><br><br><b>Business Overview</b><br><br>")
	intro.WriteString(uni(parsedModel.BusinessOverview.Description))
	html.Write(5, intro.String())
	intro.Reset()
	addCustomImages(parsedModel.BusinessOverview.Images, baseFolder, html)

	intro.WriteString("<br><br><br><b>Technical Overview</b><br><br>")
	intro.WriteString(uni(parsedModel.TechnicalOverview.Description))
	html.Write(5, intro.String())
	intro.Reset()
	addCustomImages(parsedModel.TechnicalOverview.Images, baseFolder, html)
}

func addCustomImages(customImages []map[string]string, baseFolder string, html gofpdf.HTMLBasicType) {
	var text strings.Builder
	for _, customImage := range customImages {
		for imageFilename := range customImage {
			imageFilenameWithoutPath := filepath.Base(imageFilename)
			// check JPEG, PNG or GIF
			extension := strings.ToLower(filepath.Ext(imageFilenameWithoutPath))
			if extension == ".jpeg" || extension == ".jpg" || extension == ".png" || extension == ".gif" {
				imageFullFilename := filepath.Join(baseFolder, imageFilenameWithoutPath)
				if pdf.GetY()+getHeightWhenWidthIsFix(imageFullFilename, 180) > 250 {
					pageBreak()
					pdf.SetY(36)
				} else {
					text.WriteString("<br><br>")
				}
				text.WriteString(customImage[imageFilename] + ":<br><br>")
				html.Write(5, text.String())
				text.Reset()

				var options gofpdf.ImageOptions
				options.ImageType = ""
				pdf.RegisterImage(imageFullFilename, "")
				pdf.ImageOptions(imageFullFilename, 15, pdf.GetY()+50, 170, 0, true, options, 0, "")
			} else {
				log.Print("Ignoring custom image file: ", imageFilenameWithoutPath)
			}
		}
	}
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

func getHeightWhenWidthIsFix(imageFullFilename string, width float64) float64 {
	if !fileExists(imageFullFilename) {
		panic(errors.New("Image file does not exist (or is not readable as file): " + filepath.Base(imageFullFilename)))
	}
	/* #nosec imageFullFilename is not tainted (see caller restricting it to image files of model folder only) */
	file, err := os.Open(imageFullFilename)
	defer func() { _ = file.Close() }()
	checkErr(err)
	img, _, err := image.DecodeConfig(file)
	checkErr(err)
	return float64(img.Height) / (float64(img.Width) / width)
}

func embedDataFlowDiagram(diagramFilenamePNG string, tempFolder string) {
	pdf.SetTextColor(0, 0, 0)
	title := "Data-Flow Diagram"
	addHeadline(title, false)
	defineLinkTarget("{data-flow-diagram}")
	currentChapterTitleBreadcrumb = title

	var intro strings.Builder
	intro.WriteString("The following diagram was generated by Threagile based on the model input and gives a high-level " +
		"overview of the data-flow between technical assets. " +
		"The RAA value is the calculated <i>Relative Attacker Attractiveness</i> in percent. " +
		"For a full high-resolution version of this diagram please refer to the PNG image file alongside this report.")

	html := pdf.HTMLBasicNew()
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
	isLandscapePage = false
	_ = tempFolder
	/*
		pinnedWidth, pinnedHeight := 190.0, 210.0
		if dataFlowDiagramFullscreen {
			pinnedHeight = 235.0
			if muchWiderThanHigh {
				if allowedPdfLandscapePages {
					pinnedWidth = 275.0
					isLandscapePage = true
					pdf.AddPageFormat("L", pdf.GetPageSizeStr("A4"))
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
				pdf.AddPage()
			}
		} else {
			pdf.Ln(10)
		}*/
	// embed in PDF
	var options gofpdf.ImageOptions
	options.ImageType = ""
	pdf.RegisterImage(diagramFilenamePNG, "")
	var maxWidth, maxHeight, newWidth int
	var embedWidth, embedHeight float64
	if allowedPdfLandscapePages && muchWiderThanHigh {
		maxWidth, maxHeight = 275, 150
		isLandscapePage = true
		pdf.AddPageFormat("L", pdf.GetPageSizeStr("A4"))
	} else {
		pdf.Ln(10)
		maxWidth, maxHeight = 190, 200 // reduced height as a text paragraph is above
	}
	newWidth = srcDimensions.Dx() / (srcDimensions.Dy() / maxHeight)
	if newWidth <= maxWidth {
		embedWidth, embedHeight = 0, float64(maxHeight)
	} else {
		embedWidth, embedHeight = float64(maxWidth), 0
	}
	pdf.ImageOptions(diagramFilenamePNG, 10, pdf.GetY(), embedWidth, embedHeight, true, options, 0, "")
	isLandscapePage = false

	// add diagram legend page
	if embedDiagramLegendPage {
		pdf.AddPage()
		gofpdi.UseImportedTemplate(pdf, diagramLegendTemplateId, 0, 0, 0, 300)
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

func embedDataRiskMapping(diagramFilenamePNG string, tempFolder string) {
	pdf.SetTextColor(0, 0, 0)
	title := "Data Mapping"
	addHeadline(title, false)
	defineLinkTarget("{data-risk-mapping}")
	currentChapterTitleBreadcrumb = title

	var intro strings.Builder
	intro.WriteString("The following diagram was generated by Threagile based on the model input and gives a high-level " +
		"distribution of data assets across technical assets. The color matches the identified data breach probability and risk level " +
		"(see the \"Data Breach Probabilities\" chapter for more details). " +
		"A solid line stands for <i>data is stored by the asset</i> and a dashed one means " +
		"<i>data is processed by the asset</i>. For a full high-resolution version of this diagram please refer to the PNG image " +
		"file alongside this report.")

	html := pdf.HTMLBasicNew()
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
	isLandscapePage = false
	_ = tempFolder
	/*
		if dataFlowDiagramFullscreen {
			pinnedHeight = 235.0
			if widerThanHigh {
				if allowedPdfLandscapePages {
					pinnedWidth = 275.0
					isLandscapePage = true
					pdf.AddPageFormat("L", pdf.GetPageSizeStr("A4"))
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
				pdf.AddPage()
			}
		} else {
			pdf.Ln(10)
		}
	*/
	// embed in PDF
	pdf.Ln(10)
	var options gofpdf.ImageOptions
	options.ImageType = ""
	pdf.RegisterImage(diagramFilenamePNG, "")
	if widerThanHigh {
		pinnedHeight = 0
	} else {
		pinnedWidth = 0
	}
	pdf.ImageOptions(diagramFilenamePNG, 10, pdf.GetY(), pinnedWidth, pinnedHeight, true, options, 0, "")
	isLandscapePage = false
}

func writeReportToFile(reportFilename string) {
	err := pdf.OutputFileAndClose(reportFilename)
	checkErr(err)
}

func addHeadline(headline string, small bool) {
	pdf.AddPage()
	gofpdi.UseImportedTemplate(pdf, contentTemplateId, 0, 0, 0, 300)
	fontSize := fontSizeHeadline
	if small {
		fontSize = fontSizeHeadlineSmall
	}
	pdf.SetFont("Helvetica", "B", float64(fontSize))
	pdf.Text(11, 40, headline)
	pdf.SetFont("Helvetica", "", fontSizeBody)
	pdf.SetX(17)
	pdf.SetY(46)
}

func pageBreak() {
	pdf.SetDrawColor(0, 0, 0)
	pdf.SetDashPattern([]float64{}, 0)
	pdf.AddPage()
	gofpdi.UseImportedTemplate(pdf, contentTemplateId, 0, 0, 0, 300)
	pdf.SetX(17)
	pdf.SetY(20)
}

func pageBreakInLists() {
	pageBreak()
	pdf.SetLineWidth(0.25)
	pdf.SetDrawColor(160, 160, 160)
	pdf.SetDashPattern([]float64{0.5, 0.5}, 0)
}

func pdfColorDataAssets() {
	pdf.SetTextColor(18, 36, 111)
}
func rgbHexColorDataAssets() string {
	return "#12246F"
}

func pdfColorTechnicalAssets() {
	pdf.SetTextColor(18, 36, 111)
}
func rgbHexColorTechnicalAssets() string {
	return "#12246F"
}

func pdfColorTrustBoundaries() {
	pdf.SetTextColor(18, 36, 111)
}
func rgbHexColorTrustBoundaries() string {
	return "#12246F"
}

func pdfColorSharedRuntime() {
	pdf.SetTextColor(18, 36, 111)
}
func rgbHexColorSharedRuntime() string {
	return "#12246F"
}

func pdfColorRiskFindings() {
	pdf.SetTextColor(160, 40, 30)
}

func rgbHexColorRiskFindings() string {
	return "#A0281E"
}

func pdfColorDisclaimer() {
	pdf.SetTextColor(140, 140, 140)
}
func rgbHexColorDisclaimer() string {
	return "#8C8C8C"
}

func pdfColorOutOfScope() {
	pdf.SetTextColor(127, 127, 127)
}
func rgbHexColorOutOfScope() string {
	return "#7F7F7F"
}

func pdfColorGray() {
	pdf.SetTextColor(80, 80, 80)
}
func rgbHexColorGray() string {
	return "#505050"
}

func pdfColorLightGray() {
	pdf.SetTextColor(100, 100, 100)
}
func rgbHexColorLightGray() string {
	return "#646464"
}

func pdfColorBlack() {
	pdf.SetTextColor(0, 0, 0)
}
func rgbHexColorBlack() string {
	return "#000000"
}

func pdfColorRed() {
	pdf.SetTextColor(255, 0, 0)
}
func rgbHexColorRed() string {
	return "#FF0000"
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}
