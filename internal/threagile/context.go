package threagile

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt" // TODO: no fmt.Println here
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/security/risks"
	"golang.org/x/crypto/argon2"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/threagile/threagile/pkg/common"

	addbuildpipeline "github.com/threagile/threagile/pkg/macros/built-in/add-build-pipeline"
	addvault "github.com/threagile/threagile/pkg/macros/built-in/add-vault"
	prettyprint "github.com/threagile/threagile/pkg/macros/built-in/pretty-print"
	removeunusedtags "github.com/threagile/threagile/pkg/macros/built-in/remove-unused-tags"
	seedrisktracking "github.com/threagile/threagile/pkg/macros/built-in/seed-risk-tracking"
	seedtags "github.com/threagile/threagile/pkg/macros/built-in/seed-tags"

	"gopkg.in/yaml.v3"

	"github.com/threagile/threagile/pkg/colors"
	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/report"
	"github.com/threagile/threagile/pkg/run"
	"github.com/threagile/threagile/pkg/security/types"
)

const (
	defaultGraphvizDPI, maxGraphvizDPI = 120, 240
)

type Context struct {
	common.Config

	ServerMode bool

	successCount                                                 int
	errorCount                                                   int
	drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks bool
	buildTimestamp                                               string

	modelInput input.ModelInput

	// TODO: remove refactoring note below
	// moved from types.go
	parsedModel types.ParsedModel

	modelFilename, templateFilename                                                                   *string
	verbose, ignoreOrphanedRiskTracking                                                               *bool
	generateDataFlowDiagram, generateDataAssetDiagram, generateRisksJSON, generateTechnicalAssetsJSON *bool
	generateStatsJSON, generateRisksExcel, generateTagsExcel, generateReportPDF                       *bool
	outputDir, raaPlugin, skipRiskRules, riskRulesPlugins, executeModelMacro                          *string
	customRiskRules                                                                                   map[string]*types.CustomRisk
	builtinRiskRules                                                                                  map[string]types.RiskRule
	diagramDPI, serverPort                                                                            *int
	addModelTitle                                                                                     bool
	keepDiagramSourceFiles                                                                            bool
	appFolder                                                                                         *string
	binFolder                                                                                         *string
	serverFolder                                                                                      *string
	tempFolder                                                                                        *string

	backupHistoryFilesToKeep int

	tempDir                                string
	binDir                                 string
	appDir                                 string
	dataDir                                string
	keyDir                                 string
	reportFilename                         string
	excelRisksFilename                     string
	excelTagsFilename                      string
	jsonRisksFilename                      string
	jsonTechnicalAssetsFilename            string
	jsonStatsFilename                      string
	dataFlowDiagramFilenameDOT             string
	dataFlowDiagramFilenamePNG             string
	dataAssetDiagramFilenameDOT            string
	dataAssetDiagramFilenamePNG            string
	graphvizDataFlowDiagramConversionCall  string
	graphvizDataAssetDiagramConversionCall string
	inputFile                              string

	progressReporter ProgressReporter
}

func (context *Context) addToListOfSupportedTags(tags []string) {
	for _, tag := range tags {
		context.parsedModel.AllSupportedTags[tag] = true
	}
}

func (context *Context) checkRiskTracking() {
	if *context.verbose {
		fmt.Println("Checking risk tracking")
	}
	for _, tracking := range context.parsedModel.RiskTracking {
		if _, ok := context.parsedModel.GeneratedRisksBySyntheticId[tracking.SyntheticRiskId]; !ok {
			if *context.ignoreOrphanedRiskTracking {
				fmt.Println("Risk tracking references unknown risk (risk id not found): " + tracking.SyntheticRiskId)
			} else {
				panic(errors.New("Risk tracking references unknown risk (risk id not found) - you might want to use the option -ignore-orphaned-risk-tracking: " + tracking.SyntheticRiskId +
					"\n\nNOTE: For risk tracking each risk-id needs to be defined (the string with the @ sign in it). " +
					"These unique risk IDs are visible in the PDF report (the small grey string under each risk), " +
					"the Excel (column \"ID\"), as well as the JSON responses. Some risk IDs have only one @ sign in them, " +
					"while others multiple. The idea is to allow for unique but still speaking IDs. Therefore each risk instance " +
					"creates its individual ID by taking all affected elements causing the risk to be within an @-delimited part. " +
					"Using wildcards (the * sign) for parts delimited by @ signs allows to handle groups of certain risks at once. " +
					"Best is to lookup the IDs to use in the created Excel file. Alternatively a model macro \"seed-risk-tracking\" " +
					"is available that helps in initially seeding the risk tracking part here based on already identified and not yet handled risks."))
			}
		}
	}

	// save also the risk-category-id and risk-status directly in the risk for better JSON marshalling
	for category := range context.parsedModel.GeneratedRisksByCategory {
		for i := range context.parsedModel.GeneratedRisksByCategory[category] {
			//			context.parsedModel.GeneratedRisksByCategory[category][i].CategoryId = category
			context.parsedModel.GeneratedRisksByCategory[category][i].RiskStatus = context.parsedModel.GeneratedRisksByCategory[category][i].GetRiskTrackingStatusDefaultingUnchecked(&context.parsedModel)
		}
	}
}

func (context *Context) Init(buildTimestamp string) *Context {
	*context = Context{
		keepDiagramSourceFiles: false,
		addModelTitle:          false,
		buildTimestamp:         buildTimestamp,
		customRiskRules:        make(map[string]*types.CustomRisk),
		drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks: true,
	}

	return context
}

func (context *Context) Defaults(buildTimestamp string) *Context {
	*context = *new(Context).Init(buildTimestamp)
	context.backupHistoryFilesToKeep = 50
	context.tempDir = common.TempDir
	context.binDir = common.BinDir
	context.appDir = common.AppDir
	context.dataDir = common.DataDir
	context.keyDir = common.KeyDir
	context.reportFilename = common.ReportFilename
	context.excelRisksFilename = common.ExcelRisksFilename
	context.excelTagsFilename = common.ExcelTagsFilename
	context.jsonRisksFilename = common.JsonRisksFilename
	context.jsonTechnicalAssetsFilename = common.JsonTechnicalAssetsFilename
	context.jsonStatsFilename = common.JsonStatsFilename
	context.dataFlowDiagramFilenameDOT = common.DataFlowDiagramFilenameDOT
	context.dataFlowDiagramFilenamePNG = common.DataFlowDiagramFilenamePNG
	context.dataAssetDiagramFilenameDOT = common.DataAssetDiagramFilenameDOT
	context.dataAssetDiagramFilenamePNG = common.DataAssetDiagramFilenamePNG
	context.graphvizDataFlowDiagramConversionCall = common.GraphvizDataFlowDiagramConversionCall
	context.graphvizDataAssetDiagramConversionCall = common.GraphvizDataAssetDiagramConversionCall
	context.inputFile = common.InputFile

	context.Config.Defaults()

	return context
}

func (context *Context) applyRisk(rule types.RiskRule, skippedRules *map[string]bool) {
	id := rule.Category().Id
	_, ok := (*skippedRules)[id]

	if ok {
		fmt.Printf("Skipping risk rule %q\n", rule.Category().Id)
		delete(*skippedRules, rule.Category().Id)
	} else {
		context.addToListOfSupportedTags(rule.SupportedTags())
		generatedRisks := rule.GenerateRisks(&context.parsedModel)
		if generatedRisks != nil {
			if len(generatedRisks) > 0 {
				context.parsedModel.GeneratedRisksByCategory[rule.Category().Id] = generatedRisks
			}
		} else {
			fmt.Printf("Failed to generate risks for %q\n", id)
		}
	}
}

func (context *Context) applyRiskGeneration() {
	if *context.verbose {
		fmt.Println("Applying risk generation")
	}

	skippedRules := make(map[string]bool)
	if len(*context.skipRiskRules) > 0 {
		for _, id := range strings.Split(*context.skipRiskRules, ",") {
			skippedRules[id] = true
		}
	}

	for _, rule := range context.builtinRiskRules {
		context.applyRisk(rule, &skippedRules)
	}

	// NOW THE CUSTOM RISK RULES (if any)
	for id, customRule := range context.customRiskRules {
		_, ok := skippedRules[id]
		if ok {
			if *context.verbose {
				fmt.Println("Skipping custom risk rule:", id)
			}
			delete(skippedRules, id)
		} else {
			if *context.verbose {
				fmt.Println("Executing custom risk rule:", id)
			}
			context.addToListOfSupportedTags(customRule.Tags)
			customRisks := customRule.GenerateRisks(&context.parsedModel)
			if len(customRisks) > 0 {
				context.parsedModel.GeneratedRisksByCategory[customRule.Category.Id] = customRisks
			}

			if *context.verbose {
				fmt.Println("Added custom risks:", len(customRisks))
			}
		}
	}

	if len(skippedRules) > 0 {
		keys := make([]string, 0)
		for k := range skippedRules {
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			log.Println("Unknown risk rules to skip:", keys)
		}
	}

	// save also in map keyed by synthetic risk-id
	for _, category := range types.SortedRiskCategories(&context.parsedModel) {
		someRisks := types.SortedRisksOfCategory(&context.parsedModel, category)
		for _, risk := range someRisks {
			context.parsedModel.GeneratedRisksBySyntheticId[strings.ToLower(risk.SyntheticId)] = risk
		}
	}
}

func (context *Context) writeDataFlowDiagramGraphvizDOT(diagramFilenameDOT string, dpi int) *os.File {
	if *context.verbose {
		fmt.Println("Writing data flow diagram input")
	}
	var dotContent strings.Builder
	dotContent.WriteString("digraph generatedModel { concentrate=false \n")

	// Metadata init ===============================================================================
	tweaks := ""
	if context.parsedModel.DiagramTweakNodesep > 0 {
		tweaks += "\n		nodesep=\"" + strconv.Itoa(context.parsedModel.DiagramTweakNodesep) + "\""
	}
	if context.parsedModel.DiagramTweakRanksep > 0 {
		tweaks += "\n		ranksep=\"" + strconv.Itoa(context.parsedModel.DiagramTweakRanksep) + "\""
	}
	suppressBidirectionalArrows := true
	splines := "ortho"
	if len(context.parsedModel.DiagramTweakEdgeLayout) > 0 {
		switch context.parsedModel.DiagramTweakEdgeLayout {
		case "spline":
			splines = "spline"
			context.drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "polyline":
			splines = "polyline"
			context.drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "ortho":
			splines = "ortho"
			suppressBidirectionalArrows = true
		case "curved":
			splines = "curved"
			context.drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "false":
			splines = "false"
			context.drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		default:
			panic(errors.New("unknown value for diagram_tweak_suppress_edge_labels (spline, polyline, ortho, curved, false): " +
				context.parsedModel.DiagramTweakEdgeLayout))
		}
	}
	rankdir := "TB"
	if context.parsedModel.DiagramTweakLayoutLeftToRight {
		rankdir = "LR"
	}
	modelTitle := ""
	if context.addModelTitle {
		modelTitle = `label="` + context.parsedModel.Title + `"`
	}
	dotContent.WriteString(`	graph [ ` + modelTitle + `
		labelloc=t
		fontname="Verdana"
		fontsize=40
        outputorder="nodesfirst"
		dpi=` + strconv.Itoa(dpi) + `
		splines=` + splines + `
		rankdir="` + rankdir + `"
` + tweaks + `
	];
	node [
		fontname="Verdana"
		fontsize="20"
	];
	edge [
		shape="none"
		fontname="Verdana"
		fontsize="18"
	];
`)

	// Trust Boundaries ===============================================================================
	var subgraphSnippetsById = make(map[string]string)
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	keys := make([]string, 0)
	for k := range context.parsedModel.TrustBoundaries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		trustBoundary := context.parsedModel.TrustBoundaries[key]
		var snippet strings.Builder
		if len(trustBoundary.TechnicalAssetsInside) > 0 || len(trustBoundary.TrustBoundariesNested) > 0 {
			if context.drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks {
				// see https://stackoverflow.com/questions/17247455/how-do-i-add-extra-space-between-clusters?noredirect=1&lq=1
				snippet.WriteString("\n subgraph cluster_space_boundary_for_layout_only_1" + hash(trustBoundary.Id) + " {\n")
				snippet.WriteString(`	graph [
                                              dpi=` + strconv.Itoa(dpi) + `
											  label=<<table border="0" cellborder="0" cellpadding="0" bgcolor="#FFFFFF55"><tr><td><b> </b></td></tr></table>>
											  fontsize="21"
											  style="invis"
											  color="green"
											  fontcolor="green"
											  margin="50.0"
											  penwidth="6.5"
                                              outputorder="nodesfirst"
											];`)
			}
			snippet.WriteString("\n subgraph cluster_" + hash(trustBoundary.Id) + " {\n")
			color, fontColor, bgColor, style, fontname := colors.RgbHexColorTwilight(), colors.RgbHexColorTwilight() /*"#550E0C"*/, "#FAFAFA", "dashed", "Verdana"
			penWidth := 4.5
			if len(trustBoundary.TrustBoundariesNested) > 0 {
				//color, fontColor, style, fontname = colors.Blue, colors.Blue, "dashed", "Verdana"
				penWidth = 5.5
			}
			if len(trustBoundary.ParentTrustBoundaryID(&context.parsedModel)) > 0 {
				bgColor = "#F1F1F1"
			}
			if trustBoundary.Type == types.NetworkPolicyNamespaceIsolation {
				fontColor, bgColor = "#222222", "#DFF4FF"
			}
			if trustBoundary.Type == types.ExecutionEnvironment {
				fontColor, bgColor, style = "#555555", "#FFFFF0", "dotted"
			}
			snippet.WriteString(`	graph [
      dpi=` + strconv.Itoa(dpi) + `
      label=<<table border="0" cellborder="0" cellpadding="0"><tr><td><b>` + trustBoundary.Title + `</b> (` + trustBoundary.Type.String() + `)</td></tr></table>>
      fontsize="21"
      style="` + style + `"
      color="` + color + `"
      bgcolor="` + bgColor + `"
      fontcolor="` + fontColor + `"
      fontname="` + fontname + `"
      penwidth="` + fmt.Sprintf("%f", penWidth) + `"
      forcelabels=true
      outputorder="nodesfirst"
	  margin="50.0"
    ];`)
			snippet.WriteString("\n")
			keys := trustBoundary.TechnicalAssetsInside
			sort.Strings(keys)
			for _, technicalAssetInside := range keys {
				//log.Println("About to add technical asset link to trust boundary: ", technicalAssetInside)
				technicalAsset := context.parsedModel.TechnicalAssets[technicalAssetInside]
				snippet.WriteString(hash(technicalAsset.Id))
				snippet.WriteString(";\n")
			}
			keys = trustBoundary.TrustBoundariesNested
			sort.Strings(keys)
			for _, trustBoundaryNested := range keys {
				//log.Println("About to add nested trust boundary to trust boundary: ", trustBoundaryNested)
				trustBoundaryNested := context.parsedModel.TrustBoundaries[trustBoundaryNested]
				snippet.WriteString("LINK-NEEDS-REPLACED-BY-cluster_" + hash(trustBoundaryNested.Id))
				snippet.WriteString(";\n")
			}
			snippet.WriteString(" }\n\n")
			if context.drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks {
				snippet.WriteString(" }\n\n")
			}
		}
		subgraphSnippetsById[hash(trustBoundary.Id)] = snippet.String()
	}
	// here replace links and remove from map after replacement (i.e. move snippet into nested)
	for i := range subgraphSnippetsById {
		re := regexp.MustCompile(`LINK-NEEDS-REPLACED-BY-cluster_([0-9]*);`)
		for {
			matches := re.FindStringSubmatch(subgraphSnippetsById[i])
			if len(matches) > 0 {
				embeddedSnippet := " //nested:" + subgraphSnippetsById[matches[1]]
				subgraphSnippetsById[i] = strings.ReplaceAll(subgraphSnippetsById[i], matches[0], embeddedSnippet)
				subgraphSnippetsById[matches[1]] = "" // to something like remove it
			} else {
				break
			}
		}
	}
	// now write them all
	keys = make([]string, 0)
	for k := range subgraphSnippetsById {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		snippet := subgraphSnippetsById[key]
		dotContent.WriteString(snippet)
	}

	// Technical Assets ===============================================================================
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	// Convert map to slice of values:
	var techAssets []types.TechnicalAsset
	for _, techAsset := range context.parsedModel.TechnicalAssets {
		techAssets = append(techAssets, techAsset)
	}
	sort.Sort(types.ByOrderAndIdSort(techAssets))
	for _, technicalAsset := range techAssets {
		dotContent.WriteString(context.makeTechAssetNode(technicalAsset, false))
		dotContent.WriteString("\n")
	}

	// Data Flows (Technical Communication Links) ===============================================================================
	for _, technicalAsset := range techAssets {
		for _, dataFlow := range technicalAsset.CommunicationLinks {
			sourceId := technicalAsset.Id
			targetId := dataFlow.TargetId
			//log.Println("About to add link from", sourceId, "to", targetId, "with id", dataFlow.Id)
			var arrowStyle, arrowColor, readOrWriteHead, readOrWriteTail string
			if dataFlow.Readonly {
				readOrWriteHead = "empty"
				readOrWriteTail = "odot"
			} else {
				readOrWriteHead = "normal"
				readOrWriteTail = "dot"
			}
			dir := "forward"
			if dataFlow.IsBidirectional() {
				if !suppressBidirectionalArrows { // as it does not work as bug in graphviz with ortho: https://gitlab.com/graphviz/graphviz/issues/144
					dir = "both"
				}
			}
			arrowStyle = ` style="` + dataFlow.DetermineArrowLineStyle() + `" penwidth="` + dataFlow.DetermineArrowPenWidth(&context.parsedModel) + `" arrowtail="` + readOrWriteTail + `" arrowhead="` + readOrWriteHead + `" dir="` + dir + `" arrowsize="2.0" `
			arrowColor = ` color="` + dataFlow.DetermineArrowColor(&context.parsedModel) + `"`
			tweaks := ""
			if dataFlow.DiagramTweakWeight > 0 {
				tweaks += " weight=\"" + strconv.Itoa(dataFlow.DiagramTweakWeight) + "\" "
			}

			dotContent.WriteString("\n")
			dotContent.WriteString("  " + hash(sourceId) + " -> " + hash(targetId) +
				` [` + arrowColor + ` ` + arrowStyle + tweaks + ` constraint=` + strconv.FormatBool(dataFlow.DiagramTweakConstraint) + ` `)
			if !context.parsedModel.DiagramTweakSuppressEdgeLabels {
				dotContent.WriteString(` xlabel="` + encode(dataFlow.Protocol.String()) + `" fontcolor="` + dataFlow.DetermineLabelColor(&context.parsedModel) + `" `)
			}
			dotContent.WriteString(" ];\n")
		}
	}

	dotContent.WriteString(context.makeDiagramInvisibleConnectionsTweaks())
	dotContent.WriteString(context.makeDiagramSameRankNodeTweaks())

	dotContent.WriteString("}")

	//fmt.Println(dotContent.String())

	// Write the DOT file
	file, err := os.Create(diagramFilenameDOT)
	checkErr(err)
	defer func() { _ = file.Close() }()
	_, err = fmt.Fprintln(file, dotContent.String())
	checkErr(err)
	return file
}

func (context *Context) makeDiagramSameRankNodeTweaks() string {
	// see https://stackoverflow.com/questions/25734244/how-do-i-place-nodes-on-the-same-level-in-dot
	tweak := ""
	if len(context.parsedModel.DiagramTweakSameRankAssets) > 0 {
		for _, sameRank := range context.parsedModel.DiagramTweakSameRankAssets {
			assetIDs := strings.Split(sameRank, ":")
			if len(assetIDs) > 0 {
				tweak += "{ rank=same; "
				for _, id := range assetIDs {
					checkErr(context.parsedModel.CheckTechnicalAssetExists(id, "diagram tweak same-rank", true))
					if len(context.parsedModel.TechnicalAssets[id].GetTrustBoundaryId(&context.parsedModel)) > 0 {
						panic(errors.New("technical assets (referenced in same rank diagram tweak) are inside trust boundaries: " +
							fmt.Sprintf("%v", context.parsedModel.DiagramTweakSameRankAssets)))
					}
					tweak += " " + hash(id) + "; "
				}
				tweak += " }"
			}
		}
	}
	return tweak
}

func (context *Context) makeDiagramInvisibleConnectionsTweaks() string {
	// see https://stackoverflow.com/questions/2476575/how-to-control-node-placement-in-graphviz-i-e-avoid-edge-crossings
	tweak := ""
	if len(context.parsedModel.DiagramTweakInvisibleConnectionsBetweenAssets) > 0 {
		for _, invisibleConnections := range context.parsedModel.DiagramTweakInvisibleConnectionsBetweenAssets {
			assetIDs := strings.Split(invisibleConnections, ":")
			if len(assetIDs) == 2 {
				checkErr(context.parsedModel.CheckTechnicalAssetExists(assetIDs[0], "diagram tweak connections", true))
				checkErr(context.parsedModel.CheckTechnicalAssetExists(assetIDs[1], "diagram tweak connections", true))
				tweak += "\n" + hash(assetIDs[0]) + " -> " + hash(assetIDs[1]) + " [style=invis]; \n"
			}
		}
	}
	return tweak
}

func (context *Context) DoIt() {

	defer func() {
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if *context.verbose {
				log.Println(err)
			}
			_, _ = os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(2)
		}
	}()
	if len(*context.executeModelMacro) > 0 {
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
	} else {
		if *context.verbose {
			fmt.Println("Writing into output directory:", *context.outputDir)
		}
	}

	if *context.verbose {
		fmt.Println("Parsing model:", *context.modelFilename)
	}

	context.modelInput = *new(input.ModelInput).Defaults()
	loadError := context.modelInput.Load(*context.modelFilename)
	if loadError != nil {
		log.Fatal("Unable to load model yaml: ", loadError)
	}

	context.builtinRiskRules = make(map[string]types.RiskRule)
	for _, rule := range risks.GetBuiltInRiskRules() {
		context.builtinRiskRules[rule.Category().Id] = rule
	}
	context.customRiskRules = types.LoadCustomRiskRules(strings.Split(*context.riskRulesPlugins, ","), context.progressReporter)

	parsedModel, parseError := model.ParseModel(&context.modelInput, context.builtinRiskRules, context.customRiskRules)
	if parseError != nil {
		log.Fatal("Unable to parse model yaml: ", parseError)
	}

	context.parsedModel = *parsedModel

	introTextRAA := context.applyRAA()

	context.applyRiskGeneration()
	context.applyWildcardRiskTrackingEvaluation()
	context.checkRiskTracking()

	if len(*context.executeModelMacro) > 0 {
		var macroDetails macros.MacroDetails
		switch *context.executeModelMacro {
		case addbuildpipeline.GetMacroDetails().ID:
			macroDetails = addbuildpipeline.GetMacroDetails()
		case addvault.GetMacroDetails().ID:
			macroDetails = addvault.GetMacroDetails()
		case prettyprint.GetMacroDetails().ID:
			macroDetails = prettyprint.GetMacroDetails()
		case removeunusedtags.GetMacroDetails().ID:
			macroDetails = removeunusedtags.GetMacroDetails()
		case seedrisktracking.GetMacroDetails().ID:
			macroDetails = seedrisktracking.GetMacroDetails()
		case seedtags.GetMacroDetails().ID:
			macroDetails = seedtags.GetMacroDetails()
		default:
			log.Fatal("Unknown model macro: ", *context.executeModelMacro)
		}
		fmt.Println("Executing model macro:", macroDetails.ID)
		fmt.Println()
		fmt.Println()
		context.printBorder(len(macroDetails.Title), true)
		fmt.Println(macroDetails.Title)
		context.printBorder(len(macroDetails.Title), true)
		if len(macroDetails.Description) > 0 {
			fmt.Println(macroDetails.Description)
		}
		fmt.Println()
		reader := bufio.NewReader(os.Stdin)
		var err error
		var nextQuestion macros.MacroQuestion
		for {
			switch macroDetails.ID {
			case addbuildpipeline.GetMacroDetails().ID:
				nextQuestion, err = addbuildpipeline.GetNextQuestion(&context.parsedModel)
			case addvault.GetMacroDetails().ID:
				nextQuestion, err = addvault.GetNextQuestion(&context.parsedModel)
			case prettyprint.GetMacroDetails().ID:
				nextQuestion, err = prettyprint.GetNextQuestion()
			case removeunusedtags.GetMacroDetails().ID:
				nextQuestion, err = removeunusedtags.GetNextQuestion()
			case seedrisktracking.GetMacroDetails().ID:
				nextQuestion, err = seedrisktracking.GetNextQuestion()
			case seedtags.GetMacroDetails().ID:
				nextQuestion, err = seedtags.GetNextQuestion()
			}
			checkErr(err)
			if nextQuestion.NoMoreQuestions() {
				break
			}
			fmt.Println()
			context.printBorder(len(nextQuestion.Title), false)
			fmt.Println(nextQuestion.Title)
			context.printBorder(len(nextQuestion.Title), false)
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
						checkErr(err)
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
				checkErr(err)
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
					return
				} else if strings.ToLower(answer) == "back" {
					switch macroDetails.ID {
					case addbuildpipeline.GetMacroDetails().ID:
						message, validResult, err = addbuildpipeline.GoBack()
					case addvault.GetMacroDetails().ID:
						message, validResult, err = addvault.GoBack()
					case prettyprint.GetMacroDetails().ID:
						message, validResult, err = prettyprint.GoBack()
					case removeunusedtags.GetMacroDetails().ID:
						message, validResult, err = removeunusedtags.GoBack()
					case seedrisktracking.GetMacroDetails().ID:
						message, validResult, err = seedrisktracking.GoBack()
					case seedtags.GetMacroDetails().ID:
						message, validResult, err = seedtags.GoBack()
					}
				} else if len(answer) > 0 { // individual answer
					if nextQuestion.IsValueConstrained() {
						if !nextQuestion.IsMatchingValueConstraint(answer) {
							fmt.Println()
							fmt.Println(">>> INVALID <<<")
							fmt.Println("Answer does not match any allowed value. Please try again:")
							continue
						}
					}
					switch macroDetails.ID {
					case addbuildpipeline.GetMacroDetails().ID:
						message, validResult, err = addbuildpipeline.ApplyAnswer(nextQuestion.ID, answer)
					case addvault.GetMacroDetails().ID:
						message, validResult, err = addvault.ApplyAnswer(nextQuestion.ID, answer)
					case prettyprint.GetMacroDetails().ID:
						message, validResult, err = prettyprint.ApplyAnswer(nextQuestion.ID, answer)
					case removeunusedtags.GetMacroDetails().ID:
						message, validResult, err = removeunusedtags.ApplyAnswer(nextQuestion.ID, answer)
					case seedrisktracking.GetMacroDetails().ID:
						message, validResult, err = seedrisktracking.ApplyAnswer(nextQuestion.ID, answer)
					case seedtags.GetMacroDetails().ID:
						message, validResult, err = seedtags.ApplyAnswer(nextQuestion.ID, answer)
					}
				}
			} else {
				switch macroDetails.ID {
				case addbuildpipeline.GetMacroDetails().ID:
					message, validResult, err = addbuildpipeline.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case addvault.GetMacroDetails().ID:
					message, validResult, err = addvault.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case prettyprint.GetMacroDetails().ID:
					message, validResult, err = prettyprint.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case removeunusedtags.GetMacroDetails().ID:
					message, validResult, err = removeunusedtags.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case seedrisktracking.GetMacroDetails().ID:
					message, validResult, err = seedrisktracking.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				case seedtags.GetMacroDetails().ID:
					message, validResult, err = seedtags.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
				}
			}
			checkErr(err)
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
			validResult := true
			var err error
			switch macroDetails.ID {
			case addbuildpipeline.GetMacroDetails().ID:
				changes, message, validResult, err = addbuildpipeline.GetFinalChangeImpact(&context.modelInput, &context.parsedModel)
			case addvault.GetMacroDetails().ID:
				changes, message, validResult, err = addvault.GetFinalChangeImpact(&context.modelInput, &context.parsedModel)
			case prettyprint.GetMacroDetails().ID:
				changes, message, validResult, err = prettyprint.GetFinalChangeImpact(&context.modelInput)
			case removeunusedtags.GetMacroDetails().ID:
				changes, message, validResult, err = removeunusedtags.GetFinalChangeImpact(&context.modelInput)
			case seedrisktracking.GetMacroDetails().ID:
				changes, message, validResult, err = seedrisktracking.GetFinalChangeImpact(&context.modelInput)
			case seedtags.GetMacroDetails().ID:
				changes, message, validResult, err = seedtags.GetFinalChangeImpact(&context.modelInput)
			}
			checkErr(err)
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
			checkErr(err)
			answer = strings.ToLower(answer)
			fmt.Println()
			if answer == "yes" || answer == "y" {
				message := ""
				validResult := true
				var err error
				switch macroDetails.ID {
				case addbuildpipeline.GetMacroDetails().ID:
					message, validResult, err = addbuildpipeline.Execute(&context.modelInput, &context.parsedModel)
				case addvault.GetMacroDetails().ID:
					message, validResult, err = addvault.Execute(&context.modelInput, &context.parsedModel)
				case prettyprint.GetMacroDetails().ID:
					message, validResult, err = prettyprint.Execute(&context.modelInput)
				case removeunusedtags.GetMacroDetails().ID:
					message, validResult, err = removeunusedtags.Execute(&context.modelInput, &context.parsedModel)
				case seedrisktracking.GetMacroDetails().ID:
					message, validResult, err = seedrisktracking.Execute(&context.parsedModel, &context.modelInput)
				case seedtags.GetMacroDetails().ID:
					message, validResult, err = seedtags.Execute(&context.modelInput, &context.parsedModel)
				}
				checkErr(err)
				if !validResult {
					fmt.Println()
					fmt.Println(">>> INVALID <<<")
				}
				fmt.Println(message)
				fmt.Println()
				backupFilename := *context.modelFilename + ".backup"
				fmt.Println("Creating backup model file:", backupFilename) // TODO add random files in /dev/shm space?
				_, err = copyFile(*context.modelFilename, backupFilename)
				checkErr(err)
				fmt.Println("Updating model")
				yamlBytes, err := yaml.Marshal(context.modelInput)
				checkErr(err)
				/*
					yamlBytes = model.ReformatYAML(yamlBytes)
				*/
				fmt.Println("Writing model file:", *context.modelFilename)
				err = os.WriteFile(*context.modelFilename, yamlBytes, 0400)
				checkErr(err)
				fmt.Println("Model file successfully updated")
				return
			} else if answer == "no" || answer == "n" {
				fmt.Println("Quitting without executing the model macro")
				return
			}
		}
	}

	renderDataFlowDiagram := *context.generateDataFlowDiagram
	renderDataAssetDiagram := *context.generateDataAssetDiagram
	renderRisksJSON := *context.generateRisksJSON
	renderTechnicalAssetsJSON := *context.generateTechnicalAssetsJSON
	renderStatsJSON := *context.generateStatsJSON
	renderRisksExcel := *context.generateRisksExcel
	renderTagsExcel := *context.generateTagsExcel
	renderPDF := *context.generateReportPDF
	if renderPDF { // as the PDF report includes both diagrams
		renderDataFlowDiagram, renderDataAssetDiagram = true, true
	}

	// Data-flow Diagram rendering
	if renderDataFlowDiagram {
		gvFile := filepath.Join(*context.outputDir, context.dataFlowDiagramFilenameDOT)
		if !context.keepDiagramSourceFiles {
			tmpFileGV, err := os.CreateTemp(*context.tempFolder, context.dataFlowDiagramFilenameDOT)
			checkErr(err)
			gvFile = tmpFileGV.Name()
			defer func() { _ = os.Remove(gvFile) }()
		}
		dotFile := context.writeDataFlowDiagramGraphvizDOT(gvFile, *context.diagramDPI)
		context.renderDataFlowDiagramGraphvizImage(dotFile, *context.outputDir)
	}
	// Data Asset Diagram rendering
	if renderDataAssetDiagram {
		gvFile := filepath.Join(*context.outputDir, context.dataAssetDiagramFilenameDOT)
		if !context.keepDiagramSourceFiles {
			tmpFile, err := os.CreateTemp(*context.tempFolder, context.dataAssetDiagramFilenameDOT)
			checkErr(err)
			gvFile = tmpFile.Name()
			defer func() { _ = os.Remove(gvFile) }()
		}
		dotFile := context.writeDataAssetDiagramGraphvizDOT(gvFile, *context.diagramDPI)
		context.renderDataAssetDiagramGraphvizImage(dotFile, *context.outputDir)
	}

	// risks as risks json
	if renderRisksJSON {
		if *context.verbose {
			fmt.Println("Writing risks json")
		}
		report.WriteRisksJSON(&context.parsedModel, filepath.Join(*context.outputDir, context.jsonRisksFilename))
	}

	// technical assets json
	if renderTechnicalAssetsJSON {
		if *context.verbose {
			fmt.Println("Writing technical assets json")
		}
		report.WriteTechnicalAssetsJSON(&context.parsedModel, filepath.Join(*context.outputDir, context.jsonTechnicalAssetsFilename))
	}

	// risks as risks json
	if renderStatsJSON {
		if *context.verbose {
			fmt.Println("Writing stats json")
		}
		report.WriteStatsJSON(&context.parsedModel, filepath.Join(*context.outputDir, context.jsonStatsFilename))
	}

	// risks Excel
	if renderRisksExcel {
		if *context.verbose {
			fmt.Println("Writing risks excel")
		}
		report.WriteRisksExcelToFile(&context.parsedModel, filepath.Join(*context.outputDir, context.excelRisksFilename))
	}

	// tags Excel
	if renderTagsExcel {
		if *context.verbose {
			fmt.Println("Writing tags excel")
		}
		report.WriteTagsExcelToFile(&context.parsedModel, filepath.Join(*context.outputDir, context.excelTagsFilename))
	}

	if renderPDF {
		// hash the YAML input file
		f, err := os.Open(*context.modelFilename)
		checkErr(err)
		defer func() { _ = f.Close() }()
		hasher := sha256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			panic(err)
		}
		modelHash := hex.EncodeToString(hasher.Sum(nil))
		// report PDF
		if *context.verbose {
			fmt.Println("Writing report pdf")
		}
		report.WriteReportPDF(filepath.Join(*context.outputDir, context.reportFilename),
			filepath.Join(*context.appFolder, *context.templateFilename),
			filepath.Join(*context.outputDir, context.dataFlowDiagramFilenamePNG),
			filepath.Join(*context.outputDir, context.dataAssetDiagramFilenamePNG),
			*context.modelFilename,
			*context.skipRiskRules,
			context.buildTimestamp,
			modelHash,
			introTextRAA,
			context.customRiskRules,
			*context.tempFolder,
			&context.parsedModel)
	}
}

func copyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer func() { _ = source.Close() }()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer func() { _ = destination.Close() }()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func (context *Context) printBorder(length int, bold bool) {
	char := "-"
	if bold {
		char = "="
	}
	for i := 1; i <= length; i++ {
		fmt.Print(char)
	}
	fmt.Println()
}

func (context *Context) applyRAA() string {
	if *context.verbose {
		fmt.Println("Applying RAA calculation:", *context.raaPlugin)
	}

	runner, loadError := new(run.Runner).Load(filepath.Join(*context.binFolder, *context.raaPlugin))
	if loadError != nil {
		fmt.Printf("WARNING: raa %q not loaded: %v\n", *context.raaPlugin, loadError)
		return ""
	}

	runError := runner.Run(context.parsedModel, &context.parsedModel)
	if runError != nil {
		fmt.Printf("WARNING: raa %q not applied: %v\n", *context.raaPlugin, runError)
		return ""
	}

	return runner.ErrorOutput
}

func (context *Context) exampleFile(ginContext *gin.Context) {
	example, err := os.ReadFile(filepath.Join(*context.appFolder, "threagile-example-model.yaml"))
	checkErr(err)
	ginContext.Data(http.StatusOK, gin.MIMEYAML, example)
}

func (context *Context) stubFile(ginContext *gin.Context) {
	stub, err := os.ReadFile(filepath.Join(*context.appFolder, "threagile-stub-model.yaml"))
	checkErr(err)
	ginContext.Data(http.StatusOK, gin.MIMEYAML, context.addSupportedTags(stub)) // TODO use also the MIMEYAML way of serving YAML in model export?
}

func (context *Context) addSupportedTags(input []byte) []byte {
	// add distinct tags as "tags_available"
	supportedTags := make(map[string]bool)
	for _, customRule := range context.customRiskRules {
		for _, tag := range customRule.Tags {
			supportedTags[strings.ToLower(tag)] = true
		}
	}

	for _, rule := range context.builtinRiskRules {
		for _, tag := range rule.SupportedTags() {
			supportedTags[strings.ToLower(tag)] = true
		}
	}

	tags := make([]string, 0, len(supportedTags))
	for t := range supportedTags {
		tags = append(tags, t)
	}
	if len(tags) == 0 {
		return input
	}
	sort.Strings(tags)
	if *context.verbose {
		fmt.Print("Supported tags of all risk rules: ")
		for i, tag := range tags {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(tag)
		}
		fmt.Println()
	}
	replacement := "tags_available:"
	for _, tag := range tags {
		replacement += "\n  - " + tag
	}
	return []byte(strings.Replace(string(input), "tags_available:", replacement, 1))
}

const keySize = 32

func (context *Context) stats(ginContext *gin.Context) {
	keyCount, modelCount := 0, 0
	keyFolders, err := os.ReadDir(filepath.Join(*context.serverFolder, context.keyDir))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to collect stats",
		})
		return
	}
	for _, keyFolder := range keyFolders {
		if len(keyFolder.Name()) == 128 { // it's a sha512 token hash probably, so count it as token folder for the stats
			keyCount++
			if keyFolder.Name() != filepath.Clean(keyFolder.Name()) {
				ginContext.JSON(http.StatusInternalServerError, gin.H{
					"error": "weird file path",
				})
				return
			}
			modelFolders, err := os.ReadDir(filepath.Join(*context.serverFolder, context.keyDir, keyFolder.Name()))
			if err != nil {
				log.Println(err)
				ginContext.JSON(http.StatusInternalServerError, gin.H{
					"error": "unable to collect stats",
				})
				return
			}
			for _, modelFolder := range modelFolders {
				if len(modelFolder.Name()) == 36 { // it's a uuid model folder probably, so count it as model folder for the stats
					modelCount++
				}
			}
		}
	}
	// TODO collect and deliver more stats (old model count?) and health info
	ginContext.JSON(http.StatusOK, gin.H{
		"key_count":     keyCount,
		"model_count":   modelCount,
		"success_count": context.successCount,
		"error_count":   context.errorCount,
	})
}

type payloadDataAsset struct {
	Title                  string   `yaml:"title" json:"title"`
	Id                     string   `yaml:"id" json:"id"`
	Description            string   `yaml:"description" json:"description"`
	Usage                  string   `yaml:"usage" json:"usage"`
	Tags                   []string `yaml:"tags" json:"tags"`
	Origin                 string   `yaml:"origin" json:"origin"`
	Owner                  string   `yaml:"owner" json:"owner"`
	Quantity               string   `yaml:"quantity" json:"quantity"`
	Confidentiality        string   `yaml:"confidentiality" json:"confidentiality"`
	Integrity              string   `yaml:"integrity" json:"integrity"`
	Availability           string   `yaml:"availability" json:"availability"`
	JustificationCiaRating string   `yaml:"justification_cia_rating" json:"justification_cia_rating"`
}

func (context *Context) checkTechnicalAssetsExisting(modelInput input.ModelInput, techAssetIDs []string) (ok bool) {
	for _, techAssetID := range techAssetIDs {
		exists := false
		for _, val := range modelInput.TechnicalAssets {
			if val.ID == techAssetID {
				exists = true
				break
			}
		}
		if !exists {
			return false
		}
	}
	return true
}

func (context *Context) populateDataAsset(ginContext *gin.Context, payload payloadDataAsset) (dataAssetInput input.InputDataAsset, ok bool) {
	usage, err := types.ParseUsage(payload.Usage)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	quantity, err := types.ParseQuantity(payload.Quantity)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	confidentiality, err := types.ParseConfidentiality(payload.Confidentiality)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	integrity, err := types.ParseCriticality(payload.Integrity)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	availability, err := types.ParseCriticality(payload.Availability)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	dataAssetInput = input.InputDataAsset{
		ID:                     payload.Id,
		Description:            payload.Description,
		Usage:                  usage.String(),
		Tags:                   lowerCaseAndTrim(payload.Tags),
		Origin:                 payload.Origin,
		Owner:                  payload.Owner,
		Quantity:               quantity.String(),
		Confidentiality:        confidentiality.String(),
		Integrity:              integrity.String(),
		Availability:           availability.String(),
		JustificationCiaRating: payload.JustificationCiaRating,
	}
	return dataAssetInput, true
}

func handleErrorInServiceCall(err error, ginContext *gin.Context) {
	log.Println(err)
	ginContext.JSON(http.StatusBadRequest, gin.H{
		"error": strings.TrimSpace(err.Error()),
	})
}

func (context *Context) checkModelFolder(ginContext *gin.Context, modelUUID string, folderNameOfKey string) (modelFolder string, ok bool) {
	uuidParsed, err := uuid.Parse(modelUUID)
	if err != nil {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	modelFolder = folderNameForModel(folderNameOfKey, uuidParsed.String())
	if _, err := os.Stat(modelFolder); os.IsNotExist(err) {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	return modelFolder, true
}

func (context *Context) readModel(ginContext *gin.Context, modelUUID string, key []byte, folderNameOfKey string) (modelInputResult input.ModelInput, yamlText string, ok bool) {
	modelFolder, ok := context.checkModelFolder(ginContext, modelUUID, folderNameOfKey)
	if !ok {
		return modelInputResult, yamlText, false
	}
	cryptoKey := context.generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	fileBytes, err := os.ReadFile(filepath.Join(modelFolder, context.inputFile))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	nonce := fileBytes[0:12]
	ciphertext := fileBytes[12:]
	plaintext, err := aesGcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	r, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r)
	modelInput := new(input.ModelInput).Defaults()
	yamlBytes := buf.Bytes()
	err = yaml.Unmarshal(yamlBytes, &modelInput)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	return *modelInput, string(yamlBytes), true
}

func (context *Context) writeModel(ginContext *gin.Context, key []byte, folderNameOfKey string, modelInput *input.ModelInput, changeReasonForHistory string) (ok bool) {
	modelFolder, ok := context.checkModelFolder(ginContext, ginContext.Param("model-id"), folderNameOfKey)
	if ok {
		modelInput.ThreagileVersion = docs.ThreagileVersion
		yamlBytes, err := yaml.Marshal(modelInput)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to write model",
			})
			return false
		}
		/*
			yamlBytes = model.ReformatYAML(yamlBytes)
		*/
		return context.writeModelYAML(ginContext, string(yamlBytes), key, modelFolder, changeReasonForHistory, false)
	}
	return false
}

func (context *Context) writeModelYAML(ginContext *gin.Context, yaml string, key []byte, modelFolder string, changeReasonForHistory string, skipBackup bool) (ok bool) {
	if *context.verbose {
		fmt.Println("about to write " + strconv.Itoa(len(yaml)) + " bytes of yaml into model folder: " + modelFolder)
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(yaml))
	_ = w.Close()
	plaintext := b.Bytes()
	cryptoKey := context.generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	ciphertext := aesGcm.Seal(nil, nonce, plaintext, nil)
	if !skipBackup {
		err = context.backupModelToHistory(modelFolder, changeReasonForHistory)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to write model",
			})
			return false
		}
	}
	f, err := os.Create(filepath.Join(modelFolder, context.inputFile))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	_, _ = f.Write(nonce)
	_, _ = f.Write(ciphertext)
	_ = f.Close()
	return true
}

func (context *Context) backupModelToHistory(modelFolder string, changeReasonForHistory string) (err error) {
	historyFolder := filepath.Join(modelFolder, "history")
	if _, err := os.Stat(historyFolder); os.IsNotExist(err) {
		err = os.Mkdir(historyFolder, 0700)
		if err != nil {
			return err
		}
	}
	inputModel, err := os.ReadFile(filepath.Join(modelFolder, context.inputFile))
	if err != nil {
		return err
	}
	historyFile := filepath.Join(historyFolder, time.Now().Format("2006-01-02 15:04:05")+" "+changeReasonForHistory+".backup")
	err = os.WriteFile(historyFile, inputModel, 0400)
	if err != nil {
		return err
	}
	// now delete any old files if over limit to keep
	files, err := os.ReadDir(historyFolder)
	if err != nil {
		return err
	}
	if len(files) > context.backupHistoryFilesToKeep {
		requiredToDelete := len(files) - context.backupHistoryFilesToKeep
		sort.Slice(files, func(i, j int) bool {
			return files[i].Name() < files[j].Name()
		})
		for _, file := range files {
			requiredToDelete--
			if file.Name() != filepath.Clean(file.Name()) {
				return fmt.Errorf("weird file name %v", file.Name())
			}
			err = os.Remove(filepath.Join(historyFolder, file.Name()))
			if err != nil {
				return err
			}
			if requiredToDelete <= 0 {
				break
			}
		}
	}
	return
}

func (context *Context) generateKeyFromAlreadyStrongRandomInput(alreadyRandomInput []byte) []byte {
	// Establish the parameters to use for Argon2.
	p := &argon2Params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   keySize,
	}
	// As the input is already cryptographically secure random, the salt is simply the first n bytes
	salt := alreadyRandomInput[0:p.saltLength]
	hash := argon2.IDKey(alreadyRandomInput[p.saltLength:], salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	return hash
}

func folderNameForModel(folderNameOfKey string, uuid string) string {
	return filepath.Join(folderNameOfKey, uuid)
}

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var throttlerLock sync.Mutex

var createdObjectsThrottler = make(map[string][]int64)

func (context *Context) checkObjectCreationThrottler(ginContext *gin.Context, typeName string) bool {
	throttlerLock.Lock()
	defer throttlerLock.Unlock()

	// remove all elements older than 3 minutes (= 180000000000 ns)
	now := time.Now().UnixNano()
	cutoff := now - 180000000000
	for keyCheck := range createdObjectsThrottler {
		for i := 0; i < len(createdObjectsThrottler[keyCheck]); i++ {
			if createdObjectsThrottler[keyCheck][i] < cutoff {
				// Remove the element at index i from slice (safe while looping using i as iterator)
				createdObjectsThrottler[keyCheck] = append(createdObjectsThrottler[keyCheck][:i], createdObjectsThrottler[keyCheck][i+1:]...)
				i-- // Since we just deleted a[i], we must redo that index
			}
		}
		length := len(createdObjectsThrottler[keyCheck])
		if length == 0 {
			delete(createdObjectsThrottler, keyCheck)
		}
		/*
			if *verbose {
				log.Println("Throttling count: "+strconv.Itoa(length))
			}
		*/
	}

	// check current request
	keyHash := hash(typeName) // getting the real client ip is not easy inside fully encapsulated containerized runtime
	if _, ok := createdObjectsThrottler[keyHash]; !ok {
		createdObjectsThrottler[keyHash] = make([]int64, 0)
	}
	// check the limit of 20 creations for this type per 3 minutes
	withinLimit := len(createdObjectsThrottler[keyHash]) < 20
	if withinLimit {
		createdObjectsThrottler[keyHash] = append(createdObjectsThrottler[keyHash], now)
		return true
	}
	ginContext.JSON(http.StatusTooManyRequests, gin.H{
		"error": "object creation throttling exceeded (denial-of-service protection): please wait some time and try again",
	})
	return false
}

func (context *Context) folderNameFromKey(key []byte) string {
	sha512Hash := hashSHA256(key)
	return filepath.Join(*context.serverFolder, context.keyDir, sha512Hash)
}

func hashSHA256(key []byte) string {
	hasher := sha512.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

type keyHeader struct {
	Key string `header:"key"`
}

func (context *Context) checkKeyToFolderName(ginContext *gin.Context) (folderNameOfKey string, key []byte, ok bool) {
	header := keyHeader{}
	if err := ginContext.ShouldBindHeader(&header); err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Key))
	if len(key) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	folderNameOfKey = context.folderNameFromKey(key)
	if _, err := os.Stat(folderNameOfKey); os.IsNotExist(err) {
		log.Println(err)
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	return folderNameOfKey, key, true
}

func (context *Context) userHomeDir() string {
	switch runtime.GOOS {
	case "windows":
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home

	default:
		return os.Getenv("HOME")
	}
}

func (context *Context) expandPath(path string) *string {
	home := context.userHomeDir()
	if strings.HasPrefix(path, "~") {
		path = strings.Replace(path, "~", home, 1)
	}

	if strings.HasPrefix(path, "$HOME") {
		path = strings.Replace(path, "$HOME", home, -1)
	}

	return &path
}

func (context *Context) ParseCommandlineArgs() { // folders
	context.appFolder = flag.String("app-dir", common.AppDir, "app folder (default: "+common.AppDir+")")
	context.serverFolder = flag.String("server-dir", common.DataDir, "base folder for server mode (default: "+common.DataDir+")")
	context.tempFolder = flag.String("temp-dir", common.TempDir, "temporary folder location")
	context.binFolder = flag.String("bin-dir", common.BinDir, "binary folder location")
	context.outputDir = flag.String("output", ".", "output directory")

	// files
	context.modelFilename = flag.String("model", common.InputFile, "input model yaml file")
	context.raaPlugin = flag.String("raa-run", "raa_calc", "RAA calculation run file name")

	// flags
	context.verbose = flag.Bool("verbose", false, "verbose output")
	context.diagramDPI = flag.Int("diagram-dpi", defaultGraphvizDPI, "DPI used to render: maximum is "+strconv.Itoa(maxGraphvizDPI)+"")
	context.skipRiskRules = flag.String("skip-risk-rules", "", "comma-separated list of risk rules (by their ID) to skip")
	context.riskRulesPlugins = flag.String("custom-risk-rules-plugins", "", "comma-separated list of plugins file names with custom risk rules to load")
	context.ignoreOrphanedRiskTracking = flag.Bool("ignore-orphaned-risk-tracking", false, "ignore orphaned risk tracking (just log them) not matching a concrete risk")

	// commands
	context.serverPort = flag.Int("server", 0, "start a server (instead of commandline execution) on the given port")
	context.executeModelMacro = flag.String("execute-model-macro", "", "Execute model macro (by ID)")
	context.templateFilename = flag.String("background", "background.pdf", "background pdf file")
	context.generateDataFlowDiagram = flag.Bool("generate-data-flow-diagram", true, "generate data-flow diagram")
	context.generateDataAssetDiagram = flag.Bool("generate-data-asset-diagram", true, "generate data asset diagram")
	context.generateRisksJSON = flag.Bool("generate-risks-json", true, "generate risks json")
	context.generateStatsJSON = flag.Bool("generate-stats-json", true, "generate stats json")
	context.generateTechnicalAssetsJSON = flag.Bool("generate-technical-assets-json", true, "generate technical assets json")
	context.generateRisksExcel = flag.Bool("generate-risks-excel", true, "generate risks excel")
	context.generateTagsExcel = flag.Bool("generate-tags-excel", true, "generate tags excel")
	context.generateReportPDF = flag.Bool("generate-report-pdf", true, "generate report pdf, including diagrams")

	flag.Usage = func() {
		fmt.Println(docs.Logo + "\n\n" + docs.VersionText)
		_, _ = fmt.Fprintf(os.Stderr, "Usage: threagile [options]")
		fmt.Println()
	}
	flag.Parse()

	context.modelFilename = context.expandPath(*context.modelFilename)
	context.appFolder = context.expandPath(*context.appFolder)
	context.serverFolder = context.expandPath(*context.serverFolder)
	context.tempFolder = context.expandPath(*context.tempFolder)
	context.binFolder = context.expandPath(*context.binFolder)
	context.outputDir = context.expandPath(*context.outputDir)

	if *context.diagramDPI < 20 {
		*context.diagramDPI = 20
	} else if *context.diagramDPI > context.MaxGraphvizDPI {
		*context.diagramDPI = 300
	}

	context.progressReporter = SilentProgressReporter{}
	if *context.verbose {
		context.progressReporter = CommandLineProgressReporter{}
	}

	context.ServerMode = *context.serverPort > 0
}

func (context *Context) applyWildcardRiskTrackingEvaluation() {
	if *context.verbose {
		fmt.Println("Executing risk tracking evaluation")
	}
	for syntheticRiskIdPattern, riskTracking := range context.getDeferredRiskTrackingDueToWildcardMatching() {
		if *context.verbose {
			fmt.Println("Applying wildcard risk tracking for risk id: " + syntheticRiskIdPattern)
		}

		foundSome := false
		var matchingRiskIdExpression = regexp.MustCompile(strings.ReplaceAll(regexp.QuoteMeta(syntheticRiskIdPattern), `\*`, `[^@]+`))
		for syntheticRiskId := range context.parsedModel.GeneratedRisksBySyntheticId {
			if matchingRiskIdExpression.Match([]byte(syntheticRiskId)) && context.hasNotYetAnyDirectNonWildcardRiskTracking(syntheticRiskId) {
				foundSome = true
				context.parsedModel.RiskTracking[syntheticRiskId] = types.RiskTracking{
					SyntheticRiskId: strings.TrimSpace(syntheticRiskId),
					Justification:   riskTracking.Justification,
					CheckedBy:       riskTracking.CheckedBy,
					Ticket:          riskTracking.Ticket,
					Status:          riskTracking.Status,
					Date:            riskTracking.Date,
				}
			}
		}

		if !foundSome {
			if *context.ignoreOrphanedRiskTracking {
				fmt.Println("WARNING: Wildcard risk tracking does not match any risk id: " + syntheticRiskIdPattern)
			} else {
				panic(errors.New("wildcard risk tracking does not match any risk id: " + syntheticRiskIdPattern))
			}
		}
	}
}

func (context *Context) getDeferredRiskTrackingDueToWildcardMatching() map[string]types.RiskTracking {
	deferredRiskTrackingDueToWildcardMatching := make(map[string]types.RiskTracking)
	for syntheticRiskId, riskTracking := range context.parsedModel.RiskTracking {
		if strings.Contains(syntheticRiskId, "*") { // contains a wildcard char
			deferredRiskTrackingDueToWildcardMatching[syntheticRiskId] = riskTracking
		}
	}

	return deferredRiskTrackingDueToWildcardMatching
}

func (context *Context) hasNotYetAnyDirectNonWildcardRiskTracking(syntheticRiskId string) bool {
	if _, ok := context.parsedModel.RiskTracking[syntheticRiskId]; ok {
		return false
	}
	return true
}

func (context *Context) writeDataAssetDiagramGraphvizDOT(diagramFilenameDOT string, dpi int) *os.File {
	if *context.verbose {
		fmt.Println("Writing data asset diagram input")
	}
	var dotContent strings.Builder
	dotContent.WriteString("digraph generatedModel { concentrate=true \n")

	// Metadata init ===============================================================================
	dotContent.WriteString(`	graph [
		dpi=` + strconv.Itoa(dpi) + `
		fontname="Verdana"
		labelloc="c"
		fontsize="20"
		splines=false
		rankdir="LR"
		nodesep=1.0
		ranksep=3.0
        outputorder="nodesfirst"
	];
	node [
		fontcolor="white"
		fontname="Verdana"
		fontsize="20"
	];
	edge [
		shape="none"
		fontname="Verdana"
		fontsize="18"
	];
`)

	// Technical Assets ===============================================================================
	techAssets := make([]types.TechnicalAsset, 0)
	for _, techAsset := range context.parsedModel.TechnicalAssets {
		techAssets = append(techAssets, techAsset)
	}
	sort.Sort(types.ByOrderAndIdSort(techAssets))
	for _, technicalAsset := range techAssets {
		if len(technicalAsset.DataAssetsStored) > 0 || len(technicalAsset.DataAssetsProcessed) > 0 {
			dotContent.WriteString(context.makeTechAssetNode(technicalAsset, true))
			dotContent.WriteString("\n")
		}
	}

	// Data Assets ===============================================================================
	dataAssets := make([]types.DataAsset, 0)
	for _, dataAsset := range context.parsedModel.DataAssets {
		dataAssets = append(dataAssets, dataAsset)
	}

	types.SortByDataAssetDataBreachProbabilityAndTitle(&context.parsedModel, dataAssets)
	for _, dataAsset := range dataAssets {
		dotContent.WriteString(context.makeDataAssetNode(dataAsset))
		dotContent.WriteString("\n")
	}

	// Data Asset to Tech Asset links ===============================================================================
	for _, technicalAsset := range techAssets {
		for _, sourceId := range technicalAsset.DataAssetsStored {
			targetId := technicalAsset.Id
			dotContent.WriteString("\n")
			dotContent.WriteString(hash(sourceId) + " -> " + hash(targetId) +
				` [ color="blue" style="solid" ];`)
			dotContent.WriteString("\n")
		}
		for _, sourceId := range technicalAsset.DataAssetsProcessed {
			if !contains(technicalAsset.DataAssetsStored, sourceId) { // here only if not already drawn above
				targetId := technicalAsset.Id
				dotContent.WriteString("\n")
				dotContent.WriteString(hash(sourceId) + " -> " + hash(targetId) +
					` [ color="#666666" style="dashed" ];`)
				dotContent.WriteString("\n")
			}
		}
	}

	dotContent.WriteString("}")

	// Write the DOT file
	file, err := os.Create(diagramFilenameDOT)
	checkErr(err)
	defer func() { _ = file.Close() }()
	_, err = fmt.Fprintln(file, dotContent.String())
	checkErr(err)
	return file
}

func (context *Context) makeTechAssetNode(technicalAsset types.TechnicalAsset, simplified bool) string {
	if simplified {
		color := colors.RgbHexColorOutOfScope()
		if !technicalAsset.OutOfScope {
			generatedRisks := technicalAsset.GeneratedRisks(&context.parsedModel)
			switch types.HighestSeverityStillAtRisk(&context.parsedModel, generatedRisks) {
			case types.CriticalSeverity:
				color = colors.RgbHexColorCriticalRisk()
			case types.HighSeverity:
				color = colors.RgbHexColorHighRisk()
			case types.ElevatedSeverity:
				color = colors.RgbHexColorElevatedRisk()
			case types.MediumSeverity:
				color = colors.RgbHexColorMediumRisk()
			case types.LowSeverity:
				color = colors.RgbHexColorLowRisk()
			default:
				color = "#444444" // since black is too dark here as fill color
			}
			if len(types.ReduceToOnlyStillAtRisk(&context.parsedModel, generatedRisks)) == 0 {
				color = "#444444" // since black is too dark here as fill color
			}
		}
		return "  " + hash(technicalAsset.Id) + ` [ shape="box" style="filled" fillcolor="` + color + `"
				label=<<b>` + encode(technicalAsset.Title) + `</b>> penwidth="3.0" color="` + color + `" ];
				`
	} else {
		var shape, title string
		var lineBreak = ""
		switch technicalAsset.Type {
		case types.ExternalEntity:
			shape = "box"
			title = technicalAsset.Title
		case types.Process:
			shape = "ellipse"
			title = technicalAsset.Title
		case types.Datastore:
			shape = "cylinder"
			title = technicalAsset.Title
			if technicalAsset.Redundant {
				lineBreak = "<br/>"
			}
		}

		if technicalAsset.UsedAsClientByHuman {
			shape = "octagon"
		}

		// RAA = Relative Attacker Attractiveness
		raa := technicalAsset.RAA
		var attackerAttractivenessLabel string
		if technicalAsset.OutOfScope {
			attackerAttractivenessLabel = "<font point-size=\"15\" color=\"#603112\">RAA: out of scope</font>"
		} else {
			attackerAttractivenessLabel = "<font point-size=\"15\" color=\"#603112\">RAA: " + fmt.Sprintf("%.0f", raa) + " %</font>"
		}

		compartmentBorder := "0"
		if technicalAsset.MultiTenant {
			compartmentBorder = "1"
		}

		return "  " + hash(technicalAsset.Id) + ` [
	label=<<table border="0" cellborder="` + compartmentBorder + `" cellpadding="2" cellspacing="0"><tr><td><font point-size="15" color="` + colors.DarkBlue + `">` + lineBreak + technicalAsset.Technology.String() + `</font><br/><font point-size="15" color="` + colors.LightGray + `">` + technicalAsset.Size.String() + `</font></td></tr><tr><td><b><font color="` + technicalAsset.DetermineLabelColor(&context.parsedModel) + `">` + encode(title) + `</font></b><br/></td></tr><tr><td>` + attackerAttractivenessLabel + `</td></tr></table>>
	shape=` + shape + ` style="` + technicalAsset.DetermineShapeBorderLineStyle() + `,` + technicalAsset.DetermineShapeStyle() + `" penwidth="` + technicalAsset.DetermineShapeBorderPenWidth(&context.parsedModel) + `" fillcolor="` + technicalAsset.DetermineShapeFillColor(&context.parsedModel) + `"
	peripheries=` + strconv.Itoa(technicalAsset.DetermineShapePeripheries()) + `
	color="` + technicalAsset.DetermineShapeBorderColor(&context.parsedModel) + "\"\n  ]; "
	}
}

func (context *Context) makeDataAssetNode(dataAsset types.DataAsset) string {
	var color string
	switch dataAsset.IdentifiedDataBreachProbabilityStillAtRisk(&context.parsedModel) {
	case types.Probable:
		color = colors.RgbHexColorHighRisk()
	case types.Possible:
		color = colors.RgbHexColorMediumRisk()
	case types.Improbable:
		color = colors.RgbHexColorLowRisk()
	default:
		color = "#444444" // since black is too dark here as fill color
	}
	if !dataAsset.IsDataBreachPotentialStillAtRisk(&context.parsedModel) {
		color = "#444444" // since black is too dark here as fill color
	}
	return "  " + hash(dataAsset.Id) + ` [ label=<<b>` + encode(dataAsset.Title) + `</b>> penwidth="3.0" style="filled" fillcolor="` + color + `" color="` + color + "\"\n  ]; "
}

func (context *Context) renderDataFlowDiagramGraphvizImage(dotFile *os.File, targetDir string) {
	if *context.verbose {
		fmt.Println("Rendering data flow diagram input")
	}
	// tmp files
	tmpFileDOT, err := os.CreateTemp(*context.tempFolder, "diagram-*-.gv")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFileDOT.Name()) }()

	tmpFilePNG, err := os.CreateTemp(*context.tempFolder, "diagram-*-.png")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()

	// copy into tmp file as input
	inputDOT, err := os.ReadFile(dotFile.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(tmpFileDOT.Name(), inputDOT, 0644)
	if err != nil {
		fmt.Println("Error creating", tmpFileDOT.Name())
		fmt.Println(err)
		return
	}

	// exec
	cmd := exec.Command(filepath.Join(*context.binFolder, context.graphvizDataFlowDiagramConversionCall), tmpFileDOT.Name(), tmpFilePNG.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(errors.New("graph rendering call failed with error:" + err.Error()))
	}
	// copy into resulting file
	inputPNG, err := os.ReadFile(tmpFilePNG.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(filepath.Join(targetDir, context.dataFlowDiagramFilenamePNG), inputPNG, 0644)
	if err != nil {
		fmt.Println("Error creating", context.dataFlowDiagramFilenamePNG)
		fmt.Println(err)
		return
	}
}

func (context *Context) renderDataAssetDiagramGraphvizImage(dotFile *os.File, targetDir string) { // TODO dedupe with other render...() method here
	if *context.verbose {
		fmt.Println("Rendering data asset diagram input")
	}
	// tmp files
	tmpFileDOT, err := os.CreateTemp(*context.tempFolder, "diagram-*-.gv")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFileDOT.Name()) }()

	tmpFilePNG, err := os.CreateTemp(*context.tempFolder, "diagram-*-.png")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()

	// copy into tmp file as input
	inputDOT, err := os.ReadFile(dotFile.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(tmpFileDOT.Name(), inputDOT, 0644)
	if err != nil {
		fmt.Println("Error creating", tmpFileDOT.Name())
		fmt.Println(err)
		return
	}

	// exec
	cmd := exec.Command(filepath.Join(*context.binFolder, context.graphvizDataAssetDiagramConversionCall), tmpFileDOT.Name(), tmpFilePNG.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(errors.New("graph rendering call failed with error: " + err.Error()))
	}
	// copy into resulting file
	inputPNG, err := os.ReadFile(tmpFilePNG.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(filepath.Join(targetDir, context.dataAssetDiagramFilenamePNG), inputPNG, 0644)
	if err != nil {
		fmt.Println("Error creating", context.dataAssetDiagramFilenamePNG)
		fmt.Println(err)
		return
	}
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func lowerCaseAndTrim(tags []string) []string {
	for i := range tags {
		tags[i] = strings.ToLower(strings.TrimSpace(tags[i]))
	}
	return tags
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func hash(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%v", h.Sum32())
}

func encode(value string) string {
	return strings.ReplaceAll(value, "&", "&amp;")
}
