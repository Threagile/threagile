package report

import (
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/colors"
	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/security/types"
)

func WriteDataFlowDiagramGraphvizDOT(parsedModel *types.ParsedModel,
	diagramFilenameDOT string, dpi int, addModelTitle bool,
	progressReporter progressReporter) *os.File {
	progressReporter.Info("Writing data flow diagram input")

	var dotContent strings.Builder
	dotContent.WriteString("digraph generatedModel { concentrate=false \n")

	// Metadata init ===============================================================================
	tweaks := ""
	if parsedModel.DiagramTweakNodesep > 0 {
		tweaks += "\n		nodesep=\"" + strconv.Itoa(parsedModel.DiagramTweakNodesep) + "\""
	}
	if parsedModel.DiagramTweakRanksep > 0 {
		tweaks += "\n		ranksep=\"" + strconv.Itoa(parsedModel.DiagramTweakRanksep) + "\""
	}
	suppressBidirectionalArrows := true
	drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks := true
	splines := "ortho"
	if len(parsedModel.DiagramTweakEdgeLayout) > 0 {
		switch parsedModel.DiagramTweakEdgeLayout {
		case "spline":
			splines = "spline"
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "polyline":
			splines = "polyline"
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "ortho":
			splines = "ortho"
			suppressBidirectionalArrows = true
		case "curved":
			splines = "curved"
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "false":
			splines = "false"
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		default:
			panic(errors.New("unknown value for diagram_tweak_suppress_edge_labels (spline, polyline, ortho, curved, false): " +
				parsedModel.DiagramTweakEdgeLayout))
		}
	}
	rankdir := "TB"
	if parsedModel.DiagramTweakLayoutLeftToRight {
		rankdir = "LR"
	}
	modelTitle := ""
	if addModelTitle {
		modelTitle = `label="` + parsedModel.Title + `"`
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
	for k := range parsedModel.TrustBoundaries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		trustBoundary := parsedModel.TrustBoundaries[key]
		var snippet strings.Builder
		if len(trustBoundary.TechnicalAssetsInside) > 0 || len(trustBoundary.TrustBoundariesNested) > 0 {
			if drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks {
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
			if len(trustBoundary.ParentTrustBoundaryID(parsedModel)) > 0 {
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
				technicalAsset := parsedModel.TechnicalAssets[technicalAssetInside]
				snippet.WriteString(hash(technicalAsset.Id))
				snippet.WriteString(";\n")
			}
			keys = trustBoundary.TrustBoundariesNested
			sort.Strings(keys)
			for _, trustBoundaryNested := range keys {
				//log.Println("About to add nested trust boundary to trust boundary: ", trustBoundaryNested)
				trustBoundaryNested := parsedModel.TrustBoundaries[trustBoundaryNested]
				snippet.WriteString("LINK-NEEDS-REPLACED-BY-cluster_" + hash(trustBoundaryNested.Id))
				snippet.WriteString(";\n")
			}
			snippet.WriteString(" }\n\n")
			if drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks {
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
	for _, techAsset := range parsedModel.TechnicalAssets {
		techAssets = append(techAssets, techAsset)
	}
	sort.Sort(types.ByOrderAndIdSort(techAssets))
	for _, technicalAsset := range techAssets {
		dotContent.WriteString(makeTechAssetNode(parsedModel, technicalAsset, false))
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
			arrowStyle = ` style="` + dataFlow.DetermineArrowLineStyle() + `" penwidth="` + dataFlow.DetermineArrowPenWidth(parsedModel) + `" arrowtail="` + readOrWriteTail + `" arrowhead="` + readOrWriteHead + `" dir="` + dir + `" arrowsize="2.0" `
			arrowColor = ` color="` + dataFlow.DetermineArrowColor(parsedModel) + `"`
			tweaks := ""
			if dataFlow.DiagramTweakWeight > 0 {
				tweaks += " weight=\"" + strconv.Itoa(dataFlow.DiagramTweakWeight) + "\" "
			}

			dotContent.WriteString("\n")
			dotContent.WriteString("  " + hash(sourceId) + " -> " + hash(targetId) +
				` [` + arrowColor + ` ` + arrowStyle + tweaks + ` constraint=` + strconv.FormatBool(dataFlow.DiagramTweakConstraint) + ` `)
			if !parsedModel.DiagramTweakSuppressEdgeLabels {
				dotContent.WriteString(` xlabel="` + encode(dataFlow.Protocol.String()) + `" fontcolor="` + dataFlow.DetermineLabelColor(parsedModel) + `" `)
			}
			dotContent.WriteString(" ];\n")
		}
	}

	dotContent.WriteString(makeDiagramInvisibleConnectionsTweaks(parsedModel))
	dotContent.WriteString(makeDiagramSameRankNodeTweaks(parsedModel))

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

func GenerateDataFlowDiagramGraphvizImage(dotFile *os.File, targetDir string,
	tempFolder, binFolder, dataFlowDiagramFilenamePNG string, progressReporter progressReporter) error {
	progressReporter.Info("Rendering data flow diagram input")
	// tmp files
	tmpFileDOT, err := os.CreateTemp(tempFolder, "diagram-*-.gv")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFileDOT.Name()) }()

	tmpFilePNG, err := os.CreateTemp(tempFolder, "diagram-*-.png")
	checkErr(err)
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()

	// copy into tmp file as input
	inputDOT, err := os.ReadFile(dotFile.Name())
	if err != nil {
		return fmt.Errorf("Error reading %s: %v", dotFile.Name(), err)
	}
	err = os.WriteFile(tmpFileDOT.Name(), inputDOT, 0644)
	if err != nil {
		return fmt.Errorf("Error creating %s: %v", tmpFileDOT.Name(), err)
	}

	// exec
	cmd := exec.Command(filepath.Join(binFolder, common.GraphvizDataFlowDiagramConversionCall), tmpFileDOT.Name(), tmpFilePNG.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(errors.New("graph rendering call failed with error:" + err.Error()))
	}
	// copy into resulting file
	inputPNG, err := os.ReadFile(tmpFilePNG.Name())
	if err != nil {
		return fmt.Errorf("Error copying into resulting file %s: %v", tmpFilePNG.Name(), err)
	}
	err = os.WriteFile(filepath.Join(targetDir, dataFlowDiagramFilenamePNG), inputPNG, 0644)
	if err != nil {
		return fmt.Errorf("Error creating %s: %v", filepath.Join(targetDir, dataFlowDiagramFilenamePNG), err)
	}
	return nil
}

func makeDiagramSameRankNodeTweaks(parsedModel *types.ParsedModel) string {
	// see https://stackoverflow.com/questions/25734244/how-do-i-place-nodes-on-the-same-level-in-dot
	tweak := ""
	if len(parsedModel.DiagramTweakSameRankAssets) > 0 {
		for _, sameRank := range parsedModel.DiagramTweakSameRankAssets {
			assetIDs := strings.Split(sameRank, ":")
			if len(assetIDs) > 0 {
				tweak += "{ rank=same; "
				for _, id := range assetIDs {
					checkErr(parsedModel.CheckTechnicalAssetExists(id, "diagram tweak same-rank", true))
					if len(parsedModel.TechnicalAssets[id].GetTrustBoundaryId(parsedModel)) > 0 {
						panic(errors.New("technical assets (referenced in same rank diagram tweak) are inside trust boundaries: " +
							fmt.Sprintf("%v", parsedModel.DiagramTweakSameRankAssets)))
					}
					tweak += " " + hash(id) + "; "
				}
				tweak += " }"
			}
		}
	}
	return tweak
}

func makeDiagramInvisibleConnectionsTweaks(parsedModel *types.ParsedModel) string {
	// see https://stackoverflow.com/questions/2476575/how-to-control-node-placement-in-graphviz-i-e-avoid-edge-crossings
	tweak := ""
	if len(parsedModel.DiagramTweakInvisibleConnectionsBetweenAssets) > 0 {
		for _, invisibleConnections := range parsedModel.DiagramTweakInvisibleConnectionsBetweenAssets {
			assetIDs := strings.Split(invisibleConnections, ":")
			if len(assetIDs) == 2 {
				checkErr(parsedModel.CheckTechnicalAssetExists(assetIDs[0], "diagram tweak connections", true))
				checkErr(parsedModel.CheckTechnicalAssetExists(assetIDs[1], "diagram tweak connections", true))
				tweak += "\n" + hash(assetIDs[0]) + " -> " + hash(assetIDs[1]) + " [style=invis]; \n"
			}
		}
	}
	return tweak
}

func WriteDataAssetDiagramGraphvizDOT(parsedModel *types.ParsedModel, diagramFilenameDOT string, dpi int,
	progressReporter progressReporter) *os.File {
	progressReporter.Info("Writing data asset diagram input")

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
	for _, techAsset := range parsedModel.TechnicalAssets {
		techAssets = append(techAssets, techAsset)
	}
	sort.Sort(types.ByOrderAndIdSort(techAssets))
	for _, technicalAsset := range techAssets {
		if len(technicalAsset.DataAssetsStored) > 0 || len(technicalAsset.DataAssetsProcessed) > 0 {
			dotContent.WriteString(makeTechAssetNode(parsedModel, technicalAsset, true))
			dotContent.WriteString("\n")
		}
	}

	// Data Assets ===============================================================================
	dataAssets := make([]types.DataAsset, 0)
	for _, dataAsset := range parsedModel.DataAssets {
		dataAssets = append(dataAssets, dataAsset)
	}

	types.SortByDataAssetDataBreachProbabilityAndTitle(parsedModel, dataAssets)
	for _, dataAsset := range dataAssets {
		dotContent.WriteString(makeDataAssetNode(parsedModel, dataAsset))
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

func makeDataAssetNode(parsedModel *types.ParsedModel, dataAsset types.DataAsset) string {
	var color string
	switch dataAsset.IdentifiedDataBreachProbabilityStillAtRisk(parsedModel) {
	case types.Probable:
		color = colors.RgbHexColorHighRisk()
	case types.Possible:
		color = colors.RgbHexColorMediumRisk()
	case types.Improbable:
		color = colors.RgbHexColorLowRisk()
	default:
		color = "#444444" // since black is too dark here as fill color
	}
	if !dataAsset.IsDataBreachPotentialStillAtRisk(parsedModel) {
		color = "#444444" // since black is too dark here as fill color
	}
	return "  " + hash(dataAsset.Id) + ` [ label=<<b>` + encode(dataAsset.Title) + `</b>> penwidth="3.0" style="filled" fillcolor="` + color + `" color="` + color + "\"\n  ]; "
}

func makeTechAssetNode(parsedModel *types.ParsedModel, technicalAsset types.TechnicalAsset, simplified bool) string {
	if simplified {
		color := colors.RgbHexColorOutOfScope()
		if !technicalAsset.OutOfScope {
			generatedRisks := technicalAsset.GeneratedRisks(parsedModel)
			switch types.HighestSeverityStillAtRisk(parsedModel, generatedRisks) {
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
			if len(types.ReduceToOnlyStillAtRisk(parsedModel, generatedRisks)) == 0 {
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
	label=<<table border="0" cellborder="` + compartmentBorder + `" cellpadding="2" cellspacing="0"><tr><td><font point-size="15" color="` + colors.DarkBlue + `">` + lineBreak + technicalAsset.Technology.String() + `</font><br/><font point-size="15" color="` + colors.LightGray + `">` + technicalAsset.Size.String() + `</font></td></tr><tr><td><b><font color="` + technicalAsset.DetermineLabelColor(parsedModel) + `">` + encode(title) + `</font></b><br/></td></tr><tr><td>` + attackerAttractivenessLabel + `</td></tr></table>>
	shape=` + shape + ` style="` + technicalAsset.DetermineShapeBorderLineStyle() + `,` + technicalAsset.DetermineShapeStyle() + `" penwidth="` + technicalAsset.DetermineShapeBorderPenWidth(parsedModel) + `" fillcolor="` + technicalAsset.DetermineShapeFillColor(parsedModel) + `"
	peripheries=` + strconv.Itoa(technicalAsset.DetermineShapePeripheries()) + `
	color="` + technicalAsset.DetermineShapeBorderColor(parsedModel) + "\"\n  ]; "
	}
}

func GenerateDataAssetDiagramGraphvizImage(dotFile *os.File, targetDir string,
	tempFolder, binFolder, dataAssetDiagramFilenamePNG string, progressReporter progressReporter) error { // TODO dedupe with other render...() method here
	progressReporter.Info("Rendering data asset diagram input")
	// tmp files
	tmpFileDOT, err := os.CreateTemp(tempFolder, "diagram-*-.gv")
	if err != nil {
		return fmt.Errorf("Error creating temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFileDOT.Name()) }()

	tmpFilePNG, err := os.CreateTemp(tempFolder, "diagram-*-.png")
	if err != nil {
		return fmt.Errorf("Error creating temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFilePNG.Name()) }()

	// copy into tmp file as input
	inputDOT, err := os.ReadFile(dotFile.Name())
	if err != nil {
		return fmt.Errorf("Error reading %s: %v", dotFile.Name(), err)
	}
	err = os.WriteFile(tmpFileDOT.Name(), inputDOT, 0644)
	if err != nil {
		return fmt.Errorf("Error creating %s: %v", tmpFileDOT.Name(), err)
	}

	// exec
	cmd := exec.Command(filepath.Join(binFolder, common.GraphvizDataAssetDiagramConversionCall), tmpFileDOT.Name(), tmpFilePNG.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return errors.New("graph rendering call failed with error: " + err.Error())
	}
	// copy into resulting file
	inputPNG, err := os.ReadFile(tmpFilePNG.Name())
	if err != nil {
		return fmt.Errorf("Error copying into resulting file %s: %v", tmpFilePNG.Name(), err)
	}
	err = os.WriteFile(filepath.Join(targetDir, dataAssetDiagramFilenamePNG), inputPNG, 0644)
	if err != nil {
		return fmt.Errorf("Error creating %s: %v", filepath.Join(targetDir, dataAssetDiagramFilenamePNG), err)
	}
	return nil
}

func hash(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%v", h.Sum32())
}

func encode(value string) string {
	return strings.ReplaceAll(value, "&", "&amp;")
}
