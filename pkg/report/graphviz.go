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

	"github.com/threagile/threagile/pkg/security/types"
)

func WriteDataFlowDiagramGraphvizDOT(parsedModel *types.ParsedModel,
	diagramFilenameDOT string, dpi int, addModelTitle bool,
	progressReporter progressReporter) (*os.File, error) {
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
			return nil, fmt.Errorf("unknown value for diagram_tweak_suppress_edge_labels (spline, polyline, ortho, curved, false): %s", parsedModel.DiagramTweakEdgeLayout)
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
			color, fontColor, bgColor, style, fontname := rgbHexColorTwilight(), rgbHexColorTwilight() /*"#550E0C"*/, "#FAFAFA", "dashed", "Verdana"
			penWidth := 4.5
			if len(trustBoundary.TrustBoundariesNested) > 0 {
				//color, fontColor, style, fontname = Blue, Blue, "dashed", "Verdana"
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
			arrowStyle = ` style="` + determineArrowLineStyle(dataFlow) + `" penwidth="` + determineArrowPenWidth(dataFlow, parsedModel) + `" arrowtail="` + readOrWriteTail + `" arrowhead="` + readOrWriteHead + `" dir="` + dir + `" arrowsize="2.0" `
			arrowColor = ` color="` + determineArrowColor(dataFlow, parsedModel) + `"`
			tweaks := ""
			if dataFlow.DiagramTweakWeight > 0 {
				tweaks += " weight=\"" + strconv.Itoa(dataFlow.DiagramTweakWeight) + "\" "
			}

			dotContent.WriteString("\n")
			dotContent.WriteString("  " + hash(sourceId) + " -> " + hash(targetId) +
				` [` + arrowColor + ` ` + arrowStyle + tweaks + ` constraint=` + strconv.FormatBool(dataFlow.DiagramTweakConstraint) + ` `)
			if !parsedModel.DiagramTweakSuppressEdgeLabels {
				dotContent.WriteString(` xlabel="` + encode(dataFlow.Protocol.String()) + `" fontcolor="` + determineLabelColor(dataFlow, parsedModel) + `" `)
			}
			dotContent.WriteString(" ];\n")
		}
	}

	diagramInvisibleConnectionsTweaks, err := makeDiagramInvisibleConnectionsTweaks(parsedModel)
	if err != nil {
		return nil, fmt.Errorf("error while making diagram invisible connections tweaks: %s", err)
	}
	dotContent.WriteString(diagramInvisibleConnectionsTweaks)

	diagramSameRankNodeTweaks, err := makeDiagramSameRankNodeTweaks(parsedModel)
	if err != nil {
		return nil, fmt.Errorf("error while making diagram same-rank node tweaks: %s", err)
	}
	dotContent.WriteString(diagramSameRankNodeTweaks)

	dotContent.WriteString("}")

	//fmt.Println(dotContent.String())

	// Write the DOT file
	file, err := os.Create(filepath.Clean(diagramFilenameDOT))
	if err != nil {
		return nil, fmt.Errorf("Error creating %s: %v", diagramFilenameDOT, err)
	}
	defer func() { _ = file.Close() }()
	_, err = fmt.Fprintln(file, dotContent.String())
	if err != nil {
		return nil, fmt.Errorf("Error writing %s: %v", diagramFilenameDOT, err)
	}
	return file, nil
}

// Pen Widths:

func determineArrowPenWidth(cl types.CommunicationLink, parsedModel *types.ParsedModel) string {
	if determineArrowColor(cl, parsedModel) == Pink {
		return fmt.Sprintf("%f", 3.0)
	}
	if determineArrowColor(cl, parsedModel) != Black {
		return fmt.Sprintf("%f", 2.5)
	}
	return fmt.Sprintf("%f", 1.5)
}

func determineLabelColor(cl types.CommunicationLink, parsedModel *types.ParsedModel) string {
	// TODO: Just move into main.go and let the generated risk determine the color, don't duplicate the logic here
	/*
		if dataFlow.Protocol.IsEncrypted() {
			return Gray
		} else {*/
	// check for red
	for _, sentDataAsset := range cl.DataAssetsSent {
		if parsedModel.DataAssets[sentDataAsset].Integrity == types.MissionCritical {
			return Red
		}
	}
	for _, receivedDataAsset := range cl.DataAssetsReceived {
		if parsedModel.DataAssets[receivedDataAsset].Integrity == types.MissionCritical {
			return Red
		}
	}
	// check for amber
	for _, sentDataAsset := range cl.DataAssetsSent {
		if parsedModel.DataAssets[sentDataAsset].Integrity == types.Critical {
			return Amber
		}
	}
	for _, receivedDataAsset := range cl.DataAssetsReceived {
		if parsedModel.DataAssets[receivedDataAsset].Integrity == types.Critical {
			return Amber
		}
	}
	// default
	return Gray
}

func determineArrowLineStyle(cl types.CommunicationLink) string {
	if len(cl.DataAssetsSent) == 0 && len(cl.DataAssetsReceived) == 0 {
		return "dotted" // dotted, because it's strange when too many technical communication links transfer no data... some ok, but many in a diagram ist a sign of model forgery...
	}
	if cl.Usage == types.DevOps {
		return "dashed"
	}
	return "solid"
}

// pink when model forgery attempt (i.e. nothing being sent and received)
func determineArrowColor(cl types.CommunicationLink, parsedModel *types.ParsedModel) string {
	// TODO: Just move into main.go and let the generated risk determine the color, don't duplicate the logic here
	if len(cl.DataAssetsSent) == 0 && len(cl.DataAssetsReceived) == 0 ||
		cl.Protocol == types.UnknownProtocol {
		return Pink // pink, because it's strange when too many technical communication links transfer no data... some ok, but many in a diagram ist a sign of model forgery...
	}
	if cl.Usage == types.DevOps {
		return MiddleLightGray
	} else if cl.VPN {
		return DarkBlue
	} else if cl.IpFiltered {
		return Brown
	}
	// check for red
	for _, sentDataAsset := range cl.DataAssetsSent {
		if parsedModel.DataAssets[sentDataAsset].Confidentiality == types.StrictlyConfidential {
			return Red
		}
	}
	for _, receivedDataAsset := range cl.DataAssetsReceived {
		if parsedModel.DataAssets[receivedDataAsset].Confidentiality == types.StrictlyConfidential {
			return Red
		}
	}
	// check for amber
	for _, sentDataAsset := range cl.DataAssetsSent {
		if parsedModel.DataAssets[sentDataAsset].Confidentiality == types.Confidential {
			return Amber
		}
	}
	for _, receivedDataAsset := range cl.DataAssetsReceived {
		if parsedModel.DataAssets[receivedDataAsset].Confidentiality == types.Confidential {
			return Amber
		}
	}
	// default
	return Black
	/*
		} else if dataFlow.Authentication != NoneAuthentication {
			return Black
		} else {
			// check for red
			for _, sentDataAsset := range dataFlow.DataAssetsSent { // first check if any red?
				if ParsedModelRoot.DataAssets[sentDataAsset].Integrity == MissionCritical {
					return Red
				}
			}
			for _, receivedDataAsset := range dataFlow.DataAssetsReceived { // first check if any red?
				if ParsedModelRoot.DataAssets[receivedDataAsset].Integrity == MissionCritical {
					return Red
				}
			}
			// check for amber
			for _, sentDataAsset := range dataFlow.DataAssetsSent { // then check if any amber?
				if ParsedModelRoot.DataAssets[sentDataAsset].Integrity == Critical {
					return Amber
				}
			}
			for _, receivedDataAsset := range dataFlow.DataAssetsReceived { // then check if any amber?
				if ParsedModelRoot.DataAssets[receivedDataAsset].Integrity == Critical {
					return Amber
				}
			}
			return Black
		}
	*/
}

func GenerateDataFlowDiagramGraphvizImage(dotFile *os.File, targetDir string,
	tempFolder, binFolder, dataFlowDiagramFilenamePNG string, progressReporter progressReporter) error {
	progressReporter.Info("Rendering data flow diagram input")
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
	err = os.WriteFile(tmpFileDOT.Name(), inputDOT, 0600)
	if err != nil {
		return fmt.Errorf("Error creating %s: %v", tmpFileDOT.Name(), err)
	}

	// exec

	cmd := exec.Command("dot", "-Tpng", tmpFileDOT.Name(), "-o", tmpFilePNG.Name()) // #nosec G204
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
	err = os.WriteFile(filepath.Join(targetDir, dataFlowDiagramFilenamePNG), inputPNG, 0600)
	if err != nil {
		return fmt.Errorf("Error creating %s: %v", filepath.Join(targetDir, dataFlowDiagramFilenamePNG), err)
	}
	return nil
}

func makeDiagramSameRankNodeTweaks(parsedModel *types.ParsedModel) (string, error) {
	// see https://stackoverflow.com/questions/25734244/how-do-i-place-nodes-on-the-same-level-in-dot
	tweak := ""
	if len(parsedModel.DiagramTweakSameRankAssets) > 0 {
		for _, sameRank := range parsedModel.DiagramTweakSameRankAssets {
			assetIDs := strings.Split(sameRank, ":")
			if len(assetIDs) > 0 {
				tweak += "{ rank=same; "
				for _, id := range assetIDs {
					err := parsedModel.CheckTechnicalAssetExists(id, "diagram tweak same-rank", true)
					if err != nil {
						return "", fmt.Errorf("error while checking technical asset existence: %s", err)
					}
					if len(parsedModel.TechnicalAssets[id].GetTrustBoundaryId(parsedModel)) > 0 {
						return "", fmt.Errorf("technical assets (referenced in same rank diagram tweak) are inside trust boundaries: " +
							fmt.Sprintf("%v", parsedModel.DiagramTweakSameRankAssets))
					}
					tweak += " " + hash(id) + "; "
				}
				tweak += " }"
			}
		}
	}
	return tweak, nil
}

func makeDiagramInvisibleConnectionsTweaks(parsedModel *types.ParsedModel) (string, error) {
	// see https://stackoverflow.com/questions/2476575/how-to-control-node-placement-in-graphviz-i-e-avoid-edge-crossings
	tweak := ""
	if len(parsedModel.DiagramTweakInvisibleConnectionsBetweenAssets) > 0 {
		for _, invisibleConnections := range parsedModel.DiagramTweakInvisibleConnectionsBetweenAssets {
			assetIDs := strings.Split(invisibleConnections, ":")
			if len(assetIDs) == 2 {
				err := parsedModel.CheckTechnicalAssetExists(assetIDs[0], "diagram tweak connections", true)
				if err != nil {
					return "", fmt.Errorf("error while checking technical asset existence: %s", err)
				}
				err = parsedModel.CheckTechnicalAssetExists(assetIDs[1], "diagram tweak connections", true)
				if err != nil {
					return "", fmt.Errorf("error while checking technical asset existence: %s", err)
				}

				tweak += "\n" + hash(assetIDs[0]) + " -> " + hash(assetIDs[1]) + " [style=invis]; \n"
			}
		}
	}
	return tweak, nil
}

func WriteDataAssetDiagramGraphvizDOT(parsedModel *types.ParsedModel, diagramFilenameDOT string, dpi int,
	progressReporter progressReporter) (*os.File, error) {
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
	file, err := os.Create(filepath.Clean(diagramFilenameDOT))
	if err != nil {
		return nil, fmt.Errorf("Error creating %s: %v", diagramFilenameDOT, err)
	}
	defer func() { _ = file.Close() }()
	_, err = fmt.Fprintln(file, dotContent.String())
	if err != nil {
		return nil, fmt.Errorf("Error writing %s: %v", diagramFilenameDOT, err)
	}
	return file, nil
}

func makeDataAssetNode(parsedModel *types.ParsedModel, dataAsset types.DataAsset) string {
	var color string
	switch dataAsset.IdentifiedDataBreachProbabilityStillAtRisk(parsedModel) {
	case types.Probable:
		color = rgbHexColorHighRisk()
	case types.Possible:
		color = rgbHexColorMediumRisk()
	case types.Improbable:
		color = rgbHexColorLowRisk()
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
		color := rgbHexColorOutOfScope()
		if !technicalAsset.OutOfScope {
			generatedRisks := technicalAsset.GeneratedRisks(parsedModel)
			switch types.HighestSeverityStillAtRisk(parsedModel, generatedRisks) {
			case types.CriticalSeverity:
				color = rgbHexColorCriticalRisk()
			case types.HighSeverity:
				color = rgbHexColorHighRisk()
			case types.ElevatedSeverity:
				color = rgbHexColorElevatedRisk()
			case types.MediumSeverity:
				color = rgbHexColorMediumRisk()
			case types.LowSeverity:
				color = rgbHexColorLowRisk()
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
	label=<<table border="0" cellborder="` + compartmentBorder + `" cellpadding="2" cellspacing="0"><tr><td><font point-size="15" color="` + DarkBlue + `">` + lineBreak + technicalAsset.Technology.String() + `</font><br/><font point-size="15" color="` + LightGray + `">` + technicalAsset.Size.String() + `</font></td></tr><tr><td><b><font color="` + determineTechnicalAssetLabelColor(technicalAsset, parsedModel) + `">` + encode(title) + `</font></b><br/></td></tr><tr><td>` + attackerAttractivenessLabel + `</td></tr></table>>
	shape=` + shape + ` style="` + determineShapeBorderLineStyle(technicalAsset) + `,` + determineShapeStyle(technicalAsset) + `" penwidth="` + determineShapeBorderPenWidth(technicalAsset, parsedModel) + `" fillcolor="` + determineShapeFillColor(technicalAsset, parsedModel) + `"
	peripheries=` + strconv.Itoa(determineShapePeripheries(technicalAsset)) + `
	color="` + determineShapeBorderColor(technicalAsset, parsedModel) + "\"\n  ]; "
	}
}

func determineShapeStyle(ta types.TechnicalAsset) string {
	return "filled"
}

func determineShapeFillColor(ta types.TechnicalAsset, parsedModel *types.ParsedModel) string {
	fillColor := VeryLightGray
	if len(ta.DataAssetsProcessed) == 0 && len(ta.DataAssetsStored) == 0 ||
		ta.Technology == types.UnknownTechnology {
		fillColor = LightPink // lightPink, because it's strange when too many technical assets process no data... some ok, but many in a diagram ist a sign of model forgery...
	} else if len(ta.CommunicationLinks) == 0 && len(parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[ta.Id]) == 0 {
		fillColor = LightPink
	} else if ta.Internet {
		fillColor = ExtremeLightBlue
	} else if ta.OutOfScope {
		fillColor = OutOfScopeFancy
	} else if ta.CustomDevelopedParts {
		fillColor = CustomDevelopedParts
	}
	switch ta.Machine {
	case types.Physical:
		fillColor = darkenHexColor(fillColor)
	case types.Container:
		fillColor = brightenHexColor(fillColor)
	case types.Serverless:
		fillColor = brightenHexColor(brightenHexColor(fillColor))
	case types.Virtual:
	}
	return fillColor
}

func determineShapeBorderPenWidth(ta types.TechnicalAsset, parsedModel *types.ParsedModel) string {
	if determineShapeBorderColor(ta, parsedModel) == Pink {
		return fmt.Sprintf("%f", 3.5)
	}
	if determineShapeBorderColor(ta, parsedModel) != Black {
		return fmt.Sprintf("%f", 3.0)
	}
	return fmt.Sprintf("%f", 2.0)
}

// red when mission-critical integrity, but still unauthenticated (non-readonly) channels access it
// amber when critical integrity, but still unauthenticated (non-readonly) channels access it
// pink when model forgery attempt (i.e. nothing being processed)
func determineShapeBorderColor(ta types.TechnicalAsset, parsedModel *types.ParsedModel) string {
	// Check for red
	if ta.Confidentiality == types.StrictlyConfidential {
		return Red
	}
	for _, processedDataAsset := range ta.DataAssetsProcessed {
		if parsedModel.DataAssets[processedDataAsset].Confidentiality == types.StrictlyConfidential {
			return Red
		}
	}
	// Check for amber
	if ta.Confidentiality == types.Confidential {
		return Amber
	}
	for _, processedDataAsset := range ta.DataAssetsProcessed {
		if parsedModel.DataAssets[processedDataAsset].Confidentiality == types.Confidential {
			return Amber
		}
	}
	return Black
	/*
		if what.Integrity == MissionCritical {
			for _, dataFlow := range IncomingTechnicalCommunicationLinksMappedByTargetId[what.Id] {
				if !dataFlow.Readonly && dataFlow.Authentication == NoneAuthentication {
					return Red
				}
			}
		}

		if what.Integrity == Critical {
			for _, dataFlow := range IncomingTechnicalCommunicationLinksMappedByTargetId[what.Id] {
				if !dataFlow.Readonly && dataFlow.Authentication == NoneAuthentication {
					return Amber
				}
			}
		}

		if len(what.DataAssetsProcessed) == 0 && len(what.DataAssetsStored) == 0 {
			return Pink // pink, because it's strange when too many technical assets process no data... some are ok, but many in a diagram is a sign of model forgery...
		}

		return Black
	*/
}

func determineShapePeripheries(ta types.TechnicalAsset) int {
	if ta.Redundant {
		return 2
	}
	return 1
}

// dotted when model forgery attempt (i.e. nothing being processed or stored)
func determineShapeBorderLineStyle(ta types.TechnicalAsset) string {
	if len(ta.DataAssetsProcessed) == 0 || ta.OutOfScope {
		return "dotted" // dotted, because it's strange when too many technical communication links transfer no data... some ok, but many in a diagram ist a sign of model forgery...
	}
	return "solid"
}

// red when >= confidential data stored in unencrypted technical asset
func determineTechnicalAssetLabelColor(ta types.TechnicalAsset, model *types.ParsedModel) string {
	// TODO: Just move into main.go and let the generated risk determine the color, don't duplicate the logic here
	// Check for red
	if ta.Integrity == types.MissionCritical {
		return Red
	}
	for _, storedDataAsset := range ta.DataAssetsStored {
		if model.DataAssets[storedDataAsset].Integrity == types.MissionCritical {
			return Red
		}
	}
	for _, processedDataAsset := range ta.DataAssetsProcessed {
		if model.DataAssets[processedDataAsset].Integrity == types.MissionCritical {
			return Red
		}
	}
	// Check for amber
	if ta.Integrity == types.Critical {
		return Amber
	}
	for _, storedDataAsset := range ta.DataAssetsStored {
		if model.DataAssets[storedDataAsset].Integrity == types.Critical {
			return Amber
		}
	}
	for _, processedDataAsset := range ta.DataAssetsProcessed {
		if model.DataAssets[processedDataAsset].Integrity == types.Critical {
			return Amber
		}
	}
	return Black
	/*
		if what.Encrypted {
			return Black
		} else {
			if what.Confidentiality == StrictlyConfidential {
				return Red
			}
			for _, storedDataAsset := range what.DataAssetsStored {
				if ParsedModelRoot.DataAssets[storedDataAsset].Confidentiality == StrictlyConfidential {
					return Red
				}
			}
			if what.Confidentiality == Confidential {
				return Amber
			}
			for _, storedDataAsset := range what.DataAssetsStored {
				if ParsedModelRoot.DataAssets[storedDataAsset].Confidentiality == Confidential {
					return Amber
				}
			}
			return Black
		}
	*/
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
	err = os.WriteFile(tmpFileDOT.Name(), inputDOT, 0600)
	if err != nil {
		return fmt.Errorf("Error creating %s: %v", tmpFileDOT.Name(), err)
	}

	// exec
	cmd := exec.Command("dot", "-Tpng", tmpFileDOT.Name(), "-o", tmpFilePNG.Name()) // #nosec G204
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
	err = os.WriteFile(filepath.Join(targetDir, dataAssetDiagramFilenamePNG), inputPNG, 0600)
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
