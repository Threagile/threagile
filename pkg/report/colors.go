package report

import (
	"encoding/hex"
	"fmt"

	"github.com/jung-kurt/gofpdf"
	"github.com/threagile/threagile/pkg/security/types"
)

const (
	Amber                = "#AF780E"
	Green                = "#008000"
	Blue                 = "#000080"
	DarkBlue             = "#000060"
	Black                = "#000000"
	Gray                 = "#444444"
	LightGray            = "#666666"
	MiddleLightGray      = "#999999"
	MoreLightGray        = "#D2D2D2"
	VeryLightGray        = "#E5E5E5"
	ExtremeLightGray     = "#F6F6F6"
	Pink                 = "#F987C5"
	LightPink            = "#FFE7EF"
	Red                  = "#CC0000"
	OutOfScopeFancy      = "#D5D7FF"
	CustomDevelopedParts = "#FFFC97"
	ExtremeLightBlue     = "#DDFFFF"
	LightBlue            = "#77FFFF"
	Brown                = "#8C4C17"
)

func darkenHexColor(hexString string) string {
	colorBytes, _ := hex.DecodeString(hexString[1:])
	adjusted := make([]byte, 3)
	for i := 0; i < 3; i++ {
		if colorBytes[i] > 0x22 {
			adjusted[i] = colorBytes[i] - 0x20
		} else {
			adjusted[i] = 0x00
		}
	}
	return "#" + hex.EncodeToString(adjusted)
}

func brightenHexColor(hexString string) string {
	colorBytes, _ := hex.DecodeString(hexString[1:])
	adjusted := make([]byte, 3)
	for i := 0; i < 3; i++ {
		if colorBytes[i] < 0xDD {
			adjusted[i] = colorBytes[i] + 0x20
		} else {
			adjusted[i] = 0xFF
		}
	}
	return "#" + hex.EncodeToString(adjusted)
}

func colorCriticalRisk(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(255, 38, 0)
}
func rgbHexColorCriticalRisk() string {
	return "#FF2600"
}

func colorHighRisk(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(160, 40, 30)
}
func rgbHexColorHighRisk() string {
	return "#A0281E"
}

func colorElevatedRisk(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(255, 142, 0)
}
func rgbHexColorElevatedRisk() string {
	return "#FF8E00"
}

func colorMediumRisk(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(200, 120, 50)
}
func rgbHexColorMediumRisk() string {
	return "#C87832"
}

func colorLowRisk(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(35, 70, 95)
}
func rgbHexColorLowRisk() string {
	return "#23465F"
}

func rgbHexColorOutOfScope() string {
	return "#7F7F7F"
}

func colorRiskStatusUnchecked(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(256, 0, 0)
}
func RgbHexColorRiskStatusUnchecked() string {
	return "#FF0000"
}

func colorRiskStatusMitigated(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(0, 143, 0)
}
func rgbHexColorRiskStatusMitigated() string {
	return "#008F00"
}

func colorRiskStatusInProgress(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(0, 0, 256)
}
func rgbHexColorRiskStatusInProgress() string {
	return "#0000FF"
}

func colorRiskStatusAccepted(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(255, 64, 255)
}
func rgbHexColorRiskStatusAccepted() string {
	return "#FF40FF"
}

func colorRiskStatusInDiscussion(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(256, 147, 0)
}
func rgbHexColorRiskStatusInDiscussion() string {
	return "#FF9300"
}

func colorRiskStatusFalsePositive(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(102, 102, 102)
}
func rgbHexColorRiskStatusFalsePositive() string {
	return "#666666"
}

func colorTwilight(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(58, 82, 200)
}
func rgbHexColorTwilight() string {
	return "#3A52C8"
}

func colorBusiness(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(83, 27, 147)
}
func rgbHexColorBusiness() string {
	return "#531B93"
}

func colorArchitecture(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(0, 84, 147)
}
func rgbHexColorArchitecture() string {
	return "#005493"
}

func colorDevelopment(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(222, 146, 35)
}
func rgbHexColorDevelopment() string {
	return "#DE9223"
}

func colorOperation(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(148, 127, 80)
}
func rgbHexColorOperation() string {
	return "#947F50"
}

func colorModelFailure(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(148, 82, 0)
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

// dotted when model forgery attempt (i.e. nothing being processed or stored)

func determineShapeBorderLineStyle(ta types.TechnicalAsset) string {
	if len(ta.DataAssetsProcessed) == 0 || ta.OutOfScope {
		return "dotted" // dotted, because it's strange when too many technical communication links transfer no data... some ok, but many in a diagram ist a sign of model forgery...
	}
	return "solid"
}

// 3 when redundant

func determineShapePeripheries(ta types.TechnicalAsset) int {
	if ta.Redundant {
		return 2
	}
	return 1
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
