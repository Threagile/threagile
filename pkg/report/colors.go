package report

import (
	"encoding/hex"

	"github.com/jung-kurt/gofpdf"
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
