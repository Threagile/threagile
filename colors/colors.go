package colors

import (
	"encoding/hex"
	"github.com/jung-kurt/gofpdf"
)

const Red, Amber, Green, Blue, DarkBlue, Black, Gray, LightGray, MiddleLightGray, MoreLightGray, VeryLightGray, ExtremeLightGray, Pink, LightPink = "#CC0000", "#AF780E", "#008000", "#000080", "#000060", "#000000", "#444444", "#666666", "#999999", "#D2D2D2", "#E5E5E5", "#F6F6F6", "#F987C5", "#FFE7EF"
const ExtremeLightBlue, OutOfScopeFancy, CustomDevelopedParts = "#DDFFFF", "#D5D7FF", "#FFFC97"
const LightBlue = "#77FFFF"
const Brown = "#8C4C17"

func DarkenHexColor(hexString string) string {
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

func BrightenHexColor(hexString string) string {
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

func ColorCriticalRisk(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(255, 38, 0)
}
func RgbHexColorCriticalRisk() string {
	return "#FF2600"
}

func ColorHighRisk(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(160, 40, 30)
}
func RgbHexColorHighRisk() string {
	return "#A0281E"
}

func ColorElevatedRisk(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(255, 142, 0)
}
func RgbHexColorElevatedRisk() string {
	return "#FF8E00"
}

func ColorMediumRisk(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(200, 120, 50)
}
func RgbHexColorMediumRisk() string {
	return "#C87832"
}

func ColorLowRisk(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(35, 70, 95)
}
func RgbHexColorLowRisk() string {
	return "#23465F"
}

func ColorOutOfScope(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(127, 127, 127)
}
func RgbHexColorOutOfScope() string {
	return "#7F7F7F"
}

func ColorRiskStatusUnchecked(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(256, 0, 0)
}
func RgbHexColorRiskStatusUnchecked() string {
	return "#FF0000"
}

func ColorRiskStatusMitigated(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(0, 143, 0)
}
func RgbHexColorRiskStatusMitigated() string {
	return "#008F00"
}

func ColorRiskStatusInProgress(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(0, 0, 256)
}
func RgbHexColorRiskStatusInProgress() string {
	return "#0000FF"
}

func ColorRiskStatusAccepted(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(255, 64, 255)
}
func RgbHexColorRiskStatusAccepted() string {
	return "#FF40FF"
}

func ColorRiskStatusInDiscussion(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(256, 147, 0)
}
func RgbHexColorRiskStatusInDiscussion() string {
	return "#FF9300"
}

func ColorRiskStatusFalsePositive(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(102, 102, 102)
}
func RgbHexColorRiskStatusFalsePositive() string {
	return "#666666"
}

func ColorTwilight(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(58, 82, 200)
}
func RgbHexColorTwilight() string {
	return "#3A52C8"
}

func ColorBusiness(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(83, 27, 147)
}
func RgbHexColorBusiness() string {
	return "#531B93"
}

func ColorArchitecture(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(0, 84, 147)
}
func RgbHexColorArchitecture() string {
	return "#005493"
}

func ColorDevelopment(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(222, 146, 35)
}
func RgbHexColorDevelopment() string {
	return "#DE9223"
}

func ColorOperation(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(148, 127, 80)
}
func RgbHexColorOperation() string {
	return "#947F50"
}

func ColorModelFailure(pdf *gofpdf.Fpdf) {
	pdf.SetTextColor(148, 82, 0)
}
func RgbHexColorModelFailure() string {
	return "#945200"
}
