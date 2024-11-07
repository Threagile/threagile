package report

import (
	"fmt"
	"strings"

	"github.com/threagile/threagile/pkg/types"
	"github.com/xuri/excelize/v2"
)

type ExcelStyles struct {
	severityCriticalBold   int
	severityCriticalCenter int
	severityHighBold       int
	severityHighCenter     int
	severityElevatedBold   int
	severityElevatedCenter int
	severityMediumBold     int
	severityMediumCenter   int
	severityLowBold        int
	severityLowCenter      int
	redCenter              int
	greenCenter            int
	blueCenter             int
	yellowCenter           int
	orangeCenter           int
	grayCenter             int
	blackLeft              int
	blackLeftBold          int
	blackCenter            int
	blackRight             int
	blackSmall             int
	graySmall              int
	blackBold              int
	mitigation             int
	headCenter             int
	headCenterBoldItalic   int
	headCenterBold         int
}

func NewExcelStyles(excel *excelize.File, config reportConfigReader) (*ExcelStyles, error) {
	if excel == nil {
		return nil, fmt.Errorf("no excel file provided to create styles")
	}

	creator := new(styleCreator).Init(excel)
	return &ExcelStyles{
		severityCriticalBold: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorCriticalRisk(), 12, true, false, config),
		}),
		severityCriticalCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorCriticalRisk(), 12, true, false, config),
		}),
		severityHighBold: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorHighRisk(), 12, true, false, config),
		}),
		severityHighCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorHighRisk(), 12, false, false, config),
		}),
		severityElevatedBold: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorElevatedRisk(), 12, true, false, config),
		}),
		severityElevatedCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorElevatedRisk(), 12, false, false, config),
		}),
		severityMediumBold: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorMediumRisk(), 12, true, false, config),
		}),
		severityMediumCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorMediumRisk(), 12, false, false, config),
		}),
		severityLowBold: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorLowRisk(), 12, true, false, config),
		}),
		severityLowCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorLowRisk(), 12, false, false, config),
		}),
		redCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorLowRisk(), 12, false, false, config),
		}),
		greenCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorRiskStatusMitigated(), 12, false, false, config),
		}),
		blueCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorRiskStatusInProgress(), 12, false, false, config),
		}),
		yellowCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorRiskStatusAccepted(), 12, false, false, config),
		}),
		orangeCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorRiskStatusInDiscussion(), 12, false, false, config),
		}),
		grayCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont(rgbHexColorRiskStatusFalsePositive(), 12, false, false, config),
		}),
		blackLeft: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("left", config),
			Font:      getFont("#000000", 12, false, false, config),
		}),
		blackCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont("#000000", 12, false, false, config),
		}),
		blackRight: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("right", config),
			Font:      getFont("#000000", 12, false, false, config),
		}),
		blackSmall: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("", config),
			Font:      getFont("#000000", 10, false, false, config),
		}),
		graySmall: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("", config),
			Font:      getFont(rgbHexColorOutOfScope(), 10, false, false, config),
		}),
		blackBold: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont("#000000", 12, true, false, config),
		}),
		blackLeftBold: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("left", config),
			Font:      getFont("#000000", 12, true, false, config),
		}),
		mitigation: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("", config),
			Font:      getFont(rgbHexColorRiskStatusMitigated(), 10, false, false, config),
		}),
		headCenterBoldItalic: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont("#000000", 14, true, false, config),
			Fill: excelize.Fill{
				Type:    "pattern",
				Color:   []string{"#eeeeee"},
				Pattern: 1,
			},
		}),
		headCenterBold: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont("#000000", 14, true, false, config),
			Fill:      getFill("#eeeeee"),
		}),
		headCenter: creator.NewStyle(&excelize.Style{
			Alignment: getAlignment("center", config),
			Font:      getFont("#000000", 14, false, false, config),
			Fill:      getFill("#eeeeee"),
		}),
	}, creator.Error
}

func getFont(color string, size float64, bold bool, italic bool, config reportConfigReader) *excelize.Font {
	actualColor := "#000000" // default color
	if config.GetRiskExcelColorText() {
		actualColor = color
	}
	return &excelize.Font{
		Color:  actualColor,
		Size:   size,
		Bold:   bold,
		Italic: italic,
	}
}

func getAlignment(horizontal string, config reportConfigReader) *excelize.Alignment {
	return &excelize.Alignment{
		Horizontal:  horizontal,
		ShrinkToFit: config.GetRiskExcelShrinkColumnsToFit(),
		WrapText:    config.GetRiskExcelWrapText(),
	}
}

func getFill(color string) excelize.Fill {
	return excelize.Fill{
		Type:    "pattern",
		Color:   []string{color},
		Pattern: 1,
	}
}

func (what *ExcelStyles) Get(column string, status types.RiskStatus, severity types.RiskSeverity) int {
	switch strings.ToUpper(column) {
	case "A", "B", "C", "D", "E", "F":
		if !status.IsStillAtRisk() {
			return what.blackCenter
		}

		switch severity {
		case types.CriticalSeverity:
			return what.severityCriticalCenter

		case types.HighSeverity:
			return what.severityHighCenter

		case types.ElevatedSeverity:
			return what.severityElevatedCenter

		case types.MediumSeverity:
			return what.severityMediumCenter

		case types.LowSeverity:
			return what.severityLowCenter
		}

	case "G", "H", "I":
		if !status.IsStillAtRisk() {
			return what.blackBold
		}

		switch severity {
		case types.CriticalSeverity:
			return what.severityCriticalBold

		case types.HighSeverity:
			return what.severityHighBold

		case types.ElevatedSeverity:
			return what.severityElevatedBold

		case types.MediumSeverity:
			return what.severityMediumBold

		case types.LowSeverity:
			return what.severityLowBold
		}

	case "J":
		return what.blackRight

	case "K":
		return what.blackSmall

	case "L", "M", "N":
		return what.mitigation

	case "O":
		return what.graySmall

	case "P":
		switch status {
		case types.Unchecked:
			return what.redCenter

		case types.Mitigated:
			return what.greenCenter

		case types.InProgress:
			return what.blueCenter

		case types.Accepted:
			return what.yellowCenter

		case types.InDiscussion:
			return what.orangeCenter

		case types.FalsePositive:
			return what.grayCenter

		default:
			return what.blackCenter
		}

	case "Q":
		return what.blackSmall

	case "R", "S":
		return what.blackCenter

	case "T":
		return what.blackLeft
	}

	return what.blackRight
}

type styleCreator struct {
	ExcelFile *excelize.File
	Error     error
}

func (what *styleCreator) Init(excel *excelize.File) *styleCreator {
	what.ExcelFile = excel
	return what
}

func (what *styleCreator) NewStyle(style *excelize.Style) int {
	if what.Error != nil {
		return 0
	}

	var styleID int
	styleID, what.Error = what.ExcelFile.NewStyle(style)

	return styleID
}
